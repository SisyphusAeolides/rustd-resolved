//! Answer NXDOMAIN/NODATA from cached NSEC/NSEC3 ranges without upstream.
#![allow(missing_debug_implementations)]

use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

const NSEC3_SHA1_ALGORITHM: u8 = 1;
const NSEC3_ITERATION_LIMIT: u16 = 2500;
const DNS_NAME_MAX: usize = 255;
const DNS_LABEL_MAX: usize = 63;

#[derive(Clone, Debug)]
pub struct NsecRange {
    pub zone: Vec<u8>,
    pub owner: Vec<u8>,
    pub next: Vec<u8>,
    pub types: bitflags_types::TypeBitmap,
    pub expires: Instant,
    pub secure: bool,
    pub nsec3: bool,
    pub nsec3_params: Option<Nsec3Params>,
    pub owner_hash: Option<Vec<u8>>,
    pub next_hash: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Nsec3Params {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

pub mod bitflags_types {
    #[derive(Clone, Debug, Default)]
    pub struct TypeBitmap {
        /// RFC 4034 section 4.1.2 window blocks.
        pub bits: Vec<u8>,
    }

    impl TypeBitmap {
        pub fn contains(&self, rrtype: u16) -> bool {
            let wanted_window = (rrtype >> 8) as u8;
            let wanted_bit = usize::from(rrtype & 0xff);
            let wanted_byte = wanted_bit / 8;
            let wanted_mask = 0x80u8 >> (wanted_bit % 8);
            let mut offset = 0usize;
            let mut previous_window = None;

            while offset < self.bits.len() {
                let Some((&window, rest)) = self.bits[offset..].split_first() else {
                    return false;
                };
                let Some((&length, _)) = rest.split_first() else {
                    return false;
                };
                let length = usize::from(length);
                if length == 0 || length > 32 {
                    return false;
                }
                let start = match offset.checked_add(2) {
                    Some(value) => value,
                    None => return false,
                };
                let end = match start.checked_add(length) {
                    Some(value) if value <= self.bits.len() => value,
                    _ => return false,
                };
                if previous_window.is_some_and(|previous| window <= previous) {
                    return false;
                }
                previous_window = Some(window);

                if window == wanted_window {
                    return wanted_byte < length
                        && self.bits[start + wanted_byte] & wanted_mask != 0;
                }
                if window > wanted_window {
                    return false;
                }
                offset = end;
            }
            false
        }
    }
}

#[derive(Default)]
pub struct AggressiveNsec {
    /// Keyed by zone-apex canonical wire name.
    zones: RwLock<BTreeMap<Vec<u8>, Vec<NsecRange>>>,
    hits: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggAnswer {
    NxDomain,
    NoData,
    /// The proof is insufficient and the query must go upstream.
    Miss,
}

impl AggressiveNsec {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert_ranges(&self, ranges: Vec<NsecRange>) {
        let mut zones = self.zones.write();
        for range in ranges {
            zones.entry(range.zone.clone()).or_default().push(range);
        }
    }

    pub fn lookup(&self, qname: &[u8], qtype: u16, now: Instant) -> AggAnswer {
        let zones = self.zones.read();
        for ranges in zones.values() {
            for range in ranges {
                if range.expires <= now || !range.secure {
                    continue;
                }
                if range.nsec3 {
                    if let (Some(owner_hash), Some(next_hash), Some(parameters)) =
                        (&range.owner_hash, &range.next_hash, &range.nsec3_params)
                    {
                        let query_hash = nsec3_hash(parameters, qname);
                        if query_hash.is_empty() {
                            continue;
                        }
                        if &query_hash == owner_hash {
                            if range.types.contains(qtype) {
                                return AggAnswer::Miss;
                            }
                            self.record_hit();
                            return AggAnswer::NoData;
                        }
                        if hash_covers(owner_hash, next_hash, &query_hash) {
                            self.record_hit();
                            return AggAnswer::NxDomain;
                        }
                    }
                } else if range.owner == qname {
                    if range.types.contains(qtype) {
                        return AggAnswer::Miss;
                    }
                    self.record_hit();
                    return AggAnswer::NoData;
                } else if name_covers(&range.owner, &range.next, qname) {
                    self.record_hit();
                    return AggAnswer::NxDomain;
                }
            }
        }
        AggAnswer::Miss
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn name_covers(owner: &[u8], next: &[u8], query: &[u8]) -> bool {
    if owner < next {
        owner < query && query < next
    } else {
        query > owner || query < next
    }
}

fn hash_covers(owner_hash: &[u8], next_hash: &[u8], query_hash: &[u8]) -> bool {
    if owner_hash < next_hash {
        owner_hash < query_hash && query_hash < next_hash
    } else {
        query_hash > owner_hash || query_hash < next_hash
    }
}

/// Calculate the RFC 5155 NSEC3 SHA-1 hash of an uncompressed DNS wire name.
///
/// Unsupported algorithms, malformed names, oversized salts, and iteration
/// counts above the implementation limit fail closed with an empty result.
pub fn nsec3_hash(parameters: &Nsec3Params, qname: &[u8]) -> Vec<u8> {
    if parameters.hash_alg != NSEC3_SHA1_ALGORITHM
        || parameters.iterations > NSEC3_ITERATION_LIMIT
        || parameters.salt.len() > u8::MAX as usize
    {
        return Vec::new();
    }
    let Some(canonical_name) = canonical_wire_name(qname) else {
        return Vec::new();
    };

    let mut material = Vec::with_capacity(canonical_name.len() + parameters.salt.len());
    material.extend_from_slice(&canonical_name);
    material.extend_from_slice(&parameters.salt);
    let mut digest = sha1(&material);

    for _ in 0..parameters.iterations {
        material.clear();
        material.extend_from_slice(&digest);
        material.extend_from_slice(&parameters.salt);
        digest = sha1(&material);
    }
    digest.to_vec()
}

fn canonical_wire_name(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() > DNS_NAME_MAX {
        return None;
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0usize;
    loop {
        let length = usize::from(*input.get(offset)?);
        if length == 0 {
            if offset + 1 != input.len() {
                return None;
            }
            output.push(0);
            return Some(output);
        }
        if length > DNS_LABEL_MAX || length & 0xc0 != 0 {
            return None;
        }
        let start = offset.checked_add(1)?;
        let end = start.checked_add(length)?;
        let label = input.get(start..end)?;
        output.push(length as u8);
        output.extend(label.iter().map(u8::to_ascii_lowercase));
        offset = end;
    }
}

fn sha1(input: &[u8]) -> [u8; 20] {
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(input.len().saturating_add(72));
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-1 word"));
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        for (index, word) in words.into_iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut output = [0u8; 20];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::bitflags_types::TypeBitmap;
    use super::*;

    fn wire_name(name: &str) -> Vec<u8> {
        let mut output = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            output.push(label.len() as u8);
            output.extend_from_slice(label.as_bytes());
        }
        output.push(0);
        output
    }

    #[test]
    fn parses_rfc4034_type_bitmap_windows() {
        let bitmap = TypeBitmap {
            bits: vec![
                0, 6, 0x40, 0, 0, 0, 0, 0x01, // A and NSEC
                1, 1, 0x80, // type 256
            ],
        };
        assert!(bitmap.contains(1));
        assert!(bitmap.contains(47));
        assert!(bitmap.contains(256));
        assert!(!bitmap.contains(2));
        assert!(!bitmap.contains(257));
    }

    #[test]
    fn rejects_malformed_type_bitmaps() {
        assert!(!TypeBitmap { bits: vec![0] }.contains(1));
        assert!(!TypeBitmap { bits: vec![0, 0] }.contains(1));
        assert!(!TypeBitmap {
            bits: vec![0, 2, 0x40],
        }
        .contains(1));
        assert!(!TypeBitmap {
            bits: vec![1, 1, 0x80, 0, 1, 0x40],
        }
        .contains(1));
    }

    #[test]
    fn sha1_matches_standard_vector() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
    }

    #[test]
    fn nsec3_hash_matches_rfc5155_example() {
        let parameters = Nsec3Params {
            hash_alg: 1,
            flags: 0,
            iterations: 12,
            salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        assert_eq!(
            nsec3_hash(&parameters, &wire_name("EXAMPLE.")),
            vec![
                0x06, 0x53, 0x68, 0xab, 0xee, 0xd7, 0xec, 0x6e, 0x9f, 0xeb, 0xa9, 0x6b, 0x8c, 0x8b,
                0xc3, 0xe8, 0xb7, 0x91, 0xf7, 0x16,
            ]
        );
    }

    #[test]
    fn nsec3_hash_rejects_unsupported_or_malformed_inputs() {
        let mut parameters = Nsec3Params {
            hash_alg: 2,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
        };
        assert!(nsec3_hash(&parameters, &wire_name("example.")).is_empty());
        parameters.hash_alg = 1;
        parameters.iterations = NSEC3_ITERATION_LIMIT + 1;
        assert!(nsec3_hash(&parameters, &wire_name("example.")).is_empty());
        parameters.iterations = 0;
        assert!(nsec3_hash(&parameters, b"\xc0\x0c").is_empty());
    }
}
