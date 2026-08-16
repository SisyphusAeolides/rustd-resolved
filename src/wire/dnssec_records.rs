// SPDX-License-Identifier: LGPL-2.1-or-later
pub const TYPE_DS: u16 = 43;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_NSEC3: u16 = 50;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec3ParamRecord {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt_length: u8,
    pub salt: Vec<u8>,
}

impl Nsec3ParamRecord {
    pub fn parse(rdata: &[u8]) -> Result<Self, WireError> {
        if rdata.len() < 5 {
            return Err(WireError::InvalidRecord);
        }
        let salt_length = rdata[4];
        if rdata.len() != 5 + usize::from(salt_length) {
            return Err(WireError::InvalidRecord);
        }
        Ok(Self {
            hash_algorithm: rdata[0],
            flags: rdata[1],
            iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
            salt_length,
            salt: rdata[5..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: DnsName,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NsecRecord {
    pub next_domain: DnsName,
    pub types: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec3Record {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Vec<u8>,
    pub types: Vec<u16>,
}

pub fn parse_dnskey(record: &ResourceRecord) -> Result<DnskeyRecord, WireError> {
    if record.rr_type != TYPE_DNSKEY || record.rdata.len() < 4 {
        return Err(WireError::InvalidRecord);
    }
    let protocol = record.rdata[2];
    let public_key = record.rdata[4..].to_vec();
    if protocol != 3 || public_key.is_empty() {
        return Err(WireError::InvalidRecord);
    }
    Ok(DnskeyRecord {
        flags: u16::from_be_bytes([record.rdata[0], record.rdata[1]]),
        protocol,
        algorithm: record.rdata[3],
        public_key,
    })
}

pub fn parse_ds(record: &ResourceRecord) -> Result<DsRecord, WireError> {
    if record.rr_type != TYPE_DS || record.rdata.len() < 5 {
        return Err(WireError::InvalidRecord);
    }
    let digest_type = record.rdata[3];
    let digest = record.rdata[4..].to_vec();
    let expected = match digest_type {
        1 => 20,
        2 => 32,
        4 => 48,
        _ => digest.len(),
    };
    if digest.is_empty() || digest.len() != expected {
        return Err(WireError::InvalidRecord);
    }
    Ok(DsRecord {
        key_tag: u16::from_be_bytes([record.rdata[0], record.rdata[1]]),
        algorithm: record.rdata[2],
        digest_type,
        digest,
    })
}

pub fn parse_rrsig(packet: &[u8], record: &ResourceRecord) -> Result<RrsigRecord, WireError> {
    if record.rr_type != TYPE_RRSIG || record.rdata.len() < RRSIG_MINIMUM_RDATA_LEN {
        return Err(WireError::InvalidRecord);
    }
    let signer_offset = checked_end(record.rdata_offset, RRSIG_FIXED_FIELDS_LEN)?;
    let (signer, signature_offset) = read_name(packet, signer_offset)?;
    if signature_offset >= record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    let signature = packet
        .get(signature_offset..record.next_offset)
        .ok_or(WireError::InvalidRecord)?
        .to_vec();
    if signature.is_empty() {
        return Err(WireError::InvalidRecord);
    }
    Ok(RrsigRecord {
        type_covered: u16::from_be_bytes([record.rdata[0], record.rdata[1]]),
        algorithm: record.rdata[2],
        labels: record.rdata[3],
        original_ttl: u32::from_be_bytes(record.rdata[4..8].try_into().map_err(|_| WireError::InvalidRecord)?),
        expiration: u32::from_be_bytes(record.rdata[8..12].try_into().map_err(|_| WireError::InvalidRecord)?),
        inception: u32::from_be_bytes(record.rdata[12..16].try_into().map_err(|_| WireError::InvalidRecord)?),
        key_tag: u16::from_be_bytes([record.rdata[16], record.rdata[17]]),
        signer,
        signature,
    })
}

pub fn parse_nsec(packet: &[u8], record: &ResourceRecord) -> Result<NsecRecord, WireError> {
    if record.rr_type != TYPE_NSEC || record.rdata.is_empty() {
        return Err(WireError::InvalidRecord);
    }
    let (next_domain, bitmap_offset) = read_name(packet, record.rdata_offset)?;
    if bitmap_offset >= record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    let bitmap = packet
        .get(bitmap_offset..record.next_offset)
        .ok_or(WireError::InvalidRecord)?;
    Ok(NsecRecord {
        next_domain,
        types: parse_type_bitmap(bitmap)?,
    })
}

pub fn parse_nsec3(record: &ResourceRecord) -> Result<Nsec3Record, WireError> {
    if record.rr_type != TYPE_NSEC3 || record.rdata.len() < 6 {
        return Err(WireError::InvalidRecord);
    }
    let salt_len = usize::from(record.rdata[4]);
    let salt_end = 5usize.checked_add(salt_len).ok_or(WireError::InvalidRecord)?;
    let hash_len = usize::from(*record.rdata.get(salt_end).ok_or(WireError::InvalidRecord)?);
    let hash_start = salt_end + 1;
    let hash_end = hash_start.checked_add(hash_len).ok_or(WireError::InvalidRecord)?;
    if hash_len == 0 || hash_end > record.rdata.len() {
        return Err(WireError::InvalidRecord);
    }
    Ok(Nsec3Record {
        hash_algorithm: record.rdata[0],
        flags: record.rdata[1],
        iterations: u16::from_be_bytes([record.rdata[2], record.rdata[3]]),
        salt: record.rdata[5..salt_end].to_vec(),
        next_hashed_owner: record.rdata[hash_start..hash_end].to_vec(),
        types: if hash_end == record.rdata.len() {
            Vec::new()
        } else {
            parse_type_bitmap(&record.rdata[hash_end..])?
        },
    })
}

pub fn parse_nsec3param(record: &ResourceRecord) -> Result<Nsec3ParamRecord, WireError> {
    if record.rr_type != TYPE_NSEC3PARAM || record.rdata.len() < 5 {
        return Err(WireError::InvalidRecord);
    }
    let salt_len = usize::from(record.rdata[4]);
    let salt_end = 5usize.checked_add(salt_len).ok_or(WireError::InvalidRecord)?;
    if salt_end != record.rdata.len() {
        return Err(WireError::InvalidRecord);
    }
    Ok(Nsec3ParamRecord {
        hash_algorithm: record.rdata[0],
        flags: record.rdata[1],
        iterations: u16::from_be_bytes([record.rdata[2], record.rdata[3]]),
        salt_length: record.rdata[4],
        salt: record.rdata[5..salt_end].to_vec(),
    })
}

pub fn dnskey_key_tag(record: &ResourceRecord) -> Result<u16, WireError> {
    if record.rr_type != TYPE_DNSKEY || record.rdata.len() < 4 {
        return Err(WireError::InvalidRecord);
    }
    if record.rdata[3] == 1 {
        if record.rdata.len() < 4 {
            return Err(WireError::InvalidRecord);
        }
        return Ok(u16::from_be_bytes([
            record.rdata[record.rdata.len() - 3],
            record.rdata[record.rdata.len() - 2],
        ]));
    }
    let mut accumulator = 0u32;
    for (index, byte) in record.rdata.iter().copied().enumerate() {
        accumulator = accumulator.wrapping_add(if index & 1 == 0 {
            u32::from(byte) << 8
        } else {
            u32::from(byte)
        });
    }
    accumulator = accumulator.wrapping_add((accumulator >> 16) & 0xffff);
    Ok((accumulator & 0xffff) as u16)
}

fn parse_type_bitmap(bitmap: &[u8]) -> Result<Vec<u16>, WireError> {
    let mut offset = 0usize;
    let mut previous_window = None;
    let mut types = Vec::new();
    while offset < bitmap.len() {
        let window = *bitmap.get(offset).ok_or(WireError::InvalidRecord)?;
        let length = usize::from(*bitmap.get(offset + 1).ok_or(WireError::InvalidRecord)?);
        if length == 0 || length > 32 || previous_window.is_some_and(|previous| window <= previous) {
            return Err(WireError::InvalidRecord);
        }
        let start = offset + 2;
        let end = start.checked_add(length).ok_or(WireError::InvalidRecord)?;
        let bytes = bitmap.get(start..end).ok_or(WireError::InvalidRecord)?;
        if bytes.last() == Some(&0) {
            return Err(WireError::InvalidRecord);
        }
        for (octet, byte) in bytes.iter().copied().enumerate() {
            for bit in 0..8usize {
                if byte & (0x80 >> bit) != 0 {
                    let low = octet * 8 + bit;
                    let rr_type = u16::from(window) * 256
                        + u16::try_from(low).map_err(|_| WireError::InvalidRecord)?;
                    types.push(rr_type);
                }
            }
        }
        previous_window = Some(window);
        offset = end;
    }
    if types.is_empty() {
        return Err(WireError::InvalidRecord);
    }
    Ok(types)
}

#[cfg(test)]
mod dnssec_record_tests {
    use super::*;

    #[test]
    fn computes_dnskey_key_tag() {
        let record = ResourceRecord {
            name: DnsName { text: ".".to_owned(), canonical_wire: vec![0] },
            rr_type: TYPE_DNSKEY,
            class: CLASS_IN,
            ttl: 0,
            ttl_offset: 0,
            rdata_offset: 0,
            rdata: vec![0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
            next_offset: 0,
        };
        assert_eq!(dnskey_key_tag(&record), Ok(1803));
    }

    #[test]
    fn parses_nsec_type_bitmaps() {
        let types = parse_type_bitmap(&[0, 6, 0x40, 0, 0, 0, 0, 0x03]).expect("bitmap");
        assert_eq!(types, vec![1, 46, 47]);
    }

    #[test]
    fn parses_nsec3_with_an_empty_type_bitmap() {
        let mut rdata = vec![1, 1, 0, 0, 0, 20];
        rdata.extend_from_slice(&[0xaa; 20]);
        let record = ResourceRecord {
            name: DnsName {
                text: "hash.example".to_owned(),
                canonical_wire: vec![4, b'h', b'a', b's', b'h', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0],
            },
            rr_type: TYPE_NSEC3,
            class: CLASS_IN,
            ttl: 0,
            ttl_offset: 0,
            rdata_offset: 0,
            next_offset: rdata.len(),
            rdata,
        };
        let parsed = parse_nsec3(&record).expect("empty NSEC3 bitmap");
        assert!(parsed.types.is_empty());
        assert_eq!(parsed.flags, 1);
    }

    #[test]
    fn rejects_noncanonical_nsec_type_bitmaps() {
        assert!(parse_type_bitmap(&[0, 1, 0]).is_err());
        assert!(parse_type_bitmap(&[1, 1, 1, 1, 1, 1]).is_err());
    }
}
