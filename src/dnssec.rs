// SPDX-License-Identifier: LGPL-2.1-or-later
pub mod canonical;
pub mod nta;

use crate::wire::{
    dnskey_key_tag, parse_dnskey, parse_ds, parse_rrsig, ResourceRecord, WireError, TYPE_DNSKEY,
};
use std::error::Error;
use std::fmt;
use std::io;
use std::os::raw::{c_int, c_void};
use std::time::SystemTime;

const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;
const DNSKEY_FLAG_ZONE_KEY: u16 = 1 << 8;

extern "C" {
    fn resolved_dnssec_digest(
        digest_type: u8,
        data: *const c_void,
        length: usize,
        output: *mut u8,
        capacity: usize,
    ) -> c_int;
    fn resolved_dnssec_verify(
        algorithm: u8,
        key: *const u8,
        key_length: usize,
        data: *const u8,
        data_length: usize,
        signature: *const u8,
        signature_length: usize,
    ) -> c_int;
}

#[derive(Debug)]
pub enum DnssecError {
    Wire(WireError),
    Io(io::Error),
    UnsupportedDigest(u8),
    UnsupportedAlgorithm(u8),
}

impl fmt::Display for DnssecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::UnsupportedDigest(digest) => {
                write!(formatter, "unsupported DNSSEC DS digest type {digest}")
            }
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(
                    formatter,
                    "unsupported DNSSEC signature algorithm {algorithm}"
                )
            }
        }
    }
}

impl Error for DnssecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::UnsupportedDigest(_) | Self::UnsupportedAlgorithm(_) => None,
        }
    }
}

impl From<WireError> for DnssecError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<io::Error> for DnssecError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn dnskey_ds_digest(
    dnskey_record: &ResourceRecord,
    digest_type: u8,
) -> Result<Vec<u8>, DnssecError> {
    parse_dnskey(dnskey_record)?;
    let output_length = match digest_type {
        1 => 20,
        2 => 32,
        4 => 48,
        other => return Err(DnssecError::UnsupportedDigest(other)),
    };
    let mut input =
        Vec::with_capacity(dnskey_record.name.canonical_wire().len() + dnskey_record.rdata.len());
    input.extend_from_slice(dnskey_record.name.canonical_wire());
    input.extend_from_slice(&dnskey_record.rdata);
    let mut output = vec![0; output_length];
    // SAFETY: input and output are valid contiguous buffers for the duration of the digest call.
    let result = unsafe {
        resolved_dnssec_digest(
            digest_type,
            input.as_ptr().cast::<c_void>(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result).into());
    }
    let result = usize::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid DNSSEC digest length"))?;
    if result != output_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected DNSSEC digest length",
        )
        .into());
    }
    Ok(output)
}

pub fn ds_matches_dnskey(
    ds_record: &ResourceRecord,
    dnskey_record: &ResourceRecord,
) -> Result<bool, DnssecError> {
    let ds = parse_ds(ds_record)?;
    let dnskey = parse_dnskey(dnskey_record)?;
    if ds.algorithm != dnskey.algorithm || ds.key_tag != dnskey_key_tag(dnskey_record)? {
        return Ok(false);
    }
    Ok(ds.digest == dnskey_ds_digest(dnskey_record, ds.digest_type)?)
}

pub fn verify_signature(
    algorithm: u8,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, DnssecError> {
    if !matches!(algorithm, 5 | 7 | 8 | 10 | 13 | 14 | 15) {
        return Err(DnssecError::UnsupportedAlgorithm(algorithm));
    }
    // SAFETY: every pointer references its corresponding immutable slice for the duration of the call.
    let result = unsafe {
        resolved_dnssec_verify(
            algorithm,
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    if result == 1 {
        return Ok(true);
    }
    if result == 0 {
        return Ok(false);
    }
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result).into());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid DNSSEC signature verification result",
    )
    .into())
}

pub fn verify_rrsig(
    packet: &[u8],
    rrsig_record: &ResourceRecord,
    rrset: &[ResourceRecord],
    dnskey_record: &ResourceRecord,
    now: SystemTime,
) -> Result<bool, DnssecError> {
    let Some(first) = rrset.first() else {
        return Err(WireError::InvalidRecord.into());
    };
    let signature = parse_rrsig(packet, rrsig_record)?;
    let dnskey = parse_dnskey(dnskey_record)?;
    if rrsig_record.class != first.class
        || rrsig_record.name.canonical_wire() != first.name.canonical_wire()
        || dnskey_record.class != first.class
        || dnskey_record.name.canonical_wire() != signature.signer.canonical_wire()
        || dnskey.algorithm != signature.algorithm
        || dnskey_key_tag(dnskey_record)? != signature.key_tag
        || dnskey.flags & DNSKEY_FLAG_ZONE_KEY == 0
        || dnskey.flags & DNSKEY_FLAG_REVOKE != 0
        || rrset
            .iter()
            .any(|record| record.ttl > signature.original_ttl)
        || !canonical::rrsig_time_valid(&signature, now)
    {
        return Ok(false);
    }
    let signed_data = canonical::canonical_signed_data(packet, rrsig_record, rrset)?;
    if !verify_signature(
        signature.algorithm,
        &dnskey.public_key,
        &signed_data,
        &signature.signature,
    )? {
        return Ok(false);
    }

    if first.rr_type == TYPE_DNSKEY && first.name.canonical_wire() == [0] {
        if let Err(error) = crate::dnssec_rfc5011_runtime::observe_authenticated_dnskey_rrset(
            packet,
            rrset,
            std::slice::from_ref(dnskey_record),
            now,
        ) {
            eprintln!(
                "rustd-resolved: authenticated root DNSKEY verified but RFC5011 state update failed: {error}"
            );
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        encode_name, parse_record, CLASS_IN, TYPE_A, TYPE_DNSKEY, TYPE_DS, TYPE_RRSIG,
    };
    use std::time::{Duration, UNIX_EPOCH};

    const ED25519_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const ED25519_EMPTY_SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    const EXAMPLE_A_SIGNATURE: [u8; 64] = [
        0xe1, 0x81, 0x5f, 0x4f, 0x6d, 0x63, 0x78, 0x64, 0x7f, 0xd4, 0x47, 0x02, 0xbe, 0x7f, 0x01,
        0xd7, 0x80, 0xb4, 0x0e, 0x63, 0x3d, 0x3b, 0xca, 0x9c, 0x18, 0x9b, 0xc7, 0xc1, 0x96, 0x53,
        0xa6, 0xdd, 0xa4, 0xa9, 0x04, 0x9e, 0xd2, 0xf4, 0x16, 0xdd, 0x74, 0xc9, 0xff, 0x5c, 0xb6,
        0x88, 0x94, 0x7e, 0x21, 0x98, 0x55, 0x59, 0x96, 0xc6, 0x47, 0xb6, 0x9f, 0xda, 0x7e, 0xe2,
        0xc7, 0x36, 0xdc, 0x05,
    ];

    fn record_wire(owner: &str, rr_type: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut packet = encode_name(owner).expect("owner name");
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
        packet
    }

    fn record(owner: &str, rr_type: u16, rdata: &[u8]) -> ResourceRecord {
        let packet = record_wire(owner, rr_type, 60, rdata);
        parse_record(&packet, 0).expect("resource record")
    }

    #[test]
    fn dnskey_sha256_digest_uses_canonical_owner_wire() {
        let dnskey = record(
            "ExAmPlE.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        let expected = [
            0xa7, 0x3c, 0x5f, 0x58, 0x2d, 0x70, 0xc3, 0x7a, 0x22, 0x89, 0x98, 0x09, 0x6a, 0x1d,
            0x1d, 0x51, 0x85, 0xb9, 0xe8, 0xf4, 0x9f, 0x40, 0x5e, 0xd6, 0x13, 0x8e, 0xe6, 0x0d,
            0xb8, 0x13, 0xe4, 0xe8,
        ];
        assert_eq!(dnskey_ds_digest(&dnskey, 2).expect("DS digest"), expected);
    }

    #[test]
    fn ds_match_checks_key_tag_algorithm_and_digest() {
        let dnskey = record(
            "example.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        let digest = dnskey_ds_digest(&dnskey, 2).expect("DS digest");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&dnskey_key_tag(&dnskey).expect("key tag").to_be_bytes());
        rdata.extend_from_slice(&[8, 2]);
        rdata.extend_from_slice(&digest);
        let ds = record("example.", TYPE_DS, &rdata);
        assert!(ds_matches_dnskey(&ds, &dnskey).expect("DS match"));

        let mut wrong = rdata;
        wrong[1] ^= 1;
        let ds = record("example.", TYPE_DS, &wrong);
        assert!(!ds_matches_dnskey(&ds, &dnskey).expect("DS mismatch"));
    }

    #[test]
    fn unsupported_ds_digest_is_explicit() {
        let dnskey = record(
            "example.",
            TYPE_DNSKEY,
            &[0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01],
        );
        assert!(matches!(
            dnskey_ds_digest(&dnskey, 3),
            Err(DnssecError::UnsupportedDigest(3))
        ));
    }

    #[test]
    fn native_signature_verification_reports_valid_invalid_and_unsupported() {
        assert!(
            verify_signature(15, &ED25519_PUBLIC_KEY, &[], &ED25519_EMPTY_SIGNATURE)
                .expect("valid Ed25519 signature")
        );
        let mut invalid = ED25519_EMPTY_SIGNATURE;
        invalid[0] ^= 1;
        assert!(!verify_signature(15, &ED25519_PUBLIC_KEY, &[], &invalid)
            .expect("invalid Ed25519 signature"));

        // Explicitly test unsupported algorithms as per upstream behavior
        // DSA (3), DSA-NSEC3-SHA1 (6), ECC-GOST (12), Ed448 (16)
        for &algo in &[3, 6, 12, 16] {
            assert!(matches!(
                verify_signature(algo, &ED25519_PUBLIC_KEY, &[], &ED25519_EMPTY_SIGNATURE),
                Err(DnssecError::UnsupportedAlgorithm(a)) if a == algo
            ));
        }
    }

    #[test]
    fn verifies_canonical_ed25519_rrsig_and_rejects_tampering() {
        let mut dnskey_rdata = vec![0x01, 0x01, 0x03, 0x0f];
        dnskey_rdata.extend_from_slice(&ED25519_PUBLIC_KEY);
        let dnskey = record("example.", TYPE_DNSKEY, &dnskey_rdata);
        assert_eq!(dnskey_key_tag(&dnskey).expect("DNSKEY tag"), 14_017);

        let a_wire = record_wire("example.", TYPE_A, 30, &[192, 0, 2, 1]);
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&TYPE_A.to_be_bytes());
        rrsig_rdata.extend_from_slice(&[15, 1]);
        rrsig_rdata.extend_from_slice(&60_u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&10_600_u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&9_400_u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&14_017_u16.to_be_bytes());
        rrsig_rdata.extend_from_slice(&encode_name("example.").expect("signer"));
        rrsig_rdata.extend_from_slice(&EXAMPLE_A_SIGNATURE);
        let rrsig_wire = record_wire("example.", TYPE_RRSIG, 30, &rrsig_rdata);

        let rrsig_offset = a_wire.len();
        let mut packet = a_wire;
        packet.extend_from_slice(&rrsig_wire);
        let answer = parse_record(&packet, 0).expect("A record");
        let rrsig = parse_record(&packet, rrsig_offset).expect("RRSIG record");
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        assert!(
            verify_rrsig(&packet, &rrsig, std::slice::from_ref(&answer), &dnskey, now)
                .expect("valid RRSIG")
        );

        let mut tampered = packet;
        tampered[answer.rdata_offset + 3] ^= 1;
        let answer = parse_record(&tampered, 0).expect("tampered A record");
        let rrsig = parse_record(&tampered, rrsig_offset).expect("tampered RRSIG record");
        assert!(!verify_rrsig(
            &tampered,
            &rrsig,
            std::slice::from_ref(&answer),
            &dnskey,
            now,
        )
        .expect("tampered RRSIG"));
    }
}
