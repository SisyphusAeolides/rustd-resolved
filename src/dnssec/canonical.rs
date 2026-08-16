// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::dnssec::DnssecError;
use crate::wire::{parse_rrsig, read_name, ResourceRecord, RrsigRecord, WireError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SIGNATURE_TIME_SKEW: Duration = Duration::from_secs(60 * 60);

pub fn canonical_signed_data(
    packet: &[u8],
    rrsig_record: &ResourceRecord,
    rrset: &[ResourceRecord],
) -> Result<Vec<u8>, DnssecError> {
    let signature = parse_rrsig(packet, rrsig_record)?;
    if rrset.is_empty() {
        return Err(WireError::InvalidRecord.into());
    }
    let owner = canonical_owner(rrset[0].name.canonical_wire(), signature.labels)?;
    let class = rrset[0].class;
    let mut canonical_records = Vec::with_capacity(rrset.len());
    for record in rrset {
        if record.rr_type != signature.type_covered
            || record.class != class
            || record.name.canonical_wire() != rrset[0].name.canonical_wire()
        {
            return Err(WireError::InvalidRecord.into());
        }
        let rdata = canonical_rdata(packet, record)?;
        let mut canonical = Vec::with_capacity(owner.len() + rdata.len() + 10);
        canonical.extend_from_slice(&owner);
        canonical.extend_from_slice(&record.rr_type.to_be_bytes());
        canonical.extend_from_slice(&record.class.to_be_bytes());
        canonical.extend_from_slice(&signature.original_ttl.to_be_bytes());
        canonical.extend_from_slice(
            &u16::try_from(rdata.len())
                .map_err(|_| WireError::InvalidRecord)?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&rdata);
        canonical_records.push(canonical);
    }
    canonical_records.sort();
    canonical_records.dedup();

    let mut output = rrsig_prefix(&signature);
    for record in canonical_records {
        output.extend_from_slice(&record);
    }
    Ok(output)
}

pub fn rrsig_time_valid(signature: &RrsigRecord, now: SystemTime) -> bool {
    let Ok(now) = now.duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = u64::from(u32::try_from(now.as_secs()).unwrap_or(u32::MAX));
    let skew = SIGNATURE_TIME_SKEW.as_secs();
    let inception = u64::from(signature.inception);
    let expiration = u64::from(signature.expiration);
    inception <= now.saturating_add(skew) && expiration.saturating_add(skew) >= now
}

fn rrsig_prefix(signature: &RrsigRecord) -> Vec<u8> {
    let mut output = Vec::with_capacity(18 + signature.signer.canonical_wire().len());
    output.extend_from_slice(&signature.type_covered.to_be_bytes());
    output.push(signature.algorithm);
    output.push(signature.labels);
    output.extend_from_slice(&signature.original_ttl.to_be_bytes());
    output.extend_from_slice(&signature.expiration.to_be_bytes());
    output.extend_from_slice(&signature.inception.to_be_bytes());
    output.extend_from_slice(&signature.key_tag.to_be_bytes());
    output.extend_from_slice(signature.signer.canonical_wire());
    output
}

fn canonical_owner(owner: &[u8], labels: u8) -> Result<Vec<u8>, WireError> {
    let label_offsets = label_offsets(owner)?;
    let label_count = label_offsets.len();
    let labels = usize::from(labels);
    if labels > label_count {
        return Err(WireError::InvalidRecord);
    }
    let canonical = owner.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    if labels == label_count {
        return Ok(canonical);
    }

    let mut output = vec![1, b'*'];
    if labels == 0 {
        output.push(0);
        return Ok(output);
    }
    output.extend_from_slice(
        canonical
            .get(label_offsets[label_count - labels]..)
            .ok_or(WireError::InvalidRecord)?,
    );
    Ok(output)
}

fn label_offsets(name: &[u8]) -> Result<Vec<usize>, WireError> {
    let mut offsets = Vec::new();
    let mut offset = 0usize;
    loop {
        let length =
            usize::from(*name.get(offset).ok_or_else(|| {
                WireError::InvalidName("truncated canonical DNS name".to_owned())
            })?);
        if length == 0 {
            if offset + 1 != name.len() {
                return Err(WireError::InvalidName(
                    "canonical DNS name has trailing data".to_owned(),
                ));
            }
            return Ok(offsets);
        }
        if length > 63 || offset + 1 + length >= name.len() {
            return Err(WireError::InvalidName(
                "invalid canonical DNS label".to_owned(),
            ));
        }
        offsets.push(offset);
        offset += 1 + length;
    }
}

fn canonical_rdata(packet: &[u8], record: &ResourceRecord) -> Result<Vec<u8>, WireError> {
    match record.rr_type {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 23 | 30 | 39 | 47 => {
            canonical_single_name(packet, record, 0)
        }
        6 => canonical_soa(packet, record),
        14 | 17 => canonical_two_names(packet, record, 0),
        15 | 18 | 21 | 36 | 64 | 65 | 107 => canonical_single_name(packet, record, 2),
        24 | 46 => canonical_single_name(packet, record, 18),
        26 => canonical_two_names(packet, record, 2),
        33 => canonical_single_name(packet, record, 6),
        35 => canonical_naptr(packet, record),
        _ => Ok(record.rdata.clone()),
    }
}

fn canonical_single_name(
    packet: &[u8],
    record: &ResourceRecord,
    prefix: usize,
) -> Result<Vec<u8>, WireError> {
    if record.rdata.len() < prefix + 1 {
        return Err(WireError::InvalidRecord);
    }
    let name_offset = record
        .rdata_offset
        .checked_add(prefix)
        .ok_or(WireError::InvalidRecord)?;
    let (name, next) = read_name(packet, name_offset)?;
    if next > record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    let suffix = packet
        .get(next..record.next_offset)
        .ok_or(WireError::InvalidRecord)?;
    let mut output = record.rdata[..prefix].to_vec();
    output.extend_from_slice(name.canonical_wire());
    output.extend_from_slice(suffix);
    Ok(output)
}

fn canonical_two_names(
    packet: &[u8],
    record: &ResourceRecord,
    prefix: usize,
) -> Result<Vec<u8>, WireError> {
    if record.rdata.len() < prefix + 2 {
        return Err(WireError::InvalidRecord);
    }
    let first_offset = record
        .rdata_offset
        .checked_add(prefix)
        .ok_or(WireError::InvalidRecord)?;
    let (first, second_offset) = read_name(packet, first_offset)?;
    let (second, end) = read_name(packet, second_offset)?;
    if end != record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    let mut output = record.rdata[..prefix].to_vec();
    output.extend_from_slice(first.canonical_wire());
    output.extend_from_slice(second.canonical_wire());
    Ok(output)
}

fn canonical_soa(packet: &[u8], record: &ResourceRecord) -> Result<Vec<u8>, WireError> {
    let (primary_name, mailbox_offset) = read_name(packet, record.rdata_offset)?;
    let (mailbox_name, integers_offset) = read_name(packet, mailbox_offset)?;
    let integers = packet
        .get(integers_offset..record.next_offset)
        .ok_or(WireError::InvalidRecord)?;
    if integers.len() != 20 {
        return Err(WireError::InvalidRecord);
    }
    let mut output = Vec::new();
    output.extend_from_slice(primary_name.canonical_wire());
    output.extend_from_slice(mailbox_name.canonical_wire());
    output.extend_from_slice(integers);
    Ok(output)
}

fn canonical_naptr(packet: &[u8], record: &ResourceRecord) -> Result<Vec<u8>, WireError> {
    if record.rdata.len() < 8 {
        return Err(WireError::InvalidRecord);
    }
    let mut offset = record.rdata_offset + 4;
    for _ in 0..3 {
        let length = usize::from(*packet.get(offset).ok_or(WireError::InvalidRecord)?);
        offset = offset
            .checked_add(1 + length)
            .ok_or(WireError::InvalidRecord)?;
        if offset > record.next_offset {
            return Err(WireError::InvalidRecord);
        }
    }
    let (replacement, end) = read_name(packet, offset)?;
    if end != record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    let prefix = packet
        .get(record.rdata_offset..offset)
        .ok_or(WireError::InvalidRecord)?;
    let mut output = prefix.to_vec();
    output.extend_from_slice(replacement.canonical_wire());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_name, parse_record, CLASS_IN, TYPE_A, TYPE_RRSIG};

    fn record(owner: &str, rr_type: u16, ttl: u32, rdata: &[u8]) -> (Vec<u8>, ResourceRecord) {
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
        let record = parse_record(&packet, 0).expect("resource record");
        (packet, record)
    }

    #[test]
    fn wildcard_owner_uses_rrsig_label_count() {
        let owner = encode_name("A.B.Example.").expect("owner");
        assert_eq!(
            canonical_owner(&owner, 2).expect("wildcard owner"),
            encode_name("*.b.example.").expect("wildcard")
        );
        assert!(canonical_owner(&owner, 4).is_err());
    }

    #[test]
    fn signed_data_uses_original_ttl_and_sorted_rrs() {
        let (first_wire, _) = record("example.", TYPE_A, 5, &[192, 0, 2, 2]);
        let (second_wire, _) = record("example.", TYPE_A, 999, &[192, 0, 2, 1]);
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&TYPE_A.to_be_bytes());
        rrsig_rdata.extend_from_slice(&[15, 1]);
        rrsig_rdata.extend_from_slice(&60_u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&u32::MAX.to_be_bytes());
        rrsig_rdata.extend_from_slice(&0_u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&1234_u16.to_be_bytes());
        rrsig_rdata.extend_from_slice(&encode_name("example.").expect("signer"));
        rrsig_rdata.push(1);
        let (rrsig_wire, _) = record("example.", TYPE_RRSIG, 60, &rrsig_rdata);

        let second_offset = first_wire.len();
        let mut rrset_packet = first_wire;
        rrset_packet.extend_from_slice(&second_wire);
        let rrsig_offset = rrset_packet.len();
        rrset_packet.extend_from_slice(&rrsig_wire);

        let first = parse_record(&rrset_packet, 0).expect("first RR");
        let second = parse_record(&rrset_packet, second_offset).expect("second RR");
        let rrsig = parse_record(&rrset_packet, rrsig_offset).expect("RRSIG");
        let signed =
            canonical_signed_data(&rrset_packet, &rrsig, &[first, second]).expect("signed data");
        assert!(signed
            .windows(4)
            .any(|window| window == 60_u32.to_be_bytes()));
        let first_position = signed
            .windows(4)
            .position(|window| window == [192, 0, 2, 1])
            .expect("first address");
        let second_position = signed
            .windows(4)
            .position(|window| window == [192, 0, 2, 2])
            .expect("second address");
        assert!(first_position < second_position);
    }

    #[test]
    fn signature_time_allows_one_hour_clock_skew() {
        let signer_wire = encode_name("example.").expect("signer wire");
        let (signer, signer_end) = read_name(&signer_wire, 0).expect("signer");
        assert_eq!(signer_end, signer_wire.len());
        let signature = RrsigRecord {
            type_covered: TYPE_A,
            algorithm: 15,
            labels: 1,
            original_ttl: 60,
            expiration: 10_600,
            inception: 9_400,
            key_tag: 1,
            signer,
            signature: vec![1],
        };
        assert!(rrsig_time_valid(
            &signature,
            UNIX_EPOCH + Duration::from_secs(10_000)
        ));
        assert!(!rrsig_time_valid(
            &signature,
            UNIX_EPOCH + Duration::from_secs(20_000)
        ));
    }
}
