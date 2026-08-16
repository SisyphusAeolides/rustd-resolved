// SPDX-License-Identifier: LGPL-2.1-or-later
include!("dnssec_records.rs");

const RRSIG_FIXED_FIELDS_LEN: usize = 18;
const RRSIG_MINIMUM_RDATA_LEN: usize = RRSIG_FIXED_FIELDS_LEN + 2;

pub fn root_rrsig_missing(packet: &[u8]) -> Result<bool, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let signed_record_count =
        usize::from(header.answer_count) + usize::from(header.authority_count);
    let mut required = std::collections::HashSet::new();
    let mut covered = std::collections::HashSet::new();
    for index in 0..header.total_records() {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class != CLASS_IN || *record.name.canonical_wire() != [0] {
            continue;
        }

        if record.rr_type == TYPE_RRSIG {
            if record.rdata.len() < RRSIG_MINIMUM_RDATA_LEN {
                return Err(WireError::InvalidRecord);
            }
            let type_covered = u16::from_be_bytes([record.rdata[0], record.rdata[1]]);
            let signer_offset = checked_end(record.rdata_offset, RRSIG_FIXED_FIELDS_LEN)?;
            let (signer, signature_offset) = read_name(packet, signer_offset)?;
            if *signer.canonical_wire() != [0] || signature_offset >= record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            covered.insert(type_covered);
        } else if index < signed_record_count
            && !matches!(record.rr_type, TYPE_OPT | TYPE_TSIG)
        {
            required.insert(record.rr_type);
        }
    }
    if offset != packet.len() {
        return Err(WireError::TrailingData);
    }

    Ok(!required.is_subset(&covered))
}

#[cfg(test)]
mod dnssec_tests {
    use super::*;

    #[test]
    fn detects_an_unsigned_root_record() {
        let query = make_query(".", TYPE_A, 0x7201).expect("root query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 100))],
            30,
        )
        .expect("root response");
        assert_eq!(root_rrsig_missing(&response), Ok(true));
    }

    #[test]
    fn accepts_a_root_record_with_a_covering_rrsig() {
        let query = make_query(".", TYPE_A, 0x7202).expect("root query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 101))],
            30,
        )
        .expect("root response");
        let response = append_test_rrsig(&response, TYPE_A).expect("RRSIG response");
        assert_eq!(root_rrsig_missing(&response), Ok(false));
    }

    #[test]
    fn ignores_unsigned_non_root_records() {
        let query = make_query("example.test", TYPE_A, 0x7203).expect("query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 102))],
            30,
        )
        .expect("response");
        assert_eq!(root_rrsig_missing(&response), Ok(false));
    }

    #[test]
    fn rejects_a_root_rrsig_without_a_signature() {
        let query = make_query(".", TYPE_A, 0x7204).expect("root query");
        let response = local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 103))],
            30,
        )
        .expect("root response");
        let response = append_rrsig_rdata(&response, &minimal_rrsig_rdata(TYPE_A, false))
            .expect("malformed RRSIG response");
        assert_eq!(root_rrsig_missing(&response), Err(WireError::InvalidRecord));
    }

    fn append_test_rrsig(packet: &[u8], type_covered: u16) -> Result<Vec<u8>, WireError> {
        append_rrsig_rdata(packet, &minimal_rrsig_rdata(type_covered, true))
    }

    fn minimal_rrsig_rdata(type_covered: u16, signature: bool) -> Vec<u8> {
        let mut rdata = Vec::with_capacity(RRSIG_MINIMUM_RDATA_LEN);
        rdata.extend_from_slice(&type_covered.to_be_bytes());
        rdata.push(8);
        rdata.push(0);
        rdata.extend_from_slice(&30_u32.to_be_bytes());
        rdata.extend_from_slice(&u32::MAX.to_be_bytes());
        rdata.extend_from_slice(&0_u32.to_be_bytes());
        rdata.extend_from_slice(&0_u16.to_be_bytes());
        rdata.push(0);
        if signature {
            rdata.push(0);
        }
        rdata
    }

    fn append_rrsig_rdata(packet: &[u8], rdata: &[u8]) -> Result<Vec<u8>, WireError> {
        let header = Header::parse(packet)?;
        if !header.is_response() || header.authority_count != 0 || header.additional_count != 0 {
            return Err(WireError::InvalidRecord);
        }
        let answer_count = header
            .answer_count
            .checked_add(1)
            .ok_or(WireError::ResponseTooLarge)?;

        let mut output = packet.to_vec();
        output[6..8].copy_from_slice(&answer_count.to_be_bytes());
        output.push(0);
        output.extend_from_slice(&TYPE_RRSIG.to_be_bytes());
        output.extend_from_slice(&CLASS_IN.to_be_bytes());
        output.extend_from_slice(&30_u32.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(rdata.len())
                .map_err(|_| WireError::ResponseTooLarge)?
                .to_be_bytes(),
        );
        output.extend_from_slice(rdata);
        Ok(output)
    }
}
