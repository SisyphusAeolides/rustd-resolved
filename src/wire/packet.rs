// SPDX-License-Identifier: LGPL-2.1-or-later
pub fn validate(packet: &[u8], expect_response: bool) -> Result<(), WireError> {
    let (header, questions, _, end) = parse_sections(packet)?;
    if header.is_response() != expect_response {
        return Err(WireError::WrongDirection);
    }
    if header.opcode() != 0 {
        return Err(WireError::UnsupportedOpcode(header.opcode()));
    }
    if questions.is_empty() {
        return Err(WireError::NoQuestion);
    }
    if !expect_response && header.question_count != 1 {
        return Err(WireError::WrongQuestionCount(header.question_count));
    }
    if !expect_response && header.truncated() {
        return Err(WireError::TruncatedQuery);
    }
    if !expect_response && header.answer_count != 0 {
        return Err(WireError::QueryContainsAnswers(header.answer_count));
    }
    if end != packet.len() {
        return Err(WireError::TrailingData);
    }
    Ok(())
}

pub fn validate_native(packet: &[u8], expect_response: bool) -> Result<(), WireError> {
    validate(packet, expect_response)
}

pub fn first_question(packet: &[u8]) -> Result<Question, WireError> {
    if Header::parse(packet)?.question_count == 0 {
        return Err(WireError::NoQuestion);
    }
    parse_question(packet, DNS_HEADER_LEN)
}

pub fn question_end(packet: &[u8]) -> Result<usize, WireError> {
    let header = Header::parse(packet)?;
    if header.question_count == 0 {
        return Err(WireError::NoQuestion);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }
    Ok(offset)
}

pub fn response_matches(query: &[u8], response: &[u8]) -> Result<(), WireError> {
    validate(query, false)?;
    validate(response, true)?;
    if Header::parse(query)?.id != Header::parse(response)?.id {
        return Err(WireError::QuestionMismatch);
    }
    let query_question = first_question(query)?;
    let response_question = first_question(response)?;
    if query_question.name.canonical_wire() != response_question.name.canonical_wire()
        || query_question.rr_type != response_question.rr_type
        || query_question.class != response_question.class
    {
        return Err(WireError::QuestionMismatch);
    }
    Ok(())
}

pub fn make_query(name: &str, rr_type: u16, id: u16) -> Result<Vec<u8>, WireError> {
    make_query_with_class(name, rr_type, CLASS_IN, id)
}

pub fn make_query_with_class(
    name: &str,
    rr_type: u16,
    class: u16,
    id: u16,
) -> Result<Vec<u8>, WireError> {
    if !query_type_is_valid(rr_type) {
        return Err(WireError::InvalidQuestionType(rr_type));
    }
    let encoded_name = encode_name(name)?;
    let mut packet = Vec::with_capacity(DNS_HEADER_LEN + encoded_name.len() + 4);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&FLAG_RD.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&[0; 6]);
    packet.extend_from_slice(&encoded_name);
    packet.extend_from_slice(&rr_type.to_be_bytes());
    packet.extend_from_slice(&class.to_be_bytes());
    Ok(packet)
}

pub fn rewrite_id(packet: &mut [u8], id: u16) -> Result<(), WireError> {
    write_u16(packet, 0, id)
}

pub fn servfail_for(query: &[u8]) -> Result<Vec<u8>, WireError> {
    validate(query, false)?;
    let mut response = query[..question_end(query)?].to_vec();
    let mut flags = read_u16(&response, 2)?;
    flags |= FLAG_QR | FLAG_RA;
    flags &= !(FLAG_AA | FLAG_TC | FLAG_AD | RCODE_MASK);
    flags |= 2;
    write_u16(&mut response, 2, flags)?;
    response[6..12].fill(0);
    Ok(response)
}

pub fn local_response(
    query: &[u8],
    records: &[LocalRecord],
    ttl: u32,
) -> Result<Vec<u8>, WireError> {
    validate(query, false)?;
    let question = first_question(query)?;
    let question_end = question_end(query)?;
    let mut response = query[..question_end].to_vec();
    let mut flags = read_u16(&response, 2)?;
    flags |= FLAG_QR | FLAG_AA | FLAG_RA;
    flags &= !(FLAG_TC | RCODE_MASK);
    write_u16(&mut response, 2, flags)?;
    write_u16(
        &mut response,
        6,
        u16::try_from(records.len()).map_err(|_| WireError::ResponseTooLarge)?,
    )?;
    response[8..12].fill(0);

    for record in records {
        if record.rr_type() != question.rr_type
            && record.rr_type() != TYPE_CNAME
            && question.rr_type != 255
        {
            continue;
        }
        match record {
            LocalRecord::NamedA(name, _) | LocalRecord::NamedAaaa(name, _) => {
                response.extend_from_slice(&encode_name(name)?);
            }
            _ => response.extend_from_slice(&[0xc0, 0x0c]),
        }
        response.extend_from_slice(&record.rr_type().to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        let rdata = match record {
            LocalRecord::A(address) => address.octets().to_vec(),
            LocalRecord::Aaaa(address) => address.octets().to_vec(),
            LocalRecord::NamedA(_, address) => address.octets().to_vec(),
            LocalRecord::NamedAaaa(_, address) => address.octets().to_vec(),
            LocalRecord::Cname(name) | LocalRecord::Ptr(name) => encode_name(name)?,
        };
        response.extend_from_slice(
            &u16::try_from(rdata.len())
                .map_err(|_| WireError::ResponseTooLarge)?
                .to_be_bytes(),
        );
        response.extend_from_slice(&rdata);
        if response.len() > usize::from(u16::MAX) {
            return Err(WireError::ResponseTooLarge);
        }
    }

    let actual_answers = count_records_after_question(&response, question_end)?;
    write_u16(&mut response, 6, actual_answers)?;
    Ok(response)
}

fn count_records_after_question(packet: &[u8], mut offset: usize) -> Result<u16, WireError> {
    let mut count = 0u16;
    while offset < packet.len() {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        count = count.checked_add(1).ok_or(WireError::ResponseTooLarge)?;
    }
    Ok(count)
}

fn soa_minimum(packet: &[u8], record: &ResourceRecord) -> Result<u32, WireError> {
    let (_, first_end) = read_name(packet, record.rdata_offset)?;
    let (_, second_end) = read_name(packet, first_end)?;
    let fixed_end = checked_end(second_end, 20)?;
    if fixed_end != record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    read_u32(packet, second_end + 16)
}

pub fn cache_lifetime(packet: &[u8]) -> Result<Option<u32>, WireError> {
    let (header, _, records, _) = parse_sections(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    if records.iter().any(|record| record.rr_type == TYPE_TSIG) {
        return Ok(None);
    }

    let answer_end = usize::from(header.answer_count);
    if header.response_code() == 3 || header.answer_count == 0 {
        let authority_end = answer_end + usize::from(header.authority_count);
        let negative_ttl = records
            .get(answer_end..authority_end)
            .unwrap_or_default()
            .iter()
            .filter(|record| record.rr_type == TYPE_SOA)
            .filter_map(|record| {
                soa_minimum(packet, record)
                    .ok()
                    .map(|minimum| record.ttl.min(minimum))
            })
            .min();
        return Ok(negative_ttl);
    }

    Ok(records
        .get(..answer_end)
        .unwrap_or_default()
        .iter()
        .filter(|record| record.rr_type != TYPE_OPT && record.rr_type != TYPE_TSIG)
        .map(|record| record.ttl)
        .min())
}

pub fn age_ttls(packet: &mut [u8], elapsed_seconds: u32, stale: bool) -> Result<(), WireError> {
    let (_, _, records, _) = parse_sections(packet)?;
    let ttl_offsets: Vec<(usize, u32, u16)> = records
        .iter()
        .map(|record| (record.ttl_offset, record.ttl, record.rr_type))
        .collect();
    for (offset, ttl, rr_type) in ttl_offsets {
        if rr_type == TYPE_OPT {
            continue;
        }
        let aged = if stale {
            0
        } else {
            ttl.saturating_sub(elapsed_seconds)
        };
        write_u32(packet, offset, aged)?;
    }
    Ok(())
}
