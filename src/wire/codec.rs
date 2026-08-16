// SPDX-License-Identifier: LGPL-2.1-or-later
fn checked_end(offset: usize, length: usize) -> Result<usize, WireError> {
    offset.checked_add(length).ok_or(WireError::ShortPacket)
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, WireError> {
    let end = checked_end(offset, 2)?;
    let bytes = packet.get(offset..end).ok_or(WireError::ShortPacket)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, WireError> {
    let end = checked_end(offset, 4)?;
    let bytes = packet.get(offset..end).ok_or(WireError::ShortPacket)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16(packet: &mut [u8], offset: usize, value: u16) -> Result<(), WireError> {
    let end = checked_end(offset, 2)?;
    packet
        .get_mut(offset..end)
        .ok_or(WireError::ShortPacket)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u32(packet: &mut [u8], offset: usize, value: u32) -> Result<(), WireError> {
    let end = checked_end(offset, 4)?;
    packet
        .get_mut(offset..end)
        .ok_or(WireError::ShortPacket)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn escape_label(label: &[u8]) -> Result<String, WireError> {
    if label.is_empty() || label.len() > 63 {
        return Err(WireError::InvalidLabel);
    }
    let mut output = String::new();
    for &byte in label {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                output.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\{byte:03}");
            }
        }
    }
    Ok(output)
}

pub fn decode_label(label: &str) -> Result<Vec<u8>, WireError> {
    let labels = decode_presentation_name(label)?;
    match labels.as_slice() {
        [label] => Ok(label.clone()),
        _ => Err(WireError::InvalidLabel),
    }
}

fn decode_presentation_name(name: &str) -> Result<Vec<Vec<u8>>, WireError> {
    let bytes = name.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        match bytes[offset] {
            b'.' => {
                if label.is_empty() {
                    if offset + 1 == bytes.len() && labels.is_empty() {
                        return Ok(Vec::new());
                    }
                    return Err(WireError::InvalidName(name.to_owned()));
                }
                labels.push(std::mem::take(&mut label));
                offset += 1;
                if offset == bytes.len() {
                    return Ok(labels);
                }
            }
            b'\\' => {
                offset += 1;
                let Some(&escaped) = bytes.get(offset) else {
                    return Err(WireError::InvalidName(name.to_owned()));
                };
                if matches!(escaped, b'\\' | b'.') {
                    label.push(escaped);
                    offset += 1;
                } else if escaped.is_ascii_digit() {
                    if offset + 2 >= bytes.len()
                        || !bytes[offset..offset + 3]
                            .iter()
                            .all(u8::is_ascii_digit)
                    {
                        return Err(WireError::InvalidName(name.to_owned()));
                    }
                    let value = u16::from(bytes[offset] - b'0') * 100
                        + u16::from(bytes[offset + 1] - b'0') * 10
                        + u16::from(bytes[offset + 2] - b'0');
                    label.push(
                        u8::try_from(value)
                            .map_err(|_| WireError::InvalidName(name.to_owned()))?,
                    );
                    offset += 3;
                } else {
                    return Err(WireError::InvalidName(name.to_owned()));
                }
            }
            byte if byte < b' ' || byte == 127 => {
                return Err(WireError::InvalidName(name.to_owned()));
            }
            byte => {
                label.push(byte);
                offset += 1;
            }
        }
        if label.len() > 63 {
            return Err(WireError::InvalidName(name.to_owned()));
        }
    }
    if label.is_empty() {
        return Err(WireError::InvalidName(name.to_owned()));
    }
    labels.push(label);
    Ok(labels)
}

pub fn read_name(packet: &[u8], offset: usize) -> Result<(DnsName, usize), WireError> {
    if offset >= packet.len() {
        return Err(WireError::ShortPacket);
    }

    let mut cursor = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut pointer_steps = 0usize;
    let mut expanded_length = 1usize;
    let mut labels = Vec::new();
    let mut canonical_wire = Vec::new();

    loop {
        let length = *packet.get(cursor).ok_or(WireError::ShortPacket)?;
        if length == 0 {
            if !jumped {
                next_offset = cursor + 1;
            }
            canonical_wire.push(0);
            break;
        }

        if length & 0xc0 == 0xc0 {
            let second = *packet.get(cursor + 1).ok_or(WireError::ShortPacket)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= cursor || pointer >= packet.len() {
                return Err(WireError::CompressionLoop);
            }
            pointer_steps += 1;
            if pointer_steps > 128 {
                return Err(WireError::CompressionLoop);
            }
            if !jumped {
                next_offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }

        if length & 0xc0 != 0 || length > 63 {
            return Err(WireError::InvalidLabel);
        }

        let label_length = usize::from(length);
        let start = cursor + 1;
        let end = checked_end(start, label_length)?;
        let label = packet.get(start..end).ok_or(WireError::ShortPacket)?;
        expanded_length = expanded_length
            .checked_add(label_length + 1)
            .ok_or(WireError::NameTooLong)?;
        if expanded_length > 255 {
            return Err(WireError::NameTooLong);
        }

        canonical_wire.push(length);
        canonical_wire.extend(label.iter().map(u8::to_ascii_lowercase));
        labels.push(escape_label(label)?);
        cursor = end;
        if !jumped {
            next_offset = cursor;
        }
    }

    let text = if labels.is_empty() {
        ".".to_owned()
    } else {
        labels.join(".")
    };
    Ok((
        DnsName {
            text,
            canonical_wire,
        },
        next_offset,
    ))
}

pub fn encode_name(name: &str) -> Result<Vec<u8>, WireError> {
    if name.is_empty() {
        return Err(WireError::InvalidName(name.to_owned()));
    }
    let labels = decode_presentation_name(name)?;
    if labels.is_empty() {
        return Ok(vec![0]);
    }

    let mut output = Vec::new();
    for label in labels {
        output.push(u8::try_from(label.len()).map_err(|_| WireError::NameTooLong)?);
        output.extend_from_slice(&label);
    }
    output.push(0);
    if output.len() > 255 {
        Err(WireError::NameTooLong)
    } else {
        Ok(output)
    }
}

pub fn parse_question(packet: &[u8], offset: usize) -> Result<Question, WireError> {
    let (name, offset) = read_name(packet, offset)?;
    let rr_type = read_u16(packet, offset)?;
    if !query_type_is_valid(rr_type) {
        return Err(WireError::InvalidQuestionType(rr_type));
    }
    let class = read_u16(packet, offset + 2)?;
    Ok(Question {
        name,
        rr_type,
        class,
        next_offset: offset + 4,
    })
}

const fn query_type_is_valid(rr_type: u16) -> bool {
    !matches!(rr_type, 0 | TYPE_OPT | TYPE_RRSIG | 249 | TYPE_TSIG)
}

pub fn parse_record(packet: &[u8], offset: usize) -> Result<ResourceRecord, WireError> {
    let (name, offset) = read_name(packet, offset)?;
    let rr_type = read_u16(packet, offset)?;
    let class = read_u16(packet, offset + 2)?;
    if class == CLASS_ANY || matches!(rr_type, TYPE_IXFR | TYPE_AXFR | TYPE_ANY) {
        return Err(WireError::InvalidRecord);
    }
    let ttl_offset = offset + 4;
    let mut ttl = read_u32(packet, ttl_offset)?;
    if rr_type != TYPE_OPT && ttl & 0x8000_0000 != 0 {
        ttl = 0;
    }
    let rdata_length = usize::from(read_u16(packet, offset + 8)?);
    let rdata_offset = offset + 10;
    let next_offset = checked_end(rdata_offset, rdata_length)?;
    let rdata = packet
        .get(rdata_offset..next_offset)
        .ok_or(WireError::ShortPacket)?
        .to_vec();
    let record = ResourceRecord {
        name,
        rr_type,
        class,
        ttl,
        ttl_offset,
        rdata_offset,
        rdata,
        next_offset,
    };
    validate_record_rdata(packet, &record)?;
    Ok(record)
}

pub fn parse_uncompressed_record(
    packet: &[u8],
    offset: usize,
) -> Result<ResourceRecord, WireError> {
    validate_uncompressed_name(packet, offset, packet.len())?;
    let record = parse_record(packet, offset)?;
    validate_uncompressed_record_names(packet, &record)?;
    Ok(record)
}

fn validate_uncompressed_record_names(
    packet: &[u8],
    record: &ResourceRecord,
) -> Result<(), WireError> {
    let start = record.rdata_offset;
    let end = record.next_offset;
    match record.rr_type {
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            require_name_end(packet, start, end, false)
        }
        TYPE_SOA => {
            let after_mname = read_bounded_name(packet, start, end, false)?;
            let after_rname = read_bounded_name(packet, after_mname, end, false)?;
            let fixed_end = require_offset(after_rname, 20, end)?;
            require_exact_end(fixed_end, end)
        }
        15 => {
            let name_offset = require_offset(start, 2, end)?;
            require_name_end(packet, name_offset, end, false)
        }
        TYPE_SRV => {
            let name_offset = require_offset(start, 6, end)?;
            require_name_end(packet, name_offset, end, false)
        }
        _ => Ok(()),
    }
}

fn validate_record_rdata(packet: &[u8], record: &ResourceRecord) -> Result<(), WireError> {
    let start = record.rdata_offset;
    let end = record.next_offset;
    match record.rr_type {
        TYPE_A => require_rdata_length(record, 4),
        TYPE_AAAA => require_rdata_length(record, 16),
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            require_name_end(packet, start, end, true)
        }
        TYPE_SOA => {
            let after_mname = read_bounded_name(packet, start, end, true)?;
            let after_rname = read_bounded_name(packet, after_mname, end, true)?;
            let fixed_end = require_offset(after_rname, 20, end)?;
            require_exact_end(fixed_end, end)
        }
        13 => {
            let after_cpu = read_character_string(packet, start, end, true)?;
            let after_os = read_character_string(packet, after_cpu, end, true)?;
            require_exact_end(after_os, end)
        }
        15 => {
            let name_offset = require_offset(start, 2, end)?;
            require_name_end(packet, name_offset, end, true)
        }
        TYPE_TXT | 99 => validate_character_string_list(packet, start, end),
        29 => validate_loc(record),
        TYPE_SRV => {
            let name_offset = require_offset(start, 6, end)?;
            require_name_end(packet, name_offset, end, true)
        }
        35 => validate_naptr(packet, start, end),
        43 => require_minimum_rdata_length(record, 5),
        44 => require_minimum_rdata_length(record, 3),
        TYPE_RRSIG => validate_rrsig(packet, start, end),
        47 => validate_nsec(packet, start, end),
        48 => require_minimum_rdata_length(record, 5),
        50 => validate_nsec3(packet, start, end),
        TYPE_NSEC3PARAM => validate_nsec3param(packet, start, end),
        52 => require_minimum_rdata_length(record, 4),
        64 | 65 => validate_svcb(packet, start, end),
        257 => validate_caa(packet, start, end),
        _ => Ok(()),
    }
}

fn require_rdata_length(record: &ResourceRecord, expected: usize) -> Result<(), WireError> {
    if record.rdata.len() == expected {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn require_minimum_rdata_length(
    record: &ResourceRecord,
    minimum: usize,
) -> Result<(), WireError> {
    if record.rdata.len() >= minimum {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn require_offset(offset: usize, length: usize, limit: usize) -> Result<usize, WireError> {
    let end = offset
        .checked_add(length)
        .ok_or(WireError::InvalidRecord)?;
    if end <= limit {
        Ok(end)
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn require_exact_end(actual: usize, expected: usize) -> Result<(), WireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn read_bounded_name(
    packet: &[u8],
    offset: usize,
    limit: usize,
    allow_compression: bool,
) -> Result<usize, WireError> {
    if !allow_compression {
        validate_uncompressed_name(packet, offset, limit)?;
    }
    let (_, end) = read_name(packet, offset)?;
    if end <= limit {
        Ok(end)
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn require_name_end(
    packet: &[u8],
    offset: usize,
    expected_end: usize,
    allow_compression: bool,
) -> Result<(), WireError> {
    let end = read_bounded_name(packet, offset, expected_end, allow_compression)?;
    require_exact_end(end, expected_end)
}

fn validate_uncompressed_name(
    packet: &[u8],
    mut offset: usize,
    limit: usize,
) -> Result<(), WireError> {
    let mut expanded_length = 1usize;
    loop {
        let length = *packet.get(offset).ok_or(WireError::ShortPacket)?;
        if length == 0 {
            return if offset < limit {
                Ok(())
            } else {
                Err(WireError::InvalidRecord)
            };
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(WireError::InvalidRecord);
        }
        let label_length = usize::from(length);
        expanded_length = expanded_length
            .checked_add(label_length + 1)
            .ok_or(WireError::NameTooLong)?;
        if expanded_length > 255 {
            return Err(WireError::NameTooLong);
        }
        offset = require_offset(offset, label_length + 1, limit)?;
    }
}

fn read_character_string(
    packet: &[u8],
    offset: usize,
    limit: usize,
    text: bool,
) -> Result<usize, WireError> {
    let length = usize::from(*packet.get(offset).ok_or(WireError::ShortPacket)?);
    let content = require_offset(offset, 1, limit)?;
    let end = require_offset(content, length, limit)?;
    if text {
        let bytes = packet.get(content..end).ok_or(WireError::ShortPacket)?;
        if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
            return Err(WireError::InvalidRecord);
        }
    }
    Ok(end)
}

fn validate_character_string_list(
    packet: &[u8],
    mut offset: usize,
    end: usize,
) -> Result<(), WireError> {
    while offset < end {
        offset = read_character_string(packet, offset, end, false)?;
    }
    require_exact_end(offset, end)
}

fn validate_loc(record: &ResourceRecord) -> Result<(), WireError> {
    let Some(&version) = record.rdata.first() else {
        return Err(WireError::InvalidRecord);
    };
    if version != 0 {
        return Ok(());
    }
    require_rdata_length(record, 16)?;
    if record.rdata[1..4].iter().all(|value| {
        let mantissa = value >> 4;
        let exponent = value & 0x0f;
        mantissa <= 9 && exponent <= 9 && (mantissa > 0 || exponent == 0)
    }) {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn validate_rrsig(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let name_offset = require_offset(start, 18, end)?;
    let signature_offset = read_bounded_name(packet, name_offset, end, false)?;
    if signature_offset < end {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn validate_nsec(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let bitmap_offset = read_bounded_name(packet, start, end, false)?;
    validate_type_windows(packet, bitmap_offset, end)
}

fn validate_nsec3(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let salt_length_offset = require_offset(start, 4, end)?;
    let salt_length = usize::from(
        *packet
            .get(salt_length_offset)
            .ok_or(WireError::ShortPacket)?,
    );
    let salt_offset = require_offset(salt_length_offset, 1, end)?;
    let hash_length_offset = require_offset(salt_offset, salt_length, end)?;
    let hash_length = usize::from(
        *packet
            .get(hash_length_offset)
            .ok_or(WireError::ShortPacket)?,
    );
    if hash_length == 0 {
        return Err(WireError::InvalidRecord);
    }
    let hash_offset = require_offset(hash_length_offset, 1, end)?;
    let bitmap_offset = require_offset(hash_offset, hash_length, end)?;
    validate_type_windows(packet, bitmap_offset, end)
}

fn validate_nsec3param(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let salt_length_offset = require_offset(start, 4, end)?;
    let salt_length = usize::from(
        *packet
            .get(salt_length_offset)
            .ok_or(WireError::ShortPacket)?,
    );
    let expected_end = require_offset(salt_length_offset, 1 + salt_length, end)?;
    require_exact_end(expected_end, end)
}

fn validate_type_windows(
    packet: &[u8],
    mut offset: usize,
    end: usize,
) -> Result<(), WireError> {
    while offset < end {
        let header_end = require_offset(offset, 2, end)?;
        let length = usize::from(packet[offset + 1]);
        if length == 0 || length > 32 {
            return Err(WireError::InvalidRecord);
        }
        let window_end = require_offset(header_end, length, end)?;
        if packet[window_end - 1] == 0 {
            return Err(WireError::InvalidRecord);
        }
        offset = window_end;
    }
    require_exact_end(offset, end)
}

fn validate_svcb(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let target_offset = require_offset(start, 2, end)?;
    let mut offset = read_bounded_name(packet, target_offset, end, false)?;
    let mut last_key = None;
    while offset < end {
        let header_end = require_offset(offset, 4, end)?;
        let key = read_u16(packet, offset)?;
        if last_key.is_some_and(|previous| previous >= key) {
            return Err(WireError::InvalidRecord);
        }
        let length = usize::from(read_u16(packet, offset + 2)?);
        let value_end = require_offset(header_end, length, end)?;
        validate_svc_param(key, &packet[header_end..value_end])?;
        last_key = Some(key);
        offset = value_end;
    }
    require_exact_end(offset, end)
}

fn validate_svc_param(key: u16, value: &[u8]) -> Result<(), WireError> {
    let valid = match key {
        1 => {
            if value.is_empty() {
                false
            } else {
                let mut offset = 0usize;
                while offset < value.len() {
                    offset = offset
                        .checked_add(1 + usize::from(value[offset]))
                        .ok_or(WireError::InvalidRecord)?;
                }
                offset == value.len()
            }
        }
        2 => value.is_empty(),
        3 => value.len() == 2,
        4 => !value.is_empty() && value.len() % 4 == 0,
        6 => !value.is_empty() && value.len() % 16 == 0,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn validate_caa(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let tag_offset = require_offset(start, 1, end)?;
    let value_offset = read_character_string(packet, tag_offset, end, true)?;
    if value_offset <= end {
        Ok(())
    } else {
        Err(WireError::InvalidRecord)
    }
}

fn validate_naptr(packet: &[u8], start: usize, end: usize) -> Result<(), WireError> {
    let mut offset = require_offset(start, 4, end)?;
    for _ in 0..3 {
        offset = read_character_string(packet, offset, end, true)?;
    }
    require_name_end(packet, offset, end, false)
}

pub(crate) fn parse_sections(
    packet: &[u8],
) -> Result<(Header, Vec<Question>, Vec<ResourceRecord>, usize), WireError> {
    let header = Header::parse(packet)?;
    let mut offset = DNS_HEADER_LEN;
    let question_capacity = usize::from(header.question_count).min(packet.len() / 5);
    let mut questions = Vec::with_capacity(question_capacity);
    for _ in 0..header.question_count {
        let question = parse_question(packet, offset)?;
        offset = question.next_offset;
        questions.push(question);
    }

    let record_capacity = header.total_records().min(packet.len() / 11);
    let mut records = Vec::with_capacity(record_capacity);
    for _ in 0..header.total_records() {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        records.push(record);
    }
    Ok((header, questions, records, offset))
}
