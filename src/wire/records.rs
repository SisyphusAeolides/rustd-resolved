// SPDX-License-Identifier: LGPL-2.1-or-later
const MAX_REDIRECT_CHAIN: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressRecords {
    pub addresses: Vec<IpAddr>,
    pub canonical_name: String,
}

#[derive(Default)]
struct AddressAnswerSet {
    aliases: std::collections::HashMap<Vec<u8>, DnsName>,
    dnames: std::collections::HashMap<Vec<u8>, DnsName>,
    addresses: std::collections::HashMap<Vec<u8>, Vec<IpAddr>>,
}

pub fn extract_answer_records(packet: &[u8]) -> Result<Vec<AnswerRecord>, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = Vec::with_capacity(usize::from(header.answer_count));
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;

        let rdata = canonical_record_rdata(packet, &record)?;
        let mut raw =
            Vec::with_capacity(record.name.canonical_wire().len() + 10 + rdata.len());
        raw.extend_from_slice(record.name.canonical_wire());
        raw.extend_from_slice(&record.rr_type.to_be_bytes());
        raw.extend_from_slice(&record.class.to_be_bytes());
        raw.extend_from_slice(&record.ttl.to_be_bytes());
        raw.extend_from_slice(
            &u16::try_from(rdata.len())
                .map_err(|_| WireError::InvalidRecord)?
                .to_be_bytes(),
        );
        raw.extend_from_slice(&rdata);

        output.push(AnswerRecord {
            name: record.name,
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            rdata,
            raw,
        });
    }
    Ok(output)
}

pub fn extract_matching_answer_records(
    packet: &[u8],
    name: &str,
    class: u16,
    rr_type: u16,
) -> Result<Vec<AnswerRecord>, WireError> {
    let expected = canonical_name_wire(name)?;
    Ok(extract_answer_records(packet)?
        .into_iter()
        .filter(|record| {
            record.name.canonical_wire() == expected.as_slice()
                && (class == CLASS_ANY || record.class == class)
                && (rr_type == TYPE_ANY || record.rr_type == rr_type)
        })
        .collect())
}

fn canonical_name_wire(name: &str) -> Result<Vec<u8>, WireError> {
    let encoded = encode_name(name)?;
    Ok(read_name(&encoded, 0)?.0.canonical_wire().to_vec())
}

fn canonical_record_rdata(
    packet: &[u8],
    record: &ResourceRecord,
) -> Result<Vec<u8>, WireError> {
    match record.rr_type {
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            canonical_name_rdata(packet, record.rdata_offset, record.next_offset)
        }
        6 => {
            let (mname, after_mname) = read_name(packet, record.rdata_offset)?;
            let (rname, after_rname) = read_name(packet, after_mname)?;
            let fixed_end = checked_end(after_rname, 20)?;
            if fixed_end != record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = Vec::new();
            output.extend_from_slice(mname.canonical_wire());
            output.extend_from_slice(rname.canonical_wire());
            output.extend_from_slice(&packet[after_rname..fixed_end]);
            Ok(output)
        }
        15 => {
            let name_offset = checked_end(record.rdata_offset, 2)?;
            if name_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let (exchange, end) = read_name(packet, name_offset)?;
            if end != record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = record.rdata[..2].to_vec();
            output.extend_from_slice(exchange.canonical_wire());
            Ok(output)
        }
        TYPE_SRV => {
            let name_offset = checked_end(record.rdata_offset, 6)?;
            if name_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let (target, end) = read_name(packet, name_offset)?;
            if end != record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = record.rdata[..6].to_vec();
            output.extend_from_slice(target.canonical_wire());
            Ok(output)
        }
        TYPE_RRSIG => {
            let name_offset = checked_end(record.rdata_offset, 18)?;
            if name_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let (signer, signature_offset) = read_name(packet, name_offset)?;
            if signature_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = record.rdata[..18].to_vec();
            output.extend_from_slice(signer.canonical_wire());
            output.extend_from_slice(&packet[signature_offset..record.next_offset]);
            Ok(output)
        }
        47 => {
            let (next_domain, bitmap_offset) = read_name(packet, record.rdata_offset)?;
            if bitmap_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = next_domain.canonical_wire().to_vec();
            output.extend_from_slice(&packet[bitmap_offset..record.next_offset]);
            Ok(output)
        }
        64 | 65 => {
            let name_offset = checked_end(record.rdata_offset, 2)?;
            if name_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let (target, parameters_offset) = read_name(packet, name_offset)?;
            if parameters_offset > record.next_offset {
                return Err(WireError::InvalidRecord);
            }
            let mut output = record.rdata[..2].to_vec();
            output.extend_from_slice(target.canonical_wire());
            output.extend_from_slice(&packet[parameters_offset..record.next_offset]);
            Ok(output)
        }
        _ => Ok(record.rdata.clone()),
    }
}

fn canonical_name_rdata(
    packet: &[u8],
    offset: usize,
    expected_end: usize,
) -> Result<Vec<u8>, WireError> {
    let (name, end) = read_name(packet, offset)?;
    if end != expected_end {
        return Err(WireError::InvalidRecord);
    }
    Ok(name.canonical_wire().to_vec())
}

pub fn extract_service_records(packet: &[u8]) -> Result<ServiceRecords, WireError> {
    extract_service_records_inner(packet, None)
}

pub fn extract_service_records_for_name(
    packet: &[u8],
    name: &str,
) -> Result<ServiceRecords, WireError> {
    let expected = canonical_name_wire(name)?;
    extract_service_records_inner(packet, Some(&expected))
}

fn extract_service_records_inner(
    packet: &[u8],
    expected_name: Option<&[u8]>,
) -> Result<ServiceRecords, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = ServiceRecords::default();
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class != CLASS_IN
            || expected_name.is_some_and(|expected| record.name.canonical_wire() != expected)
        {
            continue;
        }

        match record.rr_type {
            TYPE_SRV => {
                if record.rdata.len() < 7 {
                    return Err(WireError::InvalidRecord);
                }
                let target_offset = checked_end(record.rdata_offset, 6)?;
                let (target, target_end) = read_name(packet, target_offset)?;
                if target_end != record.next_offset {
                    return Err(WireError::InvalidRecord);
                }
                output.srv.push(SrvRecord {
                    priority: read_u16(packet, record.rdata_offset)?,
                    weight: read_u16(packet, record.rdata_offset + 2)?,
                    port: read_u16(packet, record.rdata_offset + 4)?,
                    target,
                });
            }
            TYPE_TXT => {
                let mut cursor = record.rdata_offset;
                while cursor < record.next_offset {
                    let length = usize::from(
                        *packet.get(cursor).ok_or(WireError::ShortPacket)?,
                    );
                    cursor = checked_end(cursor, 1)?;
                    let end = checked_end(cursor, length)?;
                    let item = packet
                        .get(cursor..end)
                        .filter(|_| end <= record.next_offset)
                        .ok_or(WireError::InvalidRecord)?;
                    if !item.is_empty() {
                        output.txt.push(item.to_vec());
                    }
                    cursor = end;
                }
            }
            _ => {}
        }
    }
    Ok(output)
}

pub fn extract_address_records(
    packet: &[u8],
    family: Option<i32>,
) -> Result<AddressRecords, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    if header.question_count != 1 {
        return Err(WireError::WrongQuestionCount(header.question_count));
    }
    let question = parse_question(packet, DNS_HEADER_LEN)?;
    let answers = parse_address_answers(packet, header.answer_count, question.next_offset)?;
    resolve_address_chain(&question.name, answers, family)
}

fn parse_address_answers(
    packet: &[u8],
    answer_count: u16,
    mut offset: usize,
) -> Result<AddressAnswerSet, WireError> {
    let mut output = AddressAnswerSet::default();
    for _ in 0..answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class != CLASS_IN {
            continue;
        }
        let owner = record.name.canonical_wire().to_vec();
        match record.rr_type {
            TYPE_CNAME => insert_redirect(packet, &record, owner, &mut output.aliases)?,
            TYPE_DNAME => insert_redirect(packet, &record, owner, &mut output.dnames)?,
            TYPE_A => {
                let [a, b, c, d] = record.rdata.as_slice() else {
                    return Err(WireError::InvalidRecord);
                };
                insert_address(
                    &mut output,
                    owner,
                    IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                );
            }
            TYPE_AAAA => {
                let bytes: [u8; 16] = record
                    .rdata
                    .as_slice()
                    .try_into()
                    .map_err(|_| WireError::InvalidRecord)?;
                insert_address(&mut output, owner, IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
    }
    if output.aliases.keys().any(|owner| {
        output.addresses.contains_key(owner) || output.dnames.contains_key(owner)
    }) {
        return Err(WireError::InvalidRecord);
    }
    Ok(output)
}

fn insert_redirect(
    packet: &[u8],
    record: &ResourceRecord,
    owner: Vec<u8>,
    redirects: &mut std::collections::HashMap<Vec<u8>, DnsName>,
) -> Result<(), WireError> {
    let (target, end) = read_name(packet, record.rdata_offset)?;
    if end != record.next_offset {
        return Err(WireError::InvalidRecord);
    }
    if let Some(existing) = redirects.get(&owner) {
        if existing.canonical_wire() != target.canonical_wire() {
            return Err(WireError::InvalidRecord);
        }
    } else {
        redirects.insert(owner, target);
    }
    Ok(())
}

fn insert_address(output: &mut AddressAnswerSet, owner: Vec<u8>, address: IpAddr) {
    let values = output.addresses.entry(owner).or_default();
    if !values.contains(&address) {
        values.push(address);
    }
}

fn resolve_address_chain(
    question: &DnsName,
    mut answers: AddressAnswerSet,
    family: Option<i32>,
) -> Result<AddressRecords, WireError> {
    let mut current = question.clone();
    let mut visited = std::collections::HashSet::new();
    for _ in 0..MAX_REDIRECT_CHAIN {
        if !visited.insert(current.canonical_wire().to_vec()) {
            return Err(WireError::InvalidRecord);
        }
        if let Some(target) = answers.aliases.get(current.canonical_wire()) {
            current = target.clone();
            continue;
        }
        if let Some(target) = rewrite_dname(&current, &answers.dnames)? {
            current = target;
            continue;
        }

        let addresses = answers
            .addresses
            .remove(current.canonical_wire())
            .unwrap_or_default()
            .into_iter()
            .filter(|address| family_matches(family, address))
            .collect();
        return Ok(AddressRecords {
            addresses,
            canonical_name: current.text().to_owned(),
        });
    }
    Err(WireError::InvalidRecord)
}

fn rewrite_dname(
    current: &DnsName,
    dnames: &std::collections::HashMap<Vec<u8>, DnsName>,
) -> Result<Option<DnsName>, WireError> {
    let canonical = current.canonical_wire();
    let mut suffix_offset = 0usize;
    let mut prefix_labels = 0usize;
    loop {
        if let Some(target) = dnames.get(&canonical[suffix_offset..]) {
            let prefix = &canonical[..suffix_offset];
            let length = prefix
                .len()
                .checked_add(target.canonical_wire().len())
                .ok_or(WireError::NameTooLong)?;
            if length > 255 {
                return Err(WireError::NameTooLong);
            }
            let mut canonical_wire = Vec::with_capacity(length);
            canonical_wire.extend_from_slice(prefix);
            canonical_wire.extend_from_slice(target.canonical_wire());
            let text = rewrite_dname_text(current.text(), prefix_labels, target.text())?;
            return Ok(Some(DnsName {
                text,
                canonical_wire,
            }));
        }

        let label_length = usize::from(
            *canonical
                .get(suffix_offset)
                .ok_or(WireError::InvalidRecord)?,
        );
        if label_length == 0 {
            return Ok(None);
        }
        if label_length > 63 {
            return Err(WireError::InvalidRecord);
        }
        suffix_offset = suffix_offset
            .checked_add(label_length + 1)
            .ok_or(WireError::NameTooLong)?;
        prefix_labels += 1;
        if suffix_offset >= canonical.len() {
            return Err(WireError::InvalidRecord);
        }
    }
}

fn rewrite_dname_text(
    current: &str,
    prefix_labels: usize,
    target: &str,
) -> Result<String, WireError> {
    let labels: Vec<&str> = if current == "." {
        Vec::new()
    } else {
        current.split('.').collect()
    };
    let prefix = labels
        .get(..prefix_labels)
        .ok_or(WireError::InvalidRecord)?
        .join(".");
    match (prefix.is_empty(), target == ".") {
        (true, true) => Ok(".".to_owned()),
        (true, false) => Ok(target.to_owned()),
        (false, true) => Ok(prefix),
        (false, false) => Ok(format!("{prefix}.{target}")),
    }
}

fn family_matches(family: Option<i32>, address: &IpAddr) -> bool {
    matches!(
        (family, address),
        (None, _) | (Some(2), IpAddr::V4(_)) | (Some(10), IpAddr::V6(_))
    )
}

pub fn extract_addresses(
    packet: &[u8],
    family: Option<i32>,
) -> Result<Vec<IpAddr>, WireError> {
    Ok(extract_address_records(packet, family)?.addresses)
}

pub fn extract_ptr_names(packet: &[u8]) -> Result<Vec<String>, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = parse_question(packet, offset)?.next_offset;
    }

    let mut output = Vec::new();
    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if record.class == CLASS_IN && record.rr_type == TYPE_PTR {
            output.push(read_name(packet, record.rdata_offset)?.0.text().to_owned());
        }
    }
    Ok(output)
}

pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let mut output = String::new();
            for byte in address.octets().iter().rev() {
                use std::fmt::Write as _;
                let _ = write!(output, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            output.push_str("ip6.arpa");
            output
        }
    }
}

pub fn parse_reverse_name(name: &str) -> Option<IpAddr> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = prefix
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        if let [d, c, b, a] = octets.as_slice() {
            return Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
        }
        return None;
    }

    if let Some(prefix) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<u8> = prefix
            .split('.')
            .map(|nibble| u8::from_str_radix(nibble, 16))
            .collect::<Result<_, _>>()
            .ok()?;
        if nibbles.len() != 32 || nibbles.iter().any(|nibble| *nibble > 0x0f) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, pair) in nibbles.chunks_exact(2).enumerate() {
            bytes[15 - index] = pair[0] | (pair[1] << 4);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}
