// SPDX-License-Identifier: LGPL-2.1-or-later
pub const CNAME_REDIRECTS_MAX: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedirectAnswer {
    Direct {
        canonical_name: String,
        redirects: usize,
    },
    Redirect {
        canonical_name: String,
        redirects: usize,
    },
    NoData,
}

pub fn classify_redirect_answer(packet: &[u8]) -> Result<RedirectAnswer, WireError> {
    let header = Header::parse(packet)?;
    if !header.is_response() {
        return Err(WireError::WrongDirection);
    }
    if header.question_count != 1 {
        return Err(WireError::WrongQuestionCount(header.question_count));
    }
    if header.response_code() != 0 {
        return Ok(RedirectAnswer::NoData);
    }

    let question = parse_question(packet, DNS_HEADER_LEN)?;
    let mut offset = question.next_offset;
    let mut direct = std::collections::HashSet::new();
    let mut aliases = std::collections::HashMap::new();
    let mut dnames = std::collections::HashMap::new();

    for _ in 0..header.answer_count {
        let record = parse_record(packet, offset)?;
        offset = record.next_offset;
        if question.class != CLASS_ANY && record.class != question.class {
            continue;
        }

        let owner = record.name.canonical_wire().to_vec();
        if question.rr_type == TYPE_ANY || record.rr_type == question.rr_type {
            direct.insert(owner);
            continue;
        }

        match record.rr_type {
            TYPE_CNAME => insert_redirect(packet, &record, owner, &mut aliases)?,
            TYPE_DNAME => insert_redirect(packet, &record, owner, &mut dnames)?,
            _ => {}
        }
    }

    if aliases
        .keys()
        .any(|owner| direct.contains(owner) || dnames.contains_key(owner))
    {
        return Err(WireError::InvalidRecord);
    }

    classify_redirect_chain(question.name, &direct, &aliases, &dnames)
}

fn classify_redirect_chain(
    mut current: DnsName,
    direct: &std::collections::HashSet<Vec<u8>>,
    aliases: &std::collections::HashMap<Vec<u8>, DnsName>,
    dnames: &std::collections::HashMap<Vec<u8>, DnsName>,
) -> Result<RedirectAnswer, WireError> {
    let mut visited = std::collections::HashSet::new();
    let mut redirects = 0usize;

    loop {
        if !visited.insert(current.canonical_wire().to_vec()) {
            return Err(WireError::CnameLoop);
        }
        if direct.contains(current.canonical_wire()) {
            return Ok(RedirectAnswer::Direct {
                canonical_name: current.text().to_owned(),
                redirects,
            });
        }

        let target = if let Some(target) = aliases.get(current.canonical_wire()) {
            Some(target.clone())
        } else {
            rewrite_covering_dname(&current, dnames)?
        };

        let Some(target) = target else {
            return if redirects == 0 {
                Ok(RedirectAnswer::NoData)
            } else {
                Ok(RedirectAnswer::Redirect {
                    canonical_name: current.text().to_owned(),
                    redirects,
                })
            };
        };

        if redirects >= CNAME_REDIRECTS_MAX {
            return Err(WireError::CnameLoop);
        }
        redirects += 1;
        current = target;
    }
}

fn rewrite_covering_dname(
    current: &DnsName,
    dnames: &std::collections::HashMap<Vec<u8>, DnsName>,
) -> Result<Option<DnsName>, WireError> {
    let canonical = current.canonical_wire();
    let first_label = usize::from(*canonical.first().ok_or(WireError::InvalidRecord)?);
    if first_label == 0 || first_label > 63 {
        return Ok(None);
    }

    let mut suffix_offset = first_label
        .checked_add(1)
        .ok_or(WireError::NameTooLong)?;
    let mut prefix_labels = 1usize;

    loop {
        if suffix_offset >= canonical.len() {
            return Err(WireError::InvalidRecord);
        }
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
    }
}
