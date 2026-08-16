// SPDX-License-Identifier: LGPL-2.1-or-later
fn build_response(
    query: &[u8],
    question: &Question,
    rrset: &[StaticRecord],
) -> Result<Vec<u8>, WireError> {
    wire::validate(query, false)?;
    let end = wire::question_end(query)?;
    let mut response = query[..end].to_vec();
    let mut flags = u16::from_be_bytes([response[2], response[3]]);
    flags |= FLAG_QR | FLAG_RA | FLAG_AD;
    flags &= !(FLAG_AA | FLAG_TC | RCODE_MASK);
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[6..12].fill(0);

    let mut answer_count = 0u16;
    for resource in rrset {
        if question.class != CLASS_ANY && resource.class != question.class {
            continue;
        }
        if question.rr_type != TYPE_ANY
            && resource.rr_type != question.rr_type
            && resource.rr_type != TYPE_CNAME
        {
            continue;
        }

        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&resource.rr_type.to_be_bytes());
        response.extend_from_slice(&resource.class.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(resource.rdata.len())
                .map_err(|_| WireError::ResponseTooLarge)?
                .to_be_bytes(),
        );
        response.extend_from_slice(&resource.rdata);
        if response.len() > usize::from(u16::MAX) {
            return Err(WireError::ResponseTooLarge);
        }
        answer_count = answer_count
            .checked_add(1)
            .ok_or(WireError::ResponseTooLarge)?;
    }
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    Ok(response)
}

fn canonical_name(name: &str) -> String {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        ".".to_owned()
    } else {
        name.to_ascii_lowercase()
    }
}

