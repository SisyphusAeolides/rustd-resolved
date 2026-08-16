// SPDX-License-Identifier: LGPL-2.1-or-later
pub fn refused_for(query: &[u8]) -> Result<Vec<u8>, WireError> {
    response_with_code(query, 5, false)
}

pub fn nxdomain_for(query: &[u8]) -> Result<Vec<u8>, WireError> {
    response_with_code(query, 3, false)
}

pub fn authoritative_nxdomain_for(query: &[u8]) -> Result<Vec<u8>, WireError> {
    response_with_code(query, 3, true)
}

fn response_with_code(
    query: &[u8],
    response_code: u16,
    authoritative: bool,
) -> Result<Vec<u8>, WireError> {
    validate(query, false)?;
    let mut response = query[..question_end(query)?].to_vec();
    let mut flags = read_u16(&response, 2)?;
    flags |= FLAG_QR | FLAG_RA;
    flags &= !(FLAG_AA | FLAG_TC | RCODE_MASK);
    if authoritative {
        flags |= FLAG_AA;
    }
    flags |= response_code;
    write_u16(&mut response, 2, flags)?;
    response[6..12].fill(0);
    Ok(response)
}
