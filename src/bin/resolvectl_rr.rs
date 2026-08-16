// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::many_single_char_names)]

use rustd_resolved::json::Value;
use std::error::Error;
use std::fmt;
use std::io::{self, Write as _};
use std::path::Path;

const TYPE_TLSA: u16 = 52;
const TYPE_OPENPGPKEY: u16 = 61;
const DNS_LABEL_MAX: usize = 63;
const DNS_NAME_MAX: usize = 253;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CanonicalRecord {
    pub(super) owner: String,
    pub(super) rr_type: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Vec<u8>,
}

struct ReturnedRecord {
    raw: Vec<u8>,
    record: CanonicalRecord,
    ifindex: Option<i32>,
}

struct ResolvedRecords {
    records: Vec<ReturnedRecord>,
    flags: u64,
}

enum ResolveRecordsResult {
    Records(ResolvedRecords),
    NoResourceRecord,
    NameNotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TlsaQuery {
    owner: String,
    target: String,
}

pub(super) fn openpgp(
    socket: &Path,
    inputs: &[String],
    options: super::LookupOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    if super::json_enabled(options.json) && options.rr_type.is_none() {
        return Err(
            "Use --json=pretty with --type= to acquire resource record information in JSON format."
                .into(),
        );
    }

    if inputs.is_empty() {
        return Err("Too few arguments.".into());
    }

    let mut failures = 0usize;
    for email in inputs {
        let result = (|| {
            let owner = openpgp_owner(email)?;
            let rr_type = options.rr_type.unwrap_or(TYPE_OPENPGPKEY);
            let resolved = match resolve_records(socket, &owner, rr_type, options)? {
                ResolveRecordsResult::Records(records) => records,
                ResolveRecordsResult::NoResourceRecord => {
                    return Err(no_resource_record_error(&owner).into());
                }
                ResolveRecordsResult::NameNotFound => {
                    let legacy_owner = openpgp_legacy_owner(email)?;
                    match resolve_records(socket, &legacy_owner, rr_type, options)? {
                        ResolveRecordsResult::Records(records) => records,
                        ResolveRecordsResult::NoResourceRecord => {
                            return Err(no_resource_record_error(&legacy_owner).into());
                        }
                        ResolveRecordsResult::NameNotFound => {
                            return Err(name_not_found_error(&legacy_owner).into());
                        }
                    }
                }
            };
            let ResolvedRecords { records, flags } = resolved;
            output_records(&records, options, super::print_record_text)?;
            if options.raw == super::RawMode::None && options.legend {
                super::print_query_legend_flags(flags, std::time::Duration::ZERO);
            }
            Ok::<(), Box<dyn Error>>(())
        })();
        if let Err(error) = result {
            eprintln!("{error}");
            failures += 1;
        }
    }
    finish_many("OPENPGPKEY", failures)
}

pub(super) fn tlsa(
    socket: &Path,
    inputs: &[String],
    options: super::LookupOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    if super::json_enabled(options.json) && options.rr_type.is_none() {
        return Err(
            "Use --json=pretty with --type= to acquire resource record information in JSON format."
                .into(),
        );
    }

    let queries = tlsa_queries(inputs)?;
    let mut failures = 0usize;
    for query in queries {
        let result = (|| {
            let rr_type = options.rr_type.unwrap_or(TYPE_TLSA);
            let resolved = match resolve_records(socket, &query.owner, rr_type, options)? {
                ResolveRecordsResult::Records(records) => records,
                ResolveRecordsResult::NoResourceRecord => {
                    return Err(no_resource_record_error(&query.owner).into());
                }
                ResolveRecordsResult::NameNotFound => {
                    return Err(name_not_found_error(&query.owner).into());
                }
            };
            let ResolvedRecords { records, flags } = resolved;
            output_records(&records, options, super::print_record_text)?;
            if options.raw == super::RawMode::None && options.legend {
                super::print_query_legend_flags(flags, std::time::Duration::ZERO);
            }
            Ok::<(), Box<dyn Error>>(())
        })();
        if let Err(error) = result {
            eprintln!("{error}");
            failures += 1;
        }
    }
    finish_many("TLSA", failures)
}

fn finish_many(_operation: &str, failures: usize) -> Result<(), Box<dyn Error>> {
    if failures == 0 {
        Ok(())
    } else {
        Err(Box::new(OperationSummarySuppressed))
    }
}

#[derive(Debug)]
struct OperationSummarySuppressed;

impl fmt::Display for OperationSummarySuppressed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("")
    }
}

impl Error for OperationSummarySuppressed {}

fn resolve_records(
    socket: &Path,
    owner: &str,
    rr_type: u16,
    options: super::LookupOptions<'_>,
) -> Result<ResolveRecordsResult, Box<dyn Error>> {
    let reply = super::call(
        socket,
        "io.rustd.Resolve.ResolveRecord",
        Value::object([
            ("ifindex", Value::Number(i128::from(options.ifindex))),
            ("name", Value::String(owner.to_owned())),
            ("class", Value::Number(i128::from(options.rr_class))),
            ("type", Value::Number(i128::from(rr_type))),
            ("flags", Value::Number(i128::from(options.request_flags))),
        ]),
    )?;
    if reply.get("error").and_then(Value::as_str) == Some("io.rustd.Resolve.NoSuchResourceRecord")
    {
        return Ok(ResolveRecordsResult::NoResourceRecord);
    }
    if reply.get("error").and_then(Value::as_str) == Some("io.rustd.Resolve.DNSError")
        && reply
            .get("parameters")
            .and_then(|parameters| parameters.get("rcode"))
            .and_then(Value::as_u64)
            == Some(3)
    {
        return Ok(ResolveRecordsResult::NameNotFound);
    }
    let parameters = super::reply_parameters_for_query(&reply, owner)
        .map_err(|error| super::resolve_record_error(owner, error))?;
    let values = parameters
        .get("rrs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("ResolveRecord reply has no record array"))?;

    let mut records = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .get("raw")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_data("ResolveRecord reply has no raw record"))?;
        let raw = decode_base64(raw)?;
        let record = parse_canonical_record(&raw)?;
        if record.class != options.rr_class {
            return Err(invalid_data("ResolveRecord reply changed the requested class").into());
        }
        if record.rr_type != rr_type {
            continue;
        }
        let ifindex = value
            .get("ifindex")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok());
        records.push(ReturnedRecord {
            raw,
            record,
            ifindex,
        });
    }
    if records.is_empty() {
        return Ok(ResolveRecordsResult::NoResourceRecord);
    }
    let flags = parameters.get("flags").and_then(Value::as_u64).unwrap_or(0);
    Ok(ResolveRecordsResult::Records(ResolvedRecords {
        records,
        flags,
    }))
}

fn output_records<F>(
    records: &[ReturnedRecord],
    options: super::LookupOptions<'_>,
    mut output_text: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&CanonicalRecord, Option<i32>) -> Result<(), Box<dyn Error>>,
{
    for returned in records {
        let ReturnedRecord {
            raw,
            record,
            ifindex,
        } = returned;
        match options.raw {
            super::RawMode::Packet => {
                io::stdout().write_all(&(raw.len() as u64).to_le_bytes())?;
                io::stdout().write_all(raw)?;
            }
            super::RawMode::Payload => io::stdout().write_all(super::record_payload(record)?)?,
            super::RawMode::None => {
                if super::json_enabled(options.json) {
                    super::print_record_json(record, raw, *ifindex, options.json)?;
                } else {
                    output_text(record, *ifindex)?;
                }
            }
        }
    }
    Ok(())
}

fn openpgp_owner(email: &str) -> Result<String, Box<dyn Error>> {
    openpgp_owner_with(email, |local| sha256(local).to_vec())
}

fn openpgp_legacy_owner(email: &str) -> Result<String, Box<dyn Error>> {
    openpgp_owner_with(email, |local| sha224(local).to_vec())
}

fn no_resource_record_error(owner: &str) -> String {
    format!(
        "{owner}: resolve call failed: Name '{owner}' does not have any RR of the requested type"
    )
}

fn name_not_found_error(owner: &str) -> String {
    format!("{owner}: resolve call failed: Name '{owner}' not found")
}

fn openpgp_owner_with(
    email: &str,
    digest: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<String, Box<dyn Error>> {
    let Some(separator) = email.rfind('@') else {
        return Err(format!("Address does not contain '@': \"{email}\"").into());
    };
    if separator == 0 || separator + 1 == email.len() {
        return Err(format!("Address starts or ends with '@': \"{email}\"").into());
    }
    let local = &email[..separator];
    let domain = canonical_domain(&email[separator + 1..])?;
    let digest = digest(local.as_bytes());
    Ok(format!(
        "{}._openpgpkey.{domain}",
        encode_hex(&digest[..28])
    ))
}

fn canonical_domain(input: &str) -> Result<String, Box<dyn Error>> {
    let input = input.trim_end_matches('.');
    if input.is_empty() {
        return Err("email or TLSA domain is empty".into());
    }
    if input.len() > DNS_NAME_MAX || rustd_resolved::wire::encode_name(input).is_err() {
        return Err(format!("invalid DNS domain: {input}").into());
    }
    Ok(input.to_owned())
}

fn tlsa_queries(inputs: &[String]) -> Result<Vec<TlsaQuery>, Box<dyn Error>> {
    if inputs.is_empty() {
        return Err("Too few arguments.".into());
    }
    let mut family = "tcp";
    let mut targets = inputs;
    if matches!(inputs[0].as_str(), "tcp" | "udp" | "sctp") {
        family = inputs[0].as_str();
        targets = &inputs[1..];
    }
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    targets
        .iter()
        .map(|target| {
            let (domain, port) = tlsa_target(target)?;
            Ok(TlsaQuery {
                owner: format!("_{port}._{family}.{domain}"),
                target: target.clone(),
            })
        })
        .collect()
}

fn tlsa_target(input: &str) -> Result<(String, u16), Box<dyn Error>> {
    let (domain, port) = match input.rsplit_once(':') {
        Some((domain, port)) => {
            if domain.is_empty() || port.is_empty() {
                return Err(format!("invalid TLSA target: {input}").into());
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid TLSA port in {input}"))?;
            if port == 0 {
                return Err(format!("invalid TLSA port in {input}").into());
            }
            (domain, port)
        }
        None => (input, 443),
    };
    Ok((canonical_domain(domain)?, port))
}

pub(super) fn parse_canonical_record(input: &[u8]) -> Result<CanonicalRecord, io::Error> {
    let parsed = rustd_resolved::wire::parse_uncompressed_record(input, 0)
        .map_err(|_| invalid_data("invalid resource record"))?;
    if parsed.next_offset != input.len() {
        return Err(invalid_data("record contains trailing data"));
    }
    let mut offset = 0usize;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(
            *input
                .get(offset)
                .ok_or_else(|| invalid_data("record owner is truncated"))?,
        );
        offset = offset
            .checked_add(1)
            .ok_or_else(|| invalid_data("record owner offset overflow"))?;
        if length == 0 {
            break;
        }
        if length > DNS_LABEL_MAX || length & 0xc0 != 0 {
            return Err(invalid_data("record owner is not an uncompressed DNS name"));
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid_data("record owner label is truncated"))?;
        labels.push(
            std::str::from_utf8(&input[offset..end])
                .map_err(|_| invalid_data("record owner label is not UTF-8"))?
                .to_owned(),
        );
        offset = end;
    }

    let fixed_end = offset
        .checked_add(10)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| invalid_data("record header is truncated"))?;
    let rr_type = read_u16(input, offset)?;
    let class = read_u16(input, offset + 2)?;
    let ttl = parsed.ttl;
    let rdata_length = usize::from(read_u16(input, offset + 8)?);
    let end = fixed_end
        .checked_add(rdata_length)
        .filter(|end| *end == input.len())
        .ok_or_else(|| invalid_data("record RDATA length does not match the raw record"))?;
    Ok(CanonicalRecord {
        owner: if labels.is_empty() {
            ".".to_owned()
        } else {
            labels.join(".")
        },
        rr_type,
        class,
        ttl,
        rdata: input[fixed_end..end].to_vec(),
    })
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, io::Error> {
    let bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("record is truncated"))?
        .try_into()
        .map_err(|_| invalid_data("record is truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn decode_base64(input: &str) -> Result<Vec<u8>, io::Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(invalid_data("invalid base64 record length"));
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let block_count = bytes.len() / 4;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == block_count;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' {
                return Err(invalid_data("invalid base64 padding"));
            }
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            if !last {
                return Err(invalid_data("invalid base64 padding"));
            }
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if c.is_none() && d.is_some() {
            return Err(invalid_data("invalid base64 padding"));
        }

        output.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            output.push((b << 4) | (c >> 2));
            if let Some(d) = d {
                output.push((c << 6) | d);
            } else if c & 0x03 != 0 {
                return Err(invalid_data("non-canonical base64 padding"));
            }
        } else if b & 0x0f != 0 {
            return Err(invalid_data("non-canonical base64 padding"));
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(invalid_data("invalid base64 character")),
    }
}

pub(super) fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        } else {
            output.push('=');
        }
    }
    output
}

fn encode_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[allow(clippy::needless_range_loop)]
#[allow(clippy::too_many_lines)]
fn sha256(input: &[u8]) -> [u8; 32] {
    sha2_digest(
        input,
        [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ],
    )
}

fn sha224(input: &[u8]) -> [u8; 28] {
    let digest = sha2_digest(
        input,
        [
            0xc105_9ed8,
            0x367c_d507,
            0x3070_dd17,
            0xf70e_5939,
            0xffc0_0b31,
            0x6858_1511,
            0x64f9_8fa7,
            0xbefa_4fa4,
        ],
    );
    digest[..28].try_into().expect("SHA-224 digest length")
}

#[allow(clippy::needless_range_loop)]
#[allow(clippy::too_many_lines)]
fn sha2_digest(input: &[u8], initial: [u32; 8]) -> [u8; 32] {
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(input.len().saturating_add(72));
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = initial;
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-256 word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (value, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *value = value.wrapping_add(addition);
        }
    }

    let mut output = [0u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LookupOptions, RawMode};
    use std::path::Path;

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode_hex(&sha224(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn openpgp_owner_matches_rfc7929_example() {
        assert_eq!(
            openpgp_owner("hugh@example.com").unwrap(),
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com"
        );
        assert_eq!(
            openpgp_owner("nobody@localhost").unwrap(),
            "6382b3cc881412b77bfcaeed026001c00d9e3025e66c20f6e7e92f07._openpgpkey.localhost"
        );
        assert_eq!(
            openpgp_legacy_owner("hugh@example.com").unwrap(),
            "8d5730bd8d76d417bf974c03f59eedb7af98cb5c3dc73ea8ebbd54b7._openpgpkey.example.com"
        );
    }

    #[test]
    fn absent_record_errors_keep_the_host_distinction() {
        assert_eq!(
            no_resource_record_error("_443._tcp.localhost"),
            "_443._tcp.localhost: resolve call failed: Name '_443._tcp.localhost' does not have any RR of the requested type"
        );
        assert_eq!(
            name_not_found_error("_443._tcp.does-not-exist.invalid"),
            "_443._tcp.does-not-exist.invalid: resolve call failed: Name '_443._tcp.does-not-exist.invalid' not found"
        );
    }

    #[test]
    fn openpgp_owner_preserves_local_part_case() {
        assert_ne!(
            openpgp_owner("Hugh@example.com").unwrap(),
            openpgp_owner("hugh@example.com").unwrap()
        );
    }

    #[test]
    fn openpgp_hashes_the_local_part_verbatim() {
        assert_ne!(
            openpgp_owner("\"h\\ugh\"@example.com").unwrap(),
            openpgp_owner("hugh@example.com").unwrap()
        );
    }

    #[test]
    fn openpgp_and_tlsa_domains_preserve_dns_presentation() {
        assert_eq!(
            openpgp_owner("hugh@Mail._Service.Example").unwrap(),
            "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.Mail._Service.Example"
        );
        assert_eq!(
            tlsa_queries(&["Example._Service:443".to_owned()]).unwrap(),
            vec![TlsaQuery {
                owner: "_443._tcp.Example._Service".to_owned(),
                target: "Example._Service:443".to_owned(),
            }]
        );
    }

    #[test]
    fn constructs_default_and_explicit_tlsa_names() {
        assert_eq!(
            tlsa_queries(&["example.com".to_owned()]).unwrap(),
            vec![TlsaQuery {
                owner: "_443._tcp.example.com".to_owned(),
                target: "example.com".to_owned(),
            }]
        );
        assert_eq!(
            tlsa_queries(&["udp".to_owned(), "example.com:853".to_owned()]).unwrap(),
            vec![TlsaQuery {
                owner: "_853._udp.example.com".to_owned(),
                target: "example.com:853".to_owned(),
            }]
        );
    }

    #[test]
    fn tlsa_family_without_targets_is_a_successful_noop() {
        assert_eq!(tlsa_queries(&["tcp".to_owned()]).unwrap(), vec![]);
    }

    #[test]
    fn openpgp_rejects_json_without_type() {
        let options = LookupOptions {
            family: 0,
            ifindex: 0,
            request_flags: 0,
            json: Some("short"),
            legend: true,
            rr_type: None,
            rr_class: 1,
            raw: RawMode::None,
        };
        assert_eq!(
            openpgp(
                Path::new("/dev/null"),
                &["hugh@example.com".to_owned()],
                options
            )
            .unwrap_err()
            .to_string(),
            "Use --json=pretty with --type= to acquire resource record information in JSON format."
        );
    }

    #[test]
    fn tlsa_rejects_json_without_type() {
        let options = LookupOptions {
            family: 0,
            ifindex: 0,
            request_flags: 0,
            json: Some("short"),
            legend: true,
            rr_type: None,
            rr_class: 1,
            raw: RawMode::None,
        };
        assert_eq!(
            tlsa(Path::new("/dev/null"), &["example.com".to_owned()], options)
                .unwrap_err()
                .to_string(),
            "Use --json=pretty with --type= to acquire resource record information in JSON format."
        );
    }

    #[test]
    fn base64_round_trip_is_strict() {
        for input in [b"".as_slice(), b"f", b"fo", b"foo", b"foobar"] {
            let encoded = encode_base64(input);
            if input.is_empty() {
                assert!(decode_base64(&encoded).is_err());
            } else {
                assert_eq!(decode_base64(&encoded).unwrap(), input);
            }
        }
        assert!(decode_base64("Zg=A").is_err());
        assert!(decode_base64("Zh==").is_err());
    }

    #[test]
    fn parses_canonical_raw_record() {
        let mut raw = vec![4, b'_', b'4', b'4', b'3', 4, b'_', b't', b'c', b'p'];
        raw.extend_from_slice(&[7]);
        raw.extend_from_slice(b"example");
        raw.extend_from_slice(&[3]);
        raw.extend_from_slice(b"com");
        raw.push(0);
        raw.extend_from_slice(&TYPE_TLSA.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&300u32.to_be_bytes());
        raw.extend_from_slice(&5u16.to_be_bytes());
        raw.extend_from_slice(&[3, 1, 1, 0xaa, 0xbb]);
        assert_eq!(
            parse_canonical_record(&raw).unwrap(),
            CanonicalRecord {
                owner: "_443._tcp.example.com".to_owned(),
                rr_type: TYPE_TLSA,
                class: 1,
                ttl: 300,
                rdata: vec![3, 1, 1, 0xaa, 0xbb],
            }
        );
    }
}
