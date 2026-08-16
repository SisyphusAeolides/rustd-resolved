// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::wire::{self, Header, WireError, DNS_HEADER_LEN, TYPE_OPT, TYPE_TSIG};
use std::time::{Duration, Instant};

pub const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;

const OPTION_DAU: u16 = 5;
const OPTION_DHU: u16 = 6;
const OPTION_N3U: u16 = 7;
const OPTION_EXTENDED_ERROR: u16 = 15;
const DNSSEC_OK: u16 = 0x8000;
const FEATURE_RETRY_ATTEMPTS: u8 = 3;
const FEATURE_GRACE_PERIOD_MIN: Duration = Duration::from_secs(5 * 60);
const FEATURE_GRACE_PERIOD_MAX: Duration = Duration::from_secs(6 * 60 * 60);

const DNSSEC_ALGORITHMS: &[u8] = &[5, 7, 8, 10, 13, 14];
const DNSSEC_DIGESTS: &[u8] = &[1, 2, 4];
const NSEC3_ALGORITHMS: &[u8] = &[1];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeatureLevel {
    Udp,
    Edns0,
    TlsPlain,
    DnssecOk,
    TlsDnssecOk,
}

impl FeatureLevel {
    pub const fn uses_edns(self) -> bool {
        !matches!(self, Self::Udp)
    }

    pub const fn uses_tls(self) -> bool {
        matches!(self, Self::TlsPlain | Self::TlsDnssecOk)
    }

    pub const fn dnssec_ok(self) -> bool {
        matches!(self, Self::DnssecOk | Self::TlsDnssecOk)
    }

    #[must_use]
    pub const fn lower(self) -> Self {
        match self {
            Self::TlsDnssecOk => Self::TlsPlain,
            Self::DnssecOk => Self::Edns0,
            Self::TlsPlain => Self::Edns0,
            Self::Edns0 | Self::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerFeatureState {
    possible: FeatureLevel,
    verified: FeatureLevel,
    verified_once: bool,
    failed_attempts: u8,
    retry_after: Option<Instant>,
    grace_period: Duration,
    required_bad_opt: bool,
    bad_opt: bool,
}

impl Default for ServerFeatureState {
    fn default() -> Self {
        Self {
            possible: FeatureLevel::TlsDnssecOk,
            verified: FeatureLevel::Udp,
            verified_once: false,
            failed_attempts: 0,
            retry_after: None,
            grace_period: FEATURE_GRACE_PERIOD_MIN,
            required_bad_opt: false,
            bad_opt: false,
        }
    }
}

impl ServerFeatureState {
    pub fn possible_level(
        &mut self,
        best: FeatureLevel,
        minimum: FeatureLevel,
        now: Instant,
    ) -> FeatureLevel {
        let minimum = if self.required_bad_opt {
            minimum.min(FeatureLevel::Udp)
        } else {
            minimum
        };
        if self.required_bad_opt && self.possible.uses_edns() {
            self.possible = self.possible.min(FeatureLevel::Udp);
        }
        if self.possible > best {
            self.possible = best;
        }
        if self.possible < minimum {
            self.possible = minimum.min(best);
            self.failed_attempts = 0;
            self.retry_after = None;
        }

        let retry_due = self
            .retry_after
            .is_some_and(|retry_after| retry_after <= now);
        if self.possible < best && retry_due {
            self.possible = best;
            self.failed_attempts = 0;
            self.retry_after = None;
            self.bad_opt = false;
            self.grace_period = self
                .grace_period
                .saturating_mul(2)
                .min(FEATURE_GRACE_PERIOD_MAX);
        }

        self.possible
    }

    pub const fn verified_level(&self) -> FeatureLevel {
        self.verified
    }

    pub const fn current_possible_level(&self) -> FeatureLevel {
        self.possible
    }

    pub const fn has_verified_level(&self) -> bool {
        self.verified_once
    }

    pub const fn bad_opt(&self) -> bool {
        self.bad_opt
    }

    pub fn record_success(&mut self, level: FeatureLevel) {
        self.verified_once = true;
        if level > self.verified {
            self.verified = level;
        }
        if level == self.possible {
            self.failed_attempts = 0;
        }
    }

    pub fn record_failure(&mut self, level: FeatureLevel, now: Instant) -> Option<FeatureLevel> {
        if level != self.possible {
            return None;
        }

        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts < FEATURE_RETRY_ATTEMPTS {
            return None;
        }

        let lower = level.lower();
        if lower == level {
            return None;
        }
        self.downgrade_to(lower, now);
        Some(lower)
    }

    pub fn record_tls_failure(
        &mut self,
        level: FeatureLevel,
        now: Instant,
    ) -> Option<FeatureLevel> {
        let lower = match level {
            FeatureLevel::TlsDnssecOk => FeatureLevel::DnssecOk,
            FeatureLevel::TlsPlain => FeatureLevel::Edns0,
            _ => return None,
        };
        self.downgrade_to(lower, now);
        Some(lower)
    }

    pub fn record_bad_opt(&mut self, level: FeatureLevel, now: Instant) -> FeatureLevel {
        if level.uses_edns() {
            self.bad_opt = true;
            self.downgrade_to(FeatureLevel::Udp, now);
        }
        self.possible
    }

    pub fn record_required_bad_opt(&mut self) {
        self.required_bad_opt = true;
        self.bad_opt = true;
        self.possible = FeatureLevel::Udp;
        self.verified = self.verified.min(FeatureLevel::Udp);
    }

    pub fn record_do_off(&mut self, level: FeatureLevel, now: Instant) -> FeatureLevel {
        if level == FeatureLevel::DnssecOk {
            self.downgrade_to(FeatureLevel::Edns0, now);
        } else if level == FeatureLevel::TlsDnssecOk {
            self.downgrade_to(FeatureLevel::TlsPlain, now);
        }
        self.possible
    }

    pub fn downgrade_to(&mut self, level: FeatureLevel, now: Instant) {
        if level >= self.possible {
            return;
        }

        self.possible = level;
        self.verified = self.verified.min(level);
        self.failed_attempts = 0;
        self.retry_after = now.checked_add(self.grace_period);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedQuery {
    pub packet: Vec<u8>,
    pub sent_edns: bool,
    pub managed_opt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptRecord {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub options: Vec<EdnsOption>,
}

pub fn extended_error(opt: &OptRecord) -> Result<Option<(u16, Option<String>)>, WireError> {
    let Some(option) = opt
        .options
        .iter()
        .find(|option| option.code == OPTION_EXTENDED_ERROR)
    else {
        return Ok(None);
    };
    let code = option.data.get(..2).ok_or(WireError::InvalidRecord)?;
    let message = option
        .data
        .get(2..)
        .filter(|message| !message.is_empty())
        .map(|message| String::from_utf8_lossy(message).into_owned());
    Ok(Some((u16::from_be_bytes([code[0], code[1]]), message)))
}

pub fn extended_error_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0 => "Other",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIG Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        25 => "Signature Never Valid",
        26 => "Too Early",
        27 => "Unsupported NSEC3 Iterations",
        28 => "Impossible Transport Policy",
        29 => "Synthesized",
        _ => return None,
    })
}

pub fn format_extended_error(code: u16, message: Option<&str>) -> String {
    let mut output = extended_error_name(code).map_or_else(|| code.to_string(), str::to_owned);
    if let Some(message) = message.filter(|message| !message.is_empty()) {
        output.push_str(": ");
        output.push_str(message);
    }
    output
}

impl OptRecord {
    pub const fn dnssec_ok(&self) -> bool {
        self.flags & DNSSEC_OK != 0
    }

    pub fn advertises_rfc6975(&self) -> bool {
        [OPTION_DAU, OPTION_DHU, OPTION_N3U]
            .iter()
            .all(|code| self.options.iter().any(|option| option.code == *code))
    }
}

#[derive(Clone, Debug)]
struct OptSpan {
    start: usize,
    end: usize,
    udp_payload_size: u16,
    flags: u16,
    options: Vec<EdnsOption>,
}

#[derive(Clone, Debug, Default)]
struct PacketLayout {
    opt: Option<OptSpan>,
    has_tsig: bool,
}

pub fn prepare_query(
    query: &[u8],
    level: FeatureLevel,
    udp_payload_size: u16,
) -> Result<PreparedQuery, WireError> {
    wire::validate(query, false)?;
    let layout = scan_packet(query)?;

    if layout.has_tsig {
        return Ok(PreparedQuery {
            packet: query.to_vec(),
            sent_edns: layout.opt.is_some(),
            managed_opt: false,
        });
    }

    if !level.uses_edns() {
        let packet = if let Some(opt) = layout.opt {
            remove_opt(query, &opt)?
        } else {
            query.to_vec()
        };
        return Ok(PreparedQuery {
            packet,
            sent_edns: false,
            managed_opt: true,
        });
    }

    let options = if level.dnssec_ok() {
        rfc6975_options()
    } else {
        Vec::new()
    };
    let flags = if level.dnssec_ok() { DNSSEC_OK } else { 0 };
    let replacement = encode_opt(udp_payload_size.max(512), 0, 0, flags, &options)?;
    let packet = if let Some(opt) = layout.opt {
        replace_span(query, opt.start, opt.end, &replacement)?
    } else {
        append_opt(query, &replacement)?
    };

    Ok(PreparedQuery {
        packet,
        sent_edns: true,
        managed_opt: true,
    })
}

pub fn inspect_opt(packet: &[u8]) -> Result<Option<OptRecord>, WireError> {
    let layout = scan_packet(packet)?;
    let Some(opt) = layout.opt else {
        return Ok(None);
    };
    let record = wire::parse_record(packet, opt.start)?;
    let ttl = record.ttl.to_be_bytes();

    Ok(Some(OptRecord {
        udp_payload_size: opt.udp_payload_size,
        extended_rcode: ttl[0],
        version: ttl[1],
        flags: opt.flags,
        options: opt.options,
    }))
}

pub fn full_rcode(packet: &[u8], opt: Option<&OptRecord>) -> Result<u16, WireError> {
    let header_rcode = Header::parse(packet)?.response_code();
    Ok(opt.map_or(header_rcode, |opt| {
        (u16::from(opt.extended_rcode) << 4) | header_rcode
    }))
}

pub fn bad_version_response(query: &[u8]) -> Result<Vec<u8>, WireError> {
    let request = inspect_opt(query)?.ok_or(WireError::InvalidRecord)?;
    let mut response = wire::refused_for(query)?;
    let flags = u16::from_be_bytes([response[2], response[3]]) & !0x000f;
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&encode_opt(
        request.udp_payload_size.max(512),
        1,
        0,
        0,
        &[],
    )?);
    Ok(response)
}

pub fn response_for_client(query: &[u8], response: &[u8]) -> Result<Vec<u8>, WireError> {
    wire::validate(query, false)?;
    wire::validate(response, true)?;
    let query_layout = scan_packet(query)?;
    if query_layout.has_tsig || query_layout.opt.is_some() {
        return Ok(response.to_vec());
    }

    let response_layout = scan_packet(response)?;
    let Some(opt_span) = response_layout.opt else {
        return Ok(response.to_vec());
    };
    let opt = inspect_opt(response)?.ok_or(WireError::InvalidRecord)?;
    let extended_rcode = full_rcode(response, Some(&opt))?;
    let mut output = remove_opt(response, &opt_span)?;
    if extended_rcode > 15 {
        let flags = u16::from_be_bytes([output[2], output[3]]);
        output[2..4].copy_from_slice(&((flags & !0x000f) | 2).to_be_bytes());
    }
    Ok(output)
}

fn rfc6975_options() -> Vec<EdnsOption> {
    vec![
        EdnsOption {
            code: OPTION_DAU,
            data: DNSSEC_ALGORITHMS.to_vec(),
        },
        EdnsOption {
            code: OPTION_DHU,
            data: DNSSEC_DIGESTS.to_vec(),
        },
        EdnsOption {
            code: OPTION_N3U,
            data: NSEC3_ALGORITHMS.to_vec(),
        },
    ]
}

fn scan_packet(packet: &[u8]) -> Result<PacketLayout, WireError> {
    let header = Header::parse(packet)?;
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.question_count {
        offset = wire::parse_question(packet, offset)?.next_offset;
    }

    let additional_start = usize::from(header.answer_count) + usize::from(header.authority_count);
    let mut layout = PacketLayout::default();
    for index in 0..header.total_records() {
        let start = offset;
        let record = wire::parse_record(packet, offset)?;
        offset = record.next_offset;

        if record.rr_type == TYPE_OPT {
            if index < additional_start
                || *record.name.canonical_wire() != [0]
                || layout.opt.is_some()
            {
                return Err(WireError::InvalidRecord);
            }
            let ttl = record.ttl.to_be_bytes();
            layout.opt = Some(OptSpan {
                start,
                end: record.next_offset,
                udp_payload_size: record.class,
                flags: u16::from_be_bytes([ttl[2], ttl[3]]),
                options: parse_options(&record.rdata)?,
            });
        } else if record.rr_type == TYPE_TSIG {
            layout.has_tsig = true;
        }
    }

    if offset != packet.len() {
        return Err(WireError::TrailingData);
    }
    Ok(layout)
}

fn parse_options(rdata: &[u8]) -> Result<Vec<EdnsOption>, WireError> {
    let mut options = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let header_end = offset.checked_add(4).ok_or(WireError::InvalidRecord)?;
        let header = rdata
            .get(offset..header_end)
            .ok_or(WireError::InvalidRecord)?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let end = header_end
            .checked_add(length)
            .ok_or(WireError::InvalidRecord)?;
        let option_data = rdata
            .get(header_end..end)
            .ok_or(WireError::InvalidRecord)?
            .to_vec();
        options.push(EdnsOption {
            code,
            data: option_data,
        });
        offset = end;
    }
    Ok(options)
}

fn encode_opt(
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    options: &[EdnsOption],
) -> Result<Vec<u8>, WireError> {
    let mut rdata = Vec::new();
    for option in options {
        rdata.extend_from_slice(&option.code.to_be_bytes());
        rdata.extend_from_slice(
            &u16::try_from(option.data.len())
                .map_err(|_| WireError::ResponseTooLarge)?
                .to_be_bytes(),
        );
        rdata.extend_from_slice(&option.data);
    }

    let mut record = Vec::with_capacity(11 + rdata.len());
    record.push(0);
    record.extend_from_slice(&TYPE_OPT.to_be_bytes());
    record.extend_from_slice(&udp_payload_size.to_be_bytes());
    record.push(extended_rcode);
    record.push(version);
    record.extend_from_slice(&flags.to_be_bytes());
    record.extend_from_slice(
        &u16::try_from(rdata.len())
            .map_err(|_| WireError::ResponseTooLarge)?
            .to_be_bytes(),
    );
    record.extend_from_slice(&rdata);
    Ok(record)
}

fn replace_span(
    packet: &[u8],
    start: usize,
    end: usize,
    replacement: &[u8],
) -> Result<Vec<u8>, WireError> {
    if start > end || end > packet.len() {
        return Err(WireError::InvalidRecord);
    }
    let new_length = packet
        .len()
        .checked_sub(end - start)
        .and_then(|length| length.checked_add(replacement.len()))
        .ok_or(WireError::ResponseTooLarge)?;
    if new_length > usize::from(u16::MAX) {
        return Err(WireError::ResponseTooLarge);
    }

    let mut output = Vec::with_capacity(new_length);
    output.extend_from_slice(&packet[..start]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&packet[end..]);
    Ok(output)
}

fn append_opt(packet: &[u8], opt: &[u8]) -> Result<Vec<u8>, WireError> {
    let header = Header::parse(packet)?;
    let additional_count = header
        .additional_count
        .checked_add(1)
        .ok_or(WireError::ResponseTooLarge)?;
    let new_length = packet
        .len()
        .checked_add(opt.len())
        .ok_or(WireError::ResponseTooLarge)?;
    if new_length > usize::from(u16::MAX) {
        return Err(WireError::ResponseTooLarge);
    }

    let mut output = Vec::with_capacity(new_length);
    output.extend_from_slice(packet);
    output.extend_from_slice(opt);
    output[10..12].copy_from_slice(&additional_count.to_be_bytes());
    Ok(output)
}

fn remove_opt(packet: &[u8], opt: &OptSpan) -> Result<Vec<u8>, WireError> {
    let header = Header::parse(packet)?;
    let additional_count = header
        .additional_count
        .checked_sub(1)
        .ok_or(WireError::InvalidRecord)?;
    let mut output = replace_span(packet, opt.start, opt.end, &[])?;
    output[10..12].copy_from_slice(&additional_count.to_be_bytes());
    Ok(output)
}

#[cfg(test)]
pub(crate) fn add_test_response_opt(
    packet: &[u8],
    extended_rcode: u8,
    dnssec_ok: bool,
) -> Result<Vec<u8>, WireError> {
    let flags = if dnssec_ok { DNSSEC_OK } else { 0 };
    let opt = encode_opt(DEFAULT_UDP_PAYLOAD_SIZE, extended_rcode, 0, flags, &[])?;
    append_opt(packet, &opt)
}

#[cfg(test)]
pub(crate) fn add_test_query_opt_version(packet: &[u8], version: u8) -> Result<Vec<u8>, WireError> {
    let opt = encode_opt(DEFAULT_UDP_PAYLOAD_SIZE, 0, version, 0, &[])?;
    append_opt(packet, &opt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{make_query, TYPE_A};

    #[test]
    fn prepares_dnssec_ok_query_with_rfc6975_options() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let prepared = prepare_query(&query, FeatureLevel::DnssecOk, DEFAULT_UDP_PAYLOAD_SIZE)
            .expect("prepared query");
        let opt = inspect_opt(&prepared.packet)
            .expect("OPT parsing")
            .expect("OPT record");
        assert_eq!(opt.udp_payload_size, DEFAULT_UDP_PAYLOAD_SIZE);
        assert!(opt.dnssec_ok());
        assert!(opt.advertises_rfc6975());
        assert_eq!(
            opt.options,
            vec![
                EdnsOption {
                    code: OPTION_DAU,
                    data: DNSSEC_ALGORITHMS.to_vec(),
                },
                EdnsOption {
                    code: OPTION_DHU,
                    data: DNSSEC_DIGESTS.to_vec(),
                },
                EdnsOption {
                    code: OPTION_N3U,
                    data: NSEC3_ALGORITHMS.to_vec(),
                },
            ]
        );
    }

    #[test]
    fn bad_version_reply_uses_extended_rcode() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let query = add_test_query_opt_version(&query, 1).expect("EDNS query");
        let response = bad_version_response(&query).expect("BADVERS response");
        let opt = inspect_opt(&response)
            .expect("OPT parsing")
            .expect("OPT response");
        assert_eq!(opt.version, 0);
        assert_eq!(full_rcode(&response, Some(&opt)).expect("full rcode"), 16);
    }

    #[test]
    fn udp_feature_level_removes_existing_opt() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let with_opt = prepare_query(&query, FeatureLevel::Edns0, DEFAULT_UDP_PAYLOAD_SIZE)
            .expect("EDNS query");
        let udp = prepare_query(
            &with_opt.packet,
            FeatureLevel::Udp,
            DEFAULT_UDP_PAYLOAD_SIZE,
        )
        .expect("UDP query");
        assert!(inspect_opt(&udp.packet).expect("OPT parsing").is_none());
        assert_eq!(
            Header::parse(&udp.packet)
                .expect("UDP header")
                .additional_count,
            0
        );
    }

    #[test]
    fn duplicate_opt_records_are_rejected() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let opt = encode_opt(DEFAULT_UDP_PAYLOAD_SIZE, 0, 0, 0, &[]).expect("OPT encoding");
        let once = append_opt(&query, &opt).expect("first OPT");
        let twice = append_opt(&once, &opt).expect("second OPT");
        assert_eq!(inspect_opt(&twice), Err(WireError::InvalidRecord));
    }

    #[test]
    fn malformed_option_length_is_rejected() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let mut opt = encode_opt(
            DEFAULT_UDP_PAYLOAD_SIZE,
            0,
            0,
            0,
            &[EdnsOption {
                code: OPTION_DAU,
                data: vec![8],
            }],
        )
        .expect("OPT encoding");
        opt.pop();
        let packet = append_opt(&query, &opt).expect("malformed OPT packet");
        assert!(inspect_opt(&packet).is_err());
    }

    #[test]
    fn full_rcode_uses_the_extended_opt_bits() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let mut response = query;
        response[2..4].copy_from_slice(&0x8007_u16.to_be_bytes());
        let response = add_test_response_opt(&response, 1, false).expect("extended RCODE response");
        let opt = inspect_opt(&response)
            .expect("OPT parsing")
            .expect("OPT record");
        assert_eq!(full_rcode(&response, Some(&opt)), Ok(23));
    }

    #[test]
    fn parses_and_formats_extended_dns_errors() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let opt = encode_opt(
            DEFAULT_UDP_PAYLOAD_SIZE,
            0,
            0,
            0,
            &[EdnsOption {
                code: OPTION_EXTENDED_ERROR,
                data: [16_u16.to_be_bytes().as_slice(), b"Nothing to see here!"].concat(),
            }],
        )
        .expect("OPT encoding");
        let packet = append_opt(&query, &opt).expect("response OPT");
        let opt = inspect_opt(&packet)
            .expect("OPT parsing")
            .expect("OPT record");
        assert_eq!(
            extended_error(&opt),
            Ok(Some((16, Some("Nothing to see here!".to_owned()))))
        );
        assert_eq!(
            format_extended_error(16, Some("Nothing to see here!")),
            "Censored: Nothing to see here!"
        );
        assert_eq!(format_extended_error(32_767, None), "32767");
    }

    #[test]
    fn strips_resolver_owned_opt_from_non_edns_client_response() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8080_u16.to_be_bytes());
        let response = add_test_response_opt(&response, 0, true).expect("response OPT");
        let restored = response_for_client(&query, &response).expect("client response");
        assert!(inspect_opt(&restored).expect("OPT parsing").is_none());
        assert_eq!(
            Header::parse(&restored).expect("header").additional_count,
            0
        );
    }

    #[test]
    fn preserves_opt_for_an_edns_client() {
        let query = make_query("example.test", TYPE_A, 7).expect("query");
        let query = prepare_query(&query, FeatureLevel::Edns0, DEFAULT_UDP_PAYLOAD_SIZE)
            .expect("EDNS query")
            .packet;
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8080_u16.to_be_bytes());
        let restored = response_for_client(&query, &response).expect("client response");
        assert!(inspect_opt(&restored).expect("OPT parsing").is_some());
    }

    #[test]
    fn feature_state_downgrades_after_three_losses_and_recovers() {
        let now = Instant::now();
        let mut state = ServerFeatureState::default();
        assert_eq!(
            state.possible_level(FeatureLevel::DnssecOk, FeatureLevel::Udp, now),
            FeatureLevel::DnssecOk
        );
        assert_eq!(state.record_failure(FeatureLevel::DnssecOk, now), None);
        assert_eq!(state.record_failure(FeatureLevel::DnssecOk, now), None);
        assert_eq!(
            state.record_failure(FeatureLevel::DnssecOk, now),
            Some(FeatureLevel::Edns0)
        );
        assert_eq!(state.verified_level(), FeatureLevel::Udp);
        assert_eq!(
            state.possible_level(
                FeatureLevel::DnssecOk,
                FeatureLevel::Udp,
                now + FEATURE_GRACE_PERIOD_MIN
            ),
            FeatureLevel::DnssecOk
        );

        state.record_bad_opt(FeatureLevel::DnssecOk, Instant::now());
        assert_eq!(
            state.possible_level(FeatureLevel::DnssecOk, FeatureLevel::Edns0, Instant::now()),
            FeatureLevel::Edns0
        );
    }

    #[test]
    fn required_edns_records_bad_opt_forced_possible_to_udp() {
        let mut state = ServerFeatureState::default();
        assert_eq!(
            state.possible_level(FeatureLevel::DnssecOk, FeatureLevel::Edns0, Instant::now()),
            FeatureLevel::DnssecOk
        );
        state.record_success(FeatureLevel::DnssecOk);

        state.record_required_bad_opt();

        assert!(state.bad_opt());
        assert_eq!(state.current_possible_level(), FeatureLevel::Udp);
        assert_eq!(
            state.possible_level(FeatureLevel::DnssecOk, FeatureLevel::Edns0, Instant::now()),
            FeatureLevel::Udp
        );
        assert_eq!(state.verified_level(), FeatureLevel::Udp);
    }

    #[test]
    fn required_edns_bad_opt_maps_a_tls_server_to_udp_verification() {
        let mut state = ServerFeatureState::default();
        state.record_success(FeatureLevel::TlsDnssecOk);

        state.record_required_bad_opt();

        assert!(state.bad_opt());
        assert_eq!(state.verified_level(), FeatureLevel::Udp);
    }

    #[test]
    fn downgrade_to_keeps_state_at_or_below() {
        let mut state = ServerFeatureState::default();
        state.record_success(FeatureLevel::TlsDnssecOk);

        state.downgrade_to(FeatureLevel::TlsDnssecOk, Instant::now());
        assert_eq!(state.current_possible_level(), FeatureLevel::TlsDnssecOk);
    }
}
