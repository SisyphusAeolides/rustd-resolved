// SPDX-License-Identifier: LGPL-2.1-or-later
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DNS_HEADER_LEN: usize = 12;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC3PARAM: u16 = 51;
pub const TYPE_TSIG: u16 = 250;
pub const TYPE_IXFR: u16 = 251;
pub const TYPE_AXFR: u16 = 252;
pub const TYPE_ANY: u16 = 255;

pub const fn record_type_is_dnssec(rr_type: u16) -> bool {
    matches!(rr_type, 43 | TYPE_RRSIG | 47 | 48 | 50 | 51)
}

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_AD: u16 = 0x0020;
const FLAG_CD: u16 = 0x0010;
const RCODE_MASK: u16 = 0x000f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl Header {
    pub fn parse(packet: &[u8]) -> Result<Self, WireError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(WireError::ShortPacket);
        }
        Ok(Self {
            id: read_u16(packet, 0)?,
            flags: read_u16(packet, 2)?,
            question_count: read_u16(packet, 4)?,
            answer_count: read_u16(packet, 6)?,
            authority_count: read_u16(packet, 8)?,
            additional_count: read_u16(packet, 10)?,
        })
    }

    pub const fn is_response(self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub const fn truncated(self) -> bool {
        self.flags & FLAG_TC != 0
    }

    pub const fn response_code(self) -> u16 {
        self.flags & RCODE_MASK
    }

    pub const fn checking_disabled(self) -> bool {
        self.flags & FLAG_CD != 0
    }

    pub const fn recursion_desired(self) -> bool {
        self.flags & FLAG_RD != 0
    }

    pub const fn authentic_data(self) -> bool {
        self.flags & FLAG_AD != 0
    }

    pub const fn opcode(self) -> u16 {
        (self.flags & FLAG_OPCODE) >> 11
    }

    pub fn total_records(self) -> usize {
        usize::from(self.answer_count)
            + usize::from(self.authority_count)
            + usize::from(self.additional_count)
    }
}

pub const fn record_type_is_obsolete(rr_type: u16) -> bool {
    matches!(
        rr_type,
        3 | 4 | 7 | 8 | 9 | 10 | 11 | 14 | 30 | 38 | 253 | 254
    )
}

pub fn set_authenticated_data(packet: &mut [u8], authenticated: bool) -> Result<(), WireError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(WireError::ShortPacket);
    }
    let mut flags = read_u16(packet, 2)?;
    if authenticated {
        flags |= FLAG_AD;
    } else {
        flags &= !FLAG_AD;
    }
    packet[2..4].copy_from_slice(&flags.to_be_bytes());
    Ok(())
}

pub fn apply_query_validation_flags(query: &[u8], response: &mut [u8]) -> Result<(), WireError> {
    let query = Header::parse(query)?;
    let response_header = Header::parse(response)?;
    let mut flags = response_header.flags & !FLAG_CD;
    if query.checking_disabled() {
        flags |= FLAG_CD;
        flags &= !FLAG_AD;
    }
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsName {
    text: String,
    canonical_wire: Vec<u8>,
}

impl DnsName {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub next_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub ttl_offset: usize,
    pub rdata_offset: usize,
    pub rdata: Vec<u8>,
    pub next_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnswerRecord {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: DnsName,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceRecords {
    pub srv: Vec<SrvRecord>,
    pub txt: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    NamedA(String, Ipv4Addr),
    NamedAaaa(String, Ipv6Addr),
    Ptr(String),
}

impl LocalRecord {
    const fn rr_type(&self) -> u16 {
        match self {
            Self::A(_) | Self::NamedA(_, _) => TYPE_A,
            Self::Aaaa(_) | Self::NamedAaaa(_, _) => TYPE_AAAA,
            Self::Cname(_) => TYPE_CNAME,
            Self::Ptr(_) => TYPE_PTR,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    ShortPacket,
    InvalidLabel,
    CompressionLoop,
    NameTooLong,
    TrailingData,
    WrongDirection,
    UnsupportedOpcode(u16),
    WrongQuestionCount(u16),
    NoQuestion,
    QuestionMismatch,
    InvalidName(String),
    InvalidRecord,
    InvalidQuestionType(u16),
    TruncatedQuery,
    QueryContainsAnswers(u16),
    CnameLoop,
    ResponseTooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortPacket => formatter.write_str("short DNS packet"),
            Self::InvalidLabel => formatter.write_str("invalid DNS label"),
            Self::CompressionLoop => formatter.write_str("DNS compression loop"),
            Self::NameTooLong => formatter.write_str("DNS name exceeds 255 wire octets"),
            Self::TrailingData => formatter.write_str("data follows the declared DNS sections"),
            Self::WrongDirection => formatter.write_str("unexpected DNS packet direction"),
            Self::UnsupportedOpcode(opcode) => write!(formatter, "unsupported DNS opcode {opcode}"),
            Self::WrongQuestionCount(count) => {
                write!(formatter, "DNS packet contains {count} questions")
            }
            Self::NoQuestion => formatter.write_str("DNS packet has no question"),
            Self::QuestionMismatch => {
                formatter.write_str("DNS response question does not match the query")
            }
            Self::InvalidName(name) => write!(formatter, "invalid DNS name: {name}"),
            Self::InvalidRecord => formatter.write_str("invalid DNS resource record"),
            Self::InvalidQuestionType(rr_type) => {
                write!(formatter, "invalid DNS question type {rr_type}")
            }
            Self::TruncatedQuery => formatter.write_str("DNS query has the truncated flag set"),
            Self::QueryContainsAnswers(count) => {
                write!(formatter, "DNS query contains {count} answer records")
            }
            Self::CnameLoop => {
                formatter.write_str("CNAME or DNAME redirect loop or limit exceeded")
            }
            Self::ResponseTooLarge => formatter.write_str("DNS response exceeds 65535 octets"),
        }
    }
}

impl Error for WireError {}

include!("wire/codec.rs");
include!("wire/packet.rs");
include!("wire/error_response.rs");
include!("wire/records.rs");
include!("wire/dnssec.rs");
include!("wire/redirects.rs");
include!("wire/tests.rs");
pub fn test_compile() {}
