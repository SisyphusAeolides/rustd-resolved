// SPDX-License-Identifier: LGPL-2.1-or-later
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
pub const MDNS_REQUIRED_HOP_LIMIT: u32 = 255;
pub const MDNS_PROBE_COUNT: u8 = 3;
pub const MDNS_ANNOUNCEMENT_COUNT: u8 = 2;
pub const MDNS_PROBE_INTERVAL: Duration = Duration::from_millis(250);
pub const MDNS_ANNOUNCEMENT_INTERVAL: Duration = Duration::from_secs(1);
pub const MDNS_CACHE_FLUSH_GRACE: Duration = Duration::from_secs(1);
pub const MDNS_QUERY_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);

const DNS_HEADER_LENGTH: usize = 12;
const DNS_FLAG_QR: u16 = 1 << 15;
const DNS_FLAG_OPCODE: u16 = 0x7800;
const DNS_FLAG_AA: u16 = 1 << 10;
const DNS_CLASS_CACHE_FLUSH_OR_QU: u16 = 1 << 15;
const DNS_CLASS_MASK: u16 = !DNS_CLASS_CACHE_FLUSH_OR_QU;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MdnsAddressFamily {
    Ipv4,
    Ipv6,
}

impl MdnsAddressFamily {
    pub const fn multicast_address(self) -> IpAddr {
        match self {
            Self::Ipv4 => IpAddr::V4(MDNS_IPV4_MULTICAST),
            Self::Ipv6 => IpAddr::V6(MDNS_IPV6_MULTICAST),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MdnsInterface {
    pub ifindex: u32,
    pub family: MdnsAddressFamily,
}

impl MdnsInterface {
    pub const fn new(ifindex: u32, family: MdnsAddressFamily) -> Self {
        Self { ifindex, family }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsMessageKind {
    Query,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdnsIngressMeta {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub ifindex: Option<u32>,
    pub hop_limit: Option<u32>,
    pub received_multicast: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMdnsPacket {
    pub id: u16,
    pub kind: MdnsMessageKind,
    pub interface: MdnsInterface,
    pub legacy_unicast: bool,
    pub authoritative: bool,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsIngressError {
    ShortPacket,
    MissingInterface,
    MissingHopLimit,
    InvalidHopLimit,
    FamilyMismatch,
    InvalidMulticastDestination,
    InvalidSource,
    InvalidSourcePort,
    InvalidIdentifier,
    UnsupportedOpcode,
    NonAuthoritativeResponse,
    EmptyMessage,
    TruncatedName,
    InvalidLabel,
    InvalidCompressionPointer,
    CompressionLoop,
    TruncatedQuestion,
    TruncatedRecord,
}

impl fmt::Display for MdnsIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ShortPacket => "short mDNS packet",
            Self::MissingInterface => "mDNS packet has no receiving interface",
            Self::MissingHopLimit => "mDNS packet has no received hop limit",
            Self::InvalidHopLimit => "mDNS packet did not arrive with hop limit 255",
            Self::FamilyMismatch => "mDNS source and destination address families differ",
            Self::InvalidMulticastDestination => "mDNS packet used the wrong multicast destination",
            Self::InvalidSource => "mDNS packet has an invalid source address",
            Self::InvalidSourcePort => "mDNS response did not originate from port 5353",
            Self::InvalidIdentifier => "multicast mDNS packet used a nonzero identifier",
            Self::UnsupportedOpcode => "mDNS packet used a nonzero DNS opcode",
            Self::NonAuthoritativeResponse => "mDNS response did not set the authoritative bit",
            Self::EmptyMessage => "mDNS packet contains no questions or records",
            Self::TruncatedName => "truncated mDNS name",
            Self::InvalidLabel => "invalid mDNS label",
            Self::InvalidCompressionPointer => "invalid mDNS compression pointer",
            Self::CompressionLoop => "mDNS compression pointer loop",
            Self::TruncatedQuestion => "truncated mDNS question",
            Self::TruncatedRecord => "truncated mDNS resource record",
        })
    }
}

impl Error for MdnsIngressError {}

pub fn validate_ingress(
    packet: &[u8],
    metadata: MdnsIngressMeta,
) -> Result<ValidatedMdnsPacket, MdnsIngressError> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(MdnsIngressError::ShortPacket);
    }

    let ifindex = metadata
        .ifindex
        .filter(|index| *index != 0)
        .ok_or(MdnsIngressError::MissingInterface)?;
    let hop_limit = metadata
        .hop_limit
        .ok_or(MdnsIngressError::MissingHopLimit)?;
    if hop_limit != MDNS_REQUIRED_HOP_LIMIT {
        return Err(MdnsIngressError::InvalidHopLimit);
    }

    let family = match (metadata.source.ip(), metadata.destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            if source.is_unspecified() || source.is_multicast() {
                return Err(MdnsIngressError::InvalidSource);
            }
            if metadata.received_multicast && destination != MDNS_IPV4_MULTICAST {
                return Err(MdnsIngressError::InvalidMulticastDestination);
            }
            MdnsAddressFamily::Ipv4
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            if source.is_unspecified() || source.is_multicast() {
                return Err(MdnsIngressError::InvalidSource);
            }
            if metadata.received_multicast && destination != MDNS_IPV6_MULTICAST {
                return Err(MdnsIngressError::InvalidMulticastDestination);
            }
            MdnsAddressFamily::Ipv6
        }
        _ => return Err(MdnsIngressError::FamilyMismatch),
    };

    if metadata.received_multicast && metadata.destination.port() != MDNS_PORT {
        return Err(MdnsIngressError::InvalidMulticastDestination);
    }

    let id = read_u16(packet, 0).ok_or(MdnsIngressError::ShortPacket)?;
    let flags = read_u16(packet, 2).ok_or(MdnsIngressError::ShortPacket)?;
    if flags & DNS_FLAG_OPCODE != 0 {
        return Err(MdnsIngressError::UnsupportedOpcode);
    }
    let kind = if flags & DNS_FLAG_QR == 0 {
        MdnsMessageKind::Query
    } else {
        MdnsMessageKind::Response
    };
    let legacy_unicast = kind == MdnsMessageKind::Query
        && (!metadata.received_multicast || metadata.source.port() != MDNS_PORT);
    if id != 0 && !legacy_unicast {
        return Err(MdnsIngressError::InvalidIdentifier);
    }
    if kind == MdnsMessageKind::Response {
        if metadata.source.port() != MDNS_PORT {
            return Err(MdnsIngressError::InvalidSourcePort);
        }
        if flags & DNS_FLAG_AA == 0 {
            return Err(MdnsIngressError::NonAuthoritativeResponse);
        }
    }

    let questions = read_u16(packet, 4).ok_or(MdnsIngressError::ShortPacket)?;
    let answers = read_u16(packet, 6).ok_or(MdnsIngressError::ShortPacket)?;
    let authorities = read_u16(packet, 8).ok_or(MdnsIngressError::ShortPacket)?;
    let additionals = read_u16(packet, 10).ok_or(MdnsIngressError::ShortPacket)?;
    if questions == 0 && answers == 0 && authorities == 0 && additionals == 0 {
        return Err(MdnsIngressError::EmptyMessage);
    }
    validate_sections(packet, questions, answers, authorities, additionals)?;

    Ok(ValidatedMdnsPacket {
        id,
        kind,
        interface: MdnsInterface::new(ifindex, family),
        legacy_unicast,
        authoritative: flags & DNS_FLAG_AA != 0,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn validate_sections(
    packet: &[u8],
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
) -> Result<(), MdnsIngressError> {
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= packet.len())
            .ok_or(MdnsIngressError::TruncatedQuestion)?;
    }
    let records = u32::from(answers) + u32::from(authorities) + u32::from(additionals);
    for _ in 0..records {
        offset = skip_name(packet, offset)?;
        let fixed_end = offset
            .checked_add(10)
            .filter(|end| *end <= packet.len())
            .ok_or(MdnsIngressError::TruncatedRecord)?;
        let length =
            usize::from(read_u16(packet, offset + 8).ok_or(MdnsIngressError::TruncatedRecord)?);
        offset = fixed_end
            .checked_add(length)
            .filter(|end| *end <= packet.len())
            .ok_or(MdnsIngressError::TruncatedRecord)?;
    }
    if offset != packet.len() {
        return Err(MdnsIngressError::TruncatedRecord);
    }
    Ok(())
}

fn skip_name(packet: &[u8], start: usize) -> Result<usize, MdnsIngressError> {
    let mut cursor = start;
    let mut next = None;
    let mut expanded = 1usize;
    let mut visited = BTreeSet::new();
    for _ in 0..128 {
        let Some(&length) = packet.get(cursor) else {
            return Err(MdnsIngressError::TruncatedName);
        };
        if length & 0xc0 == 0xc0 {
            let second = *packet
                .get(cursor + 1)
                .ok_or(MdnsIngressError::TruncatedName)?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if target >= packet.len() || target >= cursor {
                return Err(MdnsIngressError::InvalidCompressionPointer);
            }
            if next.is_none() {
                next = Some(cursor + 2);
            }
            if !visited.insert(target) {
                return Err(MdnsIngressError::CompressionLoop);
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(MdnsIngressError::InvalidLabel);
        }
        cursor += 1;
        if length == 0 {
            return Ok(next.unwrap_or(cursor));
        }
        if length > 63 {
            return Err(MdnsIngressError::InvalidLabel);
        }
        let label_length = usize::from(length);
        cursor = cursor
            .checked_add(label_length)
            .filter(|end| *end <= packet.len())
            .ok_or(MdnsIngressError::TruncatedName)?;
        expanded = expanded
            .checked_add(label_length + 1)
            .ok_or(MdnsIngressError::InvalidLabel)?;
        if expanded > 255 {
            return Err(MdnsIngressError::InvalidLabel);
        }
    }
    Err(MdnsIngressError::CompressionLoop)
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MdnsRecordKey {
    pub interface: MdnsInterface,
    pub owner: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
}

impl MdnsRecordKey {
    pub fn new(
        interface: MdnsInterface,
        owner: &[u8],
        rr_type: u16,
        class: u16,
    ) -> Result<Self, MdnsNameError> {
        Ok(Self {
            interface,
            owner: canonical_wire_name(owner)?,
            rr_type,
            class: class & DNS_CLASS_MASK,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsNameError {
    Empty,
    Compressed,
    InvalidLabel,
    TooLong,
    TrailingData,
}

impl fmt::Display for MdnsNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty wire-format DNS name",
            Self::Compressed => "compressed name is not canonical cache input",
            Self::InvalidLabel => "invalid DNS label",
            Self::TooLong => "DNS name exceeds 255 octets",
            Self::TrailingData => "wire-format DNS name has trailing data",
        })
    }
}

impl Error for MdnsNameError {}

pub fn canonical_wire_name(input: &[u8]) -> Result<Vec<u8>, MdnsNameError> {
    if input.is_empty() {
        return Err(MdnsNameError::Empty);
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0usize;
    loop {
        let Some(&length) = input.get(offset) else {
            return Err(MdnsNameError::InvalidLabel);
        };
        if length & 0xc0 != 0 {
            return Err(MdnsNameError::Compressed);
        }
        output.push(length);
        offset += 1;
        if length == 0 {
            if offset != input.len() {
                return Err(MdnsNameError::TrailingData);
            }
            break;
        }
        if length > 63 {
            return Err(MdnsNameError::InvalidLabel);
        }
        let end = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= input.len())
            .ok_or(MdnsNameError::InvalidLabel)?;
        for &byte in &input[offset..end] {
            output.push(byte.to_ascii_lowercase());
        }
        offset = end;
        if output.len() >= 255 {
            return Err(MdnsNameError::TooLong);
        }
    }
    if output.len() > 255 {
        return Err(MdnsNameError::TooLong);
    }
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsCacheRecord {
    pub rdata: Vec<u8>,
    pub cache_flush: bool,
    pub received_at: Instant,
    pub expires_at: Instant,
}

impl MdnsCacheRecord {
    pub fn remaining_ttl(&self, now: Instant) -> Duration {
        self.expires_at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO)
    }
}

#[derive(Debug, Default)]
pub struct MdnsCache {
    records: BTreeMap<MdnsRecordKey, Vec<MdnsCacheRecord>>,
    hits: u64,
    misses: u64,
}

impl MdnsCache {
    pub fn insert(
        &mut self,
        key: MdnsRecordKey,
        rdata: Vec<u8>,
        ttl: u32,
        cache_flush: bool,
        now: Instant,
    ) {
        let records = self.records.entry(key).or_default();
        records.retain(|record| record.expires_at > now);

        if ttl == 0 {
            for record in records.iter_mut().filter(|record| record.rdata == rdata) {
                let goodbye = now + MDNS_CACHE_FLUSH_GRACE;
                if record.expires_at > goodbye {
                    record.expires_at = goodbye;
                }
            }
            return;
        }

        if cache_flush {
            let grace = now + MDNS_CACHE_FLUSH_GRACE;
            for record in records.iter_mut() {
                let recently_received = now
                    .checked_duration_since(record.received_at)
                    .map_or(true, |age| age < MDNS_CACHE_FLUSH_GRACE);
                if record.rdata != rdata && !recently_received && record.expires_at > grace {
                    record.expires_at = grace;
                }
            }
        }

        let expires_at = now + Duration::from_secs(u64::from(ttl));
        if let Some(record) = records.iter_mut().find(|record| record.rdata == rdata) {
            record.cache_flush = cache_flush;
            record.received_at = now;
            record.expires_at = expires_at;
        } else {
            records.push(MdnsCacheRecord {
                rdata,
                cache_flush,
                received_at: now,
                expires_at,
            });
        }
    }

    pub fn insert_bounded(
        &mut self,
        key: MdnsRecordKey,
        rdata: Vec<u8>,
        ttl: u32,
        cache_flush: bool,
        capacity: usize,
        now: Instant,
    ) {
        if capacity == 0 {
            return;
        }
        self.insert(key, rdata, ttl, cache_flush, now);
        while self.len() > capacity {
            let Some(oldest_key) = self
                .records
                .iter()
                .filter_map(|(key, records)| {
                    records
                        .iter()
                        .map(|record| record.expires_at)
                        .min()
                        .map(|expiry| (key.clone(), expiry))
                })
                .min_by_key(|(_, expiry)| *expiry)
                .map(|(key, _)| key)
            else {
                break;
            };
            self.records.remove(&oldest_key);
        }
    }

    pub fn lookup(&mut self, key: &MdnsRecordKey, now: Instant) -> Vec<MdnsCacheRecord> {
        let Some(records) = self.records.get_mut(key) else {
            self.misses = self.misses.saturating_add(1);
            return Vec::new();
        };
        records.retain(|record| record.expires_at > now);
        let output = records.clone();
        if records.is_empty() {
            self.records.remove(key);
            self.misses = self.misses.saturating_add(1);
        } else {
            self.hits = self.hits.saturating_add(1);
        }
        output
    }

    pub fn snapshot(&mut self, now: Instant) -> Vec<(MdnsRecordKey, Vec<MdnsCacheRecord>)> {
        for records in self.records.values_mut() {
            records.retain(|record| record.expires_at > now);
        }
        self.records.retain(|_, records| !records.is_empty());
        self.records
            .iter()
            .map(|(key, records)| (key.clone(), records.clone()))
            .collect()
    }

    pub fn remove_interface(&mut self, interface: MdnsInterface) {
        self.records.retain(|key, _| key.interface != interface);
    }

    pub fn flush(&mut self) {
        self.records.clear();
    }

    pub fn statistics(&self) -> (usize, u64, u64) {
        (self.records.len(), self.hits, self.misses)
    }

    pub fn reset_statistics(&mut self) {
        self.hits = 0;
        self.misses = 0;
    }

    pub fn len(&self) -> usize {
        self.records.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsKnownAnswer {
    pub owner: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl MdnsKnownAnswer {
    pub fn canonicalized(mut self) -> Result<Self, MdnsNameError> {
        self.owner = canonical_wire_name(&self.owner)?;
        self.class &= DNS_CLASS_MASK;
        Ok(self)
    }
}

pub fn known_answer_suppresses(proposed: &MdnsKnownAnswer, known: &MdnsKnownAnswer) -> bool {
    let proposed_owner = canonical_wire_name(&proposed.owner);
    let known_owner = canonical_wire_name(&known.owner);
    proposed_owner.is_ok()
        && proposed_owner == known_owner
        && proposed.rr_type == known.rr_type
        && (proposed.class & DNS_CLASS_MASK) == (known.class & DNS_CLASS_MASK)
        && proposed.rdata == known.rdata
        && u64::from(known.ttl) * 2 >= u64::from(proposed.ttl)
}

pub fn retain_unsuppressed(
    proposed: &[MdnsKnownAnswer],
    known: &[MdnsKnownAnswer],
) -> Vec<MdnsKnownAnswer> {
    proposed
        .iter()
        .filter(|candidate| {
            !known
                .iter()
                .any(|answer| known_answer_suppresses(candidate, answer))
        })
        .cloned()
        .collect()
}

pub fn refresh_schedule(received_at: Instant, ttl: u32) -> Vec<Instant> {
    if ttl == 0 {
        return Vec::new();
    }
    let milliseconds = u64::from(ttl) * 1000;
    [80u64, 85, 90, 95]
        .iter()
        .map(|percentage| received_at + Duration::from_millis(milliseconds * percentage / 100))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsProbeAction {
    Wait,
    SendProbe,
    SendAnnouncement,
    Established,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MdnsProbePhase {
    Probing,
    Announcing,
    Established,
}

#[derive(Clone, Copy, Debug)]
pub struct MdnsProbeState {
    phase: MdnsProbePhase,
    probes_sent: u8,
    announcements_sent: u8,
    next_deadline: Instant,
}

impl MdnsProbeState {
    pub fn new(now: Instant, initial_jitter: Duration) -> Self {
        Self {
            phase: MdnsProbePhase::Probing,
            probes_sent: 0,
            announcements_sent: 0,
            next_deadline: now + initial_jitter.min(MDNS_PROBE_INTERVAL),
        }
    }

    pub fn poll(&mut self, now: Instant) -> MdnsProbeAction {
        if self.phase == MdnsProbePhase::Established {
            return MdnsProbeAction::Established;
        }
        if now < self.next_deadline {
            return MdnsProbeAction::Wait;
        }
        match self.phase {
            MdnsProbePhase::Probing => {
                self.probes_sent += 1;
                self.next_deadline = now + MDNS_PROBE_INTERVAL;
                if self.probes_sent == MDNS_PROBE_COUNT {
                    self.phase = MdnsProbePhase::Announcing;
                }
                MdnsProbeAction::SendProbe
            }
            MdnsProbePhase::Announcing => {
                self.announcements_sent += 1;
                if self.announcements_sent == MDNS_ANNOUNCEMENT_COUNT {
                    self.phase = MdnsProbePhase::Established;
                } else {
                    self.next_deadline = now + MDNS_ANNOUNCEMENT_INTERVAL;
                }
                MdnsProbeAction::SendAnnouncement
            }
            MdnsProbePhase::Established => MdnsProbeAction::Established,
        }
    }

    pub fn restart_after_conflict(&mut self, now: Instant, jitter: Duration) {
        *self = Self::new(now, jitter);
    }

    pub const fn probes_sent(&self) -> u8 {
        self.probes_sent
    }

    pub const fn announcements_sent(&self) -> u8 {
        self.announcements_sent
    }

    pub const fn is_established(&self) -> bool {
        matches!(self.phase, MdnsProbePhase::Established)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsTieBreak {
    WeWin,
    WeLose,
    Equal,
}

pub fn probe_tie_break(ours: &[Vec<u8>], theirs: &[Vec<u8>]) -> MdnsTieBreak {
    let mut ours = ours.to_vec();
    let mut theirs = theirs.to_vec();
    ours.sort();
    theirs.sort();
    match ours.cmp(&theirs) {
        std::cmp::Ordering::Greater => MdnsTieBreak::WeWin,
        std::cmp::Ordering::Less => MdnsTieBreak::WeLose,
        std::cmp::Ordering::Equal => MdnsTieBreak::Equal,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MdnsQueryBackoff {
    interval: Duration,
}

impl Default for MdnsQueryBackoff {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
        }
    }
}

impl MdnsQueryBackoff {
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub fn advance(&mut self) -> Duration {
        let current = self.interval;
        self.interval = self
            .interval
            .checked_mul(2)
            .unwrap_or(MDNS_QUERY_BACKOFF_MAX)
            .min(MDNS_QUERY_BACKOFF_MAX);
        current
    }

    pub fn reset(&mut self) {
        self.interval = Duration::from_secs(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut output = Vec::new();
        for label in labels {
            output.push(u8::try_from(label.len()).expect("label length"));
            output.extend_from_slice(label.as_bytes());
        }
        output.push(0);
        output
    }

    fn query(identifier: u16) -> Vec<u8> {
        let owner = name(&["host", "local"]);
        let mut packet = vec![0; DNS_HEADER_LENGTH];
        packet[0..2].copy_from_slice(&identifier.to_be_bytes());
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&owner);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn response() -> Vec<u8> {
        let owner = name(&["host", "local"]);
        let mut packet = vec![0; DNS_HEADER_LENGTH];
        packet[2..4].copy_from_slice(&(DNS_FLAG_QR | DNS_FLAG_AA).to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&owner);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&(1u16 | DNS_CLASS_CACHE_FLUSH_OR_QU).to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 10]);
        packet
    }

    fn ipv4_meta(source_port: u16, multicast: bool) -> MdnsIngressMeta {
        MdnsIngressMeta {
            source: SocketAddr::from(([192, 0, 2, 1], source_port)),
            destination: if multicast {
                SocketAddr::new(IpAddr::V4(MDNS_IPV4_MULTICAST), MDNS_PORT)
            } else {
                SocketAddr::from(([192, 0, 2, 2], 9999))
            },
            ifindex: Some(2),
            hop_limit: Some(MDNS_REQUIRED_HOP_LIMIT),
            received_multicast: multicast,
        }
    }

    #[test]
    fn accepts_multicast_query() {
        let parsed = validate_ingress(&query(0), ipv4_meta(MDNS_PORT, true)).expect("mDNS query");
        assert_eq!(parsed.kind, MdnsMessageKind::Query);
        assert!(!parsed.legacy_unicast);
        assert_eq!(
            parsed.interface,
            MdnsInterface::new(2, MdnsAddressFamily::Ipv4)
        );
    }

    #[test]
    fn accepts_legacy_unicast_query_and_identifier() {
        let parsed = validate_ingress(&query(77), ipv4_meta(40000, true)).expect("legacy query");
        assert!(parsed.legacy_unicast);
        assert_eq!(parsed.id, 77);
    }

    #[test]
    fn rejects_wrong_hop_limit() {
        let mut metadata = ipv4_meta(MDNS_PORT, true);
        metadata.hop_limit = Some(64);
        assert_eq!(
            validate_ingress(&query(0), metadata),
            Err(MdnsIngressError::InvalidHopLimit)
        );
    }

    #[test]
    fn rejects_response_from_ephemeral_port() {
        assert_eq!(
            validate_ingress(&response(), ipv4_meta(40000, true)),
            Err(MdnsIngressError::InvalidSourcePort)
        );
    }

    #[test]
    fn accepts_authoritative_response() {
        let parsed = validate_ingress(&response(), ipv4_meta(MDNS_PORT, true)).expect("response");
        assert_eq!(parsed.kind, MdnsMessageKind::Response);
        assert!(parsed.authoritative);
    }

    #[test]
    fn rejects_forward_compression_pointer() {
        let mut packet = vec![0; DNS_HEADER_LENGTH];
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x10, 0, 1, 0, 1]);
        assert_eq!(
            validate_ingress(&packet, ipv4_meta(MDNS_PORT, true)),
            Err(MdnsIngressError::InvalidCompressionPointer)
        );
    }

    #[test]
    fn canonicalizes_wire_names() {
        assert_eq!(
            canonical_wire_name(&name(&["HoSt", "LOCAL"])).expect("canonical name"),
            name(&["host", "local"])
        );
    }

    #[test]
    fn cache_flush_expires_old_conflicting_records_after_grace() {
        let now = Instant::now();
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let key =
            MdnsRecordKey::new(interface, &name(&["host", "local"]), 1, 1).expect("cache key");
        let mut cache = MdnsCache::default();
        cache.insert(key.clone(), vec![192, 0, 2, 1], 120, false, now);
        let later = now + Duration::from_secs(2);
        cache.insert(key.clone(), vec![192, 0, 2, 2], 120, true, later);
        assert_eq!(cache.lookup(&key, later).len(), 2);
        assert_eq!(cache.lookup(&key, later + MDNS_CACHE_FLUSH_GRACE).len(), 1);
    }

    #[test]
    fn cache_statistics_count_live_keys_hits_and_misses() {
        let now = Instant::now();
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let key =
            MdnsRecordKey::new(interface, &name(&["host", "local"]), 1, 1).expect("cache key");
        let mut cache = MdnsCache::default();
        assert!(cache.lookup(&key, now).is_empty());
        cache.insert(key.clone(), vec![192, 0, 2, 1], 120, true, now);
        assert_eq!(cache.lookup(&key, now).len(), 1);
        assert_eq!(cache.statistics(), (1, 1, 1));
        cache.reset_statistics();
        assert_eq!(cache.statistics(), (1, 0, 0));
    }

    #[test]
    fn bounded_cache_evicts_the_earliest_record_set() {
        let now = Instant::now();
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let first =
            MdnsRecordKey::new(interface, &name(&["first", "local"]), 1, 1).expect("first key");
        let second =
            MdnsRecordKey::new(interface, &name(&["second", "local"]), 1, 1).expect("second key");
        let mut cache = MdnsCache::default();
        cache.insert_bounded(first.clone(), vec![192, 0, 2, 1], 10, true, 1, now);
        cache.insert_bounded(second.clone(), vec![192, 0, 2, 2], 20, true, 1, now);
        assert!(cache.lookup(&first, now).is_empty());
        assert_eq!(cache.lookup(&second, now).len(), 1);
    }

    #[test]
    fn goodbye_shortens_matching_record_lifetime() {
        let now = Instant::now();
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let key =
            MdnsRecordKey::new(interface, &name(&["host", "local"]), 1, 1).expect("cache key");
        let mut cache = MdnsCache::default();
        let rdata = vec![192, 0, 2, 1];
        cache.insert(key.clone(), rdata.clone(), 120, true, now);
        cache.insert(key.clone(), rdata, 0, true, now + Duration::from_secs(1));
        assert!(cache.lookup(&key, now + Duration::from_secs(3)).is_empty());
    }

    #[test]
    fn cache_is_scoped_to_interface() {
        let now = Instant::now();
        let first = MdnsRecordKey::new(
            MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
            &name(&["host", "local"]),
            1,
            1,
        )
        .expect("first key");
        let second = MdnsRecordKey::new(
            MdnsInterface::new(3, MdnsAddressFamily::Ipv4),
            &name(&["host", "local"]),
            1,
            1,
        )
        .expect("second key");
        let mut cache = MdnsCache::default();
        cache.insert(first.clone(), vec![192, 0, 2, 1], 120, false, now);
        cache.insert(second.clone(), vec![192, 0, 2, 2], 120, false, now);
        cache.remove_interface(first.interface);
        assert!(cache.lookup(&first, now).is_empty());
        assert_eq!(cache.lookup(&second, now).len(), 1);
    }

    #[test]
    fn suppresses_known_answer_at_half_ttl() {
        let proposed = MdnsKnownAnswer {
            owner: name(&["host", "local"]),
            rr_type: 1,
            class: 1,
            ttl: 120,
            rdata: vec![192, 0, 2, 1],
        };
        let mut known = proposed.clone();
        known.ttl = 60;
        assert!(known_answer_suppresses(&proposed, &known));
        known.ttl = 59;
        assert!(!known_answer_suppresses(&proposed, &known));
    }

    #[test]
    fn refreshes_at_eighty_through_ninety_five_percent() {
        let now = Instant::now();
        let schedule = refresh_schedule(now, 100);
        assert_eq!(schedule.len(), 4);
        assert_eq!(schedule[0], now + Duration::from_secs(80));
        assert_eq!(schedule[3], now + Duration::from_secs(95));
    }

    #[test]
    fn probe_and_announcement_state_machine_is_bounded() {
        let start = Instant::now();
        let mut state = MdnsProbeState::new(start, Duration::ZERO);
        assert_eq!(state.poll(start), MdnsProbeAction::SendProbe);
        assert_eq!(
            state.poll(start + MDNS_PROBE_INTERVAL),
            MdnsProbeAction::SendProbe
        );
        assert_eq!(
            state.poll(start + MDNS_PROBE_INTERVAL * 2),
            MdnsProbeAction::SendProbe
        );
        assert_eq!(
            state.poll(start + MDNS_PROBE_INTERVAL * 3),
            MdnsProbeAction::SendAnnouncement
        );
        assert_eq!(
            state.poll(start + MDNS_PROBE_INTERVAL * 3 + MDNS_ANNOUNCEMENT_INTERVAL),
            MdnsProbeAction::SendAnnouncement
        );
        assert!(state.is_established());
        assert_eq!(state.probes_sent(), MDNS_PROBE_COUNT);
        assert_eq!(state.announcements_sent(), MDNS_ANNOUNCEMENT_COUNT);
    }

    #[test]
    fn lexicographically_later_probe_data_wins() {
        assert_eq!(probe_tie_break(&[vec![2]], &[vec![1]]), MdnsTieBreak::WeWin);
        assert_eq!(
            probe_tie_break(&[vec![1]], &[vec![2]]),
            MdnsTieBreak::WeLose
        );
    }

    #[test]
    fn query_backoff_caps_at_one_hour() {
        let mut backoff = MdnsQueryBackoff::default();
        for _ in 0..32 {
            backoff.advance();
        }
        assert_eq!(backoff.interval(), MDNS_QUERY_BACKOFF_MAX);
        backoff.reset();
        assert_eq!(backoff.interval(), Duration::from_secs(1));
    }
}
