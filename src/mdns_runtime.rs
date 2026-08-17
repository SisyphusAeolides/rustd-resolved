// SPDX-License-Identifier: LGPL-2.1-or-later
use super::parity::{
    canonical_wire_name, validate_ingress, MdnsAddressFamily, MdnsCache, MdnsCacheRecord,
    MdnsIngressMeta, MdnsInterface, MdnsMessageKind, MdnsRecordKey, MDNS_IPV4_MULTICAST,
    MDNS_IPV6_MULTICAST, MDNS_PORT,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DNS_HEADER_LENGTH: usize = 12;
const DNS_FLAG_QR: u16 = 1 << 15;
const DNS_FLAG_AA: u16 = 1 << 10;
const DNS_FLAG_TC: u16 = 1 << 9;
const DNS_FLAG_RD: u16 = 1 << 8;
const DNS_FLAG_RA: u16 = 1 << 7;
const DNS_CLASS_MASK: u16 = 0x7fff;
const DNS_CLASS_CACHE_FLUSH: u16 = 0x8000;
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_DNAME: u16 = 39;
const TYPE_NSEC: u16 = 47;
const TYPE_ANY: u16 = 255;
const RUSTD_RESOLVE_DNS: u64 = 1 << 0;
const RUSTD_RESOLVE_LLMNR_IPV4: u64 = 1 << 1;
const RUSTD_RESOLVE_LLMNR_IPV6: u64 = 1 << 2;
const RUSTD_RESOLVE_MDNS_IPV4: u64 = 1 << 3;
const RUSTD_RESOLVE_MDNS_IPV6: u64 = 1 << 4;
const RUSTD_RESOLVE_PROTOCOLS_ALL: u64 = RUSTD_RESOLVE_DNS
    | RUSTD_RESOLVE_LLMNR_IPV4
    | RUSTD_RESOLVE_LLMNR_IPV6
    | RUSTD_RESOLVE_MDNS_IPV4
    | RUSTD_RESOLVE_MDNS_IPV6;
const RUSTD_RESOLVE_NO_NETWORK: u64 = 1 << 15;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;
const RESPONSE_SETTLE_TIME: Duration = Duration::from_millis(120);
const RECEIVE_SLEEP: Duration = Duration::from_millis(5);
const MAX_MDNS_PACKET: usize = 65_535;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMdnsInterface {
    family: i32,
    ifindex: u32,
    address: [u8; 16],
    scope_id: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMdnsMeta {
    family: i32,
    port: u16,
    reserved: u16,
    source: [u8; 16],
    destination: [u8; 16],
    ifindex: u32,
    hop_limit: u32,
}

extern "C" {
    fn rustd_resolved_mdns_interfaces(output: *mut NativeMdnsInterface, capacity: usize) -> isize;
    fn rustd_resolved_mdns_open(family: i32, ifindex: u32, port: u16) -> i32;
    fn rustd_resolved_mdns_recv(
        fd: i32,
        buffer: *mut u8,
        capacity: usize,
        metadata: *mut NativeMdnsMeta,
    ) -> isize;
}

#[derive(Debug)]
pub enum MdnsRuntimeError {
    Io(io::Error),
    InvalidQuery(&'static str),
    InvalidResponse(&'static str),
}

impl fmt::Display for MdnsRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::InvalidQuery(message) | Self::InvalidResponse(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for MdnsRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidQuery(_) | Self::InvalidResponse(_) => None,
        }
    }
}

impl From<io::Error> for MdnsRuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
struct RuntimeInterface {
    interface: MdnsInterface,
    address: IpAddr,
}

#[derive(Debug)]
struct RuntimeSocket {
    interface: MdnsInterface,
    socket: UdpSocket,
}

#[derive(Clone, Debug)]
struct MdnsQuestion {
    id: u16,
    flags: u16,
    owner: Vec<u8>,
    text: String,
    rr_type: u16,
    class: u16,
    raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimeRecord {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    cache_flush: bool,
    rdata: Vec<u8>,
    presentation_rdata: Option<String>,
    interface: MdnsInterface,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsBrowseUpdate {
    pub added: bool,
    pub family: i32,
    pub name: String,
    pub service_type: String,
    pub domain: String,
    pub ifindex: i32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BrowseServiceKey {
    family: i32,
    name: String,
    service_type: String,
    domain: String,
    ifindex: i32,
}

impl BrowseServiceKey {
    fn update(&self, added: bool) -> MdnsBrowseUpdate {
        MdnsBrowseUpdate {
            added,
            family: self.family,
            name: self.name.clone(),
            service_type: self.service_type.clone(),
            domain: self.domain.clone(),
            ifindex: self.ifindex,
        }
    }
}

#[derive(Debug)]
pub struct MdnsBrowser {
    sockets: Vec<RuntimeSocket>,
    queries: BTreeSet<Vec<u8>>,
    requested_type: Option<String>,
    domain: String,
    active: BTreeMap<BrowseServiceKey, Instant>,
    next_query: Instant,
    query_interval: Duration,
}

impl MdnsBrowser {
    pub fn new(
        domain: &str,
        service_type: Option<&str>,
        requested_ifindex: Option<i32>,
        flags: u64,
    ) -> Result<Self, MdnsRuntimeError> {
        if diagnostics_enabled() {
            eprintln!(
                "rustd-resolved: mDNS browser input domain={domain:?} type={service_type:?} ifindex={requested_ifindex:?} flags={flags}"
            );
        }
        let domain = domain.trim_end_matches('.');
        let domain = if domain.is_empty() { "." } else { domain };
        let domain = domain.to_ascii_lowercase();
        browse_owner(&domain)?;
        let requested_type = service_type
            .map(|value| {
                super::parity_dnssd::DnsSdServiceType::parse(value)
                    .map(|service_type| service_type.presentation())
                    .map_err(|_| {
                        MdnsRuntimeError::InvalidQuery("invalid DNS-SD browse service type")
                    })
            })
            .transpose()?;
        let (first_owner, requested_type, domain) = browse_target(&domain, requested_type)?;
        let requested_ifindex = match requested_ifindex {
            Some(index) if index <= 0 => {
                return Err(MdnsRuntimeError::InvalidQuery(
                    "mDNS interface index must be positive",
                ));
            }
            Some(index) => Some(u32::try_from(index).map_err(|_| {
                MdnsRuntimeError::InvalidQuery("mDNS interface index is out of range")
            })?),
            None => None,
        };
        let protocol_flags = flags & RUSTD_RESOLVE_PROTOCOLS_ALL;
        let allow_ipv4 = protocol_flags == 0 || flags & RUSTD_RESOLVE_MDNS_IPV4 != 0;
        let allow_ipv6 = protocol_flags == 0 || flags & RUSTD_RESOLVE_MDNS_IPV6 != 0;
        let discovered = if flags & RUSTD_RESOLVE_NO_NETWORK != 0 {
            Vec::new()
        } else {
            interfaces()?
                .into_iter()
                .filter(|entry| {
                    requested_ifindex.map_or(true, |index| entry.interface.ifindex == index)
                        && match entry.interface.family {
                            MdnsAddressFamily::Ipv4 => allow_ipv4,
                            MdnsAddressFamily::Ipv6 => allow_ipv6,
                        }
                })
                .collect::<Vec<_>>()
        };
        let sockets = open_sockets(&discovered)?;
        if diagnostics_enabled() {
            eprintln!(
                "rustd-resolved: mDNS browser domain={domain} type={} ifindex={} interfaces={} sockets={}",
                requested_type.as_deref().unwrap_or("<all>"),
                requested_ifindex.map_or_else(|| "all".to_owned(), |value| value.to_string()),
                discovered.len(),
                sockets.len()
            );
        }
        Ok(Self {
            sockets,
            queries: BTreeSet::from([first_owner]),
            requested_type,
            domain,
            active: BTreeMap::new(),
            next_query: Instant::now(),
            query_interval: Duration::from_secs(1),
        })
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<MdnsBrowseUpdate>, MdnsRuntimeError> {
        let deadline = Instant::now() + timeout;
        let mut updates = self.expire(Instant::now());
        let mut buffer = vec![0u8; MAX_MDNS_PACKET];
        while Instant::now() < deadline {
            let now = Instant::now();
            if now >= self.next_query {
                self.send_queries()?;
                self.next_query = now + self.query_interval;
                self.query_interval = Duration::from_secs(
                    self.query_interval
                        .as_secs()
                        .saturating_mul(2)
                        .clamp(1, 3600),
                );
            }
            let mut received = Vec::new();
            for endpoint in &mut self.sockets {
                loop {
                    let Some(datagram) = recv_datagram(endpoint, &mut buffer)? else {
                        break;
                    };
                    let validated = match validate_ingress(datagram.packet, datagram.metadata) {
                        Ok(value) => value,
                        Err(error) => {
                            if diagnostics_enabled() {
                                eprintln!(
                                    "rustd-resolved: mDNS browser rejected packet on {}: {error}",
                                    endpoint.interface.ifindex
                                );
                            }
                            continue;
                        }
                    };
                    if validated.kind != MdnsMessageKind::Response
                        || validated.interface != endpoint.interface
                    {
                        continue;
                    }
                    let records = parse_response_records(datagram.packet, endpoint.interface)?;
                    if diagnostics_enabled() {
                        eprintln!(
                            "rustd-resolved: mDNS browser received {} records on {}",
                            records.len(),
                            endpoint.interface.ifindex
                        );
                    }
                    received.extend(records);
                }
            }
            let had_records = !received.is_empty();
            for record in received {
                self.process_record(record, Instant::now(), &mut updates)?;
            }
            updates.extend(self.expire(Instant::now()));
            if !updates.is_empty() {
                if diagnostics_enabled() {
                    eprintln!(
                        "rustd-resolved: mDNS browser produced {} service updates",
                        updates.len()
                    );
                }
                break;
            }
            if !had_records {
                thread::sleep(RECEIVE_SLEEP);
            }
        }
        Ok(updates)
    }

    fn send_queries(&self) -> Result<(), MdnsRuntimeError> {
        for owner in &self.queries {
            let query = browse_query(owner);
            for endpoint in &self.sockets {
                let destination = multicast_destination(endpoint.interface);
                match endpoint.socket.send_to(&query, destination) {
                    Ok(length) if length == query.len() => {}
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "short mDNS browse send",
                        )
                        .into());
                    }
                    Err(error) if interface_send_error(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if diagnostics_enabled() {
                eprintln!(
                    "rustd-resolved: mDNS browser sent {}-byte query on {} sockets",
                    query.len(),
                    self.sockets.len()
                );
            }
        }
        Ok(())
    }

    fn process_record(
        &mut self,
        record: RuntimeRecord,
        now: Instant,
        updates: &mut Vec<MdnsBrowseUpdate>,
    ) -> Result<(), MdnsRuntimeError> {
        if record.rr_type != TYPE_PTR || record.class != 1 {
            return Ok(());
        }
        if !self.queries.contains(&record.owner) {
            return Ok(());
        }
        let service = record
            .presentation_rdata
            .as_deref()
            .and_then(split_service_text)
            .or_else(|| split_service_wire(&record.rdata));
        let Some((Some(name), service_type, domain)) = service else {
            return Ok(());
        };
        if domain != self.domain
            || self
                .requested_type
                .as_ref()
                .is_some_and(|requested| requested != &service_type)
        {
            return Ok(());
        }
        let family = match record.interface.family {
            MdnsAddressFamily::Ipv4 => AF_INET,
            MdnsAddressFamily::Ipv6 => AF_INET6,
        };
        let ifindex = i32::try_from(record.interface.ifindex)
            .map_err(|_| MdnsRuntimeError::InvalidResponse("mDNS ifindex is out of range"))?;
        let key = BrowseServiceKey {
            family,
            name,
            service_type,
            domain,
            ifindex,
        };
        if record.ttl == 0 {
            if self.active.remove(&key).is_some() {
                updates.push(key.update(false));
            }
            return Ok(());
        }
        let expiry = now + Duration::from_secs(u64::from(record.ttl));
        if self.active.insert(key.clone(), expiry).is_none() {
            updates.push(key.update(true));
        }
        Ok(())
    }

    fn expire(&mut self, now: Instant) -> Vec<MdnsBrowseUpdate> {
        let expired = self
            .active
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &expired {
            self.active.remove(key);
        }
        expired.into_iter().map(|key| key.update(false)).collect()
    }
}

static CACHE: OnceLock<Mutex<MdnsCache>> = OnceLock::new();

fn cache() -> MutexGuard<'static, MdnsCache> {
    CACHE
        .get_or_init(|| Mutex::new(MdnsCache::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn flush_cache() {
    cache().flush();
}

pub fn cache_snapshot() -> Vec<(MdnsRecordKey, Vec<MdnsCacheRecord>)> {
    cache().snapshot(Instant::now())
}

pub fn cache_statistics() -> (usize, u64, u64) {
    let mut cache = cache();
    let _ = cache.snapshot(Instant::now());
    cache.statistics()
}

pub fn reset_cache_statistics() {
    cache().reset_statistics();
}

#[cfg(test)]
pub(crate) fn seed_cache_for_flush_test() {
    let key = MdnsRecordKey::new(
        MdnsInterface::new(u32::MAX, MdnsAddressFamily::Ipv4),
        &[
            5, b'f', b'l', b'u', b's', b'h', 5, b'l', b'o', b'c', b'a', b'l', 0,
        ],
        TYPE_A,
        1,
    )
    .expect("test mDNS key");
    cache().insert(key, vec![192, 0, 2, 1], 120, true, Instant::now());
}

#[cfg(test)]
pub(crate) fn cache_has_flush_test_record() -> bool {
    let key = MdnsRecordKey::new(
        MdnsInterface::new(u32::MAX, MdnsAddressFamily::Ipv4),
        &[
            5, b'f', b'l', b'u', b's', b'h', 5, b'l', b'o', b'c', b'a', b'l', 0,
        ],
        TYPE_A,
        1,
    )
    .expect("test mDNS key");
    !cache().lookup(&key, Instant::now()).is_empty()
}

pub fn should_handle_query(query: &[u8]) -> bool {
    parse_question(query)
        .map(|question| should_handle_name(&question.text))
        .unwrap_or(false)
}

pub fn should_handle_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "local"
        || name.ends_with(".local")
        || name.ends_with(".254.169.in-addr.arpa")
        || name.ends_with(".8.e.f.ip6.arpa")
}

pub fn query_raw(
    query: &[u8],
    requested_ifindex: Option<i32>,
    timeout: Duration,
    read_cache: bool,
    write_cache: bool,
    cache_capacity: usize,
    network_allowed: bool,
) -> Result<Option<(Vec<u8>, bool)>, MdnsRuntimeError> {
    check_query_cancellation()?;
    if !mdns_enabled() {
        return Ok(None);
    }
    let question = parse_question(query)?;
    if !should_handle_name(&question.text) {
        return Ok(None);
    }
    if question.class & DNS_CLASS_MASK != 1 {
        return Ok(None);
    }

    let requested_ifindex =
        match requested_ifindex {
            Some(index) if index <= 0 => {
                return Err(MdnsRuntimeError::InvalidQuery(
                    "mDNS interface index must be positive",
                ));
            }
            Some(index) => Some(u32::try_from(index).map_err(|_| {
                MdnsRuntimeError::InvalidQuery("mDNS interface index is out of range")
            })?),
            None => None,
        };
    let interfaces = interfaces()?
        .into_iter()
        .filter(|entry| requested_ifindex.map_or(true, |index| entry.interface.ifindex == index))
        .collect::<Vec<_>>();
    if diagnostics_enabled() {
        eprintln!(
            "rustd-resolved: mDNS query name={:?} type={} ifindex={requested_ifindex:?} interfaces={}",
            question.text,
            question.rr_type,
            interfaces.len()
        );
    }
    if interfaces.is_empty() {
        return Ok(None);
    }

    if read_cache {
        let cached = cached_records(&question, &interfaces, Instant::now())?;
        if !cached.is_empty() {
            return Ok(Some((build_stub_response(&question, &cached, &[])?, true)));
        }
    }
    if !network_allowed {
        return Ok(None);
    }

    let sockets = open_sockets(&interfaces)?;
    if diagnostics_enabled() {
        eprintln!(
            "rustd-resolved: mDNS query name={:?} opened {} sockets",
            question.text,
            sockets.len()
        );
    }
    if sockets.is_empty() {
        return Ok(None);
    }
    let multicast_query = build_multicast_query(&question);
    let mut active_sockets = Vec::with_capacity(sockets.len());
    for endpoint in sockets {
        let destination = multicast_destination(endpoint.interface);
        match endpoint.socket.send_to(&multicast_query, destination) {
            Ok(length) if length == multicast_query.len() => {
                if diagnostics_enabled() {
                    eprintln!(
                        "rustd-resolved: mDNS query sent {} bytes on ifindex={} family={:?}",
                        length, endpoint.interface.ifindex, endpoint.interface.family
                    );
                }
                active_sockets.push(endpoint);
            }
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short mDNS send").into()),
            Err(error) if interface_send_error(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut sockets = active_sockets;
    if sockets.is_empty() {
        return Ok(None);
    }

    let now = Instant::now();
    let timeout = timeout
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(250));
    let deadline = now + timeout;
    let mut settle_deadline = None;
    let mut answers = BTreeSet::new();
    let mut additionals = BTreeSet::new();
    let mut buffer = vec![0u8; MAX_MDNS_PACKET];

    while Instant::now() < deadline {
        check_query_cancellation()?;
        let mut received = false;
        for endpoint in &mut sockets {
            loop {
                let Some(datagram) = recv_datagram(endpoint, &mut buffer)? else {
                    break;
                };
                received = true;
                let metadata = datagram.metadata;
                let validated = match validate_ingress(datagram.packet, metadata) {
                    Ok(value) => value,
                    Err(error) => {
                        if diagnostics_enabled() {
                            eprintln!(
                                "rustd-resolved: mDNS query rejected {}-byte packet on ifindex={}: {error}",
                                datagram.packet.len(), endpoint.interface.ifindex
                            );
                        }
                        continue;
                    }
                };
                if validated.kind != MdnsMessageKind::Response
                    || validated.interface != endpoint.interface
                {
                    continue;
                }
                let records = parse_response_records(datagram.packet, endpoint.interface)?;
                if diagnostics_enabled() {
                    eprintln!(
                        "rustd-resolved: mDNS query received {} records on ifindex={}",
                        records.len(),
                        endpoint.interface.ifindex
                    );
                    for record in &records {
                        eprintln!(
                            "rustd-resolved: mDNS record owner={:?} type={} matches={}",
                            uncompressed_wire_labels(&record.owner)
                                .map(|labels| labels.join("."))
                                .unwrap_or_else(|| "<invalid>".to_owned()),
                            record.rr_type,
                            record_matches(&question, record)
                        );
                    }
                }
                let received_at = Instant::now();
                for record in records {
                    if record.class & DNS_CLASS_MASK != 1 {
                        continue;
                    }
                    let key = MdnsRecordKey::new(
                        record.interface,
                        &record.owner,
                        record.rr_type,
                        record.class,
                    )
                    .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid mDNS owner"))?;
                    if write_cache {
                        cache().insert_bounded(
                            key,
                            record.rdata.clone(),
                            record.ttl,
                            record.cache_flush,
                            cache_capacity,
                            received_at,
                        );
                    }
                    if record_matches(&question, &record) {
                        answers.insert(record);
                    } else {
                        additionals.insert(record);
                    }
                }
                if !answers.is_empty() {
                    settle_deadline = Some(Instant::now() + RESPONSE_SETTLE_TIME);
                }
            }
        }
        if settle_deadline.is_some_and(|settle| Instant::now() >= settle) {
            break;
        }
        if !received {
            thread::sleep(RECEIVE_SLEEP);
        }
    }

    if answers.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        build_stub_response(
            &question,
            &answers.into_iter().collect::<Vec<_>>(),
            &additionals.into_iter().collect::<Vec<_>>(),
        )?,
        false,
    )))
}

fn check_query_cancellation() -> Result<(), MdnsRuntimeError> {
    crate::query_cancel::check().map_err(|_| {
        io::Error::new(io::ErrorKind::Interrupted, "resolver client disconnected").into()
    })
}

fn mdns_enabled() -> bool {
    std::env::var("RUSTD_RESOLVED_MDNS")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "no" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

fn diagnostics_enabled() -> bool {
    std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some()
}

fn browse_owner(name: &str) -> Result<Vec<u8>, MdnsRuntimeError> {
    let query = crate::wire::make_query(name, TYPE_PTR, 0)
        .map_err(|_| MdnsRuntimeError::InvalidQuery("invalid DNS-SD browse name"))?;
    Ok(parse_question(&query)?.owner)
}

fn browse_target(
    domain: &str,
    requested_type: Option<String>,
) -> Result<(Vec<u8>, Option<String>, String), MdnsRuntimeError> {
    if requested_type.is_none() && domain == "." {
        return Ok((
            browse_owner(".")?,
            Some("_services._dns-sd._udp".to_owned()),
            ".".to_owned(),
        ));
    }
    if let Some(service_type) = requested_type {
        return Ok((
            browse_owner(&qualified_browse_name(&service_type, domain))?,
            Some(service_type),
            domain.to_owned(),
        ));
    }
    let owner = browse_owner(domain)?;
    let derived = split_service_text(domain).and_then(|(name, service_type, result_domain)| {
        name.is_none().then_some((service_type, result_domain))
    });
    Ok(match derived {
        Some((service_type, result_domain)) => (owner, Some(service_type), result_domain),
        None => (owner, None, domain.to_owned()),
    })
}

fn qualified_browse_name(prefix: &str, domain: &str) -> String {
    if domain == "." {
        prefix.to_owned()
    } else {
        format!("{prefix}.{domain}")
    }
}

fn browse_query(owner: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(DNS_HEADER_LENGTH + owner.len() + 4);
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(owner);
    output.extend_from_slice(&TYPE_PTR.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output
}

fn split_service_wire(wire: &[u8]) -> Option<(Option<String>, String, String)> {
    let labels = uncompressed_wire_labels(wire)?;
    split_service_labels(&labels)
}

fn split_service_text(text: &str) -> Option<(Option<String>, String, String)> {
    let labels = text
        .trim_end_matches('.')
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    split_service_labels(&labels)
}

fn split_service_labels(labels: &[String]) -> Option<(Option<String>, String, String)> {
    let type_index = labels.windows(2).position(|labels| {
        labels[0].starts_with('_')
            && matches!(labels[1].to_ascii_lowercase().as_str(), "_tcp" | "_udp")
    })?;
    let domain_labels = labels.get(type_index + 2..)?;
    if type_index > 1 {
        return None;
    }
    let domain = if domain_labels.is_empty() {
        ".".to_owned()
    } else {
        domain_labels.join(".")
    };
    let name = (type_index == 1).then(|| labels[0].clone());
    Some((
        name,
        format!("{}.{}", labels[type_index], labels[type_index + 1]).to_ascii_lowercase(),
        domain.to_ascii_lowercase(),
    ))
}

fn uncompressed_wire_labels(wire: &[u8]) -> Option<Vec<String>> {
    let mut labels = Vec::new();
    let mut offset = 0usize;
    loop {
        let length = usize::from(*wire.get(offset)?);
        offset += 1;
        if length == 0 {
            return (offset == wire.len()).then_some(labels);
        }
        if length > 63 {
            return None;
        }
        let end = offset.checked_add(length)?;
        let label = wire.get(offset..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        offset = end;
    }
}

fn interfaces() -> Result<Vec<RuntimeInterface>, MdnsRuntimeError> {
    // SAFETY: a null pointer with zero capacity is the documented count query.
    let count = unsafe { rustd_resolved_mdns_interfaces(std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let capacity = usize::try_from(count)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("too many network interfaces"))?;
    let mut native = vec![NativeMdnsInterface::default(); capacity];
    // SAFETY: native owns capacity initialized entries and the C function writes at most capacity.
    let populated = unsafe { rustd_resolved_mdns_interfaces(native.as_mut_ptr(), native.len()) };
    if populated < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let populated = usize::try_from(populated)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid interface count"))?
        .min(native.len());
    native.truncate(populated);

    let mut output = Vec::new();
    for entry in native {
        if entry.flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE) != 0 {
            continue;
        }
        let (family, address) = match entry.family {
            AF_INET => (
                MdnsAddressFamily::Ipv4,
                IpAddr::V4(Ipv4Addr::new(
                    entry.address[0],
                    entry.address[1],
                    entry.address[2],
                    entry.address[3],
                )),
            ),
            AF_INET6 => (
                MdnsAddressFamily::Ipv6,
                IpAddr::V6(Ipv6Addr::from(entry.address)),
            ),
            _ => continue,
        };
        output.push(RuntimeInterface {
            interface: MdnsInterface::new(entry.ifindex, family),
            address,
        });
    }
    Ok(output)
}

fn interface_send_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::Interrupted
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::WouldBlock
    ) || matches!(error.raw_os_error(), Some(19) | Some(100) | Some(101))
}

fn open_sockets(interfaces: &[RuntimeInterface]) -> Result<Vec<RuntimeSocket>, MdnsRuntimeError> {
    let mut keys = HashSet::new();
    let mut output = Vec::new();
    for entry in interfaces {
        if !keys.insert(entry.interface) {
            continue;
        }
        let family = match entry.interface.family {
            MdnsAddressFamily::Ipv4 => AF_INET,
            MdnsAddressFamily::Ipv6 => AF_INET6,
        };
        // SAFETY: the native function returns a fresh owned descriptor on success.
        let fd = unsafe { rustd_resolved_mdns_open(family, entry.interface.ifindex, MDNS_PORT) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::AddrNotAvailable | io::ErrorKind::PermissionDenied
            ) || error.raw_os_error() == Some(101)
            {
                continue;
            }
            return Err(error.into());
        }
        // SAFETY: ownership of the fresh descriptor is transferred exactly once.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        output.push(RuntimeSocket {
            interface: entry.interface,
            socket,
        });
    }
    Ok(output)
}

fn multicast_destination(interface: MdnsInterface) -> SocketAddr {
    match interface.family {
        MdnsAddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(MDNS_IPV4_MULTICAST), MDNS_PORT),
        MdnsAddressFamily::Ipv6 => SocketAddr::V6(std::net::SocketAddrV6::new(
            MDNS_IPV6_MULTICAST,
            MDNS_PORT,
            0,
            interface.ifindex,
        )),
    }
}

struct ReceivedDatagram<'a> {
    packet: &'a [u8],
    metadata: MdnsIngressMeta,
}

fn recv_datagram<'a>(
    endpoint: &RuntimeSocket,
    buffer: &'a mut [u8],
) -> Result<Option<ReceivedDatagram<'a>>, MdnsRuntimeError> {
    let mut native = NativeMdnsMeta::default();
    // SAFETY: buffer and native are valid writable objects for the supplied lengths.
    let length = unsafe {
        rustd_resolved_mdns_recv(
            endpoint.socket.as_raw_fd(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut native,
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let length = usize::try_from(length)
        .map_err(|_| MdnsRuntimeError::InvalidResponse("negative mDNS packet length"))?;
    if length > buffer.len() {
        return Err(MdnsRuntimeError::InvalidResponse(
            "native mDNS receive exceeded its buffer",
        ));
    }
    let (source_ip, destination_ip) = match native.family {
        AF_INET => (
            IpAddr::V4(Ipv4Addr::new(
                native.source[0],
                native.source[1],
                native.source[2],
                native.source[3],
            )),
            IpAddr::V4(Ipv4Addr::new(
                native.destination[0],
                native.destination[1],
                native.destination[2],
                native.destination[3],
            )),
        ),
        AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(native.source)),
            IpAddr::V6(Ipv6Addr::from(native.destination)),
        ),
        _ => {
            return Err(MdnsRuntimeError::InvalidResponse(
                "native mDNS receive returned an unsupported family",
            ))
        }
    };
    let destination = match destination_ip {
        IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), MDNS_PORT),
        IpAddr::V6(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            MDNS_PORT,
            0,
            native.ifindex,
        )),
    };
    Ok(Some(ReceivedDatagram {
        packet: &buffer[..length],
        metadata: MdnsIngressMeta {
            source: SocketAddr::new(source_ip, native.port),
            destination,
            ifindex: Some(native.ifindex),
            hop_limit: Some(native.hop_limit),
            received_multicast: matches!(
                destination_ip,
                IpAddr::V4(address) if address == MDNS_IPV4_MULTICAST
            ) || matches!(
                destination_ip,
                IpAddr::V6(address) if address == MDNS_IPV6_MULTICAST
            ),
        },
    }))
}

fn parse_question(packet: &[u8]) -> Result<MdnsQuestion, MdnsRuntimeError> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(MdnsRuntimeError::InvalidQuery("short DNS query"));
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    if flags & DNS_FLAG_QR != 0 || flags & 0x7800 != 0 {
        return Err(MdnsRuntimeError::InvalidQuery("invalid mDNS query flags"));
    }
    if read_u16(packet, 4)? != 1 {
        return Err(MdnsRuntimeError::InvalidQuery(
            "mDNS translation requires exactly one question",
        ));
    }
    let (owner, text, end) = decode_name(packet, DNS_HEADER_LENGTH)?;
    if end + 4 > packet.len() {
        return Err(MdnsRuntimeError::InvalidQuery("truncated DNS question"));
    }
    let rr_type = read_u16(packet, end)?;
    let class = read_u16(packet, end + 2)?;
    Ok(MdnsQuestion {
        id,
        flags,
        owner,
        text,
        rr_type,
        class,
        raw: packet[DNS_HEADER_LENGTH..end + 4].to_vec(),
    })
}

fn build_multicast_query(question: &MdnsQuestion) -> Vec<u8> {
    let mut output = Vec::with_capacity(DNS_HEADER_LENGTH + question.raw.len());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&question.owner);
    output.extend_from_slice(&question.rr_type.to_be_bytes());
    output.extend_from_slice(&(question.class & DNS_CLASS_MASK).to_be_bytes());
    output
}

fn parse_response_records(
    packet: &[u8],
    interface: MdnsInterface,
) -> Result<Vec<RuntimeRecord>, MdnsRuntimeError> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(MdnsRuntimeError::InvalidResponse("short mDNS response"));
    }
    let questions = read_u16(packet, 4)?;
    let answers = read_u16(packet, 6)?;
    let authorities = read_u16(packet, 8)?;
    let additionals = read_u16(packet, 10)?;
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        let (_, _, end) = decode_name(packet, offset)?;
        offset = end
            .checked_add(4)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse("truncated mDNS question"))?;
    }
    let count = u32::from(answers) + u32::from(authorities) + u32::from(additionals);
    let mut output = Vec::new();
    for _ in 0..count {
        let (owner, _, end) = decode_name(packet, offset)?;
        if end + 10 > packet.len() {
            return Err(MdnsRuntimeError::InvalidResponse(
                "truncated mDNS record header",
            ));
        }
        let rr_type = read_u16(packet, end)?;
        let raw_class = read_u16(packet, end + 2)?;
        let ttl = read_u32(packet, end + 4)?;
        let length = usize::from(read_u16(packet, end + 8)?);
        let rdata_start = end + 10;
        let rdata_end = rdata_start
            .checked_add(length)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse(
                "truncated mDNS record data",
            ))?;
        let presentation_rdata = if rr_type == TYPE_PTR {
            let (_, text, consumed) = decode_name(packet, rdata_start)?;
            if consumed != rdata_end {
                return Err(MdnsRuntimeError::InvalidResponse(
                    "trailing name record data",
                ));
            }
            Some(text)
        } else {
            None
        };
        let rdata = expand_rdata(packet, rr_type, rdata_start, rdata_end)?;
        output.push(RuntimeRecord {
            owner,
            rr_type,
            class: raw_class & DNS_CLASS_MASK,
            ttl,
            cache_flush: raw_class & DNS_CLASS_CACHE_FLUSH != 0,
            rdata,
            presentation_rdata,
            interface,
        });
        offset = rdata_end;
    }
    if offset != packet.len() {
        return Err(MdnsRuntimeError::InvalidResponse(
            "trailing data after mDNS response",
        ));
    }
    Ok(output)
}

fn expand_rdata(
    packet: &[u8],
    rr_type: u16,
    start: usize,
    end: usize,
) -> Result<Vec<u8>, MdnsRuntimeError> {
    match rr_type {
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            let (name, _, consumed) = decode_name(packet, start)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse(
                    "trailing name record data",
                ));
            }
            Ok(name)
        }
        TYPE_MX => {
            if start + 2 > end {
                return Err(MdnsRuntimeError::InvalidResponse("short MX record"));
            }
            let (name, _, consumed) = decode_name(packet, start + 2)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse("trailing MX data"));
            }
            let mut output = packet[start..start + 2].to_vec();
            output.extend_from_slice(&name);
            Ok(output)
        }
        TYPE_SRV => {
            if start + 6 > end {
                return Err(MdnsRuntimeError::InvalidResponse("short SRV record"));
            }
            let (name, _, consumed) = decode_name(packet, start + 6)?;
            if consumed != end {
                return Err(MdnsRuntimeError::InvalidResponse("trailing SRV data"));
            }
            let mut output = packet[start..start + 6].to_vec();
            output.extend_from_slice(&name);
            Ok(output)
        }
        TYPE_SOA => {
            let (mname, _, cursor) = decode_name(packet, start)?;
            let (rname, _, cursor) = decode_name(packet, cursor)?;
            if cursor + 20 != end {
                return Err(MdnsRuntimeError::InvalidResponse("invalid SOA data"));
            }
            let mut output = mname;
            output.extend_from_slice(&rname);
            output.extend_from_slice(&packet[cursor..end]);
            Ok(output)
        }
        TYPE_NSEC => {
            let (next, _, cursor) = decode_name(packet, start)?;
            if cursor > end {
                return Err(MdnsRuntimeError::InvalidResponse("invalid NSEC data"));
            }
            let mut output = next;
            output.extend_from_slice(&packet[cursor..end]);
            Ok(output)
        }
        _ => Ok(packet[start..end].to_vec()),
    }
}

fn decode_name(packet: &[u8], start: usize) -> Result<(Vec<u8>, String, usize), MdnsRuntimeError> {
    let mut output = Vec::new();
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        let Some(&length) = packet.get(cursor) else {
            return Err(MdnsRuntimeError::InvalidResponse("truncated DNS name"));
        };
        if length & 0xc0 == 0xc0 {
            let second = *packet
                .get(cursor + 1)
                .ok_or(MdnsRuntimeError::InvalidResponse(
                    "truncated DNS compression pointer",
                ))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if target >= packet.len() || !visited.insert(target) {
                return Err(MdnsRuntimeError::InvalidResponse(
                    "invalid DNS compression pointer",
                ));
            }
            if next.is_none() {
                next = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(MdnsRuntimeError::InvalidResponse("invalid DNS label"));
        }
        cursor += 1;
        output.push(length);
        if length == 0 {
            let output = canonical_wire_name(&output)
                .map_err(|_| MdnsRuntimeError::InvalidResponse("invalid DNS name"))?;
            let text = if labels.is_empty() {
                ".".to_owned()
            } else {
                format!("{}.", labels.join("."))
            };
            return Ok((output, text, next.unwrap_or(cursor)));
        }
        let length = usize::from(length);
        let end = cursor
            .checked_add(length)
            .filter(|value| *value <= packet.len())
            .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS label"))?;
        let label = &packet[cursor..end];
        output.extend(label.iter().map(u8::to_ascii_lowercase));
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor = end;
        if output.len() >= 255 {
            return Err(MdnsRuntimeError::InvalidResponse("DNS name is too long"));
        }
    }
    Err(MdnsRuntimeError::InvalidResponse(
        "too many DNS compression pointers",
    ))
}

fn record_matches(question: &MdnsQuestion, record: &RuntimeRecord) -> bool {
    record.owner == question.owner
        && (question.rr_type == TYPE_ANY || question.rr_type == record.rr_type)
        && (question.class & DNS_CLASS_MASK) == (record.class & DNS_CLASS_MASK)
}

fn cached_records(
    question: &MdnsQuestion,
    interfaces: &[RuntimeInterface],
    now: Instant,
) -> Result<Vec<RuntimeRecord>, MdnsRuntimeError> {
    if question.rr_type == TYPE_ANY {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in interfaces {
        let key = MdnsRecordKey::new(
            entry.interface,
            &question.owner,
            question.rr_type,
            question.class,
        )
        .map_err(|_| MdnsRuntimeError::InvalidQuery("invalid mDNS question owner"))?;
        for record in cache().lookup(&key, now) {
            let ttl = record.remaining_ttl(now).as_secs().min(u64::from(u32::MAX)) as u32;
            let candidate = RuntimeRecord {
                owner: question.owner.clone(),
                rr_type: question.rr_type,
                class: question.class & DNS_CLASS_MASK,
                ttl: ttl.max(1),
                cache_flush: record.cache_flush,
                rdata: record.rdata,
                presentation_rdata: None,
                interface: entry.interface,
            };
            if seen.insert(candidate.clone()) {
                output.push(candidate);
            }
        }
    }
    Ok(output)
}

fn build_stub_response(
    question: &MdnsQuestion,
    answers: &[RuntimeRecord],
    additionals: &[RuntimeRecord],
) -> Result<Vec<u8>, MdnsRuntimeError> {
    let answers = answers
        .iter()
        .filter(|record| record_matches(question, record))
        .collect::<BTreeSet<_>>();
    if answers.len() > usize::from(u16::MAX) || additionals.len() > usize::from(u16::MAX) {
        return Err(MdnsRuntimeError::InvalidResponse(
            "too many records in translated mDNS response",
        ));
    }
    let mut flags = DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
    flags |= question.flags & DNS_FLAG_RD;
    let mut output = Vec::new();
    output.extend_from_slice(&question.id.to_be_bytes());
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&(additionals.len() as u16).to_be_bytes());
    output.extend_from_slice(&question.raw);
    for record in answers {
        append_record(&mut output, record)?;
    }
    for record in additionals {
        append_record(&mut output, record)?;
    }
    if output.len() > usize::from(u16::MAX) {
        output[2..4].copy_from_slice(&(flags | DNS_FLAG_TC).to_be_bytes());
        output.truncate(1232);
    }
    Ok(output)
}

fn append_record(output: &mut Vec<u8>, record: &RuntimeRecord) -> Result<(), MdnsRuntimeError> {
    let length = u16::try_from(record.rdata.len())
        .map_err(|_| MdnsRuntimeError::InvalidResponse("mDNS RDATA exceeds 65535 octets"))?;
    output.extend_from_slice(&record.owner);
    output.extend_from_slice(&record.rr_type.to_be_bytes());
    output.extend_from_slice(&(record.class & DNS_CLASS_MASK).to_be_bytes());
    output.extend_from_slice(&record.ttl.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&record.rdata);
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, MdnsRuntimeError> {
    let bytes = packet
        .get(offset..offset.saturating_add(2))
        .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS u16"))?;
    if bytes.len() != 2 {
        return Err(MdnsRuntimeError::InvalidResponse("truncated DNS u16"));
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, MdnsRuntimeError> {
    let bytes = packet
        .get(offset..offset.saturating_add(4))
        .ok_or(MdnsRuntimeError::InvalidResponse("truncated DNS u32"))?;
    if bytes.len() != 4 {
        return Err(MdnsRuntimeError::InvalidResponse("truncated DNS u32"));
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(labels: &[&str]) -> Vec<u8> {
        let mut output = Vec::new();
        for label in labels {
            output.push(u8::try_from(label.len()).expect("label length"));
            output.extend_from_slice(label.as_bytes());
        }
        output.push(0);
        output
    }

    fn query(name: &[&str], rr_type: u16) -> Vec<u8> {
        let owner = wire_name(name);
        let mut output = Vec::new();
        output.extend_from_slice(&0x1234u16.to_be_bytes());
        output.extend_from_slice(&DNS_FLAG_RD.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&owner);
        output.extend_from_slice(&rr_type.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output
    }

    fn browser(service_type: Option<&str>) -> MdnsBrowser {
        let domain = "local".to_owned();
        let requested_type = service_type.map(str::to_owned);
        let first_owner = requested_type.as_ref().map_or_else(
            || browse_owner(&domain).expect("browse owner"),
            |service_type| browse_owner(&format!("{service_type}.local")).expect("browse owner"),
        );
        MdnsBrowser {
            sockets: Vec::new(),
            queries: BTreeSet::from([first_owner]),
            requested_type,
            domain,
            active: BTreeMap::new(),
            next_query: Instant::now(),
            query_interval: Duration::from_secs(1),
        }
    }

    #[test]
    fn root_domain_browse_names_do_not_gain_an_empty_label() {
        assert_eq!(
            qualified_browse_name("_services._dns-sd._udp", "."),
            "_services._dns-sd._udp"
        );
        assert_eq!(
            split_service_text("_ipp._tcp"),
            Some((None, "_ipp._tcp".to_owned(), ".".to_owned()))
        );
        assert_eq!(
            split_service_text("Printer._ipp._tcp"),
            Some((
                Some("Printer".to_owned()),
                "_ipp._tcp".to_owned(),
                ".".to_owned(),
            ))
        );
    }

    #[test]
    fn empty_type_uses_the_domain_as_the_pinned_browse_owner() {
        let domain = "_testservice0._udp.local".to_owned();
        let (owner, requested_type, result_domain) =
            browse_target(&domain, None).expect("browse target");
        let service_type = requested_type.expect("derived service type");
        assert_eq!(service_type, "_testservice0._udp");
        assert_eq!(result_domain, "local");

        let mut browser = browser(None);
        browser.queries = BTreeSet::from([owner.clone()]);
        browser.requested_type = Some(service_type.clone());
        browser.domain = result_domain.clone();
        let target = wire_name(&["Test Service", "_testservice0", "_udp", "local"]);
        let mut updates = Vec::new();
        browser
            .process_record(
                RuntimeRecord {
                    owner,
                    rr_type: TYPE_PTR,
                    class: 1,
                    ttl: 120,
                    cache_flush: false,
                    rdata: target,
                    presentation_rdata: Some("Test Service._testservice0._udp.local.".to_owned()),
                    interface: MdnsInterface::new(7, MdnsAddressFamily::Ipv6),
                },
                Instant::now(),
                &mut updates,
            )
            .expect("browse update");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].service_type, service_type);
        assert_eq!(updates[0].domain, result_domain);
    }

    #[test]
    fn browser_constructor_preserves_non_root_browse_domains() {
        let browser = MdnsBrowser::new(
            "_testservice0._udp.local",
            None,
            None,
            RUSTD_RESOLVE_NO_NETWORK,
        )
        .expect("browser");
        let owner = browse_owner("_testservice0._udp.local").expect("owner");
        assert_eq!(browser.queries, BTreeSet::from([owner]));
        assert_eq!(
            browser.requested_type.as_deref(),
            Some("_testservice0._udp")
        );
        assert_eq!(browser.domain, "local");
    }

    #[test]
    fn browser_constructor_preserves_non_root_browse_domains_with_trailing_dot() {
        let browser = MdnsBrowser::new(
            "_testservice0._udp.local.",
            None,
            None,
            RUSTD_RESOLVE_NO_NETWORK,
        )
        .expect("browser");
        let owner = browse_owner("_testservice0._udp.local.").expect("owner");
        assert_eq!(browser.queries, BTreeSet::from([owner]));
        assert_eq!(
            browser.requested_type.as_deref(),
            Some("_testservice0._udp")
        );
        assert_eq!(browser.domain, "local");
    }

    #[test]
    fn browser_constructor_normalizes_trailing_dots_and_uppercase_service_type() {
        let browser = MdnsBrowser::new(
            "_TESTSERVICE0._UDP.local...",
            None,
            None,
            RUSTD_RESOLVE_NO_NETWORK,
        )
        .expect("browser");
        let owner = browse_owner("_testservice0._udp.local").expect("owner");
        assert_eq!(browser.queries, BTreeSet::from([owner]));
        assert_eq!(
            browser.requested_type.as_deref(),
            Some("_testservice0._udp")
        );
        assert_eq!(browser.domain, "local");
    }

    #[test]
    fn browser_constructor_root_domain_stays_root() {
        let browser = MdnsBrowser::new(".", None, None, RUSTD_RESOLVE_NO_NETWORK).expect("browser");
        assert_eq!(browser.domain, ".");
        assert_eq!(
            browser.requested_type.as_deref(),
            Some("_services._dns-sd._udp")
        );
        assert_eq!(
            browser.queries,
            BTreeSet::from([browse_owner(".").expect("root")])
        );
    }

    #[test]
    fn routes_local_and_link_local_reverse_names_only() {
        assert!(should_handle_name("host.local"));
        assert!(should_handle_name("1.0.254.169.in-addr.arpa"));
        assert!(should_handle_name("1.0.8.e.f.ip6.arpa"));
        assert!(!should_handle_name("example.com"));
    }

    #[test]
    fn translates_query_to_identifier_zero() {
        let parsed = parse_question(&query(&["host", "local"], TYPE_A)).expect("question");
        let multicast = build_multicast_query(&parsed);
        assert_eq!(&multicast[0..2], &[0, 0]);
        assert_eq!(read_u16(&multicast, 4).expect("question count"), 1);
    }

    #[test]
    fn expands_compressed_owner_and_ptr_data() {
        let owner = wire_name(&["_http", "_tcp", "local"]);
        let target = wire_name(&["Web", "_http", "_tcp", "local"]);
        let mut packet = vec![0u8; DNS_HEADER_LENGTH];
        packet[2..4].copy_from_slice(&(DNS_FLAG_QR | DNS_FLAG_AA).to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        let owner_offset = packet.len();
        packet.extend_from_slice(&owner);
        packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&target);
        let records =
            parse_response_records(&packet, MdnsInterface::new(2, MdnsAddressFamily::Ipv4))
                .expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].owner, owner);
        assert_eq!(
            records[0].rdata,
            canonical_wire_name(&target).expect("target")
        );
        assert_eq!(owner_offset, DNS_HEADER_LENGTH);
    }

    #[test]
    fn browser_streams_add_and_goodbye_remove() {
        let mut browser = browser(Some("_http._tcp"));
        let owner = browse_owner("_http._tcp.local").expect("owner");
        let target = wire_name(&["Web", "_http", "_tcp", "local"]);
        let interface = MdnsInterface::new(7, MdnsAddressFamily::Ipv4);
        let mut updates = Vec::new();
        browser
            .process_record(
                RuntimeRecord {
                    owner: owner.clone(),
                    rr_type: TYPE_PTR,
                    class: 1,
                    ttl: 120,
                    cache_flush: false,
                    rdata: target.clone(),
                    presentation_rdata: Some("Web._http._tcp.local.".to_owned()),
                    interface,
                },
                Instant::now(),
                &mut updates,
            )
            .expect("add");
        assert_eq!(updates.len(), 1);
        assert!(updates[0].added);
        assert_eq!(updates[0].name, "Web");
        assert_eq!(updates[0].service_type, "_http._tcp");
        browser
            .process_record(
                RuntimeRecord {
                    owner,
                    rr_type: TYPE_PTR,
                    class: 1,
                    ttl: 0,
                    cache_flush: false,
                    rdata: target,
                    presentation_rdata: Some("Web._http._tcp.local.".to_owned()),
                    interface,
                },
                Instant::now(),
                &mut updates,
            )
            .expect("remove");
        assert_eq!(updates.len(), 2);
        assert!(!updates[1].added);
    }

    #[test]
    fn stub_translation_restores_id_and_clears_cache_flush() {
        let query = parse_question(&query(&["host", "local"], TYPE_A)).expect("question");
        let record = RuntimeRecord {
            owner: query.owner.clone(),
            rr_type: TYPE_A,
            class: 1,
            ttl: 120,
            cache_flush: true,
            rdata: vec![192, 0, 2, 10],
            presentation_rdata: None,
            interface: MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
        };
        let response = build_stub_response(&query, &[record], &[]).expect("response");
        assert_eq!(read_u16(&response, 0).expect("id"), 0x1234);
        assert_eq!(read_u16(&response, 6).expect("answer count"), 1);
        let (_, _, owner_end) = decode_name(&response, DNS_HEADER_LENGTH).expect("question name");
        let answer_offset = owner_end + 4;
        let (_, _, answer_owner_end) = decode_name(&response, answer_offset).expect("answer owner");
        assert_eq!(read_u16(&response, answer_owner_end + 2).expect("class"), 1);
    }

    #[test]
    fn interface_native_layout_matches_c_contract() {
        assert_eq!(std::mem::size_of::<NativeMdnsInterface>(), 32);
        assert_eq!(std::mem::size_of::<NativeMdnsMeta>(), 48);
    }
}
