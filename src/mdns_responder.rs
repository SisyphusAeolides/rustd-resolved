// SPDX-License-Identifier: LGPL-2.1-or-later
use super::parity::{
    canonical_wire_name, known_answer_suppresses, probe_tie_break, validate_ingress,
    MdnsAddressFamily, MdnsIngressMeta, MdnsInterface, MdnsKnownAnswer, MdnsMessageKind,
    MdnsProbeAction, MdnsProbeState, MdnsTieBreak, MDNS_IPV4_MULTICAST, MDNS_IPV6_MULTICAST,
    MDNS_PORT,
};
use crate::resolver::Resolver;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const DNS_HEADER_LENGTH: usize = 12;
const DNS_FLAG_QR: u16 = 1 << 15;
const DNS_FLAG_AA: u16 = 1 << 10;
const DNS_CLASS_QU_OR_FLUSH: u16 = 1 << 15;
const DNS_CLASS_MASK: u16 = !DNS_CLASS_QU_OR_FLUSH;
const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_ANY: u16 = 255;
const HOST_TTL: u32 = 120;
const LEGACY_UNICAST_TTL_MAX: u32 = 10;
const INTERFACE_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const RECEIVE_SLEEP: Duration = Duration::from_millis(10);
const MULTICAST_RESPONSE_DELAY: Duration = Duration::from_millis(25);
const DEFENSE_WINDOW: Duration = Duration::from_secs(10);
const MAX_PACKET: usize = 65_535;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;

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
    fn resolved_mdns_open(family: i32, port: u16) -> i32;
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
pub struct MdnsResponder {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MdnsResponder {
    pub fn start_from_environment(resolver: Arc<Resolver>) -> io::Result<Option<Self>> {
        if !responder_enabled() {
            return Ok(None);
        }
        // A notify-reload READY reply must not precede the protocol socket becoming usable.
        let name = NameState::new();
        let mut interfaces = BTreeMap::<MdnsInterface, InterfaceState>::new();
        let now = Instant::now();
        synchronize_interfaces(&mut interfaces, &name, &resolver, now);
        let mut listeners = ListenerSockets::default();
        listeners.synchronize(&interfaces)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_resolver = Arc::clone(&resolver);
        let thread = thread::Builder::new()
            .name("resolved-mdns-responder".to_owned())
            .spawn(move || {
                responder_loop(&thread_stop, &thread_resolver, name, interfaces, listeners);
            })?;
        Ok(Some(Self {
            stop,
            thread: Some(thread),
        }))
    }
}

impl Drop for MdnsResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn responder_enabled() -> bool {
    let mdns = environment_boolean("RUSTD_RESOLVED_MDNS", true);
    let responder = environment_boolean("RUSTD_RESOLVED_MDNS_RESPONDER", true);
    mdns && responder
}

fn environment_boolean(name: &str, default: bool) -> bool {
    std::env::var(name).map_or(default, |value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "no" | "false" | "off"
        )
    })
}

#[derive(Clone, Debug)]
struct NameState {
    base: String,
    ordinal: u32,
    generation: u64,
}

impl NameState {
    fn new() -> Self {
        let base = std::env::var("RUSTD_RESOLVED_MDNS_HOSTNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(crate::native::kernel_hostname)
            .unwrap_or_else(|| "localhost".to_owned());
        Self {
            base: sanitize_hostname(&base),
            ordinal: 1,
            generation: 1,
        }
    }

    fn label(&self) -> String {
        if self.ordinal == 1 {
            return self.base.clone();
        }
        let suffix = format!("-{}", self.ordinal);
        let maximum = 63usize.saturating_sub(suffix.len());
        let mut base = self.base.as_bytes();
        if base.len() > maximum {
            base = &base[..maximum];
        }
        format!("{}{}", String::from_utf8_lossy(base), suffix)
    }

    fn owner(&self) -> Vec<u8> {
        wire_name(&[self.label().as_bytes(), b"local"])
    }

    fn rename(&mut self) {
        self.ordinal = self.ordinal.saturating_add(1).max(2);
        self.generation = self.generation.wrapping_add(1).max(1);
    }
}

fn sanitize_hostname(value: &str) -> String {
    let first = value
        .trim()
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or("localhost");
    let mut output = String::new();
    for character in first.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() || character == '-' {
            output.push(character);
        } else {
            output.push('-');
        }
    }
    let output = output.trim_matches('-');
    let output = if output.is_empty() {
        "localhost"
    } else {
        output
    };
    output.chars().take(63).collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalRecord {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    cache_flush: bool,
    rdata: Vec<u8>,
}

impl LocalRecord {
    fn known_answer(&self) -> MdnsKnownAnswer {
        MdnsKnownAnswer {
            owner: self.owner.clone(),
            rr_type: self.rr_type,
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.clone(),
        }
    }
}

#[derive(Debug)]
struct InterfaceState {
    interface: MdnsInterface,
    addresses: BTreeSet<IpAddr>,
    socket: UdpSocket,
    probe: MdnsProbeState,
    generation: u64,
    last_defense: Option<Instant>,
}

#[derive(Debug, Default)]
struct ListenerSockets {
    sockets: BTreeMap<MdnsAddressFamily, UdpSocket>,
}

impl ListenerSockets {
    fn synchronize(
        &mut self,
        interfaces: &BTreeMap<MdnsInterface, InterfaceState>,
    ) -> io::Result<()> {
        let mut first_error = None;
        for family in [MdnsAddressFamily::Ipv4, MdnsAddressFamily::Ipv6] {
            let has_joined_socket = interfaces
                .keys()
                .any(|interface| interface.family == family);
            if has_joined_socket {
                self.sockets.remove(&family);
            } else if let Entry::Vacant(entry) = self.sockets.entry(family) {
                match open_listener_socket(family) {
                    Ok(socket) => {
                        entry.insert(socket);
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        if interfaces.is_empty() && self.sockets.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no mDNS listener available",
                )
            }));
        }
        Ok(())
    }
}

impl InterfaceState {
    fn records(&self, name: &NameState) -> Vec<LocalRecord> {
        local_records(name, self.interface, &self.addresses)
    }

    fn unique_records(&self, name: &NameState) -> Vec<LocalRecord> {
        self.records(name)
            .into_iter()
            .filter(|record| record.cache_flush)
            .collect()
    }

    fn restart_probe(&mut self, name: &NameState, now: Instant) {
        self.generation = responder_generation(name);
        self.last_defense = None;
        self.probe
            .restart_after_conflict(now, probe_jitter(self.interface));
    }
}

fn responder_loop(
    stop: &AtomicBool,
    resolver: &Resolver,
    mut name: NameState,
    mut interfaces: BTreeMap<MdnsInterface, InterfaceState>,
    mut listeners: ListenerSockets,
) {
    let mut next_scan = Instant::now() + INTERFACE_SCAN_INTERVAL;
    let mut buffer = vec![0u8; MAX_PACKET];

    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= next_scan {
            synchronize_interfaces(&mut interfaces, &name, resolver, now);
            if let Err(error) = listeners.synchronize(&interfaces) {
                eprintln!("rustd-resolved: mDNS listener synchronization failed: {error}");
            }
            next_scan = now + INTERFACE_SCAN_INTERVAL;
        }

        let mut rename = false;
        let keys = interfaces.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let Some(state) = interfaces.get_mut(&key) else {
                continue;
            };
            if state.generation != responder_generation(&name) {
                state.restart_probe(&name, now);
            }
            if let Err(error) = drive_probe(state, &name, now) {
                eprintln!(
                    "rustd-resolved: mDNS probe failed on {}/{}: {error}",
                    key.ifindex,
                    match key.family {
                        MdnsAddressFamily::Ipv4 => "IPv4",
                        MdnsAddressFamily::Ipv6 => "IPv6",
                    }
                );
            }
            loop {
                let datagram = match recv_datagram(state, &mut buffer) {
                    Ok(Some(datagram)) => datagram,
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!(
                            "rustd-resolved: mDNS receive failed on {}: {error}",
                            key.ifindex
                        );
                        break;
                    }
                };
                if state.addresses.contains(&datagram.metadata.source.ip()) {
                    continue;
                }
                let validated = match validate_ingress(datagram.packet, datagram.metadata) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if validated.interface != state.interface {
                    continue;
                }
                let parsed = match parse_message(datagram.packet) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if detect_service_conflict(state, &name, &parsed, validated.kind) {
                    state.restart_probe(&name, now);
                    continue;
                }
                if detect_conflict(state, &name, &parsed, validated.kind, now) {
                    if state.probe.is_established()
                        && state
                            .last_defense
                            .and_then(|instant| now.checked_duration_since(instant))
                            .none_or(|duration| duration >= DEFENSE_WINDOW)
                    {
                        if send_announcement(state, &name, false).is_ok() {
                            state.last_defense = Some(now);
                        }
                    } else {
                        rename = true;
                        break;
                    }
                }
                if validated.kind == MdnsMessageKind::Query && state.probe.is_established() {
                    if let Err(error) = answer_query(
                        state,
                        &name,
                        &parsed,
                        validated.legacy_unicast,
                        datagram.metadata.source,
                    ) {
                        eprintln!(
                            "rustd-resolved: mDNS response failed on {}: {error}",
                            key.ifindex
                        );
                    }
                }
            }
            if rename {
                break;
            }
        }

        if rename {
            name.rename();
            let now = Instant::now();
            for state in interfaces.values_mut() {
                state.restart_probe(&name, now);
            }
        }
        thread::sleep(RECEIVE_SLEEP);
    }

    for state in interfaces.values() {
        let _ = send_announcement(state, &name, true);
    }
}

trait OptionDurationExt {
    fn none_or(self, predicate: impl FnOnce(Duration) -> bool) -> bool;
}

impl OptionDurationExt for Option<Duration> {
    fn none_or(self, predicate: impl FnOnce(Duration) -> bool) -> bool {
        match self {
            Some(value) => predicate(value),
            None => true,
        }
    }
}

fn synchronize_interfaces(
    states: &mut BTreeMap<MdnsInterface, InterfaceState>,
    name: &NameState,
    resolver: &Resolver,
    now: Instant,
) {
    let mut discovered = match discover_interfaces() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("rustd-resolved: mDNS interface scan failed: {error}");
            return;
        }
    };
    discovered.retain(|interface, _| {
        i32::try_from(interface.ifindex)
            .ok()
            .is_some_and(|ifindex| resolver.multicast_dns_respond_enabled(ifindex))
    });
    states.retain(|key, state| {
        discovered
            .get(key)
            .is_some_and(|addresses| addresses == &state.addresses)
    });
    for (interface, addresses) in discovered {
        let Entry::Vacant(entry) = states.entry(interface) else {
            continue;
        };
        match open_socket(interface) {
            Ok(socket) => {
                if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
                    let record_count = local_records(name, interface, &addresses).len();
                    eprintln!(
                        "rustd-resolved: mDNS responder link {} {:?} has {} addresses and {} records",
                        interface.ifindex,
                        interface.family,
                        addresses.len(),
                        record_count
                    );
                }
                entry.insert(InterfaceState {
                    interface,
                    addresses,
                    socket,
                    probe: MdnsProbeState::new(now, probe_jitter(interface)),
                    generation: responder_generation(name),
                    last_defense: None,
                });
            }
            Err(error) => {
                if !matches!(
                    error.raw_os_error(),
                    Some(13) | Some(19) | Some(98) | Some(99) | Some(101)
                ) {
                    eprintln!(
                        "rustd-resolved: mDNS socket failed on {}: {error}",
                        interface.ifindex
                    );
                }
            }
        }
    }
}

fn discover_interfaces() -> io::Result<BTreeMap<MdnsInterface, BTreeSet<IpAddr>>> {
    // SAFETY: a null output pointer with zero capacity requests only the count.
    let count = unsafe { rustd_resolved_mdns_interfaces(std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let capacity = usize::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many mDNS interfaces"))?;
    if capacity == 0 {
        return Ok(BTreeMap::new());
    }
    let mut native = vec![NativeMdnsInterface::default(); capacity];
    // SAFETY: native contains capacity writable entries and the C function respects the capacity.
    let populated = unsafe { rustd_resolved_mdns_interfaces(native.as_mut_ptr(), native.len()) };
    if populated < 0 {
        return Err(io::Error::last_os_error());
    }
    let populated = usize::try_from(populated)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid interface count"))?
        .min(native.len());
    native.truncate(populated);

    let mut output = BTreeMap::<MdnsInterface, BTreeSet<IpAddr>>::new();
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
        if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
            continue;
        }
        output
            .entry(MdnsInterface::new(entry.ifindex, family))
            .or_default()
            .insert(address);
    }
    Ok(output)
}

fn open_socket(interface: MdnsInterface) -> io::Result<UdpSocket> {
    let family = match interface.family {
        MdnsAddressFamily::Ipv4 => AF_INET,
        MdnsAddressFamily::Ipv6 => AF_INET6,
    };
    // SAFETY: the native function returns a fresh owned descriptor on success.
    let fd = unsafe { rustd_resolved_mdns_open(family, interface.ifindex, MDNS_PORT) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of the fresh descriptor is transferred exactly once.
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

fn open_listener_socket(family: MdnsAddressFamily) -> io::Result<UdpSocket> {
    let family = match family {
        MdnsAddressFamily::Ipv4 => AF_INET,
        MdnsAddressFamily::Ipv6 => AF_INET6,
    };
    // SAFETY: the native function returns a fresh owned descriptor on success.
    let fd = unsafe { resolved_mdns_open(family, MDNS_PORT) };
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: ownership of the fresh descriptor is transferred exactly once.
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

fn probe_jitter(interface: MdnsInterface) -> Duration {
    Duration::from_millis(u64::from(interface.ifindex.wrapping_mul(37) % 251))
}

fn drive_probe(state: &mut InterfaceState, name: &NameState, now: Instant) -> io::Result<()> {
    match state.probe.poll(now) {
        MdnsProbeAction::Wait | MdnsProbeAction::Established => Ok(()),
        MdnsProbeAction::SendProbe => send_probe(state, name),
        MdnsProbeAction::SendAnnouncement => send_announcement(state, name, false),
    }
}

fn send_probe(state: &InterfaceState, name: &NameState) -> io::Result<()> {
    let records = state.unique_records(name);
    if records.is_empty() {
        return Ok(());
    }
    let owners = records
        .iter()
        .map(|record| record.owner.clone())
        .collect::<BTreeSet<_>>();
    let question_count =
        u16::try_from(owners.len()).map_err(|_| invalid_data("too many mDNS probe owners"))?;
    let authority_count =
        u16::try_from(records.len()).map_err(|_| invalid_data("too many mDNS probe records"))?;
    let mut output = dns_header(0, 0, question_count, 0, authority_count, 0);
    for owner in owners {
        output.extend_from_slice(&owner);
        output.extend_from_slice(&TYPE_ANY.to_be_bytes());
        output.extend_from_slice(&CLASS_IN.to_be_bytes());
    }
    for record in &records {
        append_record(&mut output, record, false, None)?;
    }
    send_multicast(state, &output)
}

fn send_announcement(state: &InterfaceState, name: &NameState, goodbye: bool) -> io::Result<()> {
    let records = state.records(name);
    if records.is_empty() {
        return Ok(());
    }
    let mut output = dns_header(0, DNS_FLAG_QR | DNS_FLAG_AA, 0, records.len() as u16, 0, 0);
    for record in &records {
        append_record(&mut output, record, true, goodbye.then_some(0))?;
    }
    send_multicast(state, &output)
}

fn send_multicast(state: &InterfaceState, packet: &[u8]) -> io::Result<()> {
    let destination = match state.interface.family {
        MdnsAddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(MDNS_IPV4_MULTICAST), MDNS_PORT),
        MdnsAddressFamily::Ipv6 => SocketAddr::V6(std::net::SocketAddrV6::new(
            MDNS_IPV6_MULTICAST,
            MDNS_PORT,
            0,
            state.interface.ifindex,
        )),
    };
    let length = state.socket.send_to(packet, destination)?;
    if length == packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::WriteZero, "short mDNS send"))
    }
}

struct ReceivedDatagram<'a> {
    packet: &'a [u8],
    metadata: MdnsIngressMeta,
}

fn recv_datagram<'a>(
    state: &InterfaceState,
    buffer: &'a mut [u8],
) -> io::Result<Option<ReceivedDatagram<'a>>> {
    let mut native = NativeMdnsMeta::default();
    // SAFETY: buffer and metadata are valid writable objects for the supplied lengths.
    let length = unsafe {
        rustd_resolved_mdns_recv(
            state.socket.as_raw_fd(),
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
        return Err(error);
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mDNS length"))?;
    if length > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native mDNS receive exceeded its buffer",
        ));
    }
    let (source, destination) = match native.family {
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported native mDNS family",
            ))
        }
    };
    let destination_socket = match destination {
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
            source: SocketAddr::new(source, native.port),
            destination: destination_socket,
            ifindex: Some(native.ifindex),
            hop_limit: Some(native.hop_limit),
            received_multicast: matches!(
                destination,
                IpAddr::V4(address) if address == MDNS_IPV4_MULTICAST
            ) || matches!(
                destination,
                IpAddr::V6(address) if address == MDNS_IPV6_MULTICAST
            ),
        },
    }))
}

#[derive(Clone, Debug)]
struct ParsedQuestion {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    qu: bool,
    raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedSection {
    Answer,
    Authority,
    Additional,
}

#[derive(Clone, Debug)]
struct ParsedRecord {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
    section: ParsedSection,
}

#[derive(Clone, Debug)]
struct ParsedMessage {
    id: u16,
    flags: u16,
    questions: Vec<ParsedQuestion>,
    records: Vec<ParsedRecord>,
}

fn parse_message(packet: &[u8]) -> io::Result<ParsedMessage> {
    if packet.len() < DNS_HEADER_LENGTH {
        return Err(invalid_data("short mDNS packet"));
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let questions = read_u16(packet, 4)?;
    let answers = read_u16(packet, 6)?;
    let authorities = read_u16(packet, 8)?;
    let additionals = read_u16(packet, 10)?;
    let mut offset = DNS_HEADER_LENGTH;
    let mut parsed_questions = Vec::new();
    for _ in 0..questions {
        let start = offset;
        let (owner, end) = decode_name(packet, offset)?;
        if end + 4 > packet.len() {
            return Err(invalid_data("truncated mDNS question"));
        }
        let rr_type = read_u16(packet, end)?;
        let raw_class = read_u16(packet, end + 2)?;
        offset = end + 4;
        parsed_questions.push(ParsedQuestion {
            owner,
            rr_type,
            class: raw_class & DNS_CLASS_MASK,
            qu: raw_class & DNS_CLASS_QU_OR_FLUSH != 0,
            raw: packet[start..offset].to_vec(),
        });
    }
    let mut records = Vec::new();
    for (section, count) in [
        (ParsedSection::Answer, answers),
        (ParsedSection::Authority, authorities),
        (ParsedSection::Additional, additionals),
    ] {
        for _ in 0..count {
            let (owner, end) = decode_name(packet, offset)?;
            if end + 10 > packet.len() {
                return Err(invalid_data("truncated mDNS record header"));
            }
            let rr_type = read_u16(packet, end)?;
            let class = read_u16(packet, end + 2)? & DNS_CLASS_MASK;
            let ttl = read_u32(packet, end + 4)?;
            let length = usize::from(read_u16(packet, end + 8)?);
            let start = end + 10;
            let record_end = start
                .checked_add(length)
                .filter(|value| *value <= packet.len())
                .ok_or_else(|| invalid_data("truncated mDNS RDATA"))?;
            records.push(ParsedRecord {
                owner,
                rr_type,
                class,
                ttl,
                rdata: expand_rdata(packet, rr_type, start, record_end)?,
                section,
            });
            offset = record_end;
        }
    }
    if offset != packet.len() {
        return Err(invalid_data("trailing mDNS packet data"));
    }
    Ok(ParsedMessage {
        id,
        flags,
        questions: parsed_questions,
        records,
    })
}

fn detect_conflict(
    state: &InterfaceState,
    name: &NameState,
    message: &ParsedMessage,
    kind: MdnsMessageKind,
    _now: Instant,
) -> bool {
    let ours = state.unique_records(name);
    let owner = name.owner();
    for rr_type in [TYPE_A, TYPE_AAAA] {
        let our_data = ours
            .iter()
            .filter(|record| record.owner == owner && record.rr_type == rr_type)
            .map(|record| record.rdata.clone())
            .collect::<Vec<_>>();
        if our_data.is_empty() {
            continue;
        }
        let their_data = message
            .records
            .iter()
            .filter(|record| {
                record.owner == owner
                    && record.rr_type == rr_type
                    && record.class == CLASS_IN
                    && (kind == MdnsMessageKind::Response
                        || record.section == ParsedSection::Authority)
            })
            .map(|record| record.rdata.clone())
            .collect::<Vec<_>>();
        if their_data.is_empty() || sets_equal(&our_data, &their_data) {
            continue;
        }
        if !state.probe.is_established() && kind == MdnsMessageKind::Query {
            return probe_tie_break(&our_data, &their_data) == MdnsTieBreak::WeLose;
        }
        return true;
    }
    false
}

fn sets_equal(left: &[Vec<u8>], right: &[Vec<u8>]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn answer_query(
    state: &InterfaceState,
    name: &NameState,
    message: &ParsedMessage,
    legacy_unicast: bool,
    source: SocketAddr,
) -> io::Result<()> {
    let all_records = state.records(name);
    let known = message
        .records
        .iter()
        .filter(|record| record.section == ParsedSection::Answer)
        .map(|record| MdnsKnownAnswer {
            owner: record.owner.clone(),
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            rdata: record.rdata.clone(),
        })
        .collect::<Vec<_>>();

    let mut multicast = BTreeSet::new();
    let mut unicast = BTreeSet::new();
    let mut legacy_questions = Vec::new();
    for question in &message.questions {
        let matches = all_records.iter().filter(|record| {
            record.owner == question.owner
                && record.class == question.class
                && (question.rr_type == TYPE_ANY || question.rr_type == record.rr_type)
        });
        for record in matches {
            if !legacy_unicast
                && !question.qu
                && known
                    .iter()
                    .any(|answer| known_answer_suppresses(&record.known_answer(), answer))
            {
                continue;
            }
            if legacy_unicast || question.qu {
                unicast.insert(record.clone());
            } else {
                multicast.insert(record.clone());
            }
        }
        if legacy_unicast {
            legacy_questions.push(question.raw.clone());
        }
    }

    add_related_records(&mut multicast, &all_records);
    add_related_records(&mut unicast, &all_records);

    if !unicast.is_empty() {
        let packet = response_packet(
            if legacy_unicast { message.id } else { 0 },
            &legacy_questions,
            &unicast.into_iter().collect::<Vec<_>>(),
            legacy_unicast,
        )?;
        let length = state.socket.send_to(&packet, source)?;
        if length != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short unicast mDNS response",
            ));
        }
    }
    if !multicast.is_empty() {
        thread::sleep(MULTICAST_RESPONSE_DELAY);
        let packet = response_packet(0, &[], &multicast.into_iter().collect::<Vec<_>>(), false)?;
        send_multicast(state, &packet)?;
    }
    Ok(())
}

fn responder_generation(name: &NameState) -> u64 {
    name.generation ^ super::dnssd_runtime::generation().rotate_left(17)
}

fn detect_service_conflict(
    state: &InterfaceState,
    name: &NameState,
    message: &ParsedMessage,
    kind: MdnsMessageKind,
) -> bool {
    let owners = match super::dnssd_runtime::instance_owners(
        state.interface,
        &state.addresses,
        &name.label(),
    ) {
        Ok(owners) => owners,
        Err(error) => {
            eprintln!("rustd-resolved: DNS-SD conflict lookup failed: {error}");
            return false;
        }
    };
    let ours = state.records(name);
    for owner in owners.keys() {
        for rr_type in [TYPE_SRV, TYPE_TXT] {
            let our_data = ours
                .iter()
                .filter(|record| {
                    record.owner == *owner && record.rr_type == rr_type && record.class == CLASS_IN
                })
                .map(|record| record.rdata.clone())
                .collect::<Vec<_>>();
            if our_data.is_empty() {
                continue;
            }
            let their_data = message
                .records
                .iter()
                .filter(|record| {
                    record.owner == *owner
                        && record.rr_type == rr_type
                        && record.class == CLASS_IN
                        && (kind == MdnsMessageKind::Response
                            || record.section == ParsedSection::Authority)
                })
                .map(|record| record.rdata.clone())
                .collect::<Vec<_>>();
            if their_data.is_empty() || sets_equal(&our_data, &their_data) {
                continue;
            }
            if !state.probe.is_established()
                && kind == MdnsMessageKind::Query
                && probe_tie_break(&our_data, &their_data) != MdnsTieBreak::WeLose
            {
                continue;
            }
            match super::dnssd_runtime::rename_conflicting_owner(
                owner,
                rr_type,
                state.interface,
                &state.addresses,
                &name.label(),
            ) {
                Ok(Some(service)) => {
                    eprintln!("rustd-resolved: renamed conflicting DNS-SD service {service}");
                    return true;
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("rustd-resolved: DNS-SD conflict rename failed: {error}");
                }
            }
        }
    }
    false
}

fn add_related_records(selected: &mut BTreeSet<LocalRecord>, all_records: &[LocalRecord]) {
    loop {
        let before = selected.len();
        let current = selected.iter().cloned().collect::<Vec<_>>();
        for record in current {
            if record.rr_type == TYPE_PTR {
                for related in all_records.iter().filter(|candidate| {
                    candidate.owner == record.rdata
                        && matches!(candidate.rr_type, TYPE_SRV | TYPE_TXT)
                }) {
                    selected.insert(related.clone());
                }
            } else if record.rr_type == TYPE_SRV && record.rdata.len() >= 7 {
                let target = &record.rdata[6..];
                for related in all_records.iter().filter(|candidate| {
                    candidate.owner == target && matches!(candidate.rr_type, TYPE_A | TYPE_AAAA)
                }) {
                    selected.insert(related.clone());
                }
            }
        }
        if selected.len() == before {
            break;
        }
    }
}

fn response_packet(
    id: u16,
    questions: &[Vec<u8>],
    records: &[LocalRecord],
    legacy: bool,
) -> io::Result<Vec<u8>> {
    let question_count = u16::try_from(questions.len())
        .map_err(|_| invalid_data("too many mDNS response questions"))?;
    let answer_count =
        u16::try_from(records.len()).map_err(|_| invalid_data("too many mDNS response records"))?;
    let mut output = dns_header(
        id,
        DNS_FLAG_QR | DNS_FLAG_AA,
        question_count,
        answer_count,
        0,
        0,
    );
    for question in questions {
        output.extend_from_slice(question);
    }
    for record in records {
        append_record(&mut output, record, !legacy, None)?;
    }
    Ok(output)
}

fn append_record(
    output: &mut Vec<u8>,
    record: &LocalRecord,
    permit_flush: bool,
    ttl_override: Option<u32>,
) -> io::Result<()> {
    let length = u16::try_from(record.rdata.len())
        .map_err(|_| invalid_data("mDNS RDATA exceeds 65535 octets"))?;
    output.extend_from_slice(&record.owner);
    output.extend_from_slice(&record.rr_type.to_be_bytes());
    let class = record.class
        | if permit_flush && record.cache_flush {
            DNS_CLASS_QU_OR_FLUSH
        } else {
            0
        };
    output.extend_from_slice(&class.to_be_bytes());
    let ttl = ttl_override.unwrap_or_else(|| {
        if permit_flush {
            record.ttl
        } else {
            record.ttl.min(LEGACY_UNICAST_TTL_MAX)
        }
    });
    output.extend_from_slice(&ttl.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&record.rdata);
    Ok(())
}

fn local_records(
    name: &NameState,
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
) -> Vec<LocalRecord> {
    let owner = name.owner();
    let mut output = Vec::new();
    for address in addresses {
        match (interface.family, address) {
            (MdnsAddressFamily::Ipv4, IpAddr::V4(address)) => {
                output.push(LocalRecord {
                    owner: owner.clone(),
                    rr_type: TYPE_A,
                    class: CLASS_IN,
                    ttl: HOST_TTL,
                    cache_flush: true,
                    rdata: address.octets().to_vec(),
                });
                output.push(LocalRecord {
                    owner: reverse_owner(IpAddr::V4(*address)),
                    rr_type: TYPE_PTR,
                    class: CLASS_IN,
                    ttl: HOST_TTL,
                    cache_flush: true,
                    rdata: owner.clone(),
                });
            }
            (MdnsAddressFamily::Ipv6, IpAddr::V6(address)) => {
                output.push(LocalRecord {
                    owner: owner.clone(),
                    rr_type: TYPE_AAAA,
                    class: CLASS_IN,
                    ttl: HOST_TTL,
                    cache_flush: true,
                    rdata: address.octets().to_vec(),
                });
                output.push(LocalRecord {
                    owner: reverse_owner(IpAddr::V6(*address)),
                    rr_type: TYPE_PTR,
                    class: CLASS_IN,
                    ttl: HOST_TTL,
                    cache_flush: true,
                    rdata: owner.clone(),
                });
            }
            _ => {}
        }
    }
    match super::dnssd_runtime::records_for(interface, addresses, &name.label(), false) {
        Ok(records) => output.extend(records.into_iter().map(|record| LocalRecord {
            owner: record.owner,
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            cache_flush: record.cache_flush,
            rdata: record.rdata,
        })),
        Err(error) => eprintln!("rustd-resolved: DNS-SD record generation failed: {error}"),
    }
    output.sort();
    output.dedup();
    output
}

fn reverse_owner(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            let labels = [
                octets[3].to_string(),
                octets[2].to_string(),
                octets[1].to_string(),
                octets[0].to_string(),
                "in-addr".to_owned(),
                "arpa".to_owned(),
            ];
            wire_name(&labels.iter().map(String::as_bytes).collect::<Vec<_>>())
        }
        IpAddr::V6(address) => {
            let mut labels = Vec::<String>::new();
            for byte in address.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            labels.push("ip6".to_owned());
            labels.push("arpa".to_owned());
            wire_name(&labels.iter().map(String::as_bytes).collect::<Vec<_>>())
        }
    }
}

fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for label in labels {
        let length = label.len().min(63);
        output.push(length as u8);
        output.extend(label[..length].iter().map(u8::to_ascii_lowercase));
    }
    output.push(0);
    canonical_wire_name(&output).unwrap_or_else(|_| vec![0])
}

fn dns_header(
    id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(DNS_HEADER_LENGTH);
    for value in [id, flags, questions, answers, authorities, additionals] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output
}

fn decode_name(packet: &[u8], start: usize) -> io::Result<(Vec<u8>, usize)> {
    let mut output = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut visited = HashSet::new();
    for _ in 0..128 {
        let Some(&length) = packet.get(cursor) else {
            return Err(invalid_data("truncated mDNS name"));
        };
        if length & 0xc0 == 0xc0 {
            let second = *packet
                .get(cursor + 1)
                .ok_or_else(|| invalid_data("truncated mDNS pointer"))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if target >= packet.len() || !visited.insert(target) {
                return Err(invalid_data("invalid mDNS pointer"));
            }
            if next.is_none() {
                next = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(invalid_data("invalid mDNS label"));
        }
        cursor += 1;
        output.push(length);
        if length == 0 {
            let output = canonical_wire_name(&output)
                .map_err(|_| invalid_data("invalid canonical mDNS name"))?;
            return Ok((output, next.unwrap_or(cursor)));
        }
        let length = usize::from(length);
        let end = cursor
            .checked_add(length)
            .filter(|value| *value <= packet.len())
            .ok_or_else(|| invalid_data("truncated mDNS label"))?;
        output.extend(packet[cursor..end].iter().map(u8::to_ascii_lowercase));
        cursor = end;
    }
    Err(invalid_data("mDNS compression loop"))
}

fn expand_rdata(packet: &[u8], rr_type: u16, start: usize, end: usize) -> io::Result<Vec<u8>> {
    match rr_type {
        TYPE_CNAME | TYPE_PTR => {
            let (name, consumed) = decode_name(packet, start)?;
            if consumed != end {
                return Err(invalid_data("trailing mDNS name data"));
            }
            Ok(name)
        }
        TYPE_SRV => {
            if start + 6 > end {
                return Err(invalid_data("short mDNS SRV data"));
            }
            let (name, consumed) = decode_name(packet, start + 6)?;
            if consumed != end {
                return Err(invalid_data("trailing mDNS SRV data"));
            }
            let mut output = packet[start..start + 6].to_vec();
            output.extend_from_slice(&name);
            Ok(output)
        }
        TYPE_A | TYPE_AAAA | TYPE_TXT => Ok(packet[start..end].to_vec()),
        _ => Ok(packet[start..end].to_vec()),
    }
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| invalid_data("truncated mDNS u16"))?;
    if bytes.len() != 2 {
        return Err(invalid_data("truncated mDNS u16"));
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> io::Result<u32> {
    let bytes = packet
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| invalid_data("truncated mDNS u32"))?;
    if bytes.len() != 4 {
        return Err(invalid_data("truncated mDNS u32"));
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn listener_exists_without_an_eligible_interface() {
        let mut listeners = ListenerSockets::default();
        listeners
            .synchronize(&BTreeMap::new())
            .expect("wildcard mDNS listener");
        assert!(listeners.sockets.contains_key(&MdnsAddressFamily::Ipv4));
    }

    #[test]
    fn sanitizes_and_bounds_hostnames() {
        assert_eq!(sanitize_hostname("My Host.example"), "my-host");
        assert_eq!(sanitize_hostname("---"), "localhost");
        assert_eq!(sanitize_hostname(&"a".repeat(80)).len(), 63);
    }

    #[test]
    fn conflict_renaming_stays_within_one_label() {
        let mut state = NameState {
            base: "a".repeat(63),
            ordinal: 1,
            generation: 1,
        };
        state.rename();
        assert!(state.label().len() <= 63);
        assert!(state.label().ends_with("-2"));
    }

    #[test]
    fn local_ipv4_records_include_forward_and_reverse_answers() {
        let name = NameState {
            base: "host".to_owned(),
            ordinal: 1,
            generation: 1,
        };
        let records = local_records(
            &name,
            MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
            &BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
        );
        // Host A + reverse PTR are required; DNS-SD may append additional records.
        assert!(records.len() >= 2);
        assert!(records.iter().any(|record| record.rr_type == TYPE_A));
        assert!(records.iter().any(|record| record.rr_type == TYPE_PTR));
    }

    #[test]
    fn legacy_unicast_response_caps_ttl_and_clears_flush() {
        let record = LocalRecord {
            owner: wire_name(&[b"host", b"local"]),
            rr_type: TYPE_A,
            class: CLASS_IN,
            ttl: HOST_TTL,
            cache_flush: true,
            rdata: vec![192, 0, 2, 10],
        };
        let packet = response_packet(7, &[], &[record], true).expect("response packet");
        let (_, owner_end) = decode_name(&packet, DNS_HEADER_LENGTH).expect("owner");
        assert_eq!(read_u16(&packet, owner_end + 2).expect("class"), CLASS_IN);
        assert_eq!(
            read_u32(&packet, owner_end + 4).expect("ttl"),
            LEGACY_UNICAST_TTL_MAX
        );
    }

    #[test]
    fn known_answers_suppress_multicast_responses() {
        let record = LocalRecord {
            owner: wire_name(&[b"host", b"local"]),
            rr_type: TYPE_A,
            class: CLASS_IN,
            ttl: HOST_TTL,
            cache_flush: true,
            rdata: vec![192, 0, 2, 10],
        };
        let mut known = record.known_answer();
        known.ttl = HOST_TTL / 2;
        assert!(known_answer_suppresses(&record.known_answer(), &known));
    }

    #[test]
    fn native_layout_matches_c_contract() {
        assert_eq!(std::mem::size_of::<NativeMdnsInterface>(), 32);
        assert_eq!(std::mem::size_of::<NativeMdnsMeta>(), 48);
    }

    #[test]
    fn large_service_catalog_answers_one_browse_type_with_related_records() {
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-dnssd-scale-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).expect("service directory");
        for service_type in 0..10 {
            for service in 0..20 {
                let number = service_type * 20 + service;
                fs::write(
                    directory.join(format!("service-{number}.dnssd")),
                    format!(
                        "[Service]\nName=Test Service {number} on %H\nType=_testService{service_type}._udp\nPort=98010\nTxtText=DC=Device PN=123456 SN=1234567890\n"
                    ),
                )
                .expect("service file");
            }
        }
        let catalog = super::super::dnssd_config::ServiceCatalog::load_from_directories(
            std::slice::from_ref(&directory),
        )
        .expect("service catalog");
        assert_eq!(catalog.len(), 200);
        let interface = MdnsInterface::new(3, MdnsAddressFamily::Ipv4);
        let addresses = BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 168, 126, 17))]);
        let records = catalog
            .records_for(interface, &addresses, "test-mdns-1", false)
            .expect("service records")
            .into_iter()
            .map(|record| LocalRecord {
                owner: record.owner,
                rr_type: record.rr_type,
                class: record.class,
                ttl: record.ttl,
                cache_flush: record.cache_flush,
                rdata: record.rdata,
            })
            .collect::<Vec<_>>();
        let owner = wire_name(&[b"_testservice0", b"_udp", b"local"]);
        let mut selected = records
            .iter()
            .filter(|record| record.owner == owner && record.rr_type == TYPE_PTR)
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(selected.len(), 20);
        add_related_records(&mut selected, &records);
        let packet = response_packet(0, &[], &selected.into_iter().collect::<Vec<_>>(), false)
            .expect("browse response");
        assert!(packet.len() <= 65_507);
        let parsed = parse_message(&packet).expect("parse browse response");
        assert_eq!(
            parsed
                .records
                .iter()
                .filter(|record| record.owner == owner && record.rr_type == TYPE_PTR)
                .count(),
            20
        );
        fs::remove_dir_all(directory).expect("remove service directory");
    }
}
