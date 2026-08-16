// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::SupportMode;
use crate::native;
use crate::resolver::Resolver;
use crate::wire::{
    self, Header, LocalRecord, CLASS_ANY, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_PTR,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket,
};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LLMNR_PORT: u16 = 5355;
const LLMNR_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
const LLMNR_IPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3);
const LLMNR_TTL: u32 = 30;
const INTERFACE_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const RECEIVE_SLEEP: Duration = Duration::from_millis(5);
const MAX_PACKET: usize = 65_535;
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LlmnrCacheKey {
    ifindex: i32,
    family: i32,
    name: Vec<u8>,
    rr_type: u16,
    class: u16,
}

#[derive(Clone, Debug)]
struct LlmnrCacheEntry {
    response: Vec<u8>,
    inserted_at: Instant,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct LlmnrCache {
    entries: BTreeMap<LlmnrCacheKey, LlmnrCacheEntry>,
    hits: u64,
    misses: u64,
}

#[derive(Clone, Debug)]
pub struct LlmnrCacheSnapshot {
    pub ifindex: i32,
    pub family: i32,
    pub entry: crate::cache::CacheSnapshot,
}

impl LlmnrCache {
    fn key(query: &[u8], ifindex: i32, family: i32) -> io::Result<LlmnrCacheKey> {
        let question = wire::first_question(query)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(LlmnrCacheKey {
            ifindex,
            family,
            name: question.name.canonical_wire().to_vec(),
            rr_type: question.rr_type,
            class: question.class,
        })
    }

    fn lookup(
        &mut self,
        query: &[u8],
        ifindex: i32,
        family: i32,
        now: Instant,
    ) -> io::Result<Option<Vec<u8>>> {
        let key = Self::key(query, ifindex, family)?;
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            self.entries.remove(&key);
        }
        if let Some(entry) = self.entries.get(&key) {
            self.hits = self.hits.saturating_add(1);
            let mut response = entry.response.clone();
            let id = Header::parse(query)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
                .id;
            let elapsed = now
                .checked_duration_since(entry.inserted_at)
                .unwrap_or_default()
                .as_secs()
                .min(u64::from(u32::MAX)) as u32;
            wire::rewrite_id(&mut response, id)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            wire::age_ttls(&mut response, elapsed, false)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Ok(Some(response))
        } else {
            self.misses = self.misses.saturating_add(1);
            Ok(None)
        }
    }

    fn insert(
        &mut self,
        query: &[u8],
        response: &[u8],
        ifindex: i32,
        family: i32,
        store_negative: bool,
        capacity: usize,
        now: Instant,
    ) -> io::Result<()> {
        let header = Header::parse(response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if capacity == 0
            || (!store_negative && (header.response_code() != 0 || header.answer_count == 0))
        {
            return Ok(());
        }
        let Some(ttl) = wire::cache_lifetime(response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        else {
            return Ok(());
        };
        if ttl == 0 {
            return Ok(());
        }
        let key = Self::key(query, ifindex, family)?;
        self.entries.retain(|_, entry| entry.expires_at > now);
        while !self.entries.contains_key(&key) && self.entries.len() >= capacity {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let mut normalized = response.to_vec();
        wire::rewrite_id(&mut normalized, 0)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.entries.insert(
            key,
            LlmnrCacheEntry {
                response: normalized,
                inserted_at: now,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
            },
        );
        Ok(())
    }

    fn snapshot(&mut self, now: Instant) -> Vec<LlmnrCacheSnapshot> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.entries
            .iter()
            .filter_map(|(key, entry)| {
                let rcode = Header::parse(&entry.response).ok()?.response_code();
                Some(LlmnrCacheSnapshot {
                    ifindex: key.ifindex,
                    family: key.family,
                    entry: crate::cache::CacheSnapshot {
                        name: key.name.clone(),
                        rr_type: key.rr_type,
                        class: key.class,
                        rcode: u8::try_from(rcode).ok()?,
                        response: entry.response.clone(),
                        remaining: entry
                            .expires_at
                            .checked_duration_since(now)
                            .unwrap_or_default(),
                        scope: crate::cache::CacheScope::Link(key.ifindex),
                    },
                })
            })
            .collect()
    }

    fn statistics(&mut self, now: Instant) -> (usize, u64, u64) {
        self.entries.retain(|_, entry| entry.expires_at > now);
        (self.entries.len(), self.hits, self.misses)
    }

    fn reset_statistics(&mut self) {
        self.hits = 0;
        self.misses = 0;
    }
}

static CACHE: OnceLock<Mutex<LlmnrCache>> = OnceLock::new();

fn cache() -> MutexGuard<'static, LlmnrCache> {
    CACHE
        .get_or_init(|| Mutex::new(LlmnrCache::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn flush_cache() {
    cache().entries.clear();
}

pub fn cache_snapshot() -> Vec<LlmnrCacheSnapshot> {
    cache().snapshot(Instant::now())
}

pub fn cache_statistics() -> (usize, u64, u64) {
    cache().statistics(Instant::now())
}

pub fn reset_cache_statistics() {
    cache().reset_statistics();
}

#[cfg(test)]
pub(crate) fn seed_cache_for_flush_test() {
    let now = Instant::now();
    let query = wire::make_query("flush-llmnr", TYPE_A, 0).expect("LLMNR flush query");
    let response = wire::local_response(
        &query,
        &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 46))],
        LLMNR_TTL,
    )
    .expect("LLMNR flush response");
    cache()
        .insert(&query, &response, 7, 2, true, 4096, now)
        .expect("seed LLMNR cache");
}

#[cfg(test)]
pub(crate) fn cache_has_flush_test_record() -> bool {
    cache()
        .entries
        .keys()
        .any(|key| key.name == wire::encode_name("flush-llmnr").expect("LLMNR flush name"))
}

extern "C" {
    fn llmnr_join_v4(fd: i32, ifindex: i32) -> i32;
    fn llmnr_join_v6(fd: i32, ifindex: i32) -> i32;
    fn llmnr_leave_v4(fd: i32, ifindex: i32) -> i32;
    fn llmnr_leave_v6(fd: i32, ifindex: i32) -> i32;
}

#[derive(Clone, Debug)]
pub struct LlmnrClient {
    sender: SyncSender<Command>,
}

impl LlmnrClient {
    pub fn query_raw(
        &self,
        query: &[u8],
        ifindex: Option<i32>,
        timeout: Duration,
        bypass_cache: bool,
        network_allowed: bool,
    ) -> io::Result<Option<(Vec<u8>, bool)>> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let cancellation = crate::query_cancel::current();
        self.sender
            .send(Command::Query {
                packet: query.to_vec(),
                ifindex,
                timeout,
                bypass_cache,
                network_allowed,
                cancellation,
                reply: reply_sender,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "LLMNR runtime stopped"))?;
        let wait = timeout
            .checked_add(Duration::from_millis(500))
            .unwrap_or(timeout);
        let started = Instant::now();
        loop {
            let remaining = wait.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(None);
            }
            match reply_receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(message)) => return Err(io::Error::other(message)),
                Err(RecvTimeoutError::Timeout) => check_query_cancellation()?,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "LLMNR runtime stopped",
                    ))
                }
            }
        }
    }
}

#[derive(Debug)]
enum Command {
    Query {
        packet: Vec<u8>,
        ifindex: Option<i32>,
        timeout: Duration,
        bypass_cache: bool,
        network_allowed: bool,
        cancellation: Option<crate::query_cancel::QueryCancellation>,
        reply: SyncSender<Result<Option<(Vec<u8>, bool)>, String>>,
    },
}

#[derive(Debug)]
pub struct LlmnrRuntime {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl LlmnrRuntime {
    pub fn start(resolver: Arc<Resolver>) -> io::Result<Option<Self>> {
        if matches!(resolver.config().llmnr, SupportMode::No) {
            return Ok(None);
        }

        let sockets = RuntimeSockets::open()?;
        let mut listeners = Vec::new();
        if sockets.ipv4.is_some() {
            listeners.push((open_tcp_listener(false)?, false));
        }
        if sockets.ipv6.is_some() {
            listeners.push((open_tcp_listener(true)?, true));
        }
        let (sender, receiver) = mpsc::sync_channel(128);
        resolver.install_llmnr_client(LlmnrClient { sender });
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let runtime_resolver = Arc::clone(&resolver);
        let mut threads = vec![thread::Builder::new()
            .name("resolved-llmnr".to_owned())
            .spawn(move || runtime_loop(&thread_stop, &runtime_resolver, &receiver, sockets))?];
        for (listener, ipv6) in listeners {
            let listener_stop = Arc::clone(&stop);
            let listener_resolver = Arc::clone(&resolver);
            let thread = thread::Builder::new()
                .name(if ipv6 {
                    "resolved-llmnr-tcp6".to_owned()
                } else {
                    "resolved-llmnr-tcp4".to_owned()
                })
                .spawn(move || {
                    tcp_listener_loop(&listener_stop, &listener_resolver, listener, ipv6)
                });
            match thread {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Some(Self { stop, threads }))
    }
}

impl Drop for LlmnrRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn open_tcp_listener(ipv6: bool) -> io::Result<TcpListener> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nodelay(true)?;
    if ipv6 {
        socket.set_only_v6(true)?;
        socket.set_unicast_hops_v6(1)?;
    } else {
        socket.set_ttl(1)?;
    }
    let address = if ipv6 {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, LLMNR_PORT))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, LLMNR_PORT))
    };
    socket.bind(&address.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[derive(Debug)]
struct FamilySocket {
    socket: UdpSocket,
    ipv6: bool,
    memberships: BTreeSet<i32>,
}

impl FamilySocket {
    fn open(ipv6: bool) -> io::Result<Self> {
        let fd = native::mdns_open(ipv6, LLMNR_PORT)?;
        // SAFETY: mdns_open returned a new descriptor and ownership is transferred once.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        Ok(Self {
            socket,
            ipv6,
            memberships: BTreeSet::new(),
        })
    }

    fn synchronize(&mut self, wanted: &BTreeSet<i32>) {
        for ifindex in self
            .memberships
            .difference(wanted)
            .copied()
            .collect::<Vec<_>>()
        {
            let _ = membership(self.socket.as_raw_fd(), self.ipv6, ifindex, false);
            self.memberships.remove(&ifindex);
        }
        for ifindex in wanted
            .difference(&self.memberships)
            .copied()
            .collect::<Vec<_>>()
        {
            match membership(self.socket.as_raw_fd(), self.ipv6, ifindex, true) {
                Ok(()) => {
                    self.memberships.insert(ifindex);
                }
                Err(error) => eprintln!(
                    "rustd-resolved: failed to join LLMNR multicast on interface {ifindex}: {error}"
                ),
            }
        }
    }

    fn destination(&self, ifindex: i32) -> SocketAddr {
        if self.ipv6 {
            SocketAddr::V6(SocketAddrV6::new(
                LLMNR_IPV6_MULTICAST,
                LLMNR_PORT,
                0,
                u32::try_from(ifindex).unwrap_or(0),
            ))
        } else {
            SocketAddr::from((LLMNR_IPV4_MULTICAST, LLMNR_PORT))
        }
    }
}

#[derive(Debug)]
struct RuntimeSockets {
    ipv4: Option<FamilySocket>,
    ipv6: Option<FamilySocket>,
}

impl RuntimeSockets {
    fn open() -> io::Result<Self> {
        let ipv4 = FamilySocket::open(false);
        let ipv6 = FamilySocket::open(true);
        match (ipv4, ipv6) {
            (Ok(ipv4), Ok(ipv6)) => Ok(Self {
                ipv4: Some(ipv4),
                ipv6: Some(ipv6),
            }),
            (Ok(ipv4), Err(_)) => Ok(Self {
                ipv4: Some(ipv4),
                ipv6: None,
            }),
            (Err(_), Ok(ipv6)) => Ok(Self {
                ipv4: None,
                ipv6: Some(ipv6),
            }),
            (Err(error), Err(_)) => Err(error),
        }
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut FamilySocket> {
        self.ipv4.iter_mut().chain(self.ipv6.iter_mut())
    }

    fn synchronize(&mut self, resolver: &Resolver, addresses: &[native::AddressInfo]) {
        let mut ipv4 = BTreeSet::new();
        let mut ipv6 = BTreeSet::new();
        for address in addresses.iter().filter(|address| usable_address(address)) {
            if !resolver.llmnr_resolve_enabled(Some(address.ifindex)) {
                continue;
            }
            match address.address {
                IpAddr::V4(_) => {
                    ipv4.insert(address.ifindex);
                }
                IpAddr::V6(_) => {
                    ipv6.insert(address.ifindex);
                }
            }
        }
        if let Some(socket) = self.ipv4.as_mut() {
            socket.synchronize(&ipv4);
        }
        if let Some(socket) = self.ipv6.as_mut() {
            socket.synchronize(&ipv6);
        }
    }
}

fn membership(fd: i32, ipv6: bool, ifindex: i32, join: bool) -> io::Result<()> {
    // SAFETY: the descriptor is borrowed, and the helpers only mutate socket membership.
    let result = unsafe {
        match (ipv6, join) {
            (false, true) => llmnr_join_v4(fd, ifindex),
            (true, true) => llmnr_join_v6(fd, ifindex),
            (false, false) => llmnr_leave_v4(fd, ifindex),
            (true, false) => llmnr_leave_v6(fd, ifindex),
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn runtime_loop(
    stop: &AtomicBool,
    resolver: &Resolver,
    commands: &Receiver<Command>,
    mut sockets: RuntimeSockets,
) {
    let mut addresses = Vec::new();
    let mut next_scan = Instant::now();
    let mut buffer = vec![0u8; MAX_PACKET];

    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= next_scan {
            match native::address_snapshot() {
                Ok(current) => {
                    addresses = current;
                    sockets.synchronize(resolver, &addresses);
                }
                Err(error) => {
                    eprintln!("rustd-resolved: failed to inspect LLMNR interfaces: {error}");
                }
            }
            next_scan = now + INTERFACE_SCAN_INTERVAL;
        }

        match commands.try_recv() {
            Ok(Command::Query {
                packet,
                ifindex,
                timeout,
                bypass_cache,
                network_allowed,
                cancellation,
                reply,
            }) => {
                let result = crate::query_cancel::with_optional(cancellation, || {
                    execute_query(
                        resolver,
                        &mut sockets,
                        &addresses,
                        &packet,
                        ifindex,
                        timeout,
                        bypass_cache,
                        network_allowed,
                        &mut buffer,
                    )
                    .map_err(|error| error.to_string())
                });
                let _ = reply.send(result);
            }
            Err(TryRecvError::Empty) => {
                receive_once(resolver, &mut sockets, &addresses, &mut buffer);
                thread::sleep(RECEIVE_SLEEP);
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
}

fn tcp_listener_loop(
    stop: &AtomicBool,
    resolver: &Arc<Resolver>,
    listener: TcpListener,
    ipv6: bool,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let resolver = Arc::clone(resolver);
                let family = if ipv6 { "tcp6" } else { "tcp4" };
                let _ = thread::Builder::new()
                    .name(format!("resolved-llmnr-{family}-client"))
                    .spawn(move || {
                        if let Err(error) = tcp_client(stream, &resolver, ipv6) {
                            eprintln!("rustd-resolved: LLMNR TCP client {peer} failed: {error}");
                        }
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(RECEIVE_SLEEP);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("rustd-resolved: LLMNR TCP accept failed: {error}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn tcp_client(mut stream: TcpStream, resolver: &Resolver, ipv6: bool) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(TCP_TIMEOUT))?;
    stream.set_write_timeout(Some(TCP_TIMEOUT))?;
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    if local.is_ipv6() != ipv6 || peer.is_ipv6() != ipv6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LLMNR TCP address family mismatch",
        ));
    }
    let addresses = native::address_snapshot()?;
    let Some(ifindex) = addresses
        .iter()
        .filter(|address| usable_address(address))
        .find(|address| address.address == local.ip())
        .map(|address| address.ifindex)
        .filter(|ifindex| resolver.llmnr_respond_enabled(*ifindex))
    else {
        return Ok(());
    };

    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length LLMNR TCP frame",
        ));
    }
    let mut query = vec![0u8; length];
    stream.read_exact(&mut query)?;
    let Some(response) = response_for_query(resolver, &addresses, ifindex, &query) else {
        return Ok(());
    };
    let response_length = u16::try_from(response.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "LLMNR response is too large"))?;
    stream.write_all(&response_length.to_be_bytes())?;
    stream.write_all(&response)
}

fn execute_query(
    resolver: &Resolver,
    sockets: &mut RuntimeSockets,
    addresses: &[native::AddressInfo],
    query: &[u8],
    requested_ifindex: Option<i32>,
    timeout: Duration,
    bypass_cache: bool,
    network_allowed: bool,
    buffer: &mut [u8],
) -> io::Result<Option<(Vec<u8>, bool)>> {
    check_query_cancellation()?;
    if !should_handle_query(query, &resolver.llmnr_hostname()) {
        return Ok(None);
    }
    let mut llmnr_query = query.to_vec();
    llmnr_query[2..4].copy_from_slice(&0u16.to_be_bytes());
    let question = wire::first_question(&llmnr_query)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let candidates = query_candidates(
        resolver,
        sockets,
        addresses,
        requested_ifindex,
        question.name.text(),
        question.rr_type,
    );
    if candidates.is_empty() {
        return Ok(None);
    }
    let config = resolver.config();
    let cache_enabled = config.cache && config.llmnr_cache_size > 0;
    if cache_enabled && !bypass_cache {
        for &(ipv6, ifindex) in &candidates {
            let family = if ipv6 { 10 } else { 2 };
            if let Some(response) = cache().lookup(&llmnr_query, ifindex, family, Instant::now())? {
                return Ok(Some((response, true)));
            }
        }
    }
    if !network_allowed {
        return Ok(None);
    }
    if let Some(address) = wire::parse_reverse_name(question.name.text()) {
        for &(ipv6, ifindex) in &candidates {
            if address.is_ipv6() != ipv6 {
                continue;
            }
            let destination = scoped_address(address, LLMNR_PORT, ifindex);
            match tcp_query(&llmnr_query, destination, timeout) {
                Ok(Some(response)) => {
                    let family = if ipv6 { 10 } else { 2 };
                    if cache_enabled
                        && (config.cache_from_localhost || !destination.ip().is_loopback())
                    {
                        cache().insert(
                            &llmnr_query,
                            &response,
                            ifindex,
                            family,
                            config.cache_negative,
                            config.llmnr_cache_size,
                            Instant::now(),
                        )?;
                    }
                    return Ok(Some((response, false)));
                }
                Ok(None) => {}
                Err(error) if transient_tcp_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        return Ok(None);
    }
    for (ipv6, ifindex) in candidates {
        let endpoint = if ipv6 {
            sockets.ipv6.as_ref()
        } else {
            sockets.ipv4.as_ref()
        };
        let Some(endpoint) = endpoint else {
            continue;
        };
        let destination = endpoint.destination(ifindex);
        match native::mdns_send(
            endpoint.socket.as_raw_fd(),
            &llmnr_query,
            destination,
            ifindex,
        ) {
            Ok(length) if length == llmnr_query.len() => {}
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short LLMNR send")),
            Err(error) if transient_interface_error(&error) => {}
            Err(error) => return Err(error),
        }
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        check_query_cancellation()?;
        for endpoint in sockets.iter_mut() {
            let packet = match native::mdns_recv(endpoint.socket.as_raw_fd(), buffer) {
                Ok((length, metadata)) => Some((buffer[..length].to_vec(), metadata)),
                Err(error) if receive_would_block(&error) => None,
                Err(error) => return Err(error),
            };
            let Some((packet, metadata)) = packet else {
                continue;
            };
            if valid_response_metadata(&metadata, endpoint.ipv6)
                && wire::response_matches(&llmnr_query, &packet).is_ok()
            {
                if Header::parse(&packet).is_ok_and(Header::truncated) {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    return match tcp_query(&llmnr_query, metadata.source, remaining) {
                        Ok(Some(response)) => {
                            let family = if endpoint.ipv6 { 10 } else { 2 };
                            if cache_enabled
                                && (config.cache_from_localhost
                                    || !metadata.source.ip().is_loopback())
                            {
                                cache().insert(
                                    &llmnr_query,
                                    &response,
                                    metadata.ifindex,
                                    family,
                                    config.cache_negative,
                                    config.llmnr_cache_size,
                                    Instant::now(),
                                )?;
                            }
                            Ok(Some((response, false)))
                        }
                        Ok(None) => Ok(None),
                        Err(error) if transient_tcp_error(&error) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
                let family = if endpoint.ipv6 { 10 } else { 2 };
                if cache_enabled
                    && (config.cache_from_localhost || !metadata.source.ip().is_loopback())
                {
                    cache().insert(
                        &llmnr_query,
                        &packet,
                        metadata.ifindex,
                        family,
                        config.cache_negative,
                        config.llmnr_cache_size,
                        Instant::now(),
                    )?;
                }
                return Ok(Some((packet, false)));
            }
            process_query(resolver, endpoint, addresses, &packet, metadata);
        }
    }
    Ok(None)
}

fn check_query_cancellation() -> io::Result<()> {
    crate::query_cancel::check()
        .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "resolver client disconnected"))
}

fn scoped_address(address: IpAddr, port: u16, ifindex: i32) -> SocketAddr {
    match address {
        IpAddr::V4(address) => SocketAddr::from((address, port)),
        IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
            address,
            port,
            0,
            u32::try_from(ifindex).unwrap_or(0),
        )),
    }
}

fn tcp_query(
    query: &[u8],
    destination: SocketAddr,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let domain = Domain::for_address(destination);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nodelay(true)?;
    if destination.is_ipv6() {
        socket.set_unicast_hops_v6(1)?;
    } else {
        socket.set_ttl(1)?;
    }
    socket.connect_timeout(&destination.into(), timeout)?;
    let mut stream = TcpStream::from(socket);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let query_length = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "LLMNR query is too large"))?;
    stream.write_all(&query_length.to_be_bytes())?;
    stream.write_all(query)?;

    let mut length = [0u8; 2];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length LLMNR TCP response",
        ));
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response)?;
    wire::response_matches(query, &response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Some(response))
}

fn receive_once(
    resolver: &Resolver,
    sockets: &mut RuntimeSockets,
    addresses: &[native::AddressInfo],
    buffer: &mut [u8],
) {
    for endpoint in sockets.iter_mut() {
        match native::mdns_recv(endpoint.socket.as_raw_fd(), buffer) {
            Ok((length, metadata)) => {
                process_query(resolver, endpoint, addresses, &buffer[..length], metadata);
            }
            Err(error) if receive_would_block(&error) => {}
            Err(error) => eprintln!("rustd-resolved: LLMNR receive failed: {error}"),
        }
    }
}

fn process_query(
    resolver: &Resolver,
    endpoint: &FamilySocket,
    addresses: &[native::AddressInfo],
    packet: &[u8],
    metadata: native::MdnsPacketInfo,
) {
    if !valid_query_metadata(&metadata, endpoint.ipv6)
        || !endpoint.memberships.contains(&metadata.ifindex)
        || !resolver.llmnr_respond_enabled(metadata.ifindex)
    {
        return;
    }
    let Some(response) = response_for_query(resolver, addresses, metadata.ifindex, packet) else {
        return;
    };
    let _ = native::mdns_send(
        endpoint.socket.as_raw_fd(),
        &response,
        metadata.source,
        metadata.ifindex,
    );
}

fn response_for_query(
    resolver: &Resolver,
    addresses: &[native::AddressInfo],
    ifindex: i32,
    packet: &[u8],
) -> Option<Vec<u8>> {
    if wire::validate(packet, false).is_err() {
        return None;
    }
    let header = Header::parse(packet).ok()?;
    if header.flags & 0x0400 != 0 {
        return None;
    }
    let question = wire::first_question(packet).ok()?;
    if !matches!(question.class, CLASS_IN | CLASS_ANY) {
        return None;
    }
    let hostname = resolver.llmnr_hostname();
    let records = local_records(
        addresses,
        ifindex,
        question.name.text(),
        question.rr_type,
        &hostname,
    );
    if records.is_empty() {
        return None;
    }
    let mut response = wire::local_response(packet, &records, LLMNR_TTL).ok()?;
    response[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
    Some(response)
}

fn local_records(
    addresses: &[native::AddressInfo],
    ifindex: i32,
    name: &str,
    rr_type: u16,
    hostname: &str,
) -> Vec<LocalRecord> {
    if name.eq_ignore_ascii_case(hostname) {
        return addresses
            .iter()
            .filter(|address| address.ifindex == ifindex && usable_address(address))
            .filter_map(|address| match (rr_type, address.address) {
                (TYPE_A | TYPE_ANY, IpAddr::V4(address)) => Some(LocalRecord::A(address)),
                (TYPE_AAAA | TYPE_ANY, IpAddr::V6(address)) => Some(LocalRecord::Aaaa(address)),
                _ => None,
            })
            .collect();
    }
    if rr_type != TYPE_PTR && rr_type != TYPE_ANY {
        return Vec::new();
    }
    addresses
        .iter()
        .filter(|address| address.ifindex == ifindex && usable_address(address))
        .find(|address| wire::reverse_name(address.address).eq_ignore_ascii_case(name))
        .map(|_| vec![LocalRecord::Ptr(hostname.to_owned())])
        .unwrap_or_default()
}

fn query_candidates(
    resolver: &Resolver,
    sockets: &RuntimeSockets,
    addresses: &[native::AddressInfo],
    requested_ifindex: Option<i32>,
    name: &str,
    rr_type: u16,
) -> BTreeSet<(bool, i32)> {
    addresses
        .iter()
        .filter(|address| usable_address(address))
        .filter(|address| requested_ifindex.map_or(true, |value| value == address.ifindex))
        .filter(|address| resolver.llmnr_resolve_enabled(Some(address.ifindex)))
        .filter_map(|address| {
            let ipv6 = address.address.is_ipv6();
            if (ipv6 && sockets.ipv6.is_none()) || (!ipv6 && sockets.ipv4.is_none()) {
                return None;
            }
            if !family_matches_query(ipv6, name, rr_type) {
                return None;
            }
            Some((ipv6, address.ifindex))
        })
        .collect()
}

fn family_matches_query(ipv6: bool, name: &str, rr_type: u16) -> bool {
    match rr_type {
        TYPE_A => !ipv6,
        TYPE_AAAA => ipv6,
        TYPE_PTR if name.ends_with(".in-addr.arpa") => !ipv6,
        TYPE_PTR if name.ends_with(".ip6.arpa") => ipv6,
        _ => true,
    }
}

pub fn should_handle_query(query: &[u8], own_hostname: &str) -> bool {
    if wire::validate(query, false).is_err() {
        return false;
    }
    let Ok(question) = wire::first_question(query) else {
        return false;
    };
    if !matches!(question.class, CLASS_IN | CLASS_ANY) || dnssec_type(question.rr_type) {
        return false;
    }
    let name = question.name.text();
    if name.eq_ignore_ascii_case(own_hostname) || name.eq_ignore_ascii_case("local") {
        return false;
    }
    (!name.contains('.') && !name.is_empty())
        || name.ends_with(".in-addr.arpa")
        || name.ends_with(".ip6.arpa")
}

fn dnssec_type(rr_type: u16) -> bool {
    matches!(rr_type, 43 | 46 | 47 | 48 | 50 | 51 | 59 | 60)
}

fn usable_address(address: &&native::AddressInfo) -> bool {
    address.ifindex > 0
        && address.flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE) == 0
        && !address.address.is_loopback()
        && !address.address.is_unspecified()
        && !address.address.is_multicast()
}

fn valid_query_metadata(metadata: &native::MdnsPacketInfo, ipv6: bool) -> bool {
    metadata.hop_limit == 255
        && metadata.destination_multicast
        && metadata.destination
            == if ipv6 {
                IpAddr::V6(LLMNR_IPV6_MULTICAST)
            } else {
                IpAddr::V4(LLMNR_IPV4_MULTICAST)
            }
}

fn valid_response_metadata(metadata: &native::MdnsPacketInfo, ipv6: bool) -> bool {
    metadata.hop_limit == 255
        && metadata.source.port() == LLMNR_PORT
        && metadata.source.is_ipv6() == ipv6
}

fn receive_would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn transient_interface_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(6 | 19 | 99 | 101 | 113))
}

fn transient_tcp_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
    ) || matches!(error.raw_os_error(), Some(6 | 19 | 99 | 101 | 110 | 113))
}

pub fn hostname() -> String {
    let value = std::env::var("RUSTD_RESOLVED_LLMNR_HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(crate::native::kernel_hostname)
        .unwrap_or_else(|| "localhost".to_owned());
    sanitize_hostname(&value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_only_llmnr_names_and_reverse_lookups() {
        let single = wire::make_query("printer", TYPE_A, 7).unwrap();
        let qualified = wire::make_query("printer.example", TYPE_A, 8).unwrap();
        let local = wire::make_query("local", TYPE_A, 9).unwrap();
        let reverse = wire::make_query("1.0.168.192.in-addr.arpa", TYPE_PTR, 10).unwrap();
        assert!(should_handle_query(&single, "workstation"));
        assert!(!should_handle_query(&qualified, "workstation"));
        assert!(!should_handle_query(&local, "workstation"));
        assert!(should_handle_query(&reverse, "workstation"));
        assert!(!should_handle_query(&single, "printer"));
    }

    #[test]
    fn reverse_queries_select_the_matching_tcp_family() {
        assert!(family_matches_query(
            false,
            "221.2.0.192.in-addr.arpa",
            TYPE_PTR
        ));
        assert!(!family_matches_query(
            true,
            "221.2.0.192.in-addr.arpa",
            TYPE_PTR
        ));
        assert!(family_matches_query(true, "1.0.0.0.ip6.arpa", TYPE_PTR));
        assert!(!family_matches_query(false, "1.0.0.0.ip6.arpa", TYPE_PTR));

        let target = scoped_address(IpAddr::V6(Ipv6Addr::LOCALHOST), LLMNR_PORT, 17);
        assert_eq!(target.port(), LLMNR_PORT);
        match target {
            SocketAddr::V6(target) => assert_eq!(target.scope_id(), 17),
            SocketAddr::V4(_) => panic!("expected IPv6 target"),
        }
    }

    #[test]
    fn rejects_dnssec_records() {
        for rr_type in [43, 46, 47, 48, 50, 51, 59, 60] {
            let mut query = wire::make_query("printer", TYPE_A, rr_type).unwrap();
            let type_offset = wire::question_end(&query).expect("question end") - 4;
            query[type_offset..type_offset + 2].copy_from_slice(&rr_type.to_be_bytes());
            assert!(!should_handle_query(&query, "workstation"));
        }
    }

    #[test]
    fn llmnr_reply_has_only_the_response_flag() {
        let query = wire::make_query("workstation", TYPE_A, 11).unwrap();
        let mut response = wire::local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))],
            LLMNR_TTL,
        )
        .unwrap();
        response[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
        assert_eq!(Header::parse(&response).unwrap().flags, 0x8000);
    }

    #[test]
    fn cache_is_scoped_live_and_resettable() {
        let now = Instant::now();
        let query = wire::make_query("printer", TYPE_A, 0).expect("LLMNR query");
        let response = wire::local_response(
            &query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 45))],
            LLMNR_TTL,
        )
        .expect("LLMNR response");
        let mut cache = LlmnrCache::default();
        assert!(cache
            .lookup(&query, 7, 2, now)
            .expect("cache lookup")
            .is_none());
        cache
            .insert(&query, &response, 7, 2, true, 4096, now)
            .expect("cache insert");
        let lookup_query = wire::make_query("printer", TYPE_A, 77).expect("second LLMNR query");
        let cached = cache
            .lookup(&lookup_query, 7, 2, now + Duration::from_secs(1))
            .expect("cache lookup")
            .expect("cached answer");
        assert_eq!(Header::parse(&cached).expect("cached header").id, 77);
        assert_eq!(wire::cache_lifetime(&cached).expect("cached TTL"), Some(29));
        assert_eq!(
            cache.lookup(&query, 7, 2, now).expect("cache lookup"),
            Some(response)
        );
        let snapshot = cache.snapshot(now);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].ifindex, 7);
        assert_eq!(snapshot[0].family, 2);
        assert_eq!(cache.statistics(now), (1, 2, 1));
        cache.reset_statistics();
        assert_eq!(cache.statistics(now), (1, 0, 0));
    }

    #[test]
    fn cache_capacity_evicts_the_earliest_scope_entry() {
        let now = Instant::now();
        let first_query = wire::make_query("first", TYPE_A, 1).expect("first query");
        let second_query = wire::make_query("second", TYPE_A, 2).expect("second query");
        let first_response = wire::local_response(
            &first_query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))],
            10,
        )
        .expect("first response");
        let second_response = wire::local_response(
            &second_query,
            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 2))],
            20,
        )
        .expect("second response");
        let mut cache = LlmnrCache::default();
        cache
            .insert(&first_query, &first_response, 7, 2, true, 1, now)
            .expect("cache first response");
        cache
            .insert(&second_query, &second_response, 7, 2, true, 1, now)
            .expect("cache second response");
        assert!(cache
            .lookup(&first_query, 7, 2, now)
            .expect("first lookup")
            .is_none());
        assert!(cache
            .lookup(&second_query, 7, 2, now)
            .expect("second lookup")
            .is_some());
    }

    #[test]
    fn sanitizes_the_published_hostname() {
        assert_eq!(sanitize_hostname("Work Station.example\n"), "work-station");
        assert_eq!(sanitize_hostname("---"), "localhost");
    }
}
