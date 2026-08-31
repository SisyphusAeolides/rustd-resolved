// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::cache::{Cache, CacheKey};
use crate::chaos_optimizer::ChaosOptimizer;
use crate::config::{Config, DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode};
use crate::edns::{self, FeatureLevel, ServerFeatureState};
use crate::hosts::Hosts;
use crate::native;
use crate::networkd::LinkState as NetworkdLinkState;
use crate::policy::{choose_server_with_bias, update_rtt, ServerMetric};
use crate::routing::{LinkError, LinkState, RouteScope, RoutingTable, ScopeKind};
use crate::tls::TlsStream;
use crate::transport::{ServerTransportState, TransportMode, TRANSPORT_RETRY_ATTEMPTS};
use crate::wire::{
    self, extract_address_records, extract_answer_records, extract_ptr_names, first_question,
    local_response, make_query, make_query_with_class, response_matches, reverse_name,
    servfail_for, validate, Header, WireError, TYPE_A, TYPE_AAAA, TYPE_AXFR, TYPE_IXFR, TYPE_PTR,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

fn dns_name_dont_resolve(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    dns_name_has_suffix(&name, "0.in-addr.arpa")
        || name == "255.255.255.255.in-addr.arpa"
        || name
            == "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        || dns_name_has_suffix(&name, "invalid")
        || dns_name_has_suffix(&name, "alt")
}

fn dns_name_has_suffix(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

const UDP_POOL_PER_SERVER_MAX: usize = 8;
const TCP_POOL_PER_SERVER_MAX: usize = 4;
const TLS_POOL_PER_SERVER_MAX: usize = 4;
const DNS_TRANSACTION_ATTEMPTS_MAX: usize = 24;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(120);
const DNS_TRANSACTION_UDP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TRANSACTION_TCP_TIMEOUT: Duration = Duration::from_secs(10);
const QUERY_CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct DnsAttemptBudget {
    attempts: usize,
    deadline: Instant,
}

impl DnsAttemptBudget {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            attempts: 0,
            deadline: now.checked_add(DNS_QUERY_TIMEOUT).unwrap_or(now),
        }
    }

    fn remaining(&self) -> Result<Duration, ResolveError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out").into())
    }

    fn begin_attempt(&mut self) -> Result<Duration, ResolveError> {
        crate::query_cancel::check()?;
        if self.exhausted() {
            return Err(ResolveError::MaxAttemptsReached);
        }
        let remaining = self.remaining()?;
        self.attempts += 1;
        Ok(remaining)
    }

    #[cfg(test)]
    const fn attempts(&self) -> usize {
        self.attempts
    }

    const fn exhausted(&self) -> bool {
        self.attempts >= DNS_TRANSACTION_ATTEMPTS_MAX
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMode {
    Full,
    Proxy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ServerKey {
    scope: ScopeKind,
    server: SocketAddr,
    slot: usize,
}

impl ServerKey {
    const fn new(scope: ScopeKind, server: SocketAddr) -> Self {
        Self::with_slot(scope, server, 0)
    }

    const fn with_slot(scope: ScopeKind, server: SocketAddr, slot: usize) -> Self {
        Self {
            scope,
            server,
            slot,
        }
    }

    const fn server(self) -> SocketAddr {
        self.server
    }

    const fn scope_kind(self) -> ScopeKind {
        self.scope
    }

    const fn slot(self) -> usize {
        self.slot
    }

    const fn ifindex(self) -> Option<i32> {
        match self.scope {
            ScopeKind::Link(ifindex) => Some(ifindex),
            ScopeKind::Global | ScopeKind::Delegate(_) | ScopeKind::Fallback => None,
        }
    }

    const fn delegate_index(self) -> Option<usize> {
        match self.scope {
            ScopeKind::Delegate(index) => Some(index),
            ScopeKind::Global | ScopeKind::Link(_) | ScopeKind::Fallback => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TlsPoolKey {
    server: ServerKey,
    strict: bool,
}

impl TlsPoolKey {
    const fn new(server: ServerKey, strict: bool) -> Self {
        Self { server, strict }
    }
}

#[derive(Debug, Default)]
struct ServerState {
    metric: ServerMetric,
    cooldown_until: Option<Instant>,
    features: ServerFeatureState,
    transport: ServerTransportState,
    missing_root_rrsig: bool,
    packet_do_off: bool,
    packet_invalid: bool,
}

#[derive(Debug, Default)]
struct Counters {
    current_transactions: AtomicU64,
    transactions: AtomicU64,
    timeouts: AtomicU64,
    timeouts_served_stale: AtomicU64,
    failures_served_stale: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    failures: AtomicU64,
    local_answers: AtomicU64,
    dnssec_secure: AtomicU64,
    dnssec_insecure: AtomicU64,
    dnssec_bogus: AtomicU64,
    dnssec_indeterminate: AtomicU64,
}

struct ActiveTransaction<'a> {
    counter: &'a AtomicU64,
}

impl Drop for ActiveTransaction<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InflightKey {
    route: u64,
    query: Vec<u8>,
}

impl InflightKey {
    fn new(route: u64, query: &[u8]) -> Result<Self, WireError> {
        let mut query = query.to_vec();
        wire::rewrite_id(&mut query, 0)?;
        Ok(Self { route, query })
    }
}

#[derive(Debug, Default)]
struct InflightState {
    running: bool,
    response: Option<SharedResponse>,
}

#[derive(Clone, Debug)]
struct SharedResponse {
    packet: Vec<u8>,
    ifindex: Option<i32>,
}

#[derive(Debug, Default)]
struct InflightEntry {
    state: Mutex<InflightState>,
    ready: Condvar,
}

impl InflightEntry {
    fn wait(&self) -> Result<Option<SharedResponse>, ResolveError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.running {
            crate::query_cancel::check()?;
            let (next_state, _) = self
                .ready
                .wait_timeout(state, QUERY_CANCELLATION_POLL_INTERVAL)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next_state;
        }
        Ok(state.response.clone())
    }
}

#[derive(Debug, Default)]
struct Inflight {
    entries: Mutex<HashMap<InflightKey, Arc<InflightEntry>>>,
}

impl Inflight {
    fn begin(&self, key: InflightKey) -> InflightRole<'_> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = entries.get(&key) {
            return InflightRole::Follower(Arc::clone(entry));
        }

        let entry = Arc::new(InflightEntry {
            state: Mutex::new(InflightState {
                running: true,
                response: None,
            }),
            ready: Condvar::new(),
        });
        entries.insert(key.clone(), Arc::clone(&entry));
        InflightRole::Leader(InflightLeader {
            owner: self,
            key,
            entry,
            completed: false,
        })
    }

    fn finish(
        &self,
        key: &InflightKey,
        entry: &Arc<InflightEntry>,
        response: Option<SharedResponse>,
    ) {
        {
            let mut state = entry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.response = response;
            state.running = false;
            entry.ready.notify_all();
        }

        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(key);
        }
    }
}

#[derive(Debug)]
enum InflightRole<'a> {
    Leader(InflightLeader<'a>),
    Follower(Arc<InflightEntry>),
}

#[derive(Debug)]
struct InflightLeader<'a> {
    owner: &'a Inflight,
    key: InflightKey,
    entry: Arc<InflightEntry>,
    completed: bool,
}

impl InflightLeader<'_> {
    fn complete(mut self, response: Option<SharedResponse>) {
        self.owner.finish(&self.key, &self.entry, response);
        self.completed = true;
    }
}

impl Drop for InflightLeader<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.finish(&self.key, &self.entry, None);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolverStats {
    pub current_transactions: u64,
    pub transactions: u64,
    pub timeouts: u64,
    pub timeouts_served_stale: u64,
    pub failures_served_stale: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub failures: u64,
    pub local_answers: u64,
    pub dnssec_secure: u64,
    pub dnssec_insecure: u64,
    pub dnssec_bogus: u64,
    pub dnssec_indeterminate: u64,
    pub cache_entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverServerState {
    pub server: String,
    pub server_type: String,
    pub interface: Option<String>,
    pub interface_index: Option<i32>,
    pub verified_feature_level: String,
    pub possible_feature_level: String,
    pub dnssec_mode: String,
    pub dnssec_supported: bool,
    pub received_udp_fragment_max: u32,
    pub failed_udp_attempts: u8,
    pub failed_tcp_attempts: u8,
    pub packet_truncated: bool,
    pub packet_bad_opt: bool,
    pub packet_rrsig_missing: bool,
    pub packet_invalid: bool,
    pub packet_do_off: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverResourceKey {
    pub class: u16,
    pub rr_type: u16,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverQueryAnswer {
    pub raw: Vec<u8>,
    pub ifindex: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverQueryEvent {
    pub sequence: u64,
    pub state: String,
    pub result: Option<String>,
    pub rcode: Option<u16>,
    pub errno: Option<i32>,
    pub extended_dns_error_code: Option<u16>,
    pub extended_dns_error_message: Option<String>,
    pub question: Vec<ResolverResourceKey>,
    pub collected_questions: Vec<ResolverResourceKey>,
    pub answer: Vec<ResolverQueryAnswer>,
}

#[derive(Debug, Default)]
struct QueryMonitor {
    sequence: AtomicU64,
    events: Mutex<VecDeque<ResolverQueryEvent>>,
    changed: Condvar,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnskeyCacheKey {
    server: ServerKey,
    zone: String,
}

#[derive(Clone, Debug)]
struct DnskeyCacheEntry {
    keys: Vec<wire::ResourceRecord>,
    expires: Instant,
}

#[derive(Debug)]
pub struct Resolver {
    config: RwLock<Config>,
    states: Mutex<HashMap<ServerKey, ServerState>>,
    udp_sockets: Mutex<HashMap<ServerKey, Vec<UdpSocket>>>,
    tcp_streams: Mutex<HashMap<ServerKey, Vec<TcpStream>>>,
    tls_streams: Mutex<HashMap<TlsPoolKey, Vec<TlsStream>>>,
    routing: RwLock<RoutingTable>,
    networkd_links: RwLock<HashMap<i32, NetworkdLinkState>>,
    link_server_specs: RwLock<HashMap<i32, Vec<DnsServerSpec>>>,
    link_dns_over_tls_overrides: RwLock<HashMap<i32, TlsMode>>,
    link_dnssec_overrides: RwLock<HashMap<i32, ValidationMode>>,
    routing_generation: AtomicU64,
    inflight: Inflight,
    cache: Cache,
    chaos_optimizer: Mutex<ChaosOptimizer>,
    hosts: RwLock<Hosts>,
    next_id: AtomicU16,
    counters: Counters,
    query_monitor: QueryMonitor,
    dnskey_cache: Mutex<HashMap<DnskeyCacheKey, DnskeyCacheEntry>>,
    llmnr_client: RwLock<Option<crate::llmnr::LlmnrClient>>,
    llmnr_mode: RwLock<SupportMode>,
    multicast_dns_mode: RwLock<SupportMode>,
}
