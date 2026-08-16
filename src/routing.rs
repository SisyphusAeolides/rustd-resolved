// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::{Domain, SupportMode, TlsMode, ValidationMode};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

const IFF_UP: u32 = 0x0001;
const IFF_LOOPBACK: u32 = 0x0008;
const IFF_RUNNING: u32 = 0x0040;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x1_0000;
const IFF_DORMANT: u32 = 0x2_0000;
const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_UP: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScopeKind {
    Global,
    Link(i32),
    Delegate(usize),
    Fallback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteScope {
    pub kind: ScopeKind,
    pub servers: Vec<SocketAddr>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelLinkState {
    pub ifindex: i32,
    pub ifname: String,
    pub flags: u32,
    pub mtu: u32,
    pub operstate: u8,
    pub has_ipv4_global: bool,
    pub has_ipv4_link_local: bool,
    pub has_ipv6_global: bool,
    pub has_ipv6_link_local: bool,
}

impl KernelLinkState {
    fn has_carrier(&self) -> bool {
        if self.operstate == IF_OPER_UP {
            return true;
        }
        if self.operstate != IF_OPER_UNKNOWN {
            return false;
        }
        self.flags & (IFF_LOWER_UP | IFF_RUNNING) == (IFF_LOWER_UP | IFF_RUNNING)
            && self.flags & IFF_DORMANT == 0
    }

    fn relevant_unicast(&self, servers: &[SocketAddr]) -> bool {
        if self.flags & (IFF_LOOPBACK | IFF_DORMANT) != 0
            || self.flags & (IFF_UP | IFF_LOWER_UP) != (IFF_UP | IFF_LOWER_UP)
            || !self.has_carrier()
        {
            return false;
        }

        let allow_ipv4_link_local = servers.iter().any(|server| match server.ip() {
            IpAddr::V4(address) => ipv4_is_link_local(address),
            IpAddr::V6(_) => false,
        });
        let allow_ipv6_link_local = servers.iter().any(|server| match server.ip() {
            IpAddr::V4(_) => false,
            IpAddr::V6(address) => ipv6_is_link_local(address),
        });

        self.has_ipv4_global
            || self.has_ipv6_global
            || (allow_ipv4_link_local && self.has_ipv4_link_local)
            || (allow_ipv6_link_local && self.has_ipv6_link_local)
    }

    pub(crate) fn relevant_multicast(&self, family: i32) -> bool {
        if self.flags & (IFF_LOOPBACK | IFF_DORMANT) != 0
            || self.flags & (IFF_UP | IFF_LOWER_UP) != (IFF_UP | IFF_LOWER_UP)
            || self.flags & IFF_MULTICAST == 0
            || !self.has_carrier()
        {
            return false;
        }
        match family {
            2 => self.has_ipv4_global || self.has_ipv4_link_local,
            10 => self.has_ipv6_global || self.has_ipv6_link_local,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkState {
    pub ifindex: i32,
    pub dns_servers: Vec<SocketAddr>,
    pub domains: Vec<Domain>,
    pub default_route: Option<bool>,
    pub llmnr: SupportMode,
    pub multicast_dns: SupportMode,
    pub dns_over_tls: TlsMode,
    pub dnssec: ValidationMode,
    pub dnssec_negative_trust_anchors: Vec<String>,
    pub kernel: Option<KernelLinkState>,
}

impl LinkState {
    fn new(ifindex: i32) -> Result<Self, LinkError> {
        validate_ifindex(ifindex)?;
        Ok(Self {
            ifindex,
            dns_servers: Vec::new(),
            domains: Vec::new(),
            default_route: None,
            llmnr: SupportMode::Yes,
            multicast_dns: SupportMode::Yes,
            dns_over_tls: TlsMode::No,
            dnssec: ValidationMode::AllowDowngrade,
            dnssec_negative_trust_anchors: Vec::new(),
            kernel: None,
        })
    }

    pub fn effective_default_route(&self) -> bool {
        if let Some(default_route) = self.default_route {
            return default_route;
        }

        if self.dns_servers.is_empty() || !self.kernel_relevant_unicast() {
            return false;
        }

        !self
            .domains
            .iter()
            .any(|domain| domain.route_only && domain.name != ".")
    }

    pub fn kernel_relevant_unicast(&self) -> bool {
        self.kernel
            .as_ref()
            .map_or(true, |kernel| kernel.relevant_unicast(&self.dns_servers))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingTable {
    links: BTreeMap<i32, LinkState>,
    kernel_synchronized: bool,
}

impl RoutingTable {
    pub fn links(&self) -> Vec<LinkState> {
        self.links.values().cloned().collect()
    }

    pub fn link(&self, ifindex: i32) -> Option<LinkState> {
        self.links.get(&ifindex).cloned()
    }

    pub fn set_dns(&mut self, ifindex: i32, servers: Vec<SocketAddr>) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        let mut normalized = Vec::new();
        for server in servers {
            let server = normalize_server(ifindex, server);
            if !normalized.contains(&server) {
                normalized.push(server);
            }
        }
        if link.dns_servers == normalized {
            return Ok(false);
        }
        link.dns_servers = normalized;
        Ok(true)
    }

    pub fn set_domains(&mut self, ifindex: i32, domains: Vec<Domain>) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        let mut normalized = Vec::new();
        for domain in domains {
            let domain = normalize_domain(&domain)?;
            if !normalized.contains(&domain) {
                normalized.push(domain);
            }
        }
        if link.domains == normalized {
            return Ok(false);
        }
        link.domains = normalized;
        Ok(true)
    }

    pub fn set_default_route(
        &mut self,
        ifindex: i32,
        default_route: Option<bool>,
    ) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        if link.default_route == default_route {
            return Ok(false);
        }
        link.default_route = default_route;
        Ok(true)
    }

    pub fn set_llmnr(&mut self, ifindex: i32, mode: SupportMode) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        if link.llmnr == mode {
            return Ok(false);
        }
        link.llmnr = mode;
        Ok(true)
    }

    pub fn set_multicast_dns(
        &mut self,
        ifindex: i32,
        mode: SupportMode,
    ) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        if link.multicast_dns == mode {
            return Ok(false);
        }
        link.multicast_dns = mode;
        Ok(true)
    }

    pub fn set_dns_over_tls(&mut self, ifindex: i32, mode: TlsMode) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        if link.dns_over_tls == mode {
            return Ok(false);
        }
        link.dns_over_tls = mode;
        Ok(true)
    }

    pub fn set_dnssec(&mut self, ifindex: i32, mode: ValidationMode) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        if link.dnssec == mode {
            return Ok(false);
        }
        link.dnssec = mode;
        Ok(true)
    }

    pub fn set_dnssec_negative_trust_anchors(
        &mut self,
        ifindex: i32,
        anchors: Vec<String>,
    ) -> Result<bool, LinkError> {
        let link = self.link_mut(ifindex)?;
        let mut normalized = Vec::new();
        for anchor in anchors {
            let anchor = normalize_name(&anchor)?;
            if !normalized.contains(&anchor) {
                normalized.push(anchor);
            }
        }
        if link.dnssec_negative_trust_anchors == normalized {
            return Ok(false);
        }
        link.dnssec_negative_trust_anchors = normalized;
        Ok(true)
    }

    pub fn sync_kernel_links(&mut self, links: Vec<KernelLinkState>) -> Result<bool, LinkError> {
        let mut changed = !self.kernel_synchronized;
        let mut seen = BTreeSet::new();
        for kernel in links {
            validate_ifindex(kernel.ifindex)?;
            seen.insert(kernel.ifindex);
            let link = match self.links.entry(kernel.ifindex) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(LinkState::new(kernel.ifindex)?),
            };
            if link.kernel.as_ref() != Some(&kernel) {
                link.kernel = Some(kernel);
                changed = true;
            }
        }

        let before = self.links.len();
        self.links.retain(|ifindex, link| {
            if seen.contains(ifindex) {
                true
            } else {
                link.kernel.is_none() && !self.kernel_synchronized
            }
        });
        changed |= self.links.len() != before;
        self.kernel_synchronized = true;
        Ok(changed)
    }

    pub fn revert(&mut self, ifindex: i32) -> Result<bool, LinkError> {
        validate_ifindex(ifindex)?;
        let link = self
            .links
            .get_mut(&ifindex)
            .ok_or(LinkError::NoSuchLink(ifindex))?;
        let kernel = link.kernel.clone();
        let mut reset = LinkState::new(ifindex)?;
        reset.kernel = kernel;
        if *link == reset {
            return Ok(false);
        }
        *link = reset;
        Ok(true)
    }

    pub fn search_domains(
        &self,
        global_domains: &[Domain],
        ifindex: Option<i32>,
    ) -> Result<Vec<Domain>, LinkError> {
        let mut domains = Vec::new();
        if let Some(ifindex) = ifindex.filter(|ifindex| *ifindex != 0) {
            validate_ifindex(ifindex)?;
            let link = self
                .links
                .get(&ifindex)
                .ok_or(LinkError::NoSuchLink(ifindex))?;
            append_search_domains(&mut domains, &link.domains);
        } else {
            append_search_domains(&mut domains, global_domains);
            for link in self.links.values() {
                append_search_domains(&mut domains, &link.domains);
            }
        }
        Ok(domains)
    }

    pub fn select(
        &self,
        name: &str,
        ifindex: Option<i32>,
        global_servers: &[SocketAddr],
        fallback_servers: &[SocketAddr],
        global_domains: &[Domain],
        delegates: &[crate::dns_delegate::DnsDelegate],
    ) -> Result<Vec<RouteScope>, LinkError> {
        if let Some(ifindex) = ifindex.filter(|ifindex| *ifindex != 0) {
            validate_ifindex(ifindex)?;
            let link = self
                .links
                .get(&ifindex)
                .ok_or(LinkError::NoSuchLink(ifindex))?;
            if link.dns_servers.is_empty() || !link.kernel_relevant_unicast() {
                return Ok(Vec::new());
            }
            return Ok(vec![RouteScope {
                kind: ScopeKind::Link(ifindex),
                servers: link.dns_servers.clone(),
            }]);
        }

        let name = normalize_name(name)?;
        let mut matches = Vec::new();
        if !global_servers.is_empty() {
            if let Some(labels) = best_domain_match(&name, global_domains) {
                matches.push((
                    labels,
                    RouteScope {
                        kind: ScopeKind::Global,
                        servers: global_servers.to_vec(),
                    },
                ));
            }
        }
        for link in self.links.values() {
            if link.dns_servers.is_empty() || !link.kernel_relevant_unicast() {
                continue;
            }
            if let Some(labels) = best_domain_match(&name, &link.domains) {
                matches.push((
                    labels,
                    RouteScope {
                        kind: ScopeKind::Link(link.ifindex),
                        servers: link.dns_servers.clone(),
                    },
                ));
            }
        }
        for (index, delegate) in delegates.iter().enumerate() {
            let servers = delegate
                .servers
                .iter()
                .map(|server| server.address)
                .collect::<Vec<_>>();
            if servers.is_empty() {
                continue;
            }
            if let Some(labels) = best_domain_match(&name, &delegate.domains) {
                matches.push((
                    labels,
                    RouteScope {
                        kind: ScopeKind::Delegate(index),
                        servers,
                    },
                ));
            }
        }

        if let Some(best) = matches.iter().map(|(labels, _)| *labels).max() {
            return Ok(matches
                .into_iter()
                .filter_map(|(labels, scope)| (labels == best).then_some(scope))
                .collect());
        }

        let mut scopes = Vec::new();
        if !global_servers.is_empty() {
            scopes.push(RouteScope {
                kind: ScopeKind::Global,
                servers: global_servers.to_vec(),
            });
        }
        for link in self.links.values() {
            if link.effective_default_route()
                && !link.dns_servers.is_empty()
                && link.kernel_relevant_unicast()
            {
                scopes.push(RouteScope {
                    kind: ScopeKind::Link(link.ifindex),
                    servers: link.dns_servers.clone(),
                });
            }
        }
        for (index, delegate) in delegates.iter().enumerate() {
            if !delegate.effective_default_route() || delegate.servers.is_empty() {
                continue;
            }
            scopes.push(RouteScope {
                kind: ScopeKind::Delegate(index),
                servers: delegate
                    .servers
                    .iter()
                    .map(|server| server.address)
                    .collect(),
            });
        }
        if scopes.is_empty() && !fallback_servers.is_empty() {
            scopes.push(RouteScope {
                kind: ScopeKind::Fallback,
                servers: fallback_servers.to_vec(),
            });
        }
        Ok(scopes)
    }

    fn link_mut(&mut self, ifindex: i32) -> Result<&mut LinkState, LinkError> {
        validate_ifindex(ifindex)?;
        match self.links.entry(ifindex) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(_) if self.kernel_synchronized => Err(LinkError::NoSuchLink(ifindex)),
            Entry::Vacant(entry) => Ok(entry.insert(LinkState::new(ifindex)?)),
        }
    }
}

fn append_search_domains(output: &mut Vec<Domain>, source: &[Domain]) {
    for domain in source {
        if domain.route_only || domain.name == "." || output.contains(domain) {
            continue;
        }
        output.push(domain.clone());
    }
}

fn validate_ifindex(ifindex: i32) -> Result<(), LinkError> {
    if ifindex <= 0 {
        Err(LinkError::InvalidIfindex(ifindex))
    } else {
        Ok(())
    }
}

fn ipv4_is_link_local(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 169 && octets[1] == 254
}

fn ipv6_is_link_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn normalize_server(ifindex: i32, server: SocketAddr) -> SocketAddr {
    let SocketAddr::V6(server) = server else {
        return server;
    };
    if server.scope_id() != 0 || server.ip().segments()[0] & 0xffc0 != 0xfe80 {
        return SocketAddr::V6(server);
    }
    let Ok(scope_id) = u32::try_from(ifindex) else {
        return SocketAddr::V6(server);
    };
    SocketAddr::V6(SocketAddrV6::new(
        *server.ip(),
        server.port(),
        server.flowinfo(),
        scope_id,
    ))
}

fn normalize_domain(domain: &Domain) -> Result<Domain, LinkError> {
    Ok(Domain {
        name: normalize_name(&domain.name)?,
        route_only: domain.route_only,
    })
}

fn normalize_name(name: &str) -> Result<String, LinkError> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name == "~" {
        return Ok(".".to_owned());
    }
    let name = name.strip_prefix('~').unwrap_or(name);
    if name.is_empty()
        || !name.is_ascii()
        || name.len() > 253
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(LinkError::InvalidDomain(name.to_owned()));
    }
    Ok(name.to_ascii_lowercase())
}

fn best_domain_match(name: &str, domains: &[Domain]) -> Option<usize> {
    domains
        .iter()
        .filter_map(|domain| domain_match_labels(name, &domain.name))
        .max()
}

fn domain_match_labels(name: &str, domain: &str) -> Option<usize> {
    if domain == "." {
        return Some(0);
    }
    if name.eq_ignore_ascii_case(domain)
        || name
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
    {
        Some(domain.split('.').count())
    } else {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkError {
    InvalidIfindex(i32),
    InvalidDomain(String),
    NoSuchLink(i32),
    ManagedLink(i32),
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIfindex(ifindex) => write!(formatter, "invalid interface index {ifindex}"),
            Self::InvalidDomain(domain) => write!(formatter, "invalid routing domain {domain}"),
            Self::NoSuchLink(ifindex) => {
                write!(formatter, "no state exists for interface {ifindex}")
            }
            Self::ManagedLink(ifindex) => write!(formatter, "link {ifindex} is managed"),
        }
    }
}

impl Error for LinkError {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServerMetrics {
    pub ewma_rtt_ms: f64,
    pub ewma_fail: f64,
    pub samples: i32,
    pub consecutive_fail: i32,
    pub dnssec_ok: i32,
    pub reachable: i32,
    pub family_pref: i32,
    pub scope_pref: i32,
}

extern "C" {
    pub fn rs_init_table(n: i32, table: *mut ServerMetrics);
    pub fn rs_update_sample(idx0: i32, success: i32, rtt_ms: f64, table: *mut ServerMetrics);
    pub fn rs_score_servers(n: i32, table: *const ServerMetrics, out_scores: *mut f64);
    pub fn rs_pick_best(n: i32, table: *const ServerMetrics) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), 53)
    }

    fn domain(name: &str, route_only: bool) -> Domain {
        Domain {
            name: name.to_owned(),
            route_only,
        }
    }

    fn delegate(
        id: &str,
        address: SocketAddr,
        domains: Vec<Domain>,
        default_route: Option<bool>,
    ) -> crate::dns_delegate::DnsDelegate {
        crate::dns_delegate::DnsDelegate {
            id: id.to_owned(),
            servers: vec![crate::config::DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            }],
            domains,
            default_route,
            firewall_mark: 0,
        }
    }

    fn live_kernel(ifindex: i32) -> KernelLinkState {
        KernelLinkState {
            ifindex,
            ifname: format!("test{ifindex}"),
            flags: IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
            mtu: 1500,
            operstate: IF_OPER_UNKNOWN,
            has_ipv4_global: true,
            has_ipv4_link_local: false,
            has_ipv6_global: false,
            has_ipv6_link_local: false,
        }
    }

    #[test]
    fn longest_suffix_selects_the_vpn_link() {
        let mut table = RoutingTable::default();
        table.set_dns(2, vec![server(2)]).expect("link DNS");
        table
            .set_domains(2, vec![domain("corp.example", true)])
            .expect("link domain");
        table.set_dns(3, vec![server(3)]).expect("link DNS");
        table
            .set_domains(3, vec![domain("example", true)])
            .expect("link domain");

        assert_eq!(
            table
                .select(
                    "host.corp.example",
                    None,
                    &[server(1)],
                    &[server(9)],
                    &[],
                    &[]
                )
                .expect("route"),
            vec![RouteScope {
                kind: ScopeKind::Link(2),
                servers: vec![server(2)],
            }]
        );
    }

    #[test]
    fn equal_best_matches_are_returned_together() {
        let mut table = RoutingTable::default();
        for ifindex in [2, 3] {
            table
                .set_dns(
                    ifindex,
                    vec![server(u8::try_from(ifindex).expect("small index"))],
                )
                .expect("link DNS");
            table
                .set_domains(ifindex, vec![domain("corp.example", true)])
                .expect("link domain");
        }
        assert_eq!(
            table
                .select("host.corp.example", None, &[], &[], &[], &[])
                .expect("route")
                .len(),
            2
        );
    }

    #[test]
    fn route_only_domain_disables_implicit_default_route() {
        let mut table = RoutingTable::default();
        table.set_dns(2, vec![server(2)]).expect("link DNS");
        table
            .set_domains(2, vec![domain("corp.example", true)])
            .expect("link domain");
        table.set_dns(3, vec![server(3)]).expect("link DNS");

        assert_eq!(
            table
                .select("public.example", None, &[], &[server(9)], &[], &[])
                .expect("route"),
            vec![RouteScope {
                kind: ScopeKind::Link(3),
                servers: vec![server(3)],
            }]
        );
    }

    #[test]
    fn root_route_domain_beats_default_route_scopes() {
        let mut table = RoutingTable::default();
        table.set_dns(2, vec![server(2)]).expect("link DNS");
        table
            .set_domains(2, vec![domain(".", true)])
            .expect("link domain");
        table.set_dns(3, vec![server(3)]).expect("link DNS");

        assert_eq!(
            table
                .select("public.example", None, &[server(1)], &[server(9)], &[], &[])
                .expect("route"),
            vec![RouteScope {
                kind: ScopeKind::Link(2),
                servers: vec![server(2)],
            }]
        );
    }

    #[test]
    fn explicit_interface_restricts_the_route() {
        let mut table = RoutingTable::default();
        table.set_dns(7, vec![server(7)]).expect("link DNS");
        assert_eq!(
            table
                .select("example", Some(7), &[server(1)], &[server(9)], &[], &[])
                .expect("route"),
            vec![RouteScope {
                kind: ScopeKind::Link(7),
                servers: vec![server(7)],
            }]
        );
        assert_eq!(
            table.select("example", Some(8), &[], &[], &[], &[]),
            Err(LinkError::NoSuchLink(8))
        );
    }

    #[test]
    fn link_local_ipv6_server_receives_the_interface_scope() {
        let mut table = RoutingTable::default();
        let address = SocketAddr::new(
            IpAddr::V6("fe80::53".parse::<Ipv6Addr>().expect("IPv6 address")),
            53,
        );
        table.set_dns(7, vec![address]).expect("link DNS");
        let link = table.link(7).expect("link");
        let SocketAddr::V6(address) = link.dns_servers[0] else {
            panic!("expected IPv6 server");
        };
        assert_eq!(address.scope_id(), 7);
    }

    #[test]
    fn kernel_down_link_is_not_selected() {
        let mut table = RoutingTable::default();
        table
            .sync_kernel_links(vec![KernelLinkState {
                flags: 0,
                ..live_kernel(2)
            }])
            .expect("kernel sync");
        table.set_dns(2, vec![server(2)]).expect("link DNS");
        assert!(table
            .select("example", Some(2), &[], &[], &[], &[])
            .expect("route")
            .is_empty());
    }

    #[test]
    fn unknown_operstate_requires_lower_up_and_running_carrier_flags() {
        let kernel = live_kernel(2);
        assert!(kernel.has_carrier());
        let mut up_without_running = kernel.clone();
        up_without_running.flags &= !IFF_RUNNING;
        assert!(!up_without_running.has_carrier());
        let mut up_without_lower_up = kernel.clone();
        up_without_lower_up.flags &= !IFF_LOWER_UP;
        assert!(!up_without_lower_up.has_carrier());
        let mut down = kernel.clone();
        down.flags &= !(IFF_UP | IFF_RUNNING | IFF_LOWER_UP);
        assert!(!down.has_carrier());
    }

    #[test]
    fn unknown_dummy_without_running_is_not_relevant_for_unicast_dns() {
        let kernel = KernelLinkState {
            flags: 0x1_0083,
            operstate: IF_OPER_UNKNOWN,
            ..live_kernel(6)
        };
        assert!(!kernel.relevant_unicast(&[server(6)]));
    }

    #[test]
    fn link_local_address_requires_link_local_dns_for_unicast() {
        let mut kernel = live_kernel(2);
        kernel.has_ipv4_global = false;
        kernel.has_ipv4_link_local = true;
        assert!(!kernel.relevant_unicast(&[server(2)]));
        let link_local_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 53)), 53);
        assert!(kernel.relevant_unicast(&[link_local_dns]));
    }

    #[test]
    fn revert_preserves_kernel_link_identity() {
        let mut table = RoutingTable::default();
        table
            .sync_kernel_links(vec![live_kernel(2)])
            .expect("kernel sync");
        table.set_dns(2, vec![server(2)]).expect("link DNS");
        table
            .set_domains(2, vec![domain("corp.example", true)])
            .expect("link domain");
        assert!(table.revert(2).expect("revert"));
        let link = table.link(2).expect("kernel link survives revert");
        assert!(link.dns_servers.is_empty());
        assert!(link.domains.is_empty());
        assert_eq!(
            link.kernel.as_ref().map(|kernel| kernel.ifname.as_str()),
            Some("test2")
        );
    }

    #[test]
    fn kernel_sync_removes_vanished_links_and_rejects_unknown_setters() {
        let mut table = RoutingTable::default();
        table
            .sync_kernel_links(vec![live_kernel(2), live_kernel(3)])
            .expect("initial kernel sync");
        table.set_dns(2, vec![server(2)]).expect("known link DNS");
        assert_eq!(
            table.set_dns(9, vec![server(9)]),
            Err(LinkError::NoSuchLink(9))
        );
        table
            .sync_kernel_links(vec![live_kernel(2)])
            .expect("updated kernel sync");
        assert!(table.link(2).is_some());
        assert!(table.link(3).is_none());
    }

    #[test]
    fn delegate_longest_suffix_participates_in_split_dns() {
        let table = RoutingTable::default();
        let delegates = [delegate(
            "corp",
            server(53),
            vec![domain("corp.example", true)],
            None,
        )];
        assert_eq!(
            table
                .select(
                    "host.corp.example",
                    None,
                    &[server(1)],
                    &[server(9)],
                    &[],
                    &delegates,
                )
                .expect("delegate route"),
            vec![RouteScope {
                kind: ScopeKind::Delegate(0),
                servers: vec![server(53)],
            }]
        );
    }

    #[test]
    fn delegates_are_default_routes_only_when_explicitly_enabled() {
        let table = RoutingTable::default();
        let delegates = [
            delegate("disabled", server(53), Vec::new(), None),
            delegate("enabled", server(54), Vec::new(), Some(true)),
        ];
        assert_eq!(
            table
                .select("public.example", None, &[], &[], &[], &delegates)
                .expect("delegate default route"),
            vec![RouteScope {
                kind: ScopeKind::Delegate(1),
                servers: vec![server(54)],
            }]
        );
    }
}
