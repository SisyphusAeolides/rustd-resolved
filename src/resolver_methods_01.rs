impl Resolver {
    pub fn new(config: Config) -> Self {
        let llmnr_mode = config.llmnr;
        let multicast_dns_mode = config.multicast_dns;
        let global_servers = config.configured_upstreams();
        let fallback_servers = config.configured_fallback_upstreams();
        let mut states = HashMap::new();
        for server in &global_servers {
            states
                .entry(ServerKey::new(ScopeKind::Global, *server))
                .or_default();
        }
        for server in &fallback_servers {
            states
                .entry(ServerKey::new(ScopeKind::Fallback, *server))
                .or_default();
        }
        let hosts = if config.read_etc_hosts {
            Hosts::load(&config.hosts_path).unwrap_or_default()
        } else {
            Hosts::default()
        };
        Self {
            cache: Cache::new(
                config.cache_size,
                config.cache_max_ttl,
                config.stale_retention,
                config.cache_negative,
            ),
            config: RwLock::new(config),
            states: Mutex::new(states),
            udp_sockets: Mutex::new(HashMap::new()),
            tcp_streams: Mutex::new(HashMap::new()),
            tls_streams: Mutex::new(HashMap::new()),
            routing: RwLock::new(RoutingTable::default()),
            networkd_links: RwLock::new(HashMap::new()),
            link_server_specs: RwLock::new(HashMap::new()),
            link_dns_over_tls_overrides: RwLock::new(HashMap::new()),
            link_dnssec_overrides: RwLock::new(HashMap::new()),
            routing_generation: AtomicU64::new(1),
            inflight: Inflight::default(),
            hosts: RwLock::new(hosts),
            next_id: AtomicU16::new(1),
            counters: Counters::default(),
            query_monitor: QueryMonitor::default(),
            dnskey_cache: Mutex::new(HashMap::new()),
            llmnr_client: RwLock::new(None),
            llmnr_mode: RwLock::new(llmnr_mode),
            multicast_dns_mode: RwLock::new(multicast_dns_mode),
        }
    }

    pub fn config(&self) -> Config {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn global_llmnr_mode(&self) -> SupportMode {
        *self
            .llmnr_mode
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn global_multicast_dns_mode(&self) -> SupportMode {
        *self
            .multicast_dns_mode
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn reload_config(&self, config: Config) -> bool {
        self.dnskey_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let previous = self.config();
        let stale_retention_changed = previous.stale_retention != config.stale_retention;
        let changed = previous.configured_upstream_specs() != config.configured_upstream_specs()
            || previous.configured_fallback_upstream_specs()
                != config.configured_fallback_upstream_specs()
            || previous.domains != config.domains
            || previous.dns_delegates != config.dns_delegates
            || previous.refuse_record_types != config.refuse_record_types
            || previous.cache != config.cache
            || previous.cache_from_localhost != config.cache_from_localhost
            || previous.resolve_unicast_single_label != config.resolve_unicast_single_label
            || previous.read_etc_hosts != config.read_etc_hosts
            || previous.read_static_records != config.read_static_records
            || previous.query_timeout != config.query_timeout
            || previous.attempts != config.attempts
            || previous.dnssec != config.dnssec
            || previous.dns_over_tls != config.dns_over_tls;
        let protocol_changed = self.reload_protocol_modes(&config);
        if stale_retention_changed {
            self.cache.set_stale_retention(config.stale_retention);
        }
        *self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
        self.reapply_link_security_policies();
        self.reset_runtime_after_reload();
        changed || protocol_changed || stale_retention_changed
    }

    fn reset_runtime_after_reload(&self) {
        self.udp_sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.tcp_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.tls_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.states()
            .retain(|server, _| matches!(server.scope_kind(), ScopeKind::Link(_)));
        self.flush_cache();
        self.routing_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn reload_protocol_modes(&self, config: &Config) -> bool {
        let mut changed = false;
        {
            let mut mode = self
                .llmnr_mode
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *mode != config.llmnr {
                *mode = config.llmnr;
                changed = true;
            }
        }
        {
            let mut mode = self
                .multicast_dns_mode
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *mode != config.multicast_dns {
                *mode = config.multicast_dns;
                changed = true;
            }
        }
        if changed {
            self.routing_generation.fetch_add(1, Ordering::AcqRel);
            self.cache.flush();
        }
        changed
    }

    fn states(&self) -> MutexGuard<'_, HashMap<ServerKey, ServerState>> {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing(&self) -> RwLockReadGuard<'_, RoutingTable> {
        self.routing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn routing_mut(&self) -> RwLockWriteGuard<'_, RoutingTable> {
        self.routing
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn networkd_links(&self) -> RwLockReadGuard<'_, HashMap<i32, NetworkdLinkState>> {
        self.networkd_links
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn networkd_links_mut(&self) -> RwLockWriteGuard<'_, HashMap<i32, NetworkdLinkState>> {
        self.networkd_links
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reapply_link_security_policies(&self) -> bool {
        let config = self.config();
        let networkd = self.networkd_links().clone();
        let dns_over_tls_overrides = self
            .link_dns_over_tls_overrides
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let dnssec_overrides = self
            .link_dnssec_overrides
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut routing = self.routing_mut();
        let mut changed = false;

        for link in routing.links() {
            let managed = networkd
                .get(&link.ifindex)
                .filter(|state| state.managed);
            let dns_over_tls = managed.map_or_else(
                || {
                    dns_over_tls_overrides
                        .get(&link.ifindex)
                        .copied()
                        .unwrap_or(config.dns_over_tls)
                },
                |state| state.dns_over_tls.unwrap_or(config.dns_over_tls),
            );
            let dnssec = managed.map_or_else(
                || {
                    dnssec_overrides
                        .get(&link.ifindex)
                        .copied()
                        .unwrap_or(config.dnssec)
                },
                |state| state.dnssec.unwrap_or(config.dnssec),
            );
            changed |= routing
                .set_dns_over_tls(link.ifindex, dns_over_tls)
                .expect("routing snapshot contains its link");
            changed |= routing
                .set_dnssec(link.ifindex, dnssec)
                .expect("routing snapshot contains its link");
        }

        changed
    }

    pub fn links(&self) -> Vec<LinkState> {
        self.routing().links()
    }

    pub fn link(&self, ifindex: i32) -> Option<LinkState> {
        self.routing().link(ifindex)
    }

    pub fn link_is_managed(&self, ifindex: i32) -> bool {
        self.networkd_links()
            .get(&ifindex)
            .is_some_and(|link| link.managed)
    }

    pub(crate) fn networkd_link_relevant(&self, ifindex: i32) -> bool {
        self.networkd_links()
            .get(&ifindex)
            .map_or(true, NetworkdLinkState::resolver_relevant)
    }

    fn ensure_link_writable(&self, ifindex: i32) -> Result<(), LinkError> {
        if self.link_is_managed(ifindex) {
            Err(LinkError::ManagedLink(ifindex))
        } else {
            Ok(())
        }
    }

    pub fn sync_kernel_links(
        &self,
        links: Vec<crate::routing::KernelLinkState>,
    ) -> Result<(), LinkError> {
        let route_changed = self.routing_mut().sync_kernel_links(links)?;
        let live_ifindices = self
            .routing()
            .links()
            .into_iter()
            .map(|link| link.ifindex)
            .collect::<HashSet<_>>();
        let identity_changed = {
            let mut specs = self.link_server_specs_mut();
            let before = specs.len();
            specs.retain(|ifindex, _| live_ifindices.contains(ifindex));
            specs.len() != before
        };
        let override_changed = {
            let mut dns_over_tls = self
                .link_dns_over_tls_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut dnssec = self
                .link_dnssec_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = dns_over_tls.len() + dnssec.len();
            dns_over_tls.retain(|ifindex, _| live_ifindices.contains(ifindex));
            dnssec.retain(|ifindex, _| live_ifindices.contains(ifindex));
            before != dns_over_tls.len() + dnssec.len()
        };
        let policy_changed = self.reapply_link_security_policies();
        self.finish_routing_change(
            route_changed || identity_changed || override_changed || policy_changed,
        );
        let networkd_links = self.networkd_links().values().cloned().collect();
        self.sync_networkd_links(networkd_links)
    }

    pub fn sync_networkd_links(&self, links: Vec<NetworkdLinkState>) -> Result<(), LinkError> {
        let incoming = links
            .into_iter()
            .map(|link| (link.ifindex, link))
            .collect::<HashMap<_, _>>();
        let managed_ifindices = incoming
            .values()
            .filter(|link| link.managed)
            .map(|link| link.ifindex)
            .collect::<HashSet<_>>();
        let mut networkd = self.networkd_links_mut();
        let mut routing = self.routing_mut();
        let mut changed = false;
        let mut removed_identities = Vec::new();
        let mut managed_identities = Vec::new();

        for (&ifindex, previous) in networkd.iter() {
            let still_managed = incoming.get(&ifindex).is_some_and(|link| link.managed);
            if previous.managed && !still_managed {
                removed_identities.push(ifindex);
                if routing.link(ifindex).is_some() {
                    changed |= routing.revert(ifindex)?;
                }
            }
        }

        for link in incoming.values().filter(|link| link.managed) {
            if routing.link(link.ifindex).is_none() {
                removed_identities.push(link.ifindex);
                continue;
            }
            changed |= routing.set_dns(link.ifindex, link.dns_servers.clone())?;
            changed |= routing.set_domains(link.ifindex, link.domains.clone())?;
            changed |= routing.set_default_route(link.ifindex, link.default_route)?;
            changed |= routing.set_llmnr(link.ifindex, link.llmnr)?;
            changed |= routing.set_multicast_dns(link.ifindex, link.multicast_dns)?;
            let config = self.config();
            changed |= routing.set_dns_over_tls(
                link.ifindex,
                link.dns_over_tls.unwrap_or(config.dns_over_tls),
            )?;
            changed |= routing.set_dnssec(
                link.ifindex,
                link.dnssec.unwrap_or(config.dnssec),
            )?;
            changed |= routing.set_dnssec_negative_trust_anchors(
                link.ifindex,
                link.dnssec_negative_trust_anchors.clone(),
            )?;
            if let Some(state) = routing.link(link.ifindex) {
                managed_identities.push((
                    link.ifindex,
                    state.dns_servers,
                    link.dns_server_specs.clone(),
                ));
            }
        }

        *networkd = incoming;
        drop(routing);
        drop(networkd);

        let override_changed = {
            let mut dns_over_tls = self
                .link_dns_over_tls_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut dnssec = self
                .link_dnssec_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = dns_over_tls.len() + dnssec.len();
            dns_over_tls.retain(|ifindex, _| !managed_ifindices.contains(ifindex));
            dnssec.retain(|ifindex, _| !managed_ifindices.contains(ifindex));
            before != dns_over_tls.len() + dnssec.len()
        };

        let mut identity_changed = false;
        for ifindex in removed_identities {
            identity_changed |= self.remove_link_server_specs(ifindex);
        }
        for (ifindex, servers, specs) in managed_identities {
            let specs = if specs.is_empty() {
                servers
                    .into_iter()
                    .map(|address| DnsServerSpec {
                        address,
                        interface: None,
                        server_name: None,
                    })
                    .collect()
            } else {
                normalize_link_specs(&servers, specs)
            };
            identity_changed |= self.replace_link_server_specs(ifindex, specs);
        }
        let policy_changed = self.reapply_link_security_policies();
        self.finish_routing_change(
            changed || identity_changed || override_changed || policy_changed,
        );
        Ok(())
    }

    pub fn set_link_dns(&self, ifindex: i32, servers: Vec<SocketAddr>) -> Result<(), LinkError> {
        let specs = servers
            .into_iter()
            .map(|address| DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            })
            .collect();
        self.set_link_dns_specs(ifindex, specs)
    }

    pub fn set_link_domains(&self, ifindex: i32, domains: Vec<Domain>) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_domains(ifindex, domains)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_default_route(
        &self,
        ifindex: i32,
        default_route: Option<bool>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self
            .routing_mut()
            .set_default_route(ifindex, default_route)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_llmnr(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_llmnr(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_multicast_dns(&self, ifindex: i32, mode: SupportMode) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self.routing_mut().set_multicast_dns(ifindex, mode)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn set_link_dns_over_tls(&self, ifindex: i32, mode: TlsMode) -> Result<(), LinkError> {
        self.set_link_dns_over_tls_override(ifindex, Some(mode))
    }

    pub fn set_link_dns_over_tls_override(
        &self,
        ifindex: i32,
        mode: Option<TlsMode>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let effective = mode.unwrap_or_else(|| self.config().dns_over_tls);
        let route_changed = self
            .routing_mut()
            .set_dns_over_tls(ifindex, effective)?;
        let override_changed = {
            let mut overrides = self
                .link_dns_over_tls_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = overrides.get(&ifindex).copied();
            match mode {
                Some(mode) => {
                    overrides.insert(ifindex, mode);
                }
                None => {
                    overrides.remove(&ifindex);
                }
            }
            previous != mode
        };
        self.finish_routing_change(route_changed || override_changed);
        Ok(())
    }

    pub fn set_link_dnssec(&self, ifindex: i32, mode: ValidationMode) -> Result<(), LinkError> {
        self.set_link_dnssec_override(ifindex, Some(mode))
    }

    pub fn set_link_dnssec_override(
        &self,
        ifindex: i32,
        mode: Option<ValidationMode>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let effective = mode.unwrap_or_else(|| self.config().dnssec);
        let route_changed = self.routing_mut().set_dnssec(ifindex, effective)?;
        let override_changed = {
            let mut overrides = self
                .link_dnssec_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = overrides.get(&ifindex).copied();
            match mode {
                Some(mode) => {
                    overrides.insert(ifindex, mode);
                }
                None => {
                    overrides.remove(&ifindex);
                }
            }
            previous != mode
        };
        self.finish_routing_change(route_changed || override_changed);
        Ok(())
    }

    pub fn set_link_dnssec_negative_trust_anchors(
        &self,
        ifindex: i32,
        anchors: Vec<String>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let changed = self
            .routing_mut()
            .set_dnssec_negative_trust_anchors(ifindex, anchors)?;
        self.finish_routing_change(changed);
        Ok(())
    }

    pub fn revert_link(&self, ifindex: i32) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let config = self.config();
        let route_changed = {
            let mut routing = self.routing_mut();
            let mut changed = routing.revert(ifindex)?;
            changed |= routing.set_dns_over_tls(ifindex, config.dns_over_tls)?;
            changed |= routing.set_dnssec(ifindex, config.dnssec)?;
            changed
        };
        let override_changed = self
            .link_dns_over_tls_overrides
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ifindex)
            .is_some()
            | self
                .link_dnssec_overrides
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&ifindex)
                .is_some();
        let identity_changed = self.remove_link_server_specs(ifindex);
        self.finish_routing_change(route_changed || identity_changed || override_changed);
        Ok(())
    }

    fn finish_routing_change(&self, changed: bool) {
        if changed {
            self.routing_generation.fetch_add(1, Ordering::AcqRel);
            self.cache.flush();
        }
    }

    fn search_domains(&self, ifindex: Option<i32>) -> Result<Vec<Domain>, ResolveError> {
        let config = self.config();
        let mut domains = self
            .routing()
            .search_domains(&config.domains, ifindex)?;
        if ifindex.is_none() || ifindex == Some(0) {
            for delegate in &config.dns_delegates {
                for domain in &delegate.domains {
                    if !domain.route_only && domain.name != "." && !domains.contains(domain) {
                        domains.push(domain.clone());
                    }
                }
            }
        }
        Ok(domains)
    }

    fn hosts(&self) -> RwLockReadGuard<'_, Hosts> {
        self.hosts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
