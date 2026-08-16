impl Resolver {
    pub fn lookup_address(&self, address: IpAddr) -> Result<AddressLookup, ResolveError> {
        self.lookup_address_on_link(address, None)
    }

    pub fn lookup_address_on_link(
        &self,
        address: IpAddr,
        ifindex: Option<i32>,
    ) -> Result<AddressLookup, ResolveError> {
        self.lookup_address_on_link_with_request_flags(address, ifindex, 0)
    }

    pub fn lookup_address_on_link_with_request_flags(
        &self,
        address: IpAddr,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<AddressLookup, ResolveError> {
        let (response, _, flags, response_ifindex) =
            self.query_following_redirects(
                &reverse_name(address),
                wire::CLASS_IN,
                TYPE_PTR,
                ifindex,
                request_flags,
            )?;
        let names = extract_ptr_names(&response)?;
        if names.is_empty() {
            Err(ResolveError::NoSuchResourceRecord)
        } else {
            let name_ifindices = vec![response_ifindex; names.len()];
            Ok(AddressLookup {
                names,
                name_ifindices,
                flags,
            })
        }
    }

    pub fn resolve_record(&self, name: &str, rr_type: u16) -> Result<Vec<u8>, ResolveError> {
        self.resolve_record_with_class(name, wire::CLASS_IN, rr_type)
    }

    pub fn resolve_record_with_class(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
    ) -> Result<Vec<u8>, ResolveError> {
        self.resolve_record_on_link(name, class, rr_type, None)
    }

    pub fn resolve_record_on_link(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
    ) -> Result<Vec<u8>, ResolveError> {
        self.resolve_record_on_link_with_flags(name, class, rr_type, ifindex)
            .map(|(response, _)| response)
    }

    pub fn resolve_record_on_link_with_flags(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
    ) -> Result<(Vec<u8>, u64), ResolveError> {
        self.resolve_record_on_link_with_request_flags(name, class, rr_type, ifindex, 0)
    }

    pub fn resolve_record_on_link_with_request_flags(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, u64), ResolveError> {
        self.resolve_record_on_link_with_request_flags_and_metadata(
            name,
            class,
            rr_type,
            ifindex,
            request_flags,
        )
        .map(|(response, flags, _)| (response, flags))
    }

    pub fn resolve_record_on_link_with_request_flags_and_metadata(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, u64, Option<i32>), ResolveError> {
        self.resolve_record_on_link_with_request_flags_and_canonical(
            name,
            class,
            rr_type,
            ifindex,
            request_flags,
        )
        .map(|(response, _, flags, response_ifindex)| {
            (response, flags, response_ifindex)
        })
    }

    pub fn resolve_record_on_link_with_request_flags_and_canonical(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects(name, class, rr_type, ifindex, request_flags)
    }

    pub(crate) fn resolve_record_on_link_with_request_flags_and_canonical_dual(
        &self,
        name: &str,
        unicast_name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects_dual(
            name,
            unicast_name,
            class,
            rr_type,
            ifindex,
            request_flags,
        )
    }

    pub(crate) fn resolve_record_on_link_with_request_flags_and_canonical_dual_after_grouped_hook(
        &self,
        name: &str,
        unicast_name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects_dual_after_grouped_hook(
            name,
            unicast_name,
            class,
            rr_type,
            ifindex,
            request_flags,
        )
    }

    pub fn reload_hosts(&self) -> io::Result<()> {
        let config = self.config();
        let hosts = if config.read_etc_hosts {
            Hosts::load(&config.hosts_path)?
        } else {
            Hosts::default()
        };
        *self.hosts_mut() = hosts;
        crate::static_records::invalidate_system();
        Ok(())
    }

    pub fn flush_cache(&self) {
        self.cache.flush();
        self.dnskey_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        crate::mdns::runtime::flush_cache();
        crate::llmnr::runtime::flush_cache();
    }

    pub fn reset_server_features(&self) {
        for state in self.states().values_mut() {
            state.metric = ServerMetric::default();
            state.cooldown_until = None;
            state.features.reset();
            state.transport.reset();
            state.missing_root_rrsig = false;
            state.packet_do_off = false;
            state.packet_invalid = false;
        }
    }

    pub fn reset_statistics(&self) {
        self.counters.transactions.store(0, Ordering::Relaxed);
        self.counters.timeouts.store(0, Ordering::Relaxed);
        self.counters
            .timeouts_served_stale
            .store(0, Ordering::Relaxed);
        self.counters
            .failures_served_stale
            .store(0, Ordering::Relaxed);
        self.counters.cache_hits.store(0, Ordering::Relaxed);
        self.counters.cache_misses.store(0, Ordering::Relaxed);
        self.counters.failures.store(0, Ordering::Relaxed);
        self.counters.local_answers.store(0, Ordering::Relaxed);
        self.counters.dnssec_secure.store(0, Ordering::Relaxed);
        self.counters.dnssec_insecure.store(0, Ordering::Relaxed);
        self.counters.dnssec_bogus.store(0, Ordering::Relaxed);
        self.counters
            .dnssec_indeterminate
            .store(0, Ordering::Relaxed);
        crate::mdns::runtime::reset_cache_statistics();
        crate::llmnr::runtime::reset_cache_statistics();
    }

    pub fn stats(&self) -> ResolverStats {
        let (mdns_entries, mdns_hits, mdns_misses) =
            crate::mdns::runtime::cache_statistics();
        let (llmnr_entries, llmnr_hits, llmnr_misses) =
            crate::llmnr::runtime::cache_statistics();
        ResolverStats {
            current_transactions: self
                .counters
                .current_transactions
                .load(Ordering::Relaxed),
            transactions: self.counters.transactions.load(Ordering::Relaxed),
            timeouts: self.counters.timeouts.load(Ordering::Relaxed),
            timeouts_served_stale: self
                .counters
                .timeouts_served_stale
                .load(Ordering::Relaxed),
            failures_served_stale: self
                .counters
                .failures_served_stale
                .load(Ordering::Relaxed),
            cache_hits: self
                .counters
                .cache_hits
                .load(Ordering::Relaxed)
                .saturating_add(mdns_hits)
                .saturating_add(llmnr_hits),
            cache_misses: self
                .counters
                .cache_misses
                .load(Ordering::Relaxed)
                .saturating_add(mdns_misses)
                .saturating_add(llmnr_misses),
            failures: self.counters.failures.load(Ordering::Relaxed),
            local_answers: self.counters.local_answers.load(Ordering::Relaxed),
            dnssec_secure: self.counters.dnssec_secure.load(Ordering::Relaxed),
            dnssec_insecure: self.counters.dnssec_insecure.load(Ordering::Relaxed),
            dnssec_bogus: self.counters.dnssec_bogus.load(Ordering::Relaxed),
            dnssec_indeterminate: self
                .counters
                .dnssec_indeterminate
                .load(Ordering::Relaxed),
            cache_entries: self
                .cache
                .len()
                .saturating_add(mdns_entries)
                .saturating_add(llmnr_entries),
        }
    }
}

#[derive(Debug)]
struct ServerStateDescriptor {
    key: ServerKey,
    spec: DnsServerSpec,
    server_type: &'static str,
    interface: Option<String>,
    interface_index: Option<i32>,
    dnssec_mode: ValidationMode,
    dns_over_tls_mode: TlsMode,
}

impl Resolver {
    pub fn cache_snapshot(&self) -> Vec<crate::cache::CacheSnapshot> {
        self.cache.snapshot()
    }

    pub fn server_state_snapshot(&self) -> Vec<ResolverServerState> {
        let config = self.config();
        let mut descriptors = Vec::new();
        extend_server_state_descriptors(
            &mut descriptors,
            ScopeKind::Global,
            config.configured_upstream_specs(),
            "system",
            None,
            config.dnssec,
            config.dns_over_tls,
        );
        extend_server_state_descriptors(
            &mut descriptors,
            ScopeKind::Fallback,
            config.configured_fallback_upstream_specs(),
            "fallback",
            None,
            config.dnssec,
            config.dns_over_tls,
        );
        for link in self.links() {
            let interface = link
                .kernel
                .as_ref()
                .map(|kernel| kernel.ifname.clone());
            extend_server_state_descriptors(
                &mut descriptors,
                ScopeKind::Link(link.ifindex),
                self.link_dns_specs(link.ifindex),
                "link",
                Some((interface, link.ifindex)),
                link.dnssec,
                link.dns_over_tls,
            );
        }

        let states = self.states();
        descriptors
            .into_iter()
            .map(|descriptor| {
                let default_state = ServerState::default();
                let state = states.get(&descriptor.key).unwrap_or(&default_state);
                let failed_tcp_attempts = state.transport.failures(TransportMode::Tcp);
                let dnssec_supported =
                    server_dnssec_supported(descriptor.dnssec_mode, state);

                let best_feature_level = match (
                    descriptor.dns_over_tls_mode != TlsMode::No,
                    descriptor.dnssec_mode != ValidationMode::No,
                ) {
                    (true, true) => FeatureLevel::TlsDnssecOk,
                    (true, false) => FeatureLevel::TlsPlain,
                    (false, true) => FeatureLevel::DnssecOk,
                    (false, false) => FeatureLevel::Edns0,
                };
                let possible_feature_level = state
                    .features
                    .current_possible_level()
                    .min(best_feature_level);
                let verified_feature_level = if state.features.has_verified_level() {
                    resolver_feature_level_name(
                        state.features.verified_level(),
                        state.transport.mode(),
                    )
                } else {
                    "n/a"
                };

                ResolverServerState {
                    server: format_server_spec(&descriptor.spec),
                    server_type: descriptor.server_type.to_owned(),
                    interface: descriptor.interface,
                    interface_index: descriptor.interface_index,
                    verified_feature_level: verified_feature_level.to_owned(),
                    possible_feature_level: resolver_feature_level_name(
                        possible_feature_level,
                        state.transport.mode(),
                    )
                    .to_owned(),
                    dnssec_mode: resolver_validation_mode_name(descriptor.dnssec_mode).to_owned(),
                    dnssec_supported,
                    received_udp_fragment_max: state.transport.received_udp_fragment_max(),
                    failed_udp_attempts: state.transport.failures(TransportMode::Udp),
                    failed_tcp_attempts,
                    packet_truncated: state.transport.packet_truncated(),
                    packet_bad_opt: state.features.bad_opt(),
                    packet_rrsig_missing: state.missing_root_rrsig,
                    packet_invalid: state.packet_invalid,
                    packet_do_off: state.packet_do_off,
                }
            })
            .collect()
    }

    pub fn link_dnssec_supported(&self, ifindex: i32) -> bool {
        let Some(link) = self.link(ifindex) else {
            return false;
        };
        if link.dnssec == ValidationMode::No {
            return false;
        }

        let specs = self.link_dns_specs(ifindex);
        self.first_server_dnssec_supported(
            ScopeKind::Link(ifindex),
            &specs,
            link.dnssec,
        )
    }

    pub fn manager_dnssec_supported(&self) -> bool {
        let config = self.config();
        if config.dnssec == ValidationMode::No {
            return false;
        }

        let global = config.configured_upstream_specs();
        let global_supported = if global.is_empty() {
            self.first_server_dnssec_supported(
                ScopeKind::Fallback,
                &config.configured_fallback_upstream_specs(),
                config.dnssec,
            )
        } else {
            self.first_server_dnssec_supported(
                ScopeKind::Global,
                &global,
                config.dnssec,
            )
        };
        global_supported
            && self
                .links()
                .iter()
                .all(|link| self.link_dnssec_supported(link.ifindex))
    }

    fn first_server_dnssec_supported(
        &self,
        scope: ScopeKind,
        specs: &[DnsServerSpec],
        mode: ValidationMode,
    ) -> bool {
        let Some(key) = server_keys_for_specs(scope, specs).into_iter().next() else {
            return true;
        };
        let states = self.states();
        let default_state = ServerState::default();
        server_dnssec_supported(mode, states.get(&key).unwrap_or(&default_state))
    }
}

fn server_dnssec_supported(mode: ValidationMode, state: &ServerState) -> bool {
    mode == ValidationMode::Yes
        || (!state.features.bad_opt()
            && !state.missing_root_rrsig
            && !state.packet_do_off
            && state.transport.failures(TransportMode::Tcp) < TRANSPORT_RETRY_ATTEMPTS)
}

fn extend_server_state_descriptors(
    output: &mut Vec<ServerStateDescriptor>,
    scope: ScopeKind,
    specs: Vec<DnsServerSpec>,
    server_type: &'static str,
    link: Option<(Option<String>, i32)>,
    dnssec_mode: ValidationMode,
    dns_over_tls_mode: TlsMode,
) {
    let keys = server_keys_for_specs(scope, &specs);
    output.extend(keys.into_iter().zip(specs).map(|(key, spec)| {
        let (interface, interface_index) = link
            .as_ref()
            .map_or((None, None), |(interface, ifindex)| {
                (
                    interface.clone().or_else(|| spec.interface.clone()),
                    Some(*ifindex),
                )
            });
        ServerStateDescriptor {
            key,
            spec,
            server_type,
            interface,
            interface_index,
            dnssec_mode,
            dns_over_tls_mode,
        }
    }));
}

fn format_server_spec(spec: &DnsServerSpec) -> String {
    let address = spec.address;
    let mut output = if address.port() == 53 {
        address.ip().to_string()
    } else if address.is_ipv6() {
        format!("[{}]:{}", address.ip(), address.port())
    } else {
        format!("{}:{}", address.ip(), address.port())
    };
    if let Some(interface) = &spec.interface {
        output.push('%');
        output.push_str(interface);
    }
    if let Some(server_name) = &spec.server_name {
        output.push('#');
        output.push_str(server_name);
    }
    output
}

const fn resolver_feature_level_name(
    level: FeatureLevel,
    transport: TransportMode,
) -> &'static str {
    match level {
        FeatureLevel::TlsDnssecOk => "TLS+EDNS0+DO",
        FeatureLevel::TlsPlain => "TLS+EDNS0",
        FeatureLevel::DnssecOk => "UDP+EDNS0+DO",
        FeatureLevel::Edns0 => "UDP+EDNS0",
        FeatureLevel::Udp if matches!(transport, TransportMode::Tcp) => "TCP",
        FeatureLevel::Udp => "UDP",
    }
}

const fn resolver_validation_mode_name(mode: ValidationMode) -> &'static str {
    match mode {
        ValidationMode::No => "no",
        ValidationMode::AllowDowngrade => "allow-downgrade",
        ValidationMode::Yes => "yes",
    }
}

#[cfg(test)]
mod dnssec_capability_tests {
    use super::*;

    #[test]
    fn server_capability_tracks_learned_dnssec_failures() {
        let mut state = ServerState::default();
        assert!(server_dnssec_supported(
            ValidationMode::AllowDowngrade,
            &state
        ));
        assert!(server_dnssec_supported(ValidationMode::No, &state));

        state.missing_root_rrsig = true;
        assert!(!server_dnssec_supported(
            ValidationMode::AllowDowngrade,
            &state
        ));
        assert!(server_dnssec_supported(ValidationMode::Yes, &state));
    }

    #[test]
    fn manager_capability_tracks_its_current_fallback_server() {
        let mut config = Config::default();
        config
            .fallback_upstreams
            .push("192.0.2.53:53".parse().expect("fallback server"));
        let resolver = Resolver::new(config);
        assert!(resolver.manager_dnssec_supported());

        let address = resolver.config().fallback_upstreams[0];
        resolver
            .states()
            .entry(ServerKey::new(ScopeKind::Fallback, address))
            .or_default()
            .missing_root_rrsig = true;
        assert!(!resolver.manager_dnssec_supported());
    }

    #[test]
    fn disabled_manager_dnssec_is_never_reported_supported() {
        let resolver = Resolver::new(Config {
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        assert!(!resolver.manager_dnssec_supported());
    }
}
