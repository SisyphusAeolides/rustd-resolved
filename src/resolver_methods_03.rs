const RCODE_REFUSED: u16 = 5;

impl Resolver {
    #[cfg(test)]
    fn query_scopes(
        &self,
        scopes: &[RouteScope],
        query: &[u8],
        request_flags: u64,
    ) -> Result<(Vec<u8>, SocketAddr), ResolveError> {
        self.query_scopes_with_attempts(scopes, query, request_flags, self.config().attempts)
            .map(|(response, server, _)| (response, server))
    }

    fn query_scopes_with_attempts(
        &self,
        scopes: &[RouteScope],
        query: &[u8],
        request_flags: u64,
        attempts: usize,
    ) -> Result<(Vec<u8>, SocketAddr, ScopeKind), ResolveError> {
        if scopes.len() == 1 {
            return self
                .query_servers(scopes[0].kind, &scopes[0].servers, query, request_flags, attempts)
                .map(|(response, server)| (response, server, scopes[0].kind));
        }

        let cancellation = crate::query_cancel::current();
        thread::scope(|thread_scope| {
            let (sender, receiver) = mpsc::channel();
            for route_scope in scopes {
                let sender = sender.clone();
                let cancellation = cancellation.clone();
                thread_scope.spawn(move || {
                    let result = crate::query_cancel::with_optional(cancellation, || {
                        self.query_servers(
                            route_scope.kind,
                            &route_scope.servers,
                            query,
                            request_flags,
                            attempts,
                        )
                        .map(|(response, server)| (response, server, route_scope.kind))
                    });
                    let _ = sender.send(result);
                });
            }
            drop(sender);

            let mut first_success = None;
            let mut last_response = None;
            let mut last_error = None;
            for result in receiver {
                match result {
                    Ok((response, server, scope)) if response_is_success(&response) => {
                        if first_success.is_none() {
                            first_success = Some((response, server, scope));
                        }
                    }
                    Ok(response) => last_response = Some(response),
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(response) = first_success.or(last_response) {
                Ok(response)
            } else {
                Err(last_error.unwrap_or(ResolveError::NoNameServers))
            }
        })
    }

    fn query_servers(
        &self,
        scope: ScopeKind,
        servers: &[SocketAddr],
        query: &[u8],
        request_flags: u64,
        attempts: usize,
    ) -> Result<(Vec<u8>, SocketAddr), ResolveError> {
        let server_specs = self.server_specs_for_scope(scope, servers);
        if server_specs.is_empty() {
            return Err(ResolveError::NoNameServers);
        }
        let all_server_keys = server_keys_for_specs(scope, &server_specs);
        let server_keys = all_server_keys
            .iter()
            .copied()
            .filter(|server| !self.server_points_to_stub(server.server()))
            .collect::<Vec<_>>();
        if server_keys.is_empty() {
            return Err(ResolveError::StubLoop);
        }
        let mut budget = DnsAttemptBudget::new();
        let mut attempted = HashSet::new();
        let mut last_response = None;
        let mut last_error = None;
        for _ in 0..attempts {
            crate::query_cancel::check()?;
            if budget.exhausted() || budget.expired() {
                break;
            }
            if attempted.len() == server_keys.len() {
                attempted.clear();
            }
            let Some(server_key) = self.select_server(&server_keys, &attempted) else {
                break;
            };
            let server = server_key.server();
            attempted.insert(server_key);
            let started = Instant::now();
            match self.exchange_with_features(server_key, query, &mut budget) {
                Ok(mut response) => {
                    if let Err(error) = self
                        .authenticate_dns_response(server_key, query, &mut response, request_flags, &mut budget)
                        .map(|verdict| self.record_dnssec_verdict(verdict))
                    {
                        self.record_dnssec_error(&error);
                        if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
                            let name = first_question(query)
                                .map(|question| question.name.text().to_owned())
                                .unwrap_or_else(|_| "<invalid>".to_owned());
                            eprintln!(
                                "rustd-resolved: DNS server {server} validation failed for {name}: {error}"
                            );
                            eprintln!(
                                "rustd-resolved: rejected DNS response for {name}: {}",
                                dns_packet_hex(&response)
                            );
                        }
                        return Err(error);
                    }
                    self.record_success(server_key, started.elapsed());
                    if response_full_rcode(&response).map_or(false, |(rcode, _, _)| {
                        (rcode & 0x000f) == RCODE_REFUSED
                    }) {
                        last_response = Some((response, server));
                        if attempted.len() == server_keys.len() {
                            break;
                        }
                        continue;
                    }
                    return Ok((response, server));
                }
                Err(error) => {
                    let terminal_extended_error = matches!(
                        &error,
                        ResolveError::DnssecValidationFailed { .. }
                            | ResolveError::DnsError {
                                extended_dns_error_code: Some(_),
                                ..
                            }
                    );
                    if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
                        eprintln!(
                            "rustd-resolved: DNS server {server} transaction failed: {error}"
                        );
                    }
                    self.record_failure(server_key, started.elapsed());
                    if terminal_extended_error {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if budget.exhausted() || budget.expired() {
                        break;
                    }
                }
            }
        }
        if let Some(response) = last_response {
            Ok(response)
        } else if budget.expired() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out").into())
        } else if budget.exhausted() {
            Err(ResolveError::MaxAttemptsReached)
        } else {
            Err(last_error.unwrap_or(ResolveError::NoNameServers))
        }
    }

    fn server_points_to_stub(&self, server: SocketAddr) -> bool {
        let config = self.config();
        let primary_stub = config.dns_stub_listener != crate::config::DnsStubListenerMode::No
            && (config.listeners.contains(&server) || config.proxy_listeners.contains(&server));
        primary_stub
            || config
                .dns_stub_listener_extra
                .iter()
                .any(|listener| listener.address() == server)
    }

    fn server_specs_for_scope(
        &self,
        scope: ScopeKind,
        servers: &[SocketAddr],
    ) -> Vec<DnsServerSpec> {
        let config = self.config();
        let configured = match scope {
            ScopeKind::Global => config.configured_upstream_specs(),
            ScopeKind::Fallback => config.configured_fallback_upstream_specs(),
            ScopeKind::Delegate(index) => config
                .dns_delegates
                .get(index)
                .map_or_else(Vec::new, |delegate| delegate.servers.clone()),
            ScopeKind::Link(ifindex) => self.link_dns_specs(ifindex),
        };
        let mut output = Vec::new();
        for &address in servers {
            let before = output.len();
            for spec in configured.iter().filter(|spec| spec.address == address) {
                if !output.contains(spec) {
                    output.push(spec.clone());
                }
            }
            if output.len() == before {
                output.push(DnsServerSpec {
                    address,
                    interface: None,
                    server_name: None,
                });
            }
        }
        output
    }

    fn select_server(
        &self,
        servers: &[ServerKey],
        attempted: &HashSet<ServerKey>,
    ) -> Option<ServerKey> {
        let now = Instant::now();
        let mut states = self.states();
        let metrics: Vec<_> = servers
            .iter()
            .map(|server| {
                let state = states.entry(*server).or_default();
                let mut metric = state.metric;
                metric.cooldown_ms = state
                    .cooldown_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map_or(0, duration_milliseconds);
                if attempted.contains(server) {
                    metric.cooldown_ms = i32::MAX;
                    metric.failures = i32::MAX / 1000;
                }
                metric
            })
            .collect();
        choose_server(&metrics).map(|index| servers[index])
    }

    fn record_success(&self, server: ServerKey, duration: Duration) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.metric.round_trip_ms = update_rtt(
            state.metric.round_trip_ms,
            duration.as_secs_f64() * 1000.0,
            true,
        );
        state.metric.failures = 0;
        state.cooldown_until = None;
    }

    fn record_failure(&self, server: ServerKey, duration: Duration) {
        let mut states = self.states();
        let state = states.entry(server).or_default();
        state.metric.round_trip_ms = update_rtt(
            state.metric.round_trip_ms,
            duration.as_secs_f64() * 1000.0,
            false,
        );
        state.metric.failures = state.metric.failures.saturating_add(1);
        let exponent = u32::try_from(state.metric.failures.clamp(0, 8)).unwrap_or(8);
        let delay = 250u64.saturating_mul(1u64 << exponent).min(60_000);
        state.cooldown_until = Instant::now().checked_add(Duration::from_millis(delay));
    }
}

fn server_keys_for_specs(
    scope: ScopeKind,
    specs: &[DnsServerSpec],
) -> Vec<ServerKey> {
    let mut slots = HashMap::<SocketAddr, usize>::new();
    specs
        .iter()
        .map(|spec| {
            let slot = slots.entry(spec.address).or_insert(0);
            let key = ServerKey::with_slot(scope, spec.address, *slot);
            *slot += 1;
            key
        })
        .collect()
}
