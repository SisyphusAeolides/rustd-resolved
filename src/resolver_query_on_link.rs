{
        crate::query_cancel::check()?;
        validate(query, false)?;
        let _header = Header::parse(query)?;
        let question = first_question(query)?;
        if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
            eprintln!(
                "rustd-resolved: query name={:?} type={} mode={mode:?} ifindex={ifindex:?} flags={request_flags:#x} mdns={} llmnr={}",
                question.name.text(),
                question.rr_type,
                crate::mdns::runtime::should_handle_query(query),
                crate::llmnr::runtime::should_handle_query(query, &self.llmnr_hostname()),
            );
        }
        let config = self.config();
        let query_generation = self.routing_generation.load(Ordering::Acquire);
        let requested_ifindex = ifindex.filter(|value| *value > 0);
        if let Some(ifindex) = ifindex.filter(|value| *value < 0) {
            return Err(LinkError::InvalidIfindex(ifindex).into());
        }
        if config.refuse_record_types.contains(&question.rr_type) {
            let response = wire::refused_for(query)?;
            return Ok((response, dns_response_flags(), requested_ifindex));
        }
        self.counters.transactions.fetch_add(1, Ordering::Relaxed);
        self.counters
            .current_transactions
            .fetch_add(1, Ordering::Relaxed);
        let _active_transaction = ActiveTransaction {
            counter: &self.counters.current_transactions,
        };

        let synthesize = request_flags
            & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_SYNTHESIZE
            == 0;
        if synthesize {
            if let Some(response) =
                crate::static_records::answer(config.read_static_records, query)?
            {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    response,
                    synthetic_response_flags(request_flags, query),
                    requested_ifindex,
                ));
            }
            let hosts = self.hosts();
            let records = if mode == QueryMode::Full {
                hosts.lookup(&question)
            } else {
                hosts.lookup_file(&question)
            };
            if let Some(records) = records {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    local_response(query, &records, 0)?,
                    synthetic_response_flags(request_flags, query),
                    requested_ifindex,
                ));
            }
            if mode == QueryMode::Full && dns_name_dont_resolve(question.name.text()) {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    wire::authoritative_nxdomain_for(query)?,
                    synthetic_response_flags(request_flags, query),
                    requested_ifindex,
                ));
            }
        }
        if mode == QueryMode::Full {
            if allow_hook {
                let hook_response =
                    crate::hook::resolve(query, unicast_query, Duration::from_secs(30));
                crate::query_cancel::check()?;
                if let Some(response) = hook_response {
                    if self.routing_generation.load(Ordering::Acquire) != query_generation {
                        return Err(ResolveError::QueryAborted);
                    }
                    return Ok((
                        response,
                        hook_response_flags(request_flags, query),
                        requested_ifindex,
                    ));
                }
            }
            if crate::mdns::runtime::should_handle_query(query) {
                if !request_protocol_enabled(request_flags, mdns_protocol_mask()) {
                    return Err(ResolveError::NoSuchResourceRecord);
                }
                if !self.multicast_dns_resolve_enabled(ifindex) {
                    return Err(ResolveError::NoSuchResourceRecord);
                }
                let cache_enabled = config.cache && config.multicast_dns_cache_size > 0;
                let response = crate::mdns::runtime::query_raw(
                    query,
                    ifindex,
                    config.query_timeout,
                    cache_enabled
                        && request_flags
                            & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CACHE
                            == 0,
                    cache_enabled,
                    config.multicast_dns_cache_size,
                    request_flags
                        & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_NETWORK
                        == 0,
                );
                crate::query_cancel::check()?;
                let response =
                    response.map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
                if self.routing_generation.load(Ordering::Acquire) != query_generation {
                    return Err(ResolveError::QueryAborted);
                }
                return response
                    .map(|(response, from_cache)| {
                        (
                            response,
                            mdns_response_flags(query, from_cache),
                            requested_ifindex,
                        )
                    })
                    .ok_or(ResolveError::NoSuchResourceRecord);
            }
            if crate::llmnr::runtime::should_handle_query(query, &self.llmnr_hostname()) {
                if !request_protocol_enabled(request_flags, llmnr_protocol_mask()) {
                    if !config.resolve_unicast_single_label
                        && request_flags
                            & crate::resolve_flags::flags::RUSTD_RESOLVE_RELAX_SINGLE_LABEL
                            == 0
                    {
                        return Err(ResolveError::NoSuchResourceRecord);
                    }
                } else if !self.llmnr_resolve_enabled(ifindex) {
                    return Err(ResolveError::NoSuchResourceRecord);
                } else {
                    let response = self.llmnr_query_raw(
                    query,
                    ifindex,
                    request_flags
                        & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CACHE
                        != 0,
                    request_flags
                        & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_NETWORK
                        == 0,
                    );
                    crate::query_cancel::check()?;
                    if let Some((response, from_cache)) = response? {
                    if self.routing_generation.load(Ordering::Acquire) != query_generation {
                        return Err(ResolveError::QueryAborted);
                    }
                    return Ok((
                        response,
                        llmnr_response_flags(query, from_cache),
                        requested_ifindex,
                    ));
                    }
                }
                if !config.resolve_unicast_single_label
                    && request_flags
                        & crate::resolve_flags::flags::RUSTD_RESOLVE_RELAX_SINGLE_LABEL
                        == 0
                {
                    return Err(ResolveError::NoSuchResourceRecord);
    }
}

        }

        let query = unicast_query;
        let header = Header::parse(query)?;
        let question = first_question(query)?;
        if self.routing_generation.load(Ordering::Acquire) != query_generation {
            return Err(ResolveError::QueryAborted);
        }
        let route = route_cache_id(query_generation, ifindex);
        let key = CacheKey {
            name: question.name.canonical_wire().to_vec(),
            rr_type: question.rr_type,
            class: question.class,
            checking_disabled: header.checking_disabled(),
            route,
        };
        let cache_enabled = config.cache;
        let read_cache = cache_enabled
            && request_flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CACHE == 0;
        if read_cache {
            if let Some((response, source_ifindex)) = self.cache.get_scoped(&key, header.id, false) {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    response.clone(),
                    cache_response_flags(&response),
                    source_ifindex,
                ));
            }
            self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        let allow_stale = read_cache
            && request_flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_STALE == 0;
        let stale_response = allow_stale
            .then(|| self.cache.get_scoped(&key, header.id, true))
            .flatten();

        if request_flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_NETWORK != 0
            || !request_protocol_enabled(
                request_flags,
                crate::resolve_flags::flags::RUSTD_RESOLVE_DNS,
            )
        {
            return Err(ResolveError::NoNameServers);
        }

        let global_servers = config.configured_upstreams();
        let fallback_servers = config.configured_fallback_upstreams();
        let scopes = self
            .routing()
            .select(
                question.name.text(),
                ifindex,
                &global_servers,
                &fallback_servers,
                &config.domains,
                &config.dns_delegates,
            )?
            .into_iter()
            .filter(|scope| match scope.kind {
                ScopeKind::Link(ifindex) => self.networkd_link_relevant(ifindex),
                ScopeKind::Global | ScopeKind::Delegate(_) | ScopeKind::Fallback => true,
            })
            .collect::<Vec<_>>();
        if scopes.is_empty() {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::NoNameServers);
        }

        let inflight_key = InflightKey::new(route, query)?;
        loop {
            match self.inflight.begin(inflight_key.clone()) {
                InflightRole::Leader(transaction_leader) => {
                    let attempts = if stale_response.is_some() {
                        1
                    } else {
                        config.attempts
                    };
                    let scope_result = self.query_scopes_with_attempts(&scopes, query, request_flags, attempts);
                    let scope_result = if self.routing_generation.load(Ordering::Acquire)
                        != query_generation
                    {
                        Err(ResolveError::QueryAborted)
                    } else {
                        scope_result
                    };
                    let result = match scope_result {
                        Ok((response, server, scope)) => {
                            let source_ifindex = match scope {
                                ScopeKind::Link(ifindex) => Some(ifindex),
                                ScopeKind::Global
                                | ScopeKind::Delegate(_)
                                | ScopeKind::Fallback => None,
                            };
                            if cache_enabled
                                && (config.cache_from_localhost || !server.ip().is_loopback())
                            {
                                let _ = self.cache.insert_scoped(
                                    key.clone(),
                                    &response,
                                    source_ifindex,
                                    scope.into(),
                                );
                            }
                            Ok((response, source_ifindex))
                        }
                        Err(error @ ResolveError::QueryAborted) => Err(error),
                        Err(error) => {
                            let timed_out = error.is_timeout();
                            if read_cache {
                                let response = stale_response
                                    .clone()
                                    .or_else(|| self.cache.get_scoped(&key, header.id, allow_stale));
                                if let Some((response, source_ifindex)) = response {
                                    self.counters
                                        .cache_hits
                                        .fetch_add(1, Ordering::Relaxed);
                                    if timed_out {
                                        self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                                        self.counters
                                            .timeouts_served_stale
                                            .fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        self.counters
                                            .failures_served_stale
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    transaction_leader.complete(normalize_shared_response(
                                        &response,
                                        source_ifindex,
                                    ));
                                    return Ok((
                                        response.clone(),
                                        cache_response_flags(&response),
                                        source_ifindex,
                                    ));
                                }
                            }
                            if timed_out {
                                self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                            }
                            self.counters.failures.fetch_add(1, Ordering::Relaxed);
                            Err(error)
                        }
                    };
                    transaction_leader.complete(
                        result
                            .as_ref()
                            .ok()
                            .and_then(|(response, source_ifindex)| {
                                normalize_shared_response(response, *source_ifindex)
                            }),
                    );
                    return result.map(|(response, source_ifindex)| {
                        let flags = dns_network_response_flags(&response);
                        (response, flags, source_ifindex)
                    });
                }
                InflightRole::Follower(entry) => {
                    if let Some(mut response) = entry.wait()? {
                        wire::rewrite_id(&mut response.packet, header.id)?;
                        let flags = dns_network_response_flags(&response.packet);
                        return Ok((response.packet, flags, response.ifindex));
                    }
                }
            }
        }
    }
