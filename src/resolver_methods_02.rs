impl Resolver {
    fn hosts_mut(&self) -> RwLockWriteGuard<'_, Hosts> {
        self.hosts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn transaction_id(&self) -> u16 {
        rand::random::<u16>() ^ self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn query(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, ResolveError> {
        self.query_on_link(query, mode, None)
    }

    pub fn query_on_link(
        &self,
        query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
    ) -> Result<Vec<u8>, ResolveError> {
        self.query_on_link_with_flags(query, mode, ifindex, 0)
            .map(|(response, _)| response)
    }

    fn query_on_link_with_flags(
        &self,
        query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, u64), ResolveError> {
        self.query_on_link_with_metadata(query, mode, ifindex, request_flags)
            .map(|(response, flags, _)| (response, flags))
    }

    fn query_on_link_with_metadata(
        &self,
        query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, u64, Option<i32>), ResolveError> {
        self.query_on_link_with_metadata_dual(query, query, mode, ifindex, request_flags)
    }

    fn query_on_link_with_metadata_dual(
        &self,
        query: &[u8],
        unicast_query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, u64, Option<i32>), ResolveError> {
        self.query_on_link_with_metadata_dual_hook_policy(
            query,
            unicast_query,
            mode,
            ifindex,
            request_flags,
            true,
        )
    }

    fn query_on_link_with_metadata_dual_hook_policy(
        &self,
        query: &[u8],
        unicast_query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
        request_flags: u64,
        allow_hook: bool,
    ) -> Result<(Vec<u8>, u64, Option<i32>), ResolveError> {
        validate(query, false)?;
        validate(unicast_query, false)?;
        let mut result = self.query_on_link_inner(
            query,
            unicast_query,
            mode,
            ifindex,
            request_flags,
            allow_hook,
        );
        if mode == QueryMode::Proxy
            && request_flags
                & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SYNTHESIZE
                == 0
            && Self::proxy_result_allows_synthesis(&result)
        {
            let question = first_question(query)?;
            let config = self.config();
            if !config.refuse_record_types.contains(&question.rr_type) {
                let response = if let Some(records) = self.hosts().lookup(&question) {
                    Some(local_response(query, &records, 0)?)
                } else if dns_name_dont_resolve(question.name.text()) {
                    Some(wire::authoritative_nxdomain_for(query)?)
                } else {
                    None
                };
                if let Some(response) = response {
                    self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                    result = Ok((
                        response,
                        synthetic_response_flags(request_flags, query),
                        ifindex.filter(|value| *value > 0),
                    ));
                }
            }
        }
        if let Ok((response, _, _)) = &mut result {
            wire::apply_query_validation_flags(query, response)?;
        }
        self.publish_query_event(query, ifindex, &result);
        result
    }

    fn proxy_result_allows_synthesis(
        result: &Result<(Vec<u8>, u64, Option<i32>), ResolveError>,
    ) -> bool {
        match result {
            Ok((response, _, _)) => response_full_rcode(response)
                .map(|(rcode, _, _)| rcode != 0)
                .unwrap_or(false),
            Err(ResolveError::NoNameServers) => true,
            Err(error) => error.is_timeout(),
        }
    }

    fn query_on_link_inner(
        &self,
        query: &[u8],
        unicast_query: &[u8],
        mode: QueryMode,
        ifindex: Option<i32>,
        request_flags: u64,
        allow_hook: bool,
    ) -> Result<(Vec<u8>, u64, Option<i32>), ResolveError> {
        include!("resolver_query_on_link.rs")
    }

    pub fn query_or_servfail(&self, query: &[u8], mode: QueryMode) -> Result<Vec<u8>, WireError> {
        let header = Header::parse(query)?;
        let question = first_question(query)?;
        if crate::wire::record_type_is_obsolete(question.rr_type)
            || matches!(question.rr_type, TYPE_IXFR | TYPE_AXFR)
            || !header.recursion_desired()
        {
            return wire::refused_for(query);
        }
        if crate::edns::inspect_opt(query)?.is_some_and(|opt| opt.version != 0) {
            return crate::edns::bad_version_response(query);
        }
        match self.query(query, mode) {
            Ok(response) => Ok(response),
            Err(error) => {
                if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
                    eprintln!("rustd-resolved: DNS query failed: {error}");
                }
                servfail_for(query)
            }
        }
    }
}
