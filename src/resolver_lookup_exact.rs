impl Resolver {
    fn lookup_name_exact(
        &self,
        name: &str,
        types: &[u16],
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<NameLookup, ResolveError> {
        let unicast_name = crate::idna_name::to_ascii(name).unwrap_or_else(|_| name.to_owned());
        let hook_types = types
            .iter()
            .copied()
            .filter(|rr_type| !self.config().refuse_record_types.contains(rr_type))
            .collect::<Vec<_>>();
        let (grouped_hook_checked, grouped_hook_response) = self
            .grouped_hook_record_response_dual(
                name,
                &unicast_name,
                &hook_types,
                ifindex,
                request_flags,
            )?;
        if let Some((response, response_flags, response_ifindex)) = grouped_hook_response {
            return self.lookup_name_from_grouped_hook(
                name,
                &hook_types,
                response,
                response_flags,
                response_ifindex,
            );
        }
        let outcomes = if types.len() > 1 {
            let cancellation = crate::query_cancel::current();
            thread::scope(|thread_scope| {
                let (sender, receiver) = mpsc::channel();
                for (index, &rr_type) in types.iter().enumerate() {
                    let sender = sender.clone();
                    let unicast_name = &unicast_name;
                    let cancellation = cancellation.clone();
                    thread_scope.spawn(move || {
                        let result = crate::query_cancel::with_optional(cancellation, || {
                            if grouped_hook_checked {
                                self.query_following_redirects_dual_after_grouped_hook(
                                    name,
                                    &unicast_name,
                                    wire::CLASS_IN,
                                    rr_type,
                                    ifindex,
                                    request_flags,
                                )
                            } else {
                                self.query_following_redirects_dual(
                                    name,
                                    &unicast_name,
                                    wire::CLASS_IN,
                                    rr_type,
                                    ifindex,
                                    request_flags,
                                )
                            }
                        });
                        let _ = sender.send((index, rr_type, result));
                    });
                }
                drop(sender);

                let mut outcomes: Vec<_> = receiver.into_iter().collect();
                outcomes.sort_by_key(|(index, _, _)| *index);
                outcomes
                    .into_iter()
                    .map(|(_, rr_type, result)| (rr_type, result))
                    .collect::<Vec<_>>()
            })
        } else {
            types
                .iter()
                .copied()
                .map(|rr_type| {
                    (
                        rr_type,
                        self.query_following_redirects_dual(
                            name,
                            &unicast_name,
                            wire::CLASS_IN,
                            rr_type,
                            ifindex,
                            request_flags,
                        ),
                    )
                })
                .collect()
        };

        let mut addresses = Vec::new();
        let mut address_ifindices = Vec::new();
        let mut canonical_name = None;
        let mut last_error = None;
        let mut flags = None;
        for (rr_type, result) in outcomes {
            match result {
                Ok((response, followed_name, response_flags, response_ifindex)) => {
                    flags = Some(merge_parallel_response_flags(flags, response_flags));
                    let response_family = match rr_type {
                        TYPE_A => Some(2),
                        TYPE_AAAA => Some(10),
                        _ => None,
                    };
                    let records = extract_address_records(&response, response_family)?;
                    if !records.addresses.is_empty() && canonical_name.is_none() {
                        canonical_name = Some(if records.canonical_name.is_empty() {
                            followed_name
                        } else {
                            records.canonical_name
                        });
                    }
                    for address in records.addresses {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                            address_ifindices.push(response_ifindex);
                        }
                    }
                }
                Err(error) => {
                    last_error = Some(error)
                }
            }
        }
        if addresses.is_empty() {
            return Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord));
        }
        Ok(NameLookup {
            addresses,
            address_ifindices,
            canonical_name: canonical_name.unwrap_or_else(|| name.trim_end_matches('.').to_owned()),
            flags: flags.unwrap_or(0),
        })
    }

    fn name_has_pre_hook_source(
        &self,
        name: &str,
        types: &[u16],
        request_flags: u64,
    ) -> Result<bool, ResolveError> {
        if request_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SYNTHESIZE != 0 {
            return Ok(false);
        }
        let config = self.config();
        let queries = types
            .iter()
            .map(|rr_type| make_query_with_class(name, *rr_type, wire::CLASS_IN, 0))
            .collect::<Result<Vec<_>, _>>()?;
        for query in &queries {
            if crate::static_records::answer(config.read_static_records, query)?.is_some() {
                return Ok(true);
            }
        }
        let hosts = self.hosts();
        for query in &queries {
            if hosts.lookup(&first_question(query)?).is_some() {
                return Ok(true);
            }
        }
        Ok(dns_name_dont_resolve(name))
    }

    pub(crate) fn grouped_hook_record_response_dual(
        &self,
        name: &str,
        unicast_name: &str,
        types: &[u16],
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(bool, Option<(Vec<u8>, u64, Option<i32>)>), ResolveError> {
        if types.len() < 2 || self.name_has_pre_hook_source(name, types, request_flags)? {
            return Ok((false, None));
        }
        let id = self.transaction_id();
        let utf8_queries = types
            .iter()
            .map(|rr_type| make_query_with_class(name, *rr_type, wire::CLASS_IN, id))
            .collect::<Result<Vec<_>, _>>()?;
        let idna_queries = types
            .iter()
            .map(|rr_type| make_query_with_class(unicast_name, *rr_type, wire::CLASS_IN, id))
            .collect::<Result<Vec<_>, _>>()?;
        let utf8_refs = utf8_queries
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let idna_refs = idna_queries
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let response = crate::hook::resolve_grouped(
            &utf8_queries[0],
            &idna_refs,
            &utf8_refs,
            Duration::from_secs(30),
        );
        crate::query_cancel::check()?;
        let Some(mut response) = response else {
            return Ok((true, None));
        };
        wire::apply_query_validation_flags(&utf8_queries[0], &mut response)?;
        Ok((
            true,
            Some((
                response,
                hook_response_flags(request_flags, &utf8_queries[0]),
                ifindex.filter(|value| *value > 0),
            )),
        ))
    }

    fn lookup_name_from_grouped_hook(
        &self,
        name: &str,
        types: &[u16],
        response: Vec<u8>,
        response_flags: u64,
        response_ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        let (rcode, extended_dns_error_code, extended_dns_error_message) =
            response_full_rcode(&response)?;
        if rcode != 0 {
            return Err(ResolveError::DnsError {
                rcode,
                query: name.to_owned(),
                extended_dns_error_code,
                extended_dns_error_message,
            });
        }

        let mut addresses = Vec::new();
        let mut canonical_name = None;
        for rr_type in types {
            let family = match *rr_type {
                TYPE_A => Some(2),
                TYPE_AAAA => Some(10),
                _ => None,
            };
            let records = extract_address_records(&response, family)?;
            if !records.addresses.is_empty() && canonical_name.is_none() {
                canonical_name = Some(if records.canonical_name.is_empty() {
                    name.trim_end_matches('.').to_owned()
                } else {
                    records.canonical_name
                });
            }
            for address in records.addresses {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        if addresses.is_empty() {
            return Err(ResolveError::NoSuchResourceRecord);
        }
        let address_ifindices = vec![response_ifindex; addresses.len()];
        Ok(NameLookup {
            addresses,
            address_ifindices,
            canonical_name: canonical_name.unwrap_or_else(|| name.trim_end_matches('.').to_owned()),
            flags: response_flags,
        })
    }
}
