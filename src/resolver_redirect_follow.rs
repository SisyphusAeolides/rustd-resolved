impl Resolver {
    fn query_following_redirects(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects_dual(name, name, class, rr_type, ifindex, request_flags)
    }

    fn query_following_redirects_dual(
        &self,
        name: &str,
        unicast_name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects_dual_hook_policy(
            name,
            unicast_name,
            class,
            rr_type,
            ifindex,
            request_flags,
            true,
        )
    }

    fn query_following_redirects_dual_after_grouped_hook(
        &self,
        name: &str,
        unicast_name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        self.query_following_redirects_dual_hook_policy(
            name,
            unicast_name,
            class,
            rr_type,
            ifindex,
            request_flags,
            false,
        )
    }

    fn query_following_redirects_dual_hook_policy(
        &self,
        name: &str,
        unicast_name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
        request_flags: u64,
        mut allow_hook: bool,
    ) -> Result<(Vec<u8>, String, u64, Option<i32>), ResolveError> {
        if self.config().refuse_record_types.contains(&rr_type) {
            return Err(ResolveError::QueryRefused);
        }
        let mut current = name.to_owned();
        let mut current_unicast = unicast_name.to_owned();
        let original_name = name.to_owned();
        let mut visited = HashSet::new();
        let mut redirects = 0usize;
        let mut flags = None;
        let mut response_ifindex = None;

        loop {
            let query = make_query_with_class(&current, rr_type, class, self.transaction_id())?;
            let unicast_query =
                make_query_with_class(&current_unicast, rr_type, class, Header::parse(&query)?.id)?;
            let question = first_question(&query)?;
            let unicast_question = first_question(&unicast_query)?;
            if !visited.insert((
                question.name.canonical_wire().to_vec(),
                unicast_question.name.canonical_wire().to_vec(),
            )) {
                return Err(ResolveError::Wire(WireError::CnameLoop));
            }

            let (response, response_flags, answer_ifindex) = self
                .query_on_link_with_metadata_dual_hook_policy(
                    &query,
                    &unicast_query,
                    QueryMode::Full,
                    ifindex,
                    request_flags,
                    allow_hook,
                )?;
            allow_hook = true;
            response_ifindex = answer_ifindex.or(response_ifindex);
            flags = Some(merge_redirect_response_flags(flags, response_flags));
            let (rcode, extended_dns_error_code, extended_dns_error_message) =
                response_full_rcode(&response)?;
            if rcode != 0 {
                return Err(ResolveError::DnsError {
                    rcode,
                    query: original_name.clone(),
                    extended_dns_error_code,
                    extended_dns_error_message,
                });
            }
            let classified = wire::classify_redirect_answer(&response)?;
            match classified {
                wire::RedirectAnswer::Direct {
                    canonical_name,
                    redirects: packet_redirects,
                } => {
                    if packet_redirects > 0
                        && request_flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CNAME
                            != 0
                    {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    redirects = redirects
                        .checked_add(packet_redirects)
                        .ok_or(ResolveError::Wire(WireError::CnameLoop))?;
                    if redirects > wire::CNAME_REDIRECTS_MAX {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    return Ok((
                        response,
                        canonical_name,
                        flags.unwrap_or(response_flags),
                        response_ifindex,
                    ));
                }
                wire::RedirectAnswer::Redirect {
                    canonical_name,
                    redirects: packet_redirects,
                } => {
                    if request_flags & crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CNAME != 0 {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    if packet_redirects == 0 {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    redirects = redirects
                        .checked_add(packet_redirects)
                        .ok_or(ResolveError::Wire(WireError::CnameLoop))?;
                    if redirects > wire::CNAME_REDIRECTS_MAX {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    current = canonical_name;
                    current_unicast = current.clone();
                }
                wire::RedirectAnswer::NoData => {
                    return Ok((
                        response,
                        current,
                        flags.unwrap_or(response_flags),
                        response_ifindex,
                    ));
                }
            }
        }
    }
}
