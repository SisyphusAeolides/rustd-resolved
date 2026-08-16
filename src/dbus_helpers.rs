// SPDX-License-Identifier: LGPL-2.1-or-later
fn manager_dns_entry(ifindex: i32, server: SocketAddr) -> (i32, i32, Vec<u8>) {
    let (family, address) = address_bytes(server.ip());
    (ifindex, family, address)
}

fn manager_dns_ex(
    servers: &[DnsServerSpec],
    ifindex: i32,
) -> Vec<(i32, i32, Vec<u8>, u16, String)> {
    servers
        .iter()
        .map(|server| manager_dns_ex_entry(ifindex, server))
        .collect()
}

fn manager_dns_ex_entry(
    ifindex: i32,
    server: &DnsServerSpec,
) -> (i32, i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.address.ip());
    let ifindex = server
        .interface
        .as_deref()
        .and_then(|interface| crate::interface::resolve_ifindex(interface).ok())
        .unwrap_or(ifindex);
    (
        ifindex,
        family,
        address,
        dns_ex_output_port(server.address.port()),
        server.server_name.clone().unwrap_or_default(),
    )
}

fn link_dns_entry(server: SocketAddr) -> (i32, Vec<u8>) {
    address_bytes(server.ip())
}

fn link_dns_ex_entry(server: DnsServerSpec) -> (i32, Vec<u8>, u16, String) {
    let (family, address) = address_bytes(server.address.ip());
    (
        family,
        address,
        dns_ex_output_port(server.address.port()),
        server.server_name.unwrap_or_default(),
    )
}

fn decode_dns_server_specs(
    addresses: Vec<(i32, Vec<u8>, u16, String)>,
) -> Result<Vec<DnsServerSpec>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address, port, server_name)| {
            Ok(DnsServerSpec {
                address: SocketAddr::new(
                    decode_address(family, &address)?,
                    dns_ex_input_port(port),
                ),
                interface: None,
                server_name: (!server_name.is_empty()).then_some(server_name),
            })
        })
        .collect()
}

const fn dns_ex_input_port(port: u16) -> u16 {
    if matches!(port, 0 | 53 | 853) {
        DNS_PORT
    } else {
        port
    }
}

const fn dns_ex_output_port(port: u16) -> u16 {
    if matches!(port, 53 | 853) {
        0
    } else {
        port
    }
}

fn name_lookup_reply(lookup: NameLookup, ifindex: i32) -> (Vec<(i32, i32, Vec<u8>)>, String, u64) {
    let NameLookup {
        addresses,
        address_ifindices,
        canonical_name,
        flags,
    } = lookup;
    let addresses = addresses
        .into_iter()
        .zip(address_ifindices)
        .map(|(address, answer_ifindex)| {
            let (family, bytes) = address_bytes(address);
            (answer_ifindex.unwrap_or(ifindex).max(0), family, bytes)
        })
        .collect();
    (addresses, canonical_name, flags)
}

fn address_lookup_reply(lookup: AddressLookup, ifindex: i32) -> (Vec<(i32, String)>, u64) {
    let AddressLookup {
        names,
        name_ifindices,
        flags,
    } = lookup;
    let names = names
        .into_iter()
        .zip(name_ifindices)
        .map(|(name, answer_ifindex)| (answer_ifindex.unwrap_or(ifindex).max(0), name))
        .collect();
    (names, flags)
}

fn response_flags(response: &[u8]) -> u64 {
    crate::resolver::response_protocol_flags(response)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn resolve_service_reply(
    resolver: &Resolver,
    ifindex: i32,
    name: &str,
    service_type: &str,
    domain: &str,
    family: i32,
    flags: u64,
) -> Result<
    (
        Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
        Vec<Vec<u8>>,
        String,
        String,
        String,
        u64,
    ),
    DbusError,
> {
    if !crate::resolver::query_flags_are_valid(
        flags,
        SD_RESOLVED_NO_ADDRESS | SD_RESOLVED_NO_TXT,
    ) {
        return Err(DbusError::InvalidArgs("invalid flags parameter".to_owned()));
    }
    let (owner, unicast_owner, _, _, _) = service_owner(name, service_type, domain)?;
    let mut flags = flags;
    let refused = &resolver.config().refuse_record_types;
    if refused.contains(&TYPE_A) && refused.contains(&TYPE_AAAA) {
        flags |= SD_RESOLVED_NO_ADDRESS;
    }
    if refused.contains(&TYPE_TXT) {
        flags |= SD_RESOLVED_NO_TXT;
    }
    let request_flags = flags | SD_RESOLVED_NO_SEARCH;
    let grouped = if flags & SD_RESOLVED_NO_TXT == 0 {
        resolver
            .grouped_hook_record_response_dual(
                &owner,
                &unicast_owner,
                &[TYPE_SRV, TYPE_TXT],
                positive_ifindex(ifindex),
                request_flags,
            )
            .map_err(map_resolve_error)?
    } else {
        (false, None)
    };
    let grouped_hook_checked = grouped.0;
    let grouped_response = grouped.1;
    let (response, canonical_owner, mut response_flags, _) =
        if let Some((response, response_flags, response_ifindex)) = &grouped_response {
            let (rcode, extended_dns_error_code, extended_dns_error_message) =
                crate::resolver::response_full_rcode(response)
                    .map_err(|error| DbusError::InvalidReply(error.to_string()))?;
            if rcode != 0 {
                return Err(map_resolve_error(ResolveError::DnsError {
                    rcode,
                    query: owner.clone(),
                    extended_dns_error_code,
                    extended_dns_error_message,
                }));
            }
            let canonical_owner = match crate::wire::classify_redirect_answer(response)
                .map_err(|error| DbusError::InvalidReply(error.to_string()))?
            {
                crate::wire::RedirectAnswer::Direct { canonical_name, .. } => canonical_name,
                crate::wire::RedirectAnswer::Redirect { .. }
                | crate::wire::RedirectAnswer::NoData => {
                    return Err(DbusError::NoSuchService("service was not found".to_owned()))
                }
            };
            (
                response.clone(),
                canonical_owner,
                *response_flags,
                *response_ifindex,
            )
        } else {
            let lookup = if grouped_hook_checked {
                Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual_after_grouped_hook
            } else {
                Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual
            };
            lookup(
                resolver,
                &owner,
                &unicast_owner,
                CLASS_IN,
                TYPE_SRV,
                positive_ifindex(ifindex),
                request_flags,
            )
            .map_err(map_resolve_error)?
        };
    let records = extract_service_records_for_name(&response, &canonical_owner)
        .map_err(|error| DbusError::InvalidReply(error.to_string()))?;
    let (canonical_name, canonical_type, canonical_domain) =
        split_service_owner(&canonical_owner).ok_or_else(|| {
            DbusError::InconsistentServiceRecords(format!(
                "'{canonical_owner}' is not a consistent service owner"
            ))
        })?;
    let mut services = Vec::new();
    let mut root_target = false;
    let mut last_error = None;

    for record in records.srv {
        if record.target.text() == "." {
            root_target = true;
            continue;
        }
        let mut addresses = Vec::new();
        let mut canonical = String::new();
        if flags & SD_RESOLVED_NO_ADDRESS == 0 {
            match resolver.lookup_name_on_link_with_request_flags(
                record.target.text(),
                family,
                positive_ifindex(ifindex),
                flags | SD_RESOLVED_NO_SEARCH,
            ) {
                Ok(lookup) => {
                    canonical = lookup.canonical_name;
                    addresses = lookup
                        .addresses
                        .into_iter()
                        .zip(lookup.address_ifindices)
                        .map(|(address, answer_ifindex)| {
                            let (family, bytes) = address_bytes(address);
                            (answer_ifindex.unwrap_or(ifindex).max(0), family, bytes)
                        })
                        .collect();
                }
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        services.push((
            record.priority,
            record.weight,
            record.port,
            record.target.text().to_owned(),
            addresses,
            canonical,
        ));
    }

    if services.is_empty() {
        if root_target {
            return Err(DbusError::NoSuchService(
                "service is explicitly not provided".to_owned(),
            ));
        }
        if let Some(error) = last_error {
            return Err(map_resolve_error(error));
        }
        return Err(DbusError::NoSuchService("service was not found".to_owned()));
    }

    let txt_data = if flags & SD_RESOLVED_NO_TXT != 0 {
        Vec::new()
    } else if let Some((response, _, _)) = grouped_response {
        extract_service_records_for_name(&response, &canonical_owner)
            .map_err(|error| DbusError::InvalidReply(error.to_string()))?
            .txt
    } else {
        let lookup = if grouped_hook_checked {
            Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual_after_grouped_hook
        } else {
            Resolver::resolve_record_on_link_with_request_flags_and_canonical_dual
        };
        match lookup(
            resolver,
            &canonical_owner,
            &canonical_owner,
            CLASS_IN,
            TYPE_TXT,
            positive_ifindex(ifindex),
            request_flags,
        ) {
            Ok((response, txt_canonical, txt_flags, _)) => {
                response_flags = crate::resolver::merge_parallel_response_flags(
                    Some(response_flags),
                    txt_flags,
                );
                extract_service_records_for_name(&response, &txt_canonical)
                    .map_err(|error| DbusError::InvalidReply(error.to_string()))?
                    .txt
            }
            Err(_) => Vec::new(),
        }
    };

    Ok((
        services,
        txt_data,
        canonical_name,
        canonical_type,
        canonical_domain,
        response_flags,
    ))
}

fn service_owner(
    name: &str,
    service_type: &str,
    domain: &str,
) -> Result<(String, String, String, String, String), DbusError> {
    let service_type = service_type.strip_suffix('.').unwrap_or(service_type);
    if service_type.ends_with('.')
        || (!service_type.is_empty() && !service_type_is_valid(service_type))
        || crate::wire::make_query(domain, TYPE_SRV, 0).is_err()
    {
        return Err(DbusError::InvalidArgs(
            "invalid service type or domain".to_owned(),
        ));
    }
    if !name.is_empty() && !service_instance_is_valid(name) {
        return Err(DbusError::InvalidArgs(
            "invalid service instance name".to_owned(),
        ));
    }
    if !name.is_empty() && service_type.is_empty() {
        return Err(DbusError::InvalidArgs(
            "service instance requires a service type".to_owned(),
        ));
    }
    let canonical_domain = domain
        .strip_suffix('.')
        .filter(|domain| !domain.is_empty())
        .unwrap_or(domain)
        .to_ascii_lowercase();
    if service_type.is_empty() {
        return Ok((
            domain.to_owned(),
            domain.to_owned(),
            String::new(),
            String::new(),
            canonical_domain,
        ));
    }
    let escaped_name = (!name.is_empty())
        .then(|| crate::wire::escape_label(name.as_bytes()))
        .transpose()
        .map_err(|error| DbusError::InvalidArgs(error.to_string()))?;
    let prefix = if let Some(name) = &escaped_name {
        format!("{name}.{service_type}")
    } else {
        service_type.to_owned()
    };
    let owner = if domain == "." {
        prefix.clone()
    } else {
        format!("{prefix}.{domain}")
    };
    let unicast_domain =
        crate::idna_name::to_ascii(domain).unwrap_or_else(|_| domain.to_owned());
    let unicast_owner = if unicast_domain == "." {
        prefix
    } else {
        format!("{prefix}.{unicast_domain}")
    };
    Ok((
        owner,
        unicast_owner,
        name.to_owned(),
        service_type.to_ascii_lowercase(),
        canonical_domain,
    ))
}

fn service_instance_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 63 && !value.chars().any(char::is_control)
}

fn split_service_owner(owner: &str) -> Option<(String, String, String)> {
    let labels: Vec<_> = owner.trim_end_matches('.').split('.').collect();
    for index in 0..labels.len().saturating_sub(1) {
        let candidate = format!("{}.{}", labels[index], labels[index + 1]);
        if !service_type_is_valid(&candidate) || index > 1 {
            continue;
        }
        let domain = match labels.get(index + 2..)? {
            [] => ".".to_owned(),
            labels => labels.join("."),
        };
        let name = if index == 1 {
            String::from_utf8(crate::wire::decode_label(labels[0]).ok()?).ok()?
        } else {
            String::new()
        };
        if !name.is_empty() && !service_instance_is_valid(&name) {
            return None;
        }
        return Some((name, candidate.to_ascii_lowercase(), domain));
    }
    None
}

fn service_type_is_valid(value: &str) -> bool {
    let mut labels = value.split('.');
    let Some(service) = labels.next() else {
        return false;
    };
    let Some(protocol) = labels.next() else {
        return false;
    };
    labels.next().is_none() && valid_service_label(service) && valid_service_label(protocol)
}

fn valid_service_label(value: &str) -> bool {
    value.starts_with('_')
        && value.len() > 1
        && value.len() <= 63
        && value.is_ascii()
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_support_mode(value: &str) -> Result<SupportMode, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "true" | "on" | "1" => Ok(SupportMode::Yes),
        "resolve" => Ok(SupportMode::Resolve),
        "no" | "false" | "off" | "0" => Ok(SupportMode::No),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid resolver support mode {value}"
        ))),
    }
}

fn parse_tls_mode(value: &str) -> Result<Option<TlsMode>, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "no" | "false" | "off" | "0" => Ok(Some(TlsMode::No)),
        "opportunistic" => Ok(Some(TlsMode::Opportunistic)),
        "yes" | "true" | "on" | "1" => Ok(Some(TlsMode::Yes)),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNS-over-TLS mode {value}"
        ))),
    }
}

fn parse_validation_mode(value: &str) -> Result<Option<ValidationMode>, DbusError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "allow-downgrade" => Ok(Some(ValidationMode::AllowDowngrade)),
        "no" | "false" | "off" | "0" => Ok(Some(ValidationMode::No)),
        "yes" | "true" | "on" | "1" => Ok(Some(ValidationMode::Yes)),
        _ => Err(DbusError::InvalidArgs(format!(
            "invalid DNSSEC mode {value}"
        ))),
    }
}

const fn support_mode_string(mode: SupportMode) -> &'static str {
    match mode {
        SupportMode::No => "no",
        SupportMode::Resolve => "resolve",
        SupportMode::Yes => "yes",
    }
}

const fn tls_mode_string(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::No => "no",
        TlsMode::Opportunistic => "opportunistic",
        TlsMode::Yes => "yes",
    }
}

const fn validation_mode_string(mode: ValidationMode) -> &'static str {
    match mode {
        ValidationMode::No => "no",
        ValidationMode::AllowDowngrade => "allow-downgrade",
        ValidationMode::Yes => "yes",
    }
}

fn map_link_error(error: LinkError) -> DbusError {
    match error {
        LinkError::NoSuchLink(_) | LinkError::InvalidIfindex(_) => {
            DbusError::NoSuchLink(error.to_string())
        }
        LinkError::ManagedLink(_) => DbusError::LinkBusy(error.to_string()),
        LinkError::InvalidDomain(_) => DbusError::InvalidArgs(error.to_string()),
    }
}

fn map_resolve_error(error: ResolveError) -> DbusError {
    match error {
        ResolveError::NoNameServers => DbusError::NoNameServers(error.to_string()),
        ResolveError::NoSuchResourceRecord => DbusError::NoSuchResourceRecord(error.to_string()),
        ResolveError::Link(_) => DbusError::NoSource(error.to_string()),
        ResolveError::UnsupportedFamily(_) => DbusError::InvalidArgs(error.to_string()),
        ResolveError::Io(ref source)
            if matches!(
                source.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            DbusError::Timeout(error.to_string())
        }
        ResolveError::Io(_) => DbusError::NetworkDown(error.to_string()),
        ResolveError::Wire(crate::wire::WireError::CnameLoop) => {
            DbusError::CNameLoop(error.to_string())
        }
        ResolveError::DnsError { rcode, .. } => dns_rcode_error(rcode, error.to_string()),
        ResolveError::QueryRefused => DbusError::DnsRefused(error.to_string()),
        ResolveError::ResourceRecordTypeUnsupported => {
            DbusError::ResourceRecordTypeUnsupported(error.to_string())
        }
        ResolveError::ResourceRecordTypeObsolete => {
            DbusError::ResourceRecordTypeUnsupported(error.to_string())
        }
        ResolveError::QueryAborted => DbusError::Aborted(error.to_string()),
        ResolveError::MaxAttemptsReached => DbusError::Timeout(error.to_string()),
        ResolveError::DnssecValidationFailed { .. } => DbusError::DnssecFailed(error.to_string()),
        ResolveError::NoTrustAnchor => DbusError::NoTrustAnchor(error.to_string()),
        ResolveError::InconsistentServiceRecords => {
            DbusError::InconsistentServiceRecords(error.to_string())
        }
        ResolveError::StubLoop => DbusError::StubLoop(error.to_string()),
        ResolveError::Wire(_) | ResolveError::Protocol(_) => DbusError::InvalidReply(error.to_string()),
    }
}

fn dns_rcode_error(rcode: u16, message: String) -> DbusError {
    match rcode {
        1 => DbusError::DnsFormErr(message),
        2 => DbusError::DnsServFail(message),
        3 => DbusError::DnsNxDomain(message),
        4 => DbusError::DnsNotImp(message),
        5 => DbusError::DnsRefused(message),
        6 => DbusError::DnsYxDomain(message),
        7 => DbusError::DnsYrrset(message),
        8 => DbusError::DnsNxrrset(message),
        9 => DbusError::DnsNotAuth(message),
        10 => DbusError::DnsNotZone(message),
        16 => DbusError::DnsBadVers(message),
        17 => DbusError::DnsBadKey(message),
        18 => DbusError::DnsBadTime(message),
        19 => DbusError::DnsBadMode(message),
        20 => DbusError::DnsBadName(message),
        21 => DbusError::DnsBadAlg(message),
        22 => DbusError::DnsBadTrunc(message),
        23 => DbusError::DnsBadCookie(message),
        _ => DbusError::InvalidReply(message),
    }
}
