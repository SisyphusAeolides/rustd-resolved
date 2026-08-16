// SPDX-License-Identifier: LGPL-2.1-or-later

const MONITOR_INTERFACE_DESCRIPTION: &str =
    include_str!("../interfaces/io.rustd.Resolve.Monitor.varlink");

fn monitor_query_event(event: crate::resolver::ResolverQueryEvent) -> Value {
    let mut fields = JsonObject::from([
        ("state".to_owned(), Value::String(event.state)),
        (
            "question".to_owned(),
            Value::Array(
                event
                    .question
                    .into_iter()
                    .map(monitor_query_resource_key)
                    .collect(),
            ),
        ),
    ]);
    if let Some(result) = event.result {
        fields.insert("result".to_owned(), Value::String(result));
    }
    if let Some(rcode) = event.rcode {
        fields.insert("rcode".to_owned(), Value::Number(i128::from(rcode)));
    }
    if let Some(errno) = event.errno {
        fields.insert("errno".to_owned(), Value::Number(i128::from(errno)));
    }
    if let Some(code) = event.extended_dns_error_code {
        fields.insert(
            "extendedDNSErrorCode".to_owned(),
            Value::Number(i128::from(code)),
        );
    }
    if let Some(message) = event.extended_dns_error_message {
        fields.insert(
            "extendedDNSErrorMessage".to_owned(),
            Value::String(message),
        );
    }
    if !event.collected_questions.is_empty() {
        fields.insert(
            "collectedQuestions".to_owned(),
            Value::Array(
                event
                    .collected_questions
                    .into_iter()
                    .map(monitor_query_resource_key)
                    .collect(),
            ),
        );
    }
    if !event.answer.is_empty() {
        fields.insert(
            "answer".to_owned(),
            Value::Array(
                event
                    .answer
                    .into_iter()
                    .map(|answer| {
                        let mut answer_fields = JsonObject::from([(
                            "raw".to_owned(),
                            Value::String(base64(&answer.raw)),
                        )]);
                        if let Some(rr) = resource_record_json_from_raw(&answer.raw) {
                            answer_fields.insert("rr".to_owned(), rr);
                        }
                        if let Some(ifindex) = answer.ifindex {
                            answer_fields.insert(
                                "ifindex".to_owned(),
                                Value::Number(i128::from(ifindex)),
                            );
                        }
                        Value::Object(answer_fields)
                    })
                    .collect(),
            ),
        );
    }
    Value::Object(fields)
}

fn monitor_query_resource_key(key: crate::resolver::ResolverResourceKey) -> Value {
    Value::object([
        ("class", Value::Number(i128::from(key.class))),
        ("type", Value::Number(i128::from(key.rr_type))),
        ("name", Value::String(key.name)),
    ])
}

fn monitor_dump_cache(can_control: bool, resolver: &Resolver) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    let cache = resolver.cache_snapshot();
    let mdns_cache = crate::mdns::runtime::cache_snapshot();
    let llmnr_cache = crate::llmnr::runtime::cache_snapshot();
    let config = resolver.config();
    let mut scopes = Vec::new();
    scopes.push(monitor_scope_cache(
        "dns",
        None,
        None,
        None,
        cache
            .iter()
            .filter(|entry| {
                matches!(
                    entry.scope,
                    crate::cache::CacheScope::Global | crate::cache::CacheScope::Fallback
                )
            })
            .cloned()
            .map(monitor_cache_entry)
            .collect(),
        Some(validation_mode_name(config.dnssec)),
        Some(tls_mode_name(config.dns_over_tls)),
    ));
    for link in resolver.links() {
        for scope in link_dns_scopes(resolver, &link) {
            let protocol = scope
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("dns");
            let family = scope
                .get("family")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok());
            let ifname = scope.get("ifname").and_then(Value::as_str);
            let dnssec = scope.get("dnssec").and_then(Value::as_str);
            let dns_over_tls = scope.get("dnsOverTLS").and_then(Value::as_str);
            let entries = match protocol {
                "dns" => cache
                    .iter()
                    .filter(|entry| {
                        entry.scope == crate::cache::CacheScope::Link(link.ifindex)
                    })
                    .cloned()
                    .map(monitor_cache_entry)
                    .collect(),
                "mdns" => mdns_cache
                    .iter()
                    .filter(|(key, _)| {
                        i32::try_from(key.interface.ifindex).ok() == Some(link.ifindex)
                            && mdns_family(key.interface.family) == family
                    })
                    .map(|(key, records)| monitor_mdns_cache_entry(key, records))
                    .collect(),
                "llmnr" => llmnr_cache
                    .iter()
                    .filter(|entry| entry.ifindex == link.ifindex && Some(entry.family) == family)
                    .map(|entry| monitor_cache_entry(entry.entry.clone()))
                    .collect(),
                _ => Vec::new(),
            };
            scopes.push(monitor_scope_cache(
                protocol,
                family,
                Some(link.ifindex),
                ifname,
                entries,
                dnssec,
                dns_over_tls,
            ));
        }
    }
    for index in 0..config.dns_delegates.len() {
        scopes.push(monitor_scope_cache(
            "dns",
            None,
            None,
            None,
            cache
                .iter()
                .filter(|entry| entry.scope == crate::cache::CacheScope::Delegate(index))
                .cloned()
                .map(monitor_cache_entry)
                .collect(),
            Some(validation_mode_name(config.dnssec)),
            Some(tls_mode_name(config.dns_over_tls)),
        ));
    }
    success(Value::object([("dump", Value::Array(scopes))]))
}

fn monitor_scope_cache(
    protocol: &str,
    family: Option<i32>,
    ifindex: Option<i32>,
    ifname: Option<&str>,
    cache: Vec<Value>,
    dnssec: Option<&str>,
    dns_over_tls: Option<&str>,
) -> Value {
    let mut fields = JsonObject::from([
        ("protocol".to_owned(), Value::String(protocol.to_owned())),
        ("cache".to_owned(), Value::Array(cache)),
    ]);
    if let Some(family) = family {
        fields.insert("family".to_owned(), Value::Number(i128::from(family)));
    }
    if let Some(ifindex) = ifindex {
        fields.insert("ifindex".to_owned(), Value::Number(i128::from(ifindex)));
    }
    if let Some(ifname) = ifname {
        fields.insert("ifname".to_owned(), Value::String(ifname.to_owned()));
    }
    if let Some(dnssec) = dnssec {
        fields.insert("dnssec".to_owned(), Value::String(dnssec.to_owned()));
    }
    if let Some(dns_over_tls) = dns_over_tls {
        fields.insert(
            "dnsOverTLS".to_owned(),
            Value::String(dns_over_tls.to_owned()),
        );
    }
    Value::Object(fields)
}

fn monitor_cache_entry(entry: crate::cache::CacheSnapshot) -> Value {
    let mut fields = JsonObject::from([
        (
            "key".to_owned(),
            monitor_resource_key(&entry.name, entry.class, entry.rr_type),
        ),
        (
            "until".to_owned(),
            Value::Number(cache_until_usec(entry.remaining)),
        ),
    ]);
    let records = if entry.rcode == 0 {
        extract_answer_records(&entry.response).unwrap_or_default()
    } else {
        Vec::new()
    };
    if entry.rcode == 0 && !records.is_empty() {
        fields.insert(
            "rrs".to_owned(),
            Value::Array(
                records
                    .into_iter()
                    .map(|record| {
                        Value::object([
                            (
                                "rr",
                                resource_record_json(&record).unwrap_or(Value::Null),
                            ),
                            ("raw", Value::String(base64(&record.raw))),
                        ])
                    })
                    .collect(),
            ),
        );
    } else {
        fields.insert(
            "type".to_owned(),
            Value::String(cache_type_name(entry.rcode).to_owned()),
        );
    }
    Value::Object(fields)
}

fn mdns_family(family: crate::mdns::parity::MdnsAddressFamily) -> Option<i32> {
    Some(match family {
        crate::mdns::parity::MdnsAddressFamily::Ipv4 => 2,
        crate::mdns::parity::MdnsAddressFamily::Ipv6 => 10,
    })
}

fn monitor_mdns_cache_entry(
    key: &crate::mdns::parity::MdnsRecordKey,
    records: &[crate::mdns::parity::MdnsCacheRecord],
) -> Value {
    let now = std::time::Instant::now();
    let rrs = records
        .iter()
        .map(|record| {
            let ttl = record
                .expires_at
                .checked_duration_since(record.received_at)
                .map_or(0, |lifetime| {
                    u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX)
                });
            let raw = raw_resource_record(&key.owner, key.rr_type, key.class, ttl, &record.rdata);
            Value::object([
                (
                    "rr",
                    resource_record_json_from_raw(&raw).unwrap_or(Value::Null),
                ),
                ("raw", Value::String(base64(&raw))),
            ])
        })
        .collect();
    let remaining = records
        .iter()
        .map(|record| record.remaining_ttl(now))
        .max()
        .unwrap_or_default();
    Value::object([
        (
            "key",
            monitor_resource_key(&key.owner, key.class, key.rr_type),
        ),
        ("rrs", Value::Array(rrs)),
        ("until", Value::Number(cache_until_usec(remaining))),
    ])
}

fn raw_resource_record(owner: &[u8], rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(owner.len().saturating_add(10).saturating_add(rdata.len()));
    raw.extend_from_slice(owner);
    raw.extend_from_slice(&rr_type.to_be_bytes());
    raw.extend_from_slice(&class.to_be_bytes());
    raw.extend_from_slice(&ttl.to_be_bytes());
    raw.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("mDNS RDATA length came from a DNS wire record")
            .to_be_bytes(),
    );
    raw.extend_from_slice(rdata);
    raw
}

fn monitor_resource_key(name: &[u8], class: u16, rr_type: u16) -> Value {
    Value::object([
        ("class", Value::Number(i128::from(class))),
        ("type", Value::Number(i128::from(rr_type))),
        ("name", Value::String(wire_name_text(name))),
    ])
}

fn wire_name_text(wire: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut offset = 0usize;
    while let Some(&length) = wire.get(offset) {
        offset += 1;
        if length == 0 {
            return if labels.is_empty() {
                ".".to_owned()
            } else {
                labels.join(".")
            };
        }
        let length = usize::from(length);
        if length > 63 {
            return "<invalid>".to_owned();
        }
        let Some(label) = wire.get(offset..offset.saturating_add(length)) else {
            return "<invalid>".to_owned();
        };
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += length;
    }
    "<invalid>".to_owned()
}

fn cache_until_usec(remaining: Duration) -> i128 {
    let remaining = i128::try_from(remaining.as_micros()).unwrap_or(i128::MAX);
    boottime_usec().saturating_add(remaining)
}

fn boottime_usec() -> i128 {
    let Ok(uptime) = fs::read_to_string("/proc/uptime") else {
        return 0;
    };
    let Some(value) = uptime.split_whitespace().next() else {
        return 0;
    };
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let Ok(seconds) = seconds.parse::<u128>() else {
        return 0;
    };
    let mut fractional_micros = 0u128;
    let mut scale = 100_000u128;
    for byte in fraction.bytes().take(6) {
        if !byte.is_ascii_digit() {
            return 0;
        }
        fractional_micros = fractional_micros
            .saturating_add(u128::from(byte - b'0').saturating_mul(scale));
        scale /= 10;
    }
    let micros = seconds
        .saturating_mul(1_000_000)
        .saturating_add(fractional_micros);
    i128::try_from(micros).unwrap_or(i128::MAX)
}

const fn cache_type_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NODATA",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        5 => "REFUSED",
        _ => "ERROR",
    }
}

fn monitor_dump_server_state(can_control: bool, resolver: &Resolver) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    success(Value::object([(
        "dump",
        Value::Array(
            resolver
                .server_state_snapshot()
                .into_iter()
                .map(monitor_server_state)
                .collect(),
        ),
    )]))
}

fn monitor_server_state(state: crate::resolver::ResolverServerState) -> Value {
    let mut fields = JsonObject::from([
        ("Server".to_owned(), Value::String(state.server)),
        ("Type".to_owned(), Value::String(state.server_type)),
        (
            "VerifiedFeatureLevel".to_owned(),
            Value::String(state.verified_feature_level),
        ),
        (
            "PossibleFeatureLevel".to_owned(),
            Value::String(state.possible_feature_level),
        ),
        ("DNSSECMode".to_owned(), Value::String(state.dnssec_mode)),
        (
            "DNSSECSupported".to_owned(),
            Value::Bool(state.dnssec_supported),
        ),
        (
            "ReceivedUDPFragmentMax".to_owned(),
            Value::Number(i128::from(state.received_udp_fragment_max)),
        ),
        (
            "FailedUDPAttempts".to_owned(),
            Value::Number(i128::from(state.failed_udp_attempts)),
        ),
        (
            "FailedTCPAttempts".to_owned(),
            Value::Number(i128::from(state.failed_tcp_attempts)),
        ),
        (
            "PacketTruncated".to_owned(),
            Value::Bool(state.packet_truncated),
        ),
        ("PacketBadOpt".to_owned(), Value::Bool(state.packet_bad_opt)),
        (
            "PacketRRSIGMissing".to_owned(),
            Value::Bool(state.packet_rrsig_missing),
        ),
        ("PacketInvalid".to_owned(), Value::Bool(state.packet_invalid)),
        ("PacketDoOff".to_owned(), Value::Bool(state.packet_do_off)),
    ]);
    if let Some(interface) = state.interface {
        fields.insert("Interface".to_owned(), Value::String(interface));
    }
    if let Some(ifindex) = state.interface_index {
        fields.insert(
            "InterfaceIndex".to_owned(),
            Value::Number(i128::from(ifindex)),
        );
    }
    Value::Object(fields)
}

fn monitor_dump_statistics(can_control: bool, resolver: &Resolver) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    let statistics = resolver.stats();
    success(Value::object([
        (
            "transactions",
            Value::object([
                (
                    "currentTransactions",
                    Value::Number(i128::from(statistics.current_transactions)),
                ),
                (
                    "totalTransactions",
                    Value::Number(i128::from(statistics.transactions)),
                ),
                (
                    "totalTimeouts",
                    Value::Number(i128::from(statistics.timeouts)),
                ),
                (
                    "totalTimeoutsServedStale",
                    Value::Number(i128::from(statistics.timeouts_served_stale)),
                ),
                (
                    "totalFailedResponses",
                    Value::Number(i128::from(statistics.failures)),
                ),
                (
                    "totalFailedResponsesServedStale",
                    Value::Number(i128::from(statistics.failures_served_stale)),
                ),
            ]),
        ),
        (
            "cache",
            Value::object([
                (
                    "size",
                    Value::Number(i128::try_from(statistics.cache_entries).unwrap_or(i128::MAX)),
                ),
                ("hits", Value::Number(i128::from(statistics.cache_hits))),
                (
                    "misses",
                    Value::Number(i128::from(statistics.cache_misses)),
                ),
            ]),
        ),
        (
            "dnssec",
            Value::object([
                (
                    "secure",
                    Value::Number(i128::from(statistics.dnssec_secure)),
                ),
                (
                    "insecure",
                    Value::Number(i128::from(statistics.dnssec_insecure)),
                ),
                (
                    "bogus",
                    Value::Number(i128::from(statistics.dnssec_bogus)),
                ),
                (
                    "indeterminate",
                    Value::Number(i128::from(statistics.dnssec_indeterminate)),
                ),
            ]),
        ),
    ]))
}

fn monitor_reset_statistics(can_control: bool, resolver: &Resolver) -> Value {
    monitor_authorized(can_control, || {
        resolver.reset_statistics();
        success(Value::Object(JsonObject::new()))
    })
}

fn monitor_authorized(can_control: bool, operation: impl FnOnce() -> Value) -> Value {
    if !can_control {
        return error("org.varlink.service.PermissionDenied");
    }
    operation()
}

#[cfg(test)]
mod monitor_tests {
    use super::*;
    use crate::config::{Config, DnsServerSpec};
    use crate::routing::KernelLinkState;

    #[test]
    fn interface_description_lists_pinned_monitor_dumps() {
        for name in [
            "SubscribeQueryResults",
            "SubscribeDNSConfiguration",
            "DumpCache",
            "DumpServerState",
            "DumpStatistics",
            "ResetStatistics",
        ] {
            assert!(MONITOR_INTERFACE_DESCRIPTION.contains(name), "{name}");
        }
        for field in [
            "ReceivedUDPFragmentMax",
            "FailedUDPAttempts",
            "PacketRRSIGMissing",
            "totalFailedResponsesServedStale",
            "indeterminate",
        ] {
            assert!(MONITOR_INTERFACE_DESCRIPTION.contains(field), "{field}");
        }
    }

    #[test]
    fn monitor_dumps_and_reset_require_authorization() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.Monitor.DumpStatistics","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.PermissionDenied")
        );

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.Monitor.ResetStatistics","parameters":{}}"#,
            &resolver,
        );
        assert_eq!(
            reply.get("error").and_then(Value::as_str),
            Some("org.varlink.service.PermissionDenied")
        );
    }

    #[test]
    fn statistics_dump_uses_nested_upstream_contract() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch_with_access(
            r#"{"method":"io.rustd.Resolve.Monitor.DumpStatistics","parameters":{}}"#,
            &resolver,
            true,
        );
        let parameters = reply.get("parameters").expect("parameters");
        assert!(parameters.get("transactions").is_some());
        assert!(parameters.get("cache").is_some());
        assert!(parameters.get("dnssec").is_some());
        assert_eq!(
            parameters
                .get("cache")
                .and_then(|cache| cache.get("size"))
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn server_state_dump_reports_configured_identity() {
        let server = DnsServerSpec {
            address: "192.0.2.53:853".parse().expect("server"),
            interface: Some("7".to_owned()),
            server_name: Some("resolver.example".to_owned()),
        };
        let resolver = Resolver::new(Config {
            upstreams: vec![server.address],
            upstream_specs: vec![server],
            ..Config::default()
        });
        let reply = dispatch_with_access(
            r#"{"method":"io.rustd.Resolve.Monitor.DumpServerState","parameters":{}}"#,
            &resolver,
            true,
        );
        let server = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("dump"))
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .expect("server state");
        assert_eq!(server.get("Type").and_then(Value::as_str), Some("system"));
        assert_eq!(
            server.get("Server").and_then(Value::as_str),
            Some("192.0.2.53:853%7#resolver.example")
        );
        assert_eq!(
            server.get("VerifiedFeatureLevel").and_then(Value::as_str),
            Some("n/a")
        );
        assert_eq!(
            server
                .get("ReceivedUDPFragmentMax")
                .and_then(Value::as_u64),
            Some(512)
        );
    }

    #[test]
    fn cache_dump_reports_global_scope_even_when_empty() {
        let resolver = Resolver::new(Config::default());
        let reply = dispatch_with_access(
            r#"{"method":"io.rustd.Resolve.Monitor.DumpCache","parameters":{}}"#,
            &resolver,
            true,
        );
        let scopes = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("dump"))
            .and_then(Value::as_array)
            .expect("scope dump");
        assert_eq!(
            scopes[0].get("protocol").and_then(Value::as_str),
            Some("dns")
        );
        assert_eq!(
            scopes[0]
                .get("cache")
                .and_then(Value::as_array)
                .map(|cache| cache.len()),
            Some(0)
        );
    }

    #[test]
    fn cache_dump_reports_each_live_link_scope() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 7,
                ifname: "dns0".to_owned(),
                flags: 0x0001 | 0x0040 | 0x1000 | 0x1_0000,
                mtu: 1500,
                operstate: 0,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: true,
            }])
            .expect("synchronize link");
        resolver
            .set_link_dns(7, vec!["192.0.2.53:53".parse().expect("DNS server")])
            .expect("set link DNS");

        let reply = monitor_dump_cache(true, &resolver);
        let scopes = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("dump"))
            .and_then(Value::as_array)
            .expect("scope dump");
        let link_scopes = scopes
            .iter()
            .filter(|scope| scope.get("ifindex").and_then(Value::as_i64) == Some(7))
            .collect::<Vec<_>>();
        assert_eq!(link_scopes.len(), 5);
        assert_eq!(
            link_scopes
                .iter()
                .filter(|scope| scope.get("protocol").and_then(Value::as_str) == Some("dns"))
                .count(),
            1
        );
        for protocol in ["llmnr", "mdns"] {
            assert_eq!(
                link_scopes
                    .iter()
                    .filter(|scope| {
                        scope.get("protocol").and_then(Value::as_str) == Some(protocol)
                    })
                    .count(),
                2
            );
        }
    }

    #[test]
    fn mdns_cache_entries_keep_scope_and_structured_record_data() {
        let now = std::time::Instant::now();
        let key = crate::mdns::parity::MdnsRecordKey::new(
            crate::mdns::parity::MdnsInterface::new(
                7,
                crate::mdns::parity::MdnsAddressFamily::Ipv4,
            ),
            &crate::wire::encode_name("printer.local").expect("mDNS owner"),
            crate::wire::TYPE_A,
            crate::wire::CLASS_IN,
        )
        .expect("mDNS cache key");
        let entry = monitor_mdns_cache_entry(
            &key,
            &[crate::mdns::parity::MdnsCacheRecord {
                rdata: vec![192, 0, 2, 45],
                cache_flush: true,
                received_at: now,
                expires_at: now + Duration::from_secs(120),
            }],
        );
        assert_eq!(
            entry
                .get("key")
                .and_then(|key| key.get("name"))
                .and_then(Value::as_str),
            Some("printer.local")
        );
        assert_eq!(
            entry
                .get("rrs")
                .and_then(Value::as_array)
                .and_then(|records| records.first())
                .and_then(|record| record.get("rr"))
                .and_then(|rr| rr.get("address"))
                .and_then(Value::as_array)
                .map(|values| values.len()),
            Some(4)
        );
    }
}
