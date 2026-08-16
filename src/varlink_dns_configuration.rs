// SPDX-License-Identifier: LGPL-2.1-or-later

fn dns_configuration_object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    let mut object = JsonObject::new();
    for (name, value) in fields {
        if !matches!(value, Value::Null) {
            object.insert(name.to_owned(), value);
        }
    }
    Value::Object(object)
}

fn optional_array(values: Vec<Value>) -> Value {
    if values.is_empty() {
        Value::Null
    } else {
        Value::Array(values)
    }
}

fn dump_dns_configuration(resolver: &Resolver) -> Value {
    let config = resolver.config();
    let mut configuration = Vec::new();
    configuration.push(global_dns_configuration(resolver, &config));
    configuration.extend(
        resolver
            .links()
            .into_iter()
            .map(|link| link_dns_configuration(resolver, &link)),
    );
    configuration.extend(
        config
            .dns_delegates
            .iter()
            .map(|delegate| delegate_dns_configuration(&config, delegate)),
    );
    success(Value::object([(
        "configuration",
        Value::Array(configuration),
    )]))
}

fn delegate_dns_configuration(
    config: &crate::config::Config,
    delegate: &crate::dns_delegate::DnsDelegate,
) -> Value {
    let current_server = delegate.servers.first().map_or(Value::Null, |server| {
        dns_server_configuration(server, None, true)
    });
    dns_configuration_object([
        ("ifname", Value::Null),
        ("ifindex", Value::Null),
        ("delegate", Value::String(delegate.id.clone())),
        (
            "defaultRoute",
            Value::Bool(delegate.effective_default_route()),
        ),
        ("currentServer", current_server),
        (
            "servers",
            optional_array(
                delegate
                    .servers
                    .iter()
                    .map(|server| dns_server_configuration(server, None, true))
                    .collect(),
            ),
        ),
        ("fallbackServers", Value::Null),
        (
            "searchDomains",
            optional_array(
                delegate
                    .domains
                    .iter()
                    .map(|domain| search_domain_configuration(domain, None))
                    .collect(),
            ),
        ),
        ("negativeTrustAnchors", Value::Null),
        ("dnssec", Value::Null),
        ("dnssecSupported", Value::Null),
        ("dnsOverTLS", Value::Null),
        ("llmnr", Value::Null),
        ("mDNS", Value::Null),
        ("resolvConfMode", Value::Null),
        (
            "scopes",
            Value::Array(vec![dns_scope_configuration(
                "dns",
                None,
                None,
                None,
                Some(validation_mode_name(config.dnssec)),
                Some(tls_mode_name(config.dns_over_tls)),
            )]),
        ),
    ])
}

fn global_dns_configuration(resolver: &Resolver, config: &crate::config::Config) -> Value {
    let servers = configured_server_specs(config, false);
    let fallback_servers = configured_server_specs(config, true);
    let current_server = servers
        .first()
        .or_else(|| fallback_servers.first())
        .map_or(Value::Null, |server| {
            dns_server_configuration(server, None, true)
        });
    let resolv_conf_mode = crate::resolvconf_publish::system_resolv_conf_mode(
        &config.runtime_directory,
    )
    .unwrap_or(crate::resolvconf_publish::ResolvConfMode::Foreign)
    .as_str()
    .to_owned();

    dns_configuration_object([
        ("ifname", Value::Null),
        ("ifindex", Value::Null),
        ("delegate", Value::Null),
        ("defaultRoute", Value::Null),
        ("currentServer", current_server),
        (
            "servers",
            optional_array(
                servers
                    .iter()
                    .map(|server| dns_server_configuration(server, None, true))
                    .collect(),
            ),
        ),
        (
            "fallbackServers",
            optional_array(
                fallback_servers
                    .iter()
                    .map(|server| dns_server_configuration(server, None, true))
                    .collect(),
            ),
        ),
        (
            "searchDomains",
            optional_array(
                config
                    .domains
                    .iter()
                    .map(|domain| search_domain_configuration(domain, None))
                    .collect(),
            ),
        ),
        (
            "negativeTrustAnchors",
            optional_array(
                resolver
                    .dnssec_negative_trust_anchors()
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        (
            "dnssec",
            Value::String(validation_mode_name(config.dnssec).to_owned()),
        ),
        (
            "dnssecSupported",
            Value::Bool(resolver.manager_dnssec_supported()),
        ),
        (
            "dnsOverTLS",
            Value::String(tls_mode_name(config.dns_over_tls).to_owned()),
        ),
        (
            "llmnr",
            Value::String(support_mode_name(config.llmnr).to_owned()),
        ),
        (
            "mDNS",
            Value::String(support_mode_name(config.multicast_dns).to_owned()),
        ),
        ("resolvConfMode", Value::String(resolv_conf_mode)),
        (
            "scopes",
            Value::Array(vec![dns_scope_configuration(
                "dns",
                None,
                None,
                None,
                Some(validation_mode_name(config.dnssec)),
                Some(tls_mode_name(config.dns_over_tls)),
            )]),
        ),
    ])
}

fn link_dns_configuration(
    resolver: &Resolver,
    link: &crate::routing::LinkState,
) -> Value {
    let servers = resolver.link_dns_specs(link.ifindex);
    let accessible = link.kernel_relevant_unicast();
    let current_server = servers.first().map_or(Value::Null, |server| {
        dns_server_configuration(server, Some(link.ifindex), accessible)
    });
    let ifname = link.kernel.as_ref().map_or(Value::Null, |kernel| {
        Value::String(kernel.ifname.clone())
    });
    let default_route = Value::Bool(link.effective_default_route());
    let scopes = link_dns_scopes(resolver, link);

    dns_configuration_object([
        ("ifname", ifname),
        ("ifindex", Value::Number(i128::from(link.ifindex))),
        ("delegate", Value::Null),
        ("defaultRoute", default_route),
        ("currentServer", current_server),
        (
            "servers",
            optional_array(
                servers
                    .iter()
                    .map(|server| {
                        dns_server_configuration(
                            server,
                            Some(link.ifindex),
                            accessible,
                        )
                    })
                    .collect(),
            ),
        ),
        ("fallbackServers", Value::Null),
        (
            "searchDomains",
            optional_array(
                link.domains
                    .iter()
                    .map(|domain| {
                        search_domain_configuration(domain, Some(link.ifindex))
                    })
                    .collect(),
            ),
        ),
        (
            "negativeTrustAnchors",
            optional_array(
                link.dnssec_negative_trust_anchors
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        (
            "dnssec",
            Value::String(validation_mode_name(link.dnssec).to_owned()),
        ),
        (
            "dnssecSupported",
            Value::Bool(resolver.link_dnssec_supported(link.ifindex)),
        ),
        (
            "dnsOverTLS",
            Value::String(tls_mode_name(link.dns_over_tls).to_owned()),
        ),
        (
            "llmnr",
            Value::String(support_mode_name(link.llmnr).to_owned()),
        ),
        (
            "mDNS",
            Value::String(support_mode_name(link.multicast_dns).to_owned()),
        ),
        ("resolvConfMode", Value::Null),
        ("scopes", optional_array(scopes)),
    ])
}

fn link_dns_scopes(resolver: &Resolver, link: &crate::routing::LinkState) -> Vec<Value> {
    let ifname = link.kernel.as_ref().map(|kernel| kernel.ifname.as_str());
    let mut scopes = Vec::new();
    if !link.dns_servers.is_empty()
        && link.kernel_relevant_unicast()
        && resolver.networkd_link_relevant(link.ifindex)
    {
        scopes.push(dns_scope_configuration(
            "dns",
            None,
            Some(link.ifindex),
            ifname,
            Some(validation_mode_name(link.dnssec)),
            Some(tls_mode_name(link.dns_over_tls)),
        ));
    }
    let Some(kernel) = &link.kernel else {
        return scopes;
    };
    let llmnr = resolver.llmnr_mode_for_link(Some(link.ifindex));
    let mdns = resolver.multicast_dns_mode_for_link(Some(link.ifindex));
    for (family, relevant) in [
        (
            2,
            kernel.relevant_multicast(2) && resolver.networkd_link_relevant(link.ifindex),
        ),
        (
            10,
            kernel.relevant_multicast(10) && resolver.networkd_link_relevant(link.ifindex),
        ),
    ] {
        if relevant && llmnr != crate::config::SupportMode::No {
            scopes.push(dns_scope_configuration(
                "llmnr",
                Some(family),
                Some(link.ifindex),
                ifname,
                None,
                None,
            ));
        }
        if relevant && mdns != crate::config::SupportMode::No {
            scopes.push(dns_scope_configuration(
                "mdns",
                Some(family),
                Some(link.ifindex),
                ifname,
                None,
                None,
            ));
        }
    }
    scopes
}

fn dns_scope_configuration(
    protocol: &str,
    family: Option<i32>,
    ifindex: Option<i32>,
    ifname: Option<&str>,
    dnssec: Option<&str>,
    dns_over_tls: Option<&str>,
) -> Value {
    dns_configuration_object([
        ("protocol", Value::String(protocol.to_owned())),
        (
            "family",
            family.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
        (
            "ifindex",
            ifindex.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
        (
            "ifname",
            ifname.map_or(Value::Null, |value| Value::String(value.to_owned())),
        ),
        (
            "dnssec",
            dnssec.map_or(Value::Null, |value| Value::String(value.to_owned())),
        ),
        (
            "dnsOverTLS",
            dns_over_tls.map_or(Value::Null, |value| Value::String(value.to_owned())),
        ),
    ])
}

fn configured_server_specs(
    config: &crate::config::Config,
    fallback: bool,
) -> Vec<crate::config::DnsServerSpec> {
    let (specs, addresses) = if fallback {
        (&config.fallback_upstream_specs, &config.fallback_upstreams)
    } else {
        (&config.upstream_specs, &config.upstreams)
    };
    if specs.is_empty() {
        addresses
            .iter()
            .copied()
            .map(|address| crate::config::DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            })
            .collect()
    } else {
        specs.clone()
    }
}

fn dns_server_configuration(
    server: &crate::config::DnsServerSpec,
    default_ifindex: Option<i32>,
    accessible: bool,
) -> Value {
    let (family, address): (i32, Vec<u8>) = match server.address.ip() {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    };
    let ifindex = server
        .interface
        .as_deref()
        .and_then(|interface| crate::interface::resolve_ifindex(interface).ok())
        .or(default_ifindex);
    let address_string = match (server.address.ip(), server.interface.as_deref()) {
        (IpAddr::V6(address), Some(interface)) => format!("{address}%{interface}"),
        (address, _) => address.to_string(),
    };

    dns_configuration_object([
        (
            "address",
            Value::Array(
                address
                    .into_iter()
                    .map(|byte| Value::Number(i128::from(byte)))
                    .collect(),
            ),
        ),
        ("addressString", Value::String(address_string)),
        ("family", Value::Number(i128::from(family))),
        (
            "port",
            Value::Number(i128::from(server.address.port())),
        ),
        (
            "ifindex",
            ifindex.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
        (
            "name",
            server
                .server_name
                .as_ref()
                .map_or(Value::Null, |name| Value::String(name.clone())),
        ),
        ("accessible", Value::Bool(accessible)),
    ])
}

fn search_domain_configuration(
    domain: &crate::config::Domain,
    ifindex: Option<i32>,
) -> Value {
    dns_configuration_object([
        ("name", Value::String(domain.name.clone())),
        ("routeOnly", Value::Bool(domain.route_only)),
        (
            "ifindex",
            ifindex.map_or(Value::Null, |value| Value::Number(i128::from(value))),
        ),
    ])
}

const fn support_mode_name(mode: crate::config::SupportMode) -> &'static str {
    match mode {
        crate::config::SupportMode::No => "no",
        crate::config::SupportMode::Resolve => "resolve",
        crate::config::SupportMode::Yes => "yes",
    }
}

const fn validation_mode_name(mode: crate::config::ValidationMode) -> &'static str {
    match mode {
        crate::config::ValidationMode::No => "no",
        crate::config::ValidationMode::AllowDowngrade => "allow-downgrade",
        crate::config::ValidationMode::Yes => "yes",
    }
}

const fn tls_mode_name(mode: crate::config::TlsMode) -> &'static str {
    match mode {
        crate::config::TlsMode::No => "no",
        crate::config::TlsMode::Opportunistic => "opportunistic",
        crate::config::TlsMode::Yes => "yes",
    }
}

#[cfg(test)]
mod dns_configuration_tests {
    use super::*;
    use crate::config::{
        Config, DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode,
    };
    use crate::routing::KernelLinkState;

    #[test]
    fn dump_reports_global_and_per_link_configuration() {
        let global_server = DnsServerSpec {
            address: "192.0.2.53:9953".parse().expect("global server"),
            interface: None,
            server_name: Some("resolver.example".to_owned()),
        };
        let fallback_server = DnsServerSpec {
            address: "198.51.100.53:53".parse().expect("fallback server"),
            interface: None,
            server_name: None,
        };
        let config = Config {
            upstreams: vec![global_server.address],
            upstream_specs: vec![global_server],
            fallback_upstreams: vec![fallback_server.address],
            fallback_upstream_specs: vec![fallback_server],
            domains: vec![Domain {
                name: "example.test".to_owned(),
                route_only: false,
            }],
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Opportunistic,
            llmnr: SupportMode::Resolve,
            multicast_dns: SupportMode::Yes,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 7,
                ifname: "test7".to_owned(),
                flags: 0x1_1001,
                mtu: 1500,
                operstate: 6,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");
        resolver
            .set_link_dns_specs(
                7,
                vec![DnsServerSpec {
                    address: "203.0.113.53:853".parse().expect("link server"),
                    interface: Some("test7".to_owned()),
                    server_name: Some("link-resolver.example".to_owned()),
                }],
            )
            .expect("set link DNS");
        resolver
            .set_link_domains(
                7,
                vec![Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                }],
            )
            .expect("set link domains");
        resolver
            .set_link_default_route(7, Some(true))
            .expect("set link default route");
        resolver
            .set_link_dnssec_negative_trust_anchors(
                7,
                vec!["internal.example".to_owned()],
            )
            .expect("set link NTA");

        let reply = dispatch(
            r#"{"method":"io.rustd.Resolve.DumpDNSConfiguration","parameters":{}}"#,
            &resolver,
        );
        assert!(reply.get("error").is_none(), "{}", reply.to_json());
        assert!(
            !reply.to_json().contains(":null"),
            "optional DNS configuration fields must be omitted: {}",
            reply.to_json()
        );
        let configuration = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("configuration"))
            .and_then(Value::as_array)
            .expect("configuration array");
        assert_eq!(configuration.len(), 2);

        let global = &configuration[0];
        assert!(global.get("ifname").is_none());
        assert!(global.get("delegate").is_none());
        let current = global.get("currentServer").expect("current global server");
        assert_eq!(current.get("port").and_then(Value::as_u64), Some(9953));
        assert_eq!(
            current.get("name").and_then(Value::as_str),
            Some("resolver.example")
        );
        assert_eq!(global.get("dnssec").and_then(Value::as_str), Some("yes"));
        assert!(global.get("resolvConfMode").and_then(Value::as_str).is_some());
        let global_scope = global
            .get("scopes")
            .and_then(Value::as_array)
            .and_then(|scopes| scopes.first())
            .expect("global DNS scope");
        assert_eq!(
            global_scope.get("protocol").and_then(Value::as_str),
            Some("dns")
        );
        assert_eq!(
            global_scope.get("dnssec").and_then(Value::as_str),
            Some("yes")
        );
        assert!(global_scope.get("family").is_none());

        let link = &configuration[1];
        assert!(link.get("delegate").is_none());
        assert_eq!(link.get("ifindex").and_then(Value::as_i64), Some(7));
        assert_eq!(link.get("ifname").and_then(Value::as_str), Some("test7"));
        assert_eq!(link.get("defaultRoute").and_then(Value::as_bool), Some(true));
        let link_server = link
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .expect("link server");
        assert_eq!(link_server.get("port").and_then(Value::as_u64), Some(853));
        assert_eq!(
            link_server.get("name").and_then(Value::as_str),
            Some("link-resolver.example")
        );
        assert_eq!(
            link_server.get("accessible").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            link.get("searchDomains")
                .and_then(Value::as_array)
                .and_then(|domains| domains.first())
                .and_then(|domain| domain.get("routeOnly"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            link.get("negativeTrustAnchors")
                .and_then(Value::as_array)
                .and_then(|anchors| anchors.first())
                .and_then(Value::as_str),
            Some("internal.example")
        );
        let link_scopes = link
            .get("scopes")
            .and_then(Value::as_array)
            .expect("link DNS scopes");
        assert!(link_scopes.iter().any(|scope| {
            scope.get("protocol").and_then(Value::as_str) == Some("dns")
                && scope.get("family").is_none()
        }));
        for protocol in ["llmnr", "mdns"] {
            assert!(link_scopes.iter().any(|scope| {
                scope.get("protocol").and_then(Value::as_str) == Some(protocol)
                    && scope.get("family").and_then(Value::as_i64) == Some(2)
            }));
        }
    }

    #[test]
    fn link_without_unicast_scope_is_not_a_default_route() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 8,
                ifname: "dns2".to_owned(),
                flags: 0x83,
                mtu: 1500,
                operstate: 0,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");
        let link = resolver.link(8).expect("link state");
        let configuration = link_dns_configuration(&resolver, &link);
        assert_eq!(
            configuration
                .get("defaultRoute")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn explicit_link_default_route_is_reported_without_unicast_scope() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 8,
                ifname: "dns2".to_owned(),
                flags: 0x83,
                mtu: 1500,
                operstate: 0,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");
        resolver
            .set_link_default_route(8, Some(true))
            .expect("set explicit default route");

        let link = resolver.link(8).expect("link state");
        let configuration = link_dns_configuration(&resolver, &link);
        assert_eq!(
            configuration
                .get("defaultRoute")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn empty_optional_configuration_lists_are_omitted() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![KernelLinkState {
                ifindex: 8,
                ifname: "dns2".to_owned(),
                flags: 0x83,
                mtu: 1500,
                operstate: 0,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");

        let reply = dump_dns_configuration(&resolver);
        let configuration = reply
            .get("parameters")
            .and_then(|parameters| parameters.get("configuration"))
            .and_then(Value::as_array)
            .expect("configuration array");
        for entry in configuration {
            assert!(entry.get("servers").is_none(), "{}", entry.to_json());
            assert!(entry.get("searchDomains").is_none(), "{}", entry.to_json());
        }
        assert!(
            configuration[1].get("negativeTrustAnchors").is_none(),
            "{}",
            configuration[1].to_json()
        );
    }
}
