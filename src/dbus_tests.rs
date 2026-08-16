// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v261_resolve1_surface_inventory_is_exact() {
        assert_eq!(
            crate::dbus_resolve1_abi::MANAGER_METHODS,
            [
                "ResolveHostname",
                "ResolveAddress",
                "ResolveRecord",
                "ResolveService",
                "GetLink",
                "SetLinkDNS",
                "SetLinkDNSEx",
                "SetLinkDomains",
                "SetLinkDefaultRoute",
                "SetLinkLLMNR",
                "SetLinkMulticastDNS",
                "SetLinkDNSOverTLS",
                "SetLinkDNSSEC",
                "SetLinkDNSSECNegativeTrustAnchors",
                "RevertLink",
                "RegisterService",
                "UnregisterService",
                "GetDelegate",
                "ListDelegates",
                "ResetStatistics",
                "FlushCaches",
                "ResetServerFeatures",
            ]
        );
        assert_eq!(
            crate::dbus_resolve1_abi::MANAGER_PROPERTIES,
            [
                "LLMNRHostname",
                "LLMNR",
                "MulticastDNS",
                "DNSOverTLS",
                "DNS",
                "DNSEx",
                "FallbackDNS",
                "FallbackDNSEx",
                "CurrentDNSServer",
                "CurrentDNSServerEx",
                "Domains",
                "TransactionStatistics",
                "CacheStatistics",
                "DNSSECStatistics",
                "DNSSECSupported",
                "DNSSECNegativeTrustAnchors",
                "DNSSEC",
                "DNSStubListener",
                "ResolvConfMode",
            ]
        );
        assert_eq!(
            crate::dbus_resolve1_abi::LINK_METHODS,
            [
                "SetDNS",
                "SetDNSEx",
                "SetDomains",
                "SetDefaultRoute",
                "SetLLMNR",
                "SetMulticastDNS",
                "SetDNSOverTLS",
                "SetDNSSEC",
                "SetDNSSECNegativeTrustAnchors",
                "Revert",
            ]
        );
        assert_eq!(
            crate::dbus_resolve1_abi::LINK_PROPERTIES,
            [
                "ScopesMask",
                "DNS",
                "DNSEx",
                "CurrentDNSServer",
                "CurrentDNSServerEx",
                "Domains",
                "DefaultRoute",
                "LLMNR",
                "MulticastDNS",
                "DNSOverTLS",
                "DNSSEC",
                "DNSSECNegativeTrustAnchors",
                "DNSSECSupported",
            ]
        );

        assert!(crate::dbus_resolve1_abi::method_supported("RegisterService"));
        assert!(!crate::dbus_resolve1_abi::method_supported("Reload"));
        assert!(crate::dbus_resolve1_abi::manager_property_supported("FallbackDNSEx"));
        assert!(crate::dbus_resolve1_abi::link_method_supported("Revert"));
        assert!(crate::dbus_resolve1_abi::link_property_supported("ScopesMask"));
    }

    #[test]
    fn vanished_dbus_owner_cancels_only_its_registered_queries() {
        let registry = ClientQueryRegistry::default();
        let vanished = crate::query_cancel::QueryCancellation::default();
        let active = crate::query_cancel::QueryCancellation::default();
        {
            let mut queries = registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queries.insert(":1.40".to_owned(), vec![vanished.clone()]);
            queries.insert(":1.41".to_owned(), vec![active.clone()]);
        }

        cancel_client_queries(&registry, ":1.40");

        assert!(vanished.is_cancelled());
        assert!(!active.is_cancelled());
        let queries = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!queries.contains_key(":1.40"));
        assert!(queries.contains_key(":1.41"));
    }

    #[test]
    fn object_paths_match_systemd_bus_label_encoding() {
        assert_eq!(
            link_object_path(2).expect("path").as_str(),
            "/org/freedesktop/resolve1/link/_32"
        );
        assert_eq!(
            link_object_path(12).expect("path").as_str(),
            "/org/freedesktop/resolve1/link/_312"
        );
        assert_eq!(
            dnssd_object_path("web.service").expect("path").as_str(),
            "/org/freedesktop/resolve1/dnssd/web_2eservice"
        );
        assert_eq!(
            delegate_object_path("corp-vpn").expect("path").as_str(),
            "/org/freedesktop/resolve1/dns_delegate/corp_2dvpn"
        );
    }

    #[test]
    fn address_conversion_is_strict() {
        assert_eq!(
            decode_address(AF_INET, &[192, 0, 2, 1]).expect("IPv4"),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert!(decode_address(AF_INET6, &[0; 15]).is_err());
        assert!(decode_address(AF_UNSPEC, &[]).is_err());
    }

    #[test]
    fn modes_round_trip() {
        assert_eq!(
            parse_support_mode("resolve").expect("support"),
            SupportMode::Resolve
        );
        assert_eq!(
            parse_tls_mode("opportunistic").expect("TLS"),
            Some(TlsMode::Opportunistic)
        );
        assert_eq!(
            parse_validation_mode("allow-downgrade").expect("DNSSEC"),
            Some(ValidationMode::AllowDowngrade)
        );
        assert_eq!(parse_tls_mode("").expect("inherited TLS"), None);
        assert_eq!(parse_validation_mode("").expect("inherited DNSSEC"), None);
    }

    #[test]
    #[cfg(feature = "idna-name")]
    fn service_names_are_validated() {
        assert!(service_owner("printer", "_ipp._tcp", "example.test").is_ok());
        let (owner, unicast_owner, name, _, _) =
            service_owner("Café.Desk", "_ipp._tcp", "bücher.example")
                .expect("internationalized service owner");
        assert_eq!(owner, r"Caf\195\169\046Desk._ipp._tcp.bücher.example");
        assert_eq!(
            unicast_owner,
            r"Caf\195\169\046Desk._ipp._tcp.xn--bcher-kva.example"
        );
        assert_eq!(name, "Café.Desk");
        assert_eq!(
            split_service_owner(r"Caf\195\169\046Desk._ipp._tcp.xn--bcher-kva.example"),
            Some((
                "Café.Desk".to_owned(),
                "_ipp._tcp".to_owned(),
                "xn--bcher-kva.example".to_owned(),
            ))
        );
        assert!(service_owner("printer", "ipp.tcp", "example.test").is_err());
    }

    #[test]
    fn cname_loops_keep_the_dbus_error_contract() {
        let error = map_resolve_error(ResolveError::Wire(crate::wire::WireError::CnameLoop));
        assert!(matches!(error, DbusError::CNameLoop(_)));
    }

    #[test]
    fn aborted_queries_keep_the_dbus_error_contract() {
        let error = map_resolve_error(ResolveError::QueryAborted);
        assert!(matches!(error, DbusError::Aborted(_)));
    }

    #[test]
    fn resolver_states_keep_their_specific_dbus_errors() {
        for (error, expected) in [
            (ResolveError::MaxAttemptsReached, "org.freedesktop.DBus.Error.Timeout"),
            (ResolveError::NoTrustAnchor, "org.freedesktop.resolve1.NoTrustAnchor"),
            (ResolveError::StubLoop, "org.freedesktop.resolve1.StubLoop"),
            (
                ResolveError::InconsistentServiceRecords,
                "org.freedesktop.resolve1.InconsistentServiceRecords",
            ),
            (
                ResolveError::Link(LinkError::NoSuchLink(99)),
                "org.freedesktop.resolve1.NoSource",
            ),
            (
                ResolveError::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
                "org.freedesktop.DBus.Error.Timeout",
            ),
        ] {
            assert_eq!(
                zbus::DBusError::name(&map_resolve_error(error)).as_str(),
                expected
            );
        }
        let dnssec = map_resolve_error(ResolveError::DnssecValidationFailed {
            result: "bogus".to_owned(),
            extended_dns_error_code: None,
            extended_dns_error_message: None,
        });
        assert_eq!(
            zbus::DBusError::name(&dnssec).as_str(),
            "org.freedesktop.resolve1.DnssecFailed"
        );
    }

    #[test]
    fn managed_links_keep_the_dbus_link_busy_contract() {
        let error = map_link_error(LinkError::ManagedLink(7));
        assert!(matches!(error, DbusError::LinkBusy(_)));
    }

    #[test]
    fn scopes_mask_reports_only_allocated_protocol_families() {
        let resolver = Resolver::new(crate::config::Config::default());
        resolver
            .sync_kernel_links(vec![crate::routing::KernelLinkState {
                ifindex: 7,
                ifname: "dns0".to_owned(),
                flags: 0x0001 | 0x0040 | 0x1000 | 0x1_0000,
                mtu: 1500,
                operstate: 0,
                has_ipv4_global: true,
                has_ipv4_link_local: false,
                has_ipv6_global: false,
                has_ipv6_link_local: false,
            }])
            .expect("synchronize link");
        resolver
            .set_link_dns(7, vec!["192.0.2.53:53".parse().expect("DNS server")])
            .expect("set link DNS");
        let link = resolver.link(7).expect("link");
        assert_eq!(
            link_scopes_mask(&resolver, &link),
            SD_RESOLVED_DNS | SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_MDNS_IPV4
        );
    }

    #[test]
    fn dns_ex_default_ports_and_server_names_round_trip() {
        let decoded = decode_dns_server_specs(vec![(
            AF_INET,
            vec![192, 0, 2, 53],
            853,
            "resolver.example".to_owned(),
        )])
        .expect("DNSEx server");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].address.port(), DNS_PORT);
        assert_eq!(decoded[0].server_name.as_deref(), Some("resolver.example"));

        let entry = link_dns_ex_entry(decoded[0].clone());
        assert_eq!(entry.2, 0);
        assert_eq!(entry.3, "resolver.example");
    }

    #[test]
    fn dns_ex_custom_ports_are_preserved() {
        assert_eq!(dns_ex_input_port(9953), 9953);
        assert_eq!(dns_ex_output_port(9953), 9953);
        assert_eq!(dns_ex_input_port(53), DNS_PORT);
        assert_eq!(dns_ex_input_port(853), DNS_PORT);
        assert_eq!(dns_ex_output_port(53), 0);
        assert_eq!(dns_ex_output_port(853), 0);
    }

    #[test]
    fn reply_flags_distinguish_dns_from_no_validate() {
        let response = crate::wire::local_response(
            &crate::wire::make_query("localhost", crate::wire::TYPE_A, 7).expect("query"),
            &[],
            0,
        )
        .expect("response");
        let flags = response_flags(&response);
        assert_ne!(flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_DNS, 0);
        assert_eq!(
            flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_VALIDATE,
            0
        );
    }

    #[test]
    fn reverse_lookup_replies_use_the_answering_interface() {
        let lookup = AddressLookup {
            names: vec!["host.example".to_owned()],
            name_ifindices: vec![Some(8)],
            flags: 17,
        };
        assert_eq!(
            address_lookup_reply(lookup, 7),
            (vec![(8, "host.example".to_owned())], 17)
        );
    }

    #[test]
    fn authorization_errors_use_standard_dbus_names() {
        assert_eq!(
            zbus::DBusError::name(&DbusError::AccessDenied("denied".to_owned())).as_str(),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
        assert_eq!(
            zbus::DBusError::name(&DbusError::InteractiveAuthorizationRequired(
                "interaction required".to_owned()
            ))
            .as_str(),
            "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
        );
        assert_eq!(
            zbus::DBusError::name(&DbusError::InvalidArgs("invalid".to_owned())).as_str(),
            "org.freedesktop.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::name(&DbusError::NotSupported("unsupported".to_owned())).as_str(),
            "org.freedesktop.DBus.Error.NotSupported"
        );
        assert_eq!(
            zbus::DBusError::name(&DbusError::NoNameServers("none".to_owned())).as_str(),
            "org.freedesktop.resolve1.NoNameServers"
        );
        assert_eq!(
            zbus::DBusError::name(&DbusError::NoSuchDelegate("missing".to_owned())).as_str(),
            "org.freedesktop.resolve1.NoSuchDelegate"
        );
    }

    #[test]
    fn policy_file_covers_the_pinned_v261_actions() {
        let policy = include_str!("../packaging/polkit/org.freedesktop.resolve1.policy");
        let actions = policy
            .split("<action id=\"")
            .skip(1)
            .map(|entry| entry.split_once('"').expect("action id").0)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                "org.freedesktop.resolve1.register-service",
                "org.freedesktop.resolve1.unregister-service",
                "org.freedesktop.resolve1.set-dns-servers",
                "org.freedesktop.resolve1.set-domains",
                "org.freedesktop.resolve1.set-default-route",
                "org.freedesktop.resolve1.set-llmnr",
                "org.freedesktop.resolve1.set-mdns",
                "org.freedesktop.resolve1.set-dns-over-tls",
                "org.freedesktop.resolve1.set-dnssec",
                "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors",
                "org.freedesktop.resolve1.revert",
                "org.freedesktop.resolve1.subscribe-query-results",
                "org.freedesktop.resolve1.subscribe-dns-configuration",
                "org.freedesktop.resolve1.dump-cache",
                "org.freedesktop.resolve1.dump-server-state",
                "org.freedesktop.resolve1.dump-statistics",
                "org.freedesktop.resolve1.reset-statistics",
                "org.freedesktop.resolve1.flush-caches",
                "org.freedesktop.resolve1.reset-server-features",
            ]
        );
    }
}
