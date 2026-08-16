#[cfg(test)]
mod test_28_configuration_reload {
    use super::*;
    use crate::routing::KernelLinkState;

    fn kernel_link(ifindex: i32) -> KernelLinkState {
        KernelLinkState {
            ifindex,
            ifname: format!("test{ifindex}"),
            flags: 0x0083,
            mtu: 1500,
            operstate: 0,
            has_ipv4_global: true,
            has_ipv4_link_local: false,
            has_ipv6_global: false,
            has_ipv6_link_local: false,
        }
    }

    #[test]
    fn reload_replaces_live_fallback_servers() {
        let mut initial = Config::default();
        initial
            .fallback_upstreams
            .push("192.0.2.53:53".parse().expect("fallback server"));
        let resolver = Resolver::new(initial);
        assert!(!resolver.config().configured_fallback_upstreams().is_empty());

        let mut reloaded = Config::default();
        reloaded.fallback_upstreams.clear();
        reloaded.fallback_upstream_specs.clear();
        assert!(resolver.reload_config(reloaded));
        assert!(resolver.config().configured_fallback_upstreams().is_empty());

        let query = make_query(".", 33, 0x2800).expect("root SRV query");
        assert!(matches!(
            resolver.query_on_link_with_flags(&query, QueryMode::Full, None, 0),
            Err(ResolveError::NoNameServers)
        ));
    }

    #[test]
    fn reload_applies_stale_retention() {
        let resolver = Resolver::new(Config::default());
        let mut reloaded = Config::default();
        reloaded.stale_retention = Duration::from_secs(86_400);

        assert!(resolver.reload_config(reloaded));
        assert_eq!(resolver.config().stale_retention, Duration::from_secs(86_400));
    }

    #[test]
    fn every_reload_disconnects_transports_and_drops_non_link_server_state() {
        let resolver = Resolver::new(Config::default());
        let address: SocketAddr = "127.0.0.1:53".parse().expect("server address");
        let global = ServerKey::new(ScopeKind::Global, address);
        let link = ServerKey::new(ScopeKind::Link(7), address);
        resolver.record_failure(global, Duration::from_millis(10));
        resolver.record_failure(link, Duration::from_millis(10));
        resolver.recycle_udp_socket(
            global,
            UdpSocket::bind("127.0.0.1:0").expect("UDP socket"),
        );

        assert!(!resolver.reload_config(resolver.config()));
        assert!(resolver
            .udp_sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty());
        let states = resolver.states();
        assert!(!states.contains_key(&global));
        assert!(states.contains_key(&link));
    }

    #[test]
    fn new_links_inherit_global_dnssec_and_tls_policy() {
        let resolver = Resolver::new(Config {
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Opportunistic,
            ..Config::default()
        });

        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");

        let link = resolver.link(7).expect("link state");
        assert_eq!(link.dnssec, ValidationMode::Yes);
        assert_eq!(link.dns_over_tls, TlsMode::Opportunistic);
    }

    #[test]
    fn reload_updates_inherited_link_policy_and_preserves_explicit_overrides() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7), kernel_link(8)])
            .expect("kernel link state");
        resolver
            .set_link_dnssec(8, ValidationMode::AllowDowngrade)
            .expect("explicit DNSSEC policy");
        resolver
            .set_link_dns_over_tls(8, TlsMode::No)
            .expect("explicit TLS policy");

        let reloaded = Config {
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Yes,
            ..Config::default()
        };
        assert!(resolver.reload_config(reloaded));

        let inherited = resolver.link(7).expect("inherited link state");
        assert_eq!(inherited.dnssec, ValidationMode::Yes);
        assert_eq!(inherited.dns_over_tls, TlsMode::Yes);
        let explicit = resolver.link(8).expect("explicit link state");
        assert_eq!(explicit.dnssec, ValidationMode::AllowDowngrade);
        assert_eq!(explicit.dns_over_tls, TlsMode::No);
    }

    #[test]
    fn clearing_link_overrides_restores_live_manager_policy() {
        let resolver = Resolver::new(Config {
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Yes,
            ..Config::default()
        });
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .set_link_dnssec(7, ValidationMode::No)
            .expect("explicit DNSSEC policy");
        resolver
            .set_link_dns_over_tls(7, TlsMode::No)
            .expect("explicit TLS policy");

        resolver
            .set_link_dnssec_override(7, None)
            .expect("clear DNSSEC override");
        resolver
            .set_link_dns_over_tls_override(7, None)
            .expect("clear TLS override");

        let link = resolver.link(7).expect("link state");
        assert_eq!(link.dnssec, ValidationMode::Yes);
        assert_eq!(link.dns_over_tls, TlsMode::Yes);
    }
}
