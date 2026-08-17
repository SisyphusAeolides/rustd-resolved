#[cfg(test)]
mod test_26_request_flags {
    use super::*;
    use crate::resolve_flags::flags::{
        RUSTD_RESOLVE_DNS, RUSTD_RESOLVE_MDNS_IPV4, RUSTD_RESOLVE_MDNS_IPV6,
        RUSTD_RESOLVE_NO_NETWORK, RUSTD_RESOLVE_NO_SYNTHESIZE,
    };

    #[test]
    fn no_synthesize_and_no_network_exclude_localhost() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 0x7600).expect("localhost query");
        resolver
            .query_on_link_with_flags(
                &query,
                QueryMode::Full,
                None,
                RUSTD_RESOLVE_NO_SYNTHESIZE | RUSTD_RESOLVE_NO_NETWORK,
            )
            .expect_err("synthesis and network are both disabled");
    }

    #[test]
    fn no_network_still_allows_synthetic_answers() {
        let resolver = Resolver::new(Config::default());
        let query = make_query("localhost", TYPE_A, 0x7601).expect("localhost query");
        let (_, flags) = resolver
            .query_on_link_with_flags(
                &query,
                QueryMode::Full,
                None,
                RUSTD_RESOLVE_NO_NETWORK,
            )
            .expect("synthetic response");
        assert_eq!(flags, synthetic_response_flags(0, &query));
    }

    #[test]
    fn protocol_masks_exclude_incompatible_scopes() {
        let resolver = Resolver::new(Config::default());
        let local = make_query("printer.local", TYPE_A, 0x7602).expect("mDNS query");
        assert!(matches!(
            resolver.query_on_link_with_flags(&local, QueryMode::Full, None, RUSTD_RESOLVE_DNS),
            Err(ResolveError::NoSuchResourceRecord)
        ));

        let dns = make_query("example.test", TYPE_A, 0x7603).expect("DNS query");
        assert!(matches!(
            resolver.query_on_link_with_flags(
                &dns,
                QueryMode::Full,
                None,
                RUSTD_RESOLVE_MDNS_IPV4 | RUSTD_RESOLVE_MDNS_IPV6,
            ),
            Err(ResolveError::NoNameServers)
        ));
    }

    #[test]
    fn grouped_hook_completion_does_not_skip_multicast_routing() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let result = resolver.query_following_redirects_dual_after_grouped_hook(
            "printer.local",
            "printer.local",
            wire::CLASS_IN,
            TYPE_A,
            None,
            RUSTD_RESOLVE_MDNS_IPV4 | RUSTD_RESOLVE_NO_NETWORK,
        );
        assert!(matches!(result, Err(ResolveError::NoSuchResourceRecord)));
    }

    #[test]
    fn synthetic_protocol_follows_the_request_mask() {
        let resolver = Resolver::new(Config::default());
        let query = make_query("localhost", TYPE_A, 0x7604).expect("localhost query");
        let (_, flags) = resolver
            .query_on_link_with_flags(
                &query,
                QueryMode::Full,
                None,
                crate::resolve_flags::flags::RUSTD_RESOLVE_LLMNR_IPV4,
            )
            .expect("LLMNR-labelled synthetic response");
        assert_ne!(flags & crate::resolve_flags::flags::RUSTD_RESOLVE_LLMNR_IPV4, 0);
        assert_eq!(flags & RUSTD_RESOLVE_DNS, 0);
    }

    #[test]
    fn output_only_flags_are_rejected() {
        assert!(query_flags_are_valid(0, 0));
        assert!(!query_flags_are_valid(
            crate::resolve_flags::flags::RUSTD_RESOLVE_FROM_NETWORK,
            0
        ));
        assert!(!query_flags_are_valid(
            crate::resolve_flags::flags::RUSTD_RESOLVE_REQUIRE_PRIMARY
                | crate::resolve_flags::flags::RUSTD_RESOLVE_CLAMP_TTL,
            0
        ));
    }
}
