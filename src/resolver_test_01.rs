#[cfg(test)]
mod test_01_localhost_is_answered_without_an_upstream {
    use super::*;

    #[test]
    fn localhost_is_answered_without_an_upstream() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 55).expect("query");
        let (response, flags) = resolver
            .query_on_link_with_flags(&query, QueryMode::Full, None, 0)
            .expect("local response");
        assert_eq!(
            wire::extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        use crate::resolve_flags::flags::{
            RUSTD_RESOLVE_AUTHENTICATED, RUSTD_RESOLVE_CONFIDENTIAL, RUSTD_RESOLVE_DNS,
            RUSTD_RESOLVE_SYNTHETIC,
        };
        assert_eq!(
            flags,
            RUSTD_RESOLVE_DNS
                | RUSTD_RESOLVE_AUTHENTICATED
                | RUSTD_RESOLVE_CONFIDENTIAL
                | RUSTD_RESOLVE_SYNTHETIC
        );
    }

}
