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
        use crate::dbus_resolve1_abi::flags::{
            SD_RESOLVED_AUTHENTICATED, SD_RESOLVED_CONFIDENTIAL, SD_RESOLVED_DNS,
            SD_RESOLVED_SYNTHETIC,
        };
        assert_eq!(
            flags,
            SD_RESOLVED_DNS
                | SD_RESOLVED_AUTHENTICATED
                | SD_RESOLVED_CONFIDENTIAL
                | SD_RESOLVED_SYNTHETIC
        );
    }

}
