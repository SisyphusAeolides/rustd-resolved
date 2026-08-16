#[cfg(test)]
mod test_27_special_names_are_synthetic_nxdomain {
    use super::*;

    #[test]
    fn pinned_never_resolve_names_return_nxdomain_without_servers() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);

        for name in [
            "0.in-addr.arpa",
            "1.0.in-addr.arpa",
            "255.255.255.255.in-addr.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "hello.invalid",
            "hello.alt",
        ] {
            let query = make_query(name, TYPE_A, 0x2700).expect("query");
            let (response, flags) = resolver
                .query_on_link_with_flags(&query, QueryMode::Full, None, 0)
                .expect("synthetic NXDOMAIN");
            assert_eq!(Header::parse(&response).expect("header").response_code(), 3);
            assert_eq!(flags, synthetic_response_flags(0, &query));
        }
    }

    #[test]
    fn special_suffixes_match_on_dns_label_boundaries() {
        assert!(dns_name_dont_resolve("INVALID."));
        assert!(dns_name_dont_resolve("child.example.alt"));
        assert!(!dns_name_dont_resolve("notinvalid"));
        assert!(!dns_name_dont_resolve("salt"));
        assert!(!dns_name_dont_resolve("10.in-addr.arpa"));
    }
}
