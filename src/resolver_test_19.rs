// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod test_19_refuse_record_types {
    use super::*;

    #[test]
    fn configured_type_is_refused_before_local_synthesis() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA SRV TXT\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_AAAA, 0x7500).expect("AAAA query");
        let response = resolver.query(&query, QueryMode::Full).expect("REFUSED reply");
        let header = Header::parse(&response).expect("response header");
        assert_eq!(header.response_code(), 5);
        assert_eq!(header.answer_count, 0);
        assert_eq!(&response[..2], &0x7500u16.to_be_bytes());
    }

    #[test]
    fn stub_refuses_zone_transfers() {
        let resolver = Resolver::new(Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        });
        for rr_type in [TYPE_IXFR, TYPE_AXFR] {
            let query = make_query("example.test", rr_type, rr_type).expect("transfer query");
            let response = resolver
                .query_or_servfail(&query, QueryMode::Full)
                .expect("REFUSED transfer reply");
            let header = Header::parse(&response).expect("response header");
            assert_eq!(header.response_code(), 5);
            assert_eq!(header.answer_count, 0);
            assert_eq!(&response[..2], &rr_type.to_be_bytes());
        }
    }

    #[test]
    fn stub_refuses_obsolete_and_non_recursive_queries() {
        let resolver = Resolver::new(Config::default());
        for rr_type in [3, 4, 7, 8, 9, 10, 11, 14, 30, 38, 253, 254] {
            let query = make_query("example.test", rr_type, rr_type).expect("obsolete query");
            let response = resolver
                .query_or_servfail(&query, QueryMode::Full)
                .expect("REFUSED obsolete reply");
            assert_eq!(
                Header::parse(&response)
                    .expect("obsolete response header")
                    .response_code(),
                5
            );
        }

        let mut query = make_query("example.test", TYPE_A, 0x7502).expect("query");
        query[2] &= !0x01;
        let response = resolver
            .query_or_servfail(&query, QueryMode::Full)
            .expect("REFUSED non-recursive reply");
        assert_eq!(
            Header::parse(&response)
                .expect("non-recursive response header")
                .response_code(),
            5
        );
    }

    #[test]
    fn stub_replies_badvers_to_unknown_edns_versions() {
        let resolver = Resolver::new(Config::default());
        let query = make_query("example.test", TYPE_A, 0x7503).expect("query");
        let query = crate::edns::add_test_query_opt_version(&query, 1).expect("EDNS query");
        let response = resolver
            .query_or_servfail(&query, QueryMode::Full)
            .expect("BADVERS reply");
        let opt = crate::edns::inspect_opt(&response)
            .expect("OPT parsing")
            .expect("OPT response");
        assert_eq!(
            crate::edns::full_rcode(&response, Some(&opt)).expect("full rcode"),
            16
        );
    }

    #[test]
    fn high_level_record_api_reports_query_refused() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let error = resolver
            .resolve_record("localhost", TYPE_AAAA)
            .expect_err("AAAA must be refused");
        assert!(matches!(error, ResolveError::QueryRefused));
        assert_eq!(error.varlink_id(), "io.rustd.Resolve.QueryRefused");
    }

    #[test]
    fn unrefused_type_still_uses_local_synthesis() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA SRV TXT\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 0x7501).expect("A query");
        let response = resolver.query(&query, QueryMode::Full).expect("A reply");
        let header = Header::parse(&response).expect("response header");
        assert_eq!(header.response_code(), 0);
        assert!(header.answer_count > 0);
    }

    #[test]
    fn proxy_stub_refuses_configured_type_before_fallback_synthesis() {
        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA SRV TXT\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);

        let refused = make_query("localhost", TYPE_AAAA, 0x7505).expect("AAAA query");
        let response = resolver
            .query(&refused, QueryMode::Proxy)
            .expect("REFUSED response");
        assert_eq!(Header::parse(&response).expect("header").response_code(), 5);

        let allowed = make_query("localhost", TYPE_A, 0x7506).expect("A query");
        let response = resolver
            .query(&allowed, QueryMode::Proxy)
            .expect("synthetic response");
        assert_eq!(Header::parse(&response).expect("header").response_code(), 0);
        assert!(Header::parse(&response).expect("header").answer_count > 0);

        let mut config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            ..Config::default()
        };
        config
            .apply_text("[Resolve]\nRefuseRecordTypes=AAAA\n")
            .expect("refuse record type configuration");
        let resolver = Resolver::new(config);
        let allowed = make_query("localhost", 33, 0x7507).expect("SRV query");
        let response = resolver
            .query(&allowed, QueryMode::Proxy)
            .expect("synthetic NODATA response");
        let header = Header::parse(&response).expect("header");
        assert_eq!(header.response_code(), 0);
        assert_eq!(header.answer_count, 0);
    }

    #[test]
    fn empty_assignment_clears_refused_types() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 RefuseRecordTypes=AAAA TYPE65400\n\
                 RefuseRecordTypes=\n",
            )
            .expect("refuse record type configuration");
        assert!(config.refuse_record_types.is_empty());
    }
}
