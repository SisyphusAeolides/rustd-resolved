#[cfg(test)]
#[allow(clippy::similar_names)]
mod test_14_root_rrsig_detection {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn missing_root_rrsig_downgrades_allow_downgrade_mode() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server_address = socket.local_addr().expect("mock DNS address");

        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
                let query = &buffer[..length];
                let opt = edns::inspect_opt(query)
                    .expect("query OPT")
                    .expect("EDNS query");
                if attempt == 0 {
                    assert!(opt.dnssec_ok());
                } else {
                    assert!(!opt.dnssec_ok());
                }

                let response = unsigned_root_response(
                    query,
                    Ipv4Addr::new(192, 0, 2, 110),
                    attempt == 0,
                );
                socket
                    .send_to(&response, peer)
                    .expect("mock DNS response");
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query(".", TYPE_A, 0x7204).expect("root query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("downgraded response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 110))]
        );

        let mut states = resolver.states();
        let state = states
            .get_mut(&ServerKey::new(ScopeKind::Global, server_address))
            .expect("server state");
        assert!(state.missing_root_rrsig);
        assert_eq!(
            state
                .features
                .possible_level(
                    FeatureLevel::DnssecOk,
                    FeatureLevel::Udp,
                    Instant::now()
                ),
            FeatureLevel::Edns0
        );
        drop(states);
        server.join().expect("mock DNS thread");
    }

    #[test]
    fn missing_root_rrsig_fails_strict_dnssec_mode() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server_address = socket.local_addr().expect("mock DNS address");

        let server = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
            let query = &buffer[..length];
            let opt = edns::inspect_opt(query)
                .expect("query OPT")
                .expect("DNSSEC query");
            assert!(opt.dnssec_ok());
            let response =
                unsigned_root_response(query, Ipv4Addr::new(192, 0, 2, 111), true);
            socket
                .send_to(&response, peer)
                .expect("mock DNS response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::Yes,
            ..Config::default()
        });
        let query = make_query(".", TYPE_A, 0x7205).expect("root query");
        let error = resolver
            .query(&query, QueryMode::Full)
            .expect_err("strict DNSSEC must reject missing RRSIG");
        assert!(matches!(error, ResolveError::Protocol(_)));
        assert!(resolver
            .states()
            .get(&ServerKey::new(ScopeKind::Global, server_address))
            .expect("server state")
            .missing_root_rrsig);
        server.join().expect("mock DNS thread");
    }

    fn unsigned_root_response(
        query: &[u8],
        address: Ipv4Addr,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        let response = local_response(query, &[LocalRecord::A(address)], 30)
            .expect("unsigned root response");
        edns::add_test_response_opt(&response, 0, dnssec_ok).expect("response OPT")
    }
}
