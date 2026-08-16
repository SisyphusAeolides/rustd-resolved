#[cfg(test)]
mod test_23_dns_over_tls_policy {
    use super::*;
    use crate::wire::LocalRecord;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn opportunistic_tls_failure_falls_back_to_plain_dns() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TLS bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDP timeout");

        let stream_thread = thread::spawn(move || {
            let (stream, _) = stream_listener.accept().expect("mock TLS accept");
            drop(stream);
        });
        let datagram_thread = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = datagram_socket
                .recv_from(&mut buffer)
                .expect("plaintext DNS fallback");
            let response = local_response(
                &buffer[..length],
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 123))],
                30,
            )
            .expect("mock DNS response");
            let response = edns::add_test_response_opt(&response, 0, false).expect("response OPT");
            datagram_socket
                .send_to(&response, peer)
                .expect("plaintext DNS response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 2,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            dns_over_tls: TlsMode::Opportunistic,
            ..Config::default()
        });
        let query = make_query("opportunistic-tls.example", TYPE_A, 0x7a01).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("opportunistic fallback response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123))]
        );

        let mut states = resolver.states();
        let state = states
            .get_mut(&ServerKey::new(ScopeKind::Global, server_address))
            .expect("server state");
        assert!(!state.features.current_possible_level().uses_tls());
        drop(states);

        stream_thread.join().expect("mock TLS thread");
        datagram_thread.join().expect("mock UDP thread");
    }

    #[test]
    fn strict_tls_failure_never_emits_plain_dns() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TLS bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("mock UDP timeout");

        let stream_thread = thread::spawn(move || {
            let (stream, _) = stream_listener.accept().expect("mock TLS accept");
            drop(stream);
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 2,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            dns_over_tls: TlsMode::Yes,
            ..Config::default()
        });
        let query = make_query("strict-tls.example", TYPE_A, 0x7a02).expect("client query");
        assert!(resolver.query(&query, QueryMode::Full).is_err());

        let mut buffer = [0; 2048];
        let error = datagram_socket
            .recv_from(&mut buffer)
            .expect_err("strict TLS must not fall back to UDP");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));

        stream_thread.join().expect("mock TLS thread");
    }

    #[test]
    fn strict_tls_dnssec_mode_also_refuses_plain_dns_fallback() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TLS bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("mock UDP timeout");
        let udp_seen = Arc::new(AtomicBool::new(false));
        let udp_seen_worker = Arc::clone(&udp_seen);

        let stream_thread = thread::spawn(move || {
            let (stream, _) = stream_listener.accept().expect("mock TLS accept");
            drop(stream);
        });
        let udp_thread = thread::spawn(move || {
            let mut buffer = [0; 2048];
            if datagram_socket.recv_from(&mut buffer).is_ok_and(|_| {
                udp_seen_worker.store(true, Ordering::SeqCst);
                true
            }) {
                panic!("resolver should not fallback to UDP");
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 2,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::Yes,
            dns_over_tls: TlsMode::Yes,
            ..Config::default()
        });
        let query = make_query("strict-tls-dnssec.example", TYPE_A, 0x7a03).expect("client query");
        assert!(resolver.query(&query, QueryMode::Full).is_err());
        assert!(!udp_seen.load(Ordering::SeqCst));

        stream_thread.join().expect("mock TLS thread");
        udp_thread.join().expect("mock UDP thread");
    }

    #[test]
    fn strict_tls_malformed_reply_drops_dnssec_but_stays_on_tls() {
        let resolver = Resolver::new(Config::default());
        let server = ServerKey::new(
            ScopeKind::Global,
            "192.0.2.53:853".parse().expect("test server"),
        );

        assert_eq!(
            resolver.record_invalid_packet(
                server,
                FeatureLevel::TlsPlain,
                ValidationMode::No,
                true,
            ),
            None
        );
        assert_eq!(
            resolver
                .states()
                .get(&server)
                .expect("server state")
                .features
                .current_possible_level(),
            FeatureLevel::TlsDnssecOk
        );
        assert!(
            resolver
                .states()
                .get(&server)
                .expect("server state")
                .packet_invalid
        );

        assert_eq!(
            resolver.record_invalid_packet(
                server,
                FeatureLevel::TlsDnssecOk,
                ValidationMode::No,
                true,
            ),
            Some(FeatureLevel::TlsPlain)
        );
        assert_eq!(
            resolver
                .states()
                .get(&server)
                .expect("server state")
                .features
                .current_possible_level(),
            FeatureLevel::TlsPlain
        );
    }
}
