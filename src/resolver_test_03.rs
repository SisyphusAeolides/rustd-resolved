#[cfg(test)]
mod test_03_synthetic_and_parallel_scopes {
    use super::*;
    use crate::routing::ScopeKind;
    use crate::wire::LocalRecord;
    use std::sync::{Arc, Barrier};

    #[test]
    fn synthetic_answers_do_not_depend_on_reading_etc_hosts() {
        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("localhost", 2)
            .expect("synthetic lookup");
        assert_eq!(lookup.addresses, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn fragmented_edns_udp_retries_over_tcp() {
        assert!(udp_requires_tcp_retry(false, 1280, FeatureLevel::Edns0));
        assert!(udp_requires_tcp_retry(
            false,
            1280,
            FeatureLevel::DnssecOk
        ));
        assert!(!udp_requires_tcp_retry(false, 1280, FeatureLevel::Udp));
        assert!(udp_requires_tcp_retry(true, 0, FeatureLevel::Udp));
    }

    #[test]
    fn equivalent_scopes_dispatch_queries_in_parallel() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").expect("first mock DNS bind");
        let second_socket = UdpSocket::bind("127.0.0.1:0").expect("second mock DNS bind");
        let first_server = first_socket.local_addr().expect("first mock DNS address");
        let second_server = second_socket.local_addr().expect("second mock DNS address");
        for socket in [&first_socket, &second_socket] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("mock DNS timeout");
        }

        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let first_thread = thread::spawn(move || {
            reply_after_both_scopes_arrive(
                &first_socket,
                first_barrier.as_ref(),
                Ipv4Addr::new(192, 0, 2, 21),
            );
        });
        let second_thread = thread::spawn(move || {
            reply_after_both_scopes_arrive(
                &second_socket,
                barrier.as_ref(),
                Ipv4Addr::new(192, 0, 2, 22),
            );
        });

        let resolver = Resolver::new(Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let scopes = vec![
            RouteScope {
                kind: ScopeKind::Link(2),
                servers: vec![first_server],
            },
            RouteScope {
                kind: ScopeKind::Link(3),
                servers: vec![second_server],
            },
        ];
        let query = make_query("parallel.example", TYPE_A, 0x7200).expect("client query");
        let started = Instant::now();
        let (response, winning_server) = resolver
            .query_scopes(&scopes, &query, 0)
            .expect("parallel scoped query");
        assert!(started.elapsed() < Duration::from_millis(750));
        assert!(winning_server == first_server || winning_server == second_server);

        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert!(records.addresses.iter().any(|address| {
            matches!(
                address,
                IpAddr::V4(address)
                    if *address == Ipv4Addr::new(192, 0, 2, 21)
                        || *address == Ipv4Addr::new(192, 0, 2, 22)
            )
        }));

        first_thread.join().expect("first mock DNS thread");
        second_thread.join().expect("second mock DNS thread");
    }

    #[test]
    fn localhost_upstream_is_not_cached_by_default() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server = socket.local_addr().expect("mock DNS address");
        let server_thread = thread::spawn(move || {
            for _ in 0..2 {
                reply_once(&socket, Ipv4Addr::new(192, 0, 2, 31));
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let first = make_query("local-cache.example", TYPE_A, 0x7300).expect("first query");
        resolver
            .query(&first, QueryMode::Full)
            .expect("first response");
        assert!(resolver.cache.is_empty());

        let second = make_query("local-cache.example", TYPE_A, 0x7301).expect("second query");
        resolver
            .query(&second, QueryMode::Full)
            .expect("second response");
        assert!(resolver.cache.is_empty());
        server_thread.join().expect("mock DNS thread");
    }

    #[test]
    fn cache_from_localhost_allows_explicit_local_caching() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server = socket.local_addr().expect("mock DNS address");
        let server_thread = thread::spawn(move || {
            reply_once(&socket, Ipv4Addr::new(192, 0, 2, 32));
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            cache_from_localhost: true,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let first = make_query("local-cache.example", TYPE_A, 0x7400).expect("first query");
        let (_, first_flags) = resolver
            .query_on_link_with_flags(&first, QueryMode::Full, None, 0)
            .expect("first response");
        assert_eq!(resolver.cache.len(), 1);
        assert_ne!(
            first_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_NETWORK,
            0
        );
        assert_eq!(
            first_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE,
            0
        );

        let second = make_query("local-cache.example", TYPE_A, 0x7401).expect("second query");
        let (response, second_flags) = resolver
            .query_on_link_with_flags(&second, QueryMode::Full, None, 0)
            .expect("cached response");
        assert_eq!(&response[..2], &0x7401u16.to_be_bytes());
        assert_ne!(
            second_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE,
            0
        );
        assert_eq!(
            second_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_NETWORK,
            0
        );

        let third = make_query("local-cache.example", TYPE_A, 0x7402).expect("third query");
        let (_, third_flags) = resolver
            .query_on_link_with_flags(
                &third,
                QueryMode::Full,
                None,
                crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_NETWORK,
            )
            .expect("network-disabled cache hit");
        assert_ne!(
            third_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE,
            0
        );

        let fourth = make_query("local-cache.example", TYPE_A, 0x7403).expect("fourth query");
        assert!(matches!(
            resolver.query_on_link_with_flags(
                &fourth,
                QueryMode::Full,
                None,
                crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_NETWORK
                    | crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_CACHE,
            ),
            Err(ResolveError::NoNameServers)
        ));
        server_thread.join().expect("mock DNS thread");
    }

    #[test]
    fn configured_stub_loop_is_skipped_or_reported() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let healthy = socket.local_addr().expect("mock DNS address");
        let stub: SocketAddr = "127.0.0.1:53535".parse().expect("stub address");
        let extra = crate::config::DnsStubListenerExtra::parse(&stub.to_string())
            .expect("extra stub listener");

        let loop_only = Resolver::new(Config {
            upstreams: vec![stub],
            fallback_upstreams: Vec::new(),
            dns_stub_listener_extra: vec![extra],
            cache: false,
            attempts: 1,
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let query = make_query("loop.example", TYPE_A, 0x7450).expect("loop query");
        assert!(matches!(
            loop_only.query(&query, QueryMode::Full),
            Err(ResolveError::StubLoop)
        ));

        let server_thread = thread::spawn(move || {
            reply_once(&socket, Ipv4Addr::new(192, 0, 2, 35));
        });
        let resolver = Resolver::new(Config {
            upstreams: vec![stub, healthy],
            fallback_upstreams: Vec::new(),
            dns_stub_listener_extra: vec![extra],
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("healthy peer response");
        assert_eq!(
            extract_address_records(&response, Some(2))
                .expect("address records")
                .addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 35))]
        );
        server_thread.join().expect("mock DNS thread");
    }

    #[test]
    fn no_cache_bypasses_lookup_but_stores_the_network_answer() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");
        let server = socket.local_addr().expect("mock DNS address");
        let server_thread = thread::spawn(move || {
            reply_once(&socket, Ipv4Addr::new(192, 0, 2, 33));
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            cache_from_localhost: true,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let first = make_query("bypass-cache.example", TYPE_A, 0x7410).expect("first query");
        let (_, first_flags) = resolver
            .query_on_link_with_flags(
                &first,
                QueryMode::Full,
                None,
                crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_CACHE,
            )
            .expect("network response");
        assert_ne!(
            first_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_NETWORK,
            0
        );
        assert_eq!(resolver.cache.len(), 1);

        let second = make_query("bypass-cache.example", TYPE_A, 0x7411).expect("second query");
        let (_, second_flags) = resolver
            .query_on_link_with_flags(
                &second,
                QueryMode::Full,
                None,
                crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_NETWORK,
            )
            .expect("cached response");
        assert_ne!(
            second_flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE,
            0
        );
        server_thread.join().expect("mock DNS thread");
    }

    fn reply_after_both_scopes_arrive(socket: &UdpSocket, barrier: &Barrier, address: Ipv4Addr) {
        let mut buffer = [0; 2048];
        let (length, peer) = socket.recv_from(&mut buffer).expect("mock scoped query");
        barrier.wait();
        let response = local_response(&buffer[..length], &[LocalRecord::A(address)], 30)
            .expect("mock scoped response");
        socket
            .send_to(&response, peer)
            .expect("mock scoped response send");
    }

    fn reply_once(socket: &UdpSocket, address: Ipv4Addr) {
        let mut buffer = [0; 2048];
        let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
        let response = local_response(&buffer[..length], &[LocalRecord::A(address)], 30)
            .expect("mock DNS response");
        socket
            .send_to(&response, peer)
            .expect("mock DNS response send");
    }
}
