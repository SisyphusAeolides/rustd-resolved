#[cfg(all(test, feature = "idna-name"))]
mod test_29_idna_questions {
    use super::*;
    use crate::wire::LocalRecord;

    fn resolver_for(server: SocketAddr) -> Resolver {
        Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        })
    }

    fn serve_one(expected_name: &'static str) -> (SocketAddr, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock DNS timeout");
        let address = socket.local_addr().expect("mock DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
            let query = &buffer[..length];
            assert_eq!(
                first_question(query).expect("question").name.text(),
                expected_name
            );
            let response = local_response(
                query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 29))],
                30,
            )
            .expect("mock A response");
            socket.send_to(&response, peer).expect("mock DNS response");
        });
        (address, worker)
    }

    #[test]
    fn hostname_lookup_uses_idna_for_classic_dns() {
        let (server, worker) = serve_one("xn--bcher-kva.example");
        let lookup = resolver_for(server)
            .lookup_name_on_link_with_request_flags(
                "bücher.example",
                2,
                None,
                crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_SEARCH,
            )
            .expect("IDNA hostname lookup");
        assert_eq!(lookup.canonical_name, "xn--bcher-kva.example");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 29))]
        );
        worker.join().expect("mock DNS worker");
    }

    #[test]
    fn explicit_record_lookup_preserves_utf8_question() {
        let (server, worker) = serve_one(r"b\195\188cher.example");
        resolver_for(server)
            .resolve_record("bücher.example", TYPE_A)
            .expect("UTF-8 record lookup");
        worker.join().expect("mock DNS worker");
    }
}
