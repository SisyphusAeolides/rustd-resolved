#[cfg(test)]
mod test_30_query_abort {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn configuration_reload_aborts_an_active_unicast_query() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock DNS timeout");
        let server_address = socket.local_addr().expect("mock DNS address");
        let (query_seen, wait_for_query) = mpsc::channel();
        let (release_response, response_released) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
            let query = &buffer[..length];
            query_seen.send(()).expect("signal active query");
            response_released.recv().expect("release mock response");
            let response = local_response(
                query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 30))],
                30,
            )
            .expect("mock A response");
            socket.send_to(&response, peer).expect("mock DNS response");
        });

        let resolver = Arc::new(Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_secs(1),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        }));
        let lookup_resolver = Arc::clone(&resolver);
        let lookup = thread::spawn(move || {
            lookup_resolver.lookup_name_on_link_with_request_flags(
                "abort.example",
                2,
                None,
                crate::resolve_flags::flags::RUSTD_RESOLVE_NO_SEARCH,
            )
        });

        wait_for_query.recv().expect("active query notification");
        resolver.reload_config(resolver.config());
        release_response.send(()).expect("release response");

        assert!(matches!(
            lookup.join().expect("lookup thread"),
            Err(ResolveError::QueryAborted)
        ));
        server.join().expect("mock DNS server");
    }
}
