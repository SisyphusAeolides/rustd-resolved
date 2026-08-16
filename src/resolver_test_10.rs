#[cfg(test)]
mod test_10_proxy_mode_synthesis {
    use super::*;
    use std::net::UdpSocket;
    use std::thread;

    fn upstream_response(response: impl FnOnce(&[u8]) -> Vec<u8> + Send + 'static) -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind DNS server");
        let address = socket.local_addr().expect("DNS server address");
        thread::spawn(move || {
            let mut packet = [0; 512];
            let (length, peer) = socket.recv_from(&mut packet).expect("receive query");
            let reply = response(&packet[..length]);
            socket.send_to(&reply, peer).expect("send response");
        });
        address
    }

    #[test]
    fn proxy_mode_synthesizes_localhost_without_servers() {
        let mut config = Config::default();
        config.upstreams.clear();
        config.fallback_upstreams.clear();
        let resolver = Resolver::new(config);
        let query = make_query("localhost", TYPE_A, 55).expect("query");
        let response = resolver
            .query(&query, QueryMode::Proxy)
            .expect("synthetic response");
        assert_eq!(
            wire::extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn proxy_mode_synthesizes_localhost_after_nxdomain() {
        let server = upstream_response(|query| wire::nxdomain_for(query).expect("NXDOMAIN"));
        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            ..Config::default()
        });
        let query = make_query("localhost", TYPE_A, 56).expect("query");
        let response = resolver
            .query(&query, QueryMode::Proxy)
            .expect("synthetic response");
        assert_eq!(Header::parse(&response).expect("header").response_code(), 0);
        assert_eq!(
            wire::extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn proxy_mode_preserves_successful_network_answer() {
        let server = upstream_response(|query| {
            local_response(
                query,
                &[crate::wire::LocalRecord::A(Ipv4Addr::new(192, 0, 2, 1))],
                30,
            )
            .expect("answer")
        });
        let resolver = Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            ..Config::default()
        });
        let query = make_query("localhost", TYPE_A, 57).expect("query");
        let response = resolver
            .query(&query, QueryMode::Proxy)
            .expect("network response");
        assert_eq!(
            wire::extract_addresses(&response, Some(2)).expect("address"),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
    }
}
