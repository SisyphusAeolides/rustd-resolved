#[cfg(test)]
#[allow(clippy::similar_names)]
mod test_13_transport_fallback {
    use super::*;
    use crate::wire::LocalRecord;
    use std::net::TcpListener;

    #[test]
    fn reuses_idle_connected_udp_socket() {
        let datagram_socket = UdpSocket::bind("127.0.0.1:0").expect("mock UDP bind");
        let server_address = datagram_socket.local_addr().expect("mock DNS address");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDP timeout");

        let datagram_thread = thread::spawn(move || {
            let mut peer_ports = Vec::new();
            for address in [Ipv4Addr::new(192, 0, 2, 20), Ipv4Addr::new(192, 0, 2, 21)] {
                let mut buffer = [0; 2048];
                let (length, peer) = datagram_socket
                    .recv_from(&mut buffer)
                    .expect("mock UDP query");
                peer_ports.push(peer.port());
                let response = local_response(
                    &buffer[..length],
                    &[LocalRecord::A(address)],
                    30,
                )
                .expect("mock A response");
                let response =
                    edns::add_test_response_opt(&response, 0, false).expect("response OPT");
                datagram_socket
                    .send_to(&response, peer)
                    .expect("mock UDP response");
            }
            peer_ports
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });

        for (id, name) in [(0x70f0, "pool-one.example"), (0x70f1, "pool-two.example")] {
            let query = make_query(name, TYPE_A, id).expect("client query");
            resolver
                .query(&query, QueryMode::Full)
                .expect("resolver response");
        }

        let peer_ports = datagram_thread.join().expect("mock UDP thread");
        assert_eq!(peer_ports.len(), 2);
        assert_eq!(peer_ports[0], peer_ports[1]);
    }

    #[test]
    fn ignores_unrelated_udp_reply_and_uses_path_mtu_payload_size() {
        let datagram_socket = UdpSocket::bind("127.0.0.1:0").expect("mock UDP bind");
        let server_address = datagram_socket.local_addr().expect("mock DNS address");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDP timeout");

        let datagram_thread = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = datagram_socket
                .recv_from(&mut buffer)
                .expect("mock UDP query");
            let query = &buffer[..length];
            let opt = edns::inspect_opt(query)
                .expect("query OPT")
                .expect("EDNS query");
            assert_eq!(opt.udp_payload_size, 65_508);

            let mut unrelated = local_response(
                query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 10))],
                30,
            )
            .expect("unrelated response");
            unrelated[0..2].copy_from_slice(&0x9999_u16.to_be_bytes());
            datagram_socket
                .send_to(&unrelated, peer)
                .expect("unrelated UDP response");

            let response = local_response(
                query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 11))],
                30,
            )
            .expect("matching response");
            datagram_socket
                .send_to(&response, peer)
                .expect("matching UDP response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let query = make_query("udp-filter.example", TYPE_A, 0x7100).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );

        datagram_thread.join().expect("mock UDP thread");
    }

    #[test]
    fn truncated_udp_uses_tcp_without_permanently_switching_transport() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TCP bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDP timeout");

        let datagram_thread = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = datagram_socket
                .recv_from(&mut buffer)
                .expect("mock UDP query");
            let query = &buffer[..length];
            datagram_socket
                .send_to(&truncated_response(query), peer)
                .expect("mock truncated response");
        });

        let stream_thread = thread::spawn(move || {
            let (mut stream, _) = stream_listener.accept().expect("mock TCP accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("mock TCP timeout");
            let query = read_tcp_query(&mut stream);
            let response = local_response(
                &query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 90))],
                30,
            )
            .expect("mock A response");
            let response =
                edns::add_test_response_opt(&response, 0, false).expect("response OPT");
            write_tcp_response(&mut stream, &response);
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 1,
            query_timeout: Duration::from_millis(250),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let query = make_query("truncated.example", TYPE_A, 0x7101).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90))]
        );

        let states = resolver.states();
        let state = states
            .get(&ServerKey::new(ScopeKind::Global, server_address))
            .expect("server state");
        assert_eq!(state.transport.mode(), TransportMode::Udp);
        assert!(state.transport.packet_truncated());
        drop(states);

        datagram_thread.join().expect("mock UDP thread");
        stream_thread.join().expect("mock TCP thread");
    }

    #[test]
    fn repeated_udp_loss_reaches_plain_tcp() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TCP bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock UDP timeout");

        let datagram_thread = thread::spawn(move || {
            for index in 0..9 {
                let mut buffer = [0; 2048];
                let (length, _) = datagram_socket
                    .recv_from(&mut buffer)
                    .expect("mock UDP query");
                let opt = edns::inspect_opt(&buffer[..length]).expect("query OPT");
                match index {
                    0..=2 => assert!(opt.expect("DNSSEC OPT").dnssec_ok()),
                    3..=5 => assert!(!opt.expect("EDNS0 OPT").dnssec_ok()),
                    6..=8 => assert!(opt.is_none()),
                    _ => unreachable!(),
                }
            }
        });

        let stream_thread = thread::spawn(move || {
            let (mut stream, _) = stream_listener.accept().expect("mock TCP accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("mock TCP timeout");
            let query = read_tcp_query(&mut stream);
            assert!(edns::inspect_opt(&query).expect("TCP query OPT").is_none());
            let response = local_response(
                &query,
                &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 91))],
                30,
            )
            .expect("mock A response");
            write_tcp_response(&mut stream, &response);
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            attempts: 7,
            query_timeout: Duration::from_millis(100),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query("transport.example", TYPE_A, 0x7102).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 91))]
        );

        let states = resolver.states();
        assert_eq!(
            states
                .get(&ServerKey::new(ScopeKind::Global, server_address))
                .expect("server state")
                .transport
                .mode(),
            TransportMode::Tcp
        );
        drop(states);

        datagram_thread.join().expect("mock UDP thread");
        stream_thread.join().expect("mock TCP thread");
    }

    fn truncated_response(query: &[u8]) -> Vec<u8> {
        let end = wire::question_end(query).expect("question end");
        let mut response = query[..end].to_vec();
        let query_flags = u16::from_be_bytes([query[2], query[3]]);
        let flags = (query_flags & 0x0100) | 0x8000 | 0x0200 | 0x0080;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..12].fill(0);
        response
    }

    fn read_tcp_query(stream: &mut TcpStream) -> Vec<u8> {
        let mut length = [0; 2];
        stream.read_exact(&mut length).expect("TCP query length");
        let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).expect("TCP query body");
        query
    }

    fn write_tcp_response(stream: &mut TcpStream, response: &[u8]) {
        let length = u16::try_from(response.len()).expect("TCP response length");
        stream
            .write_all(&length.to_be_bytes())
            .expect("TCP response length write");
        stream
            .write_all(response)
            .expect("TCP response body write");
    }
}
