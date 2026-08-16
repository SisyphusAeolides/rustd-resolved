#[cfg(test)]
mod test_15_tcp_pool {
    use super::*;
    use crate::wire::LocalRecord;
    use std::net::TcpListener;

    #[test]
    fn rejects_truncated_dns_over_tcp_reply() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TCP bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let server = thread::spawn(move || {
            let (mut stream, _) = stream_listener.accept().expect("mock TCP accept");
            let query = read_tcp_query(&mut stream);
            write_tcp_response(&mut stream, &truncated_response(&query));
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
        let query = make_query("tcp-truncated.example", TYPE_A, 0x72e0).expect("client query");
        let error = resolver
            .exchange_tcp(
                ServerKey::new(ScopeKind::Global, server_address),
                &query,
                Duration::from_millis(500),
            )
            .expect_err("truncated TCP response must be rejected");
        assert!(matches!(error, ResolveError::Protocol(_)));
        server.join().expect("mock TCP thread");
    }

    #[test]
    fn reuses_idle_tcp_stream_after_udp_truncation() {
        let stream_listener = TcpListener::bind("127.0.0.1:0").expect("mock TCP bind");
        let server_address = stream_listener.local_addr().expect("mock DNS address");
        let datagram_socket = UdpSocket::bind(server_address).expect("mock UDP bind");
        datagram_socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock UDP timeout");

        let datagram_thread = thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 2048];
                let (length, peer) = datagram_socket
                    .recv_from(&mut buffer)
                    .expect("mock UDP query");
                let query = &buffer[..length];
                datagram_socket
                    .send_to(&truncated_response(query), peer)
                    .expect("mock truncated response");
            }
        });

        let stream_thread = thread::spawn(move || {
            let (mut stream, _) = stream_listener.accept().expect("single TCP accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("mock TCP timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .expect("mock TCP timeout");

            for address in [Ipv4Addr::new(192, 0, 2, 30), Ipv4Addr::new(192, 0, 2, 31)] {
                let query = read_tcp_query(&mut stream);
                let response = local_response(&query, &[LocalRecord::A(address)], 30)
                    .expect("mock A response");
                let response =
                    edns::add_test_response_opt(&response, 0, false).expect("response OPT");
                write_tcp_response(&mut stream, &response);
            }
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

        for (id, name) in [(0x72f0, "tcp-pool-one.example"), (0x72f1, "tcp-pool-two.example")] {
            let query = make_query(name, TYPE_A, id).expect("client query");
            resolver
                .query(&query, QueryMode::Full)
                .expect("resolver response");
        }

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
