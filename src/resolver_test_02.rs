#[cfg(test)]
mod test_02_lookup_and_server_failover {
    use super::*;

    fn append_test_answer(packet: &mut Vec<u8>, owner: &[u8], rr_type: u16, rdata: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test RDATA length")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    #[test]
    fn lookup_name_follows_cname_and_ignores_unrelated_addresses() {
        use crate::wire::{encode_name, question_end, TYPE_CNAME};
        use std::thread;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&3u16.to_be_bytes());
            response[8..12].fill(0);

            let canonical = encode_name("real.example.test").expect("canonical name");
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_CNAME, &canonical);
            append_test_answer(
                &mut response,
                &encode_name("unrelated.example.test").expect("unrelated owner"),
                TYPE_A,
                &[203, 0, 113, 9],
            );
            append_test_answer(&mut response, &canonical, TYPE_A, &[192, 0, 2, 42]);
            socket.send_to(&response, peer).expect("send DNS response");
        });

        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("alias.example.test", 2)
            .expect("CNAME lookup");
        worker.join().expect("test DNS worker");

        assert_eq!(lookup.canonical_name, "real.example.test");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
        );
    }

    #[test]
    fn refused_response_retries_another_server() {
        use std::thread;

        let refused_socket = UdpSocket::bind("127.0.0.1:0").expect("bind refusing DNS server");
        let success_socket = UdpSocket::bind("127.0.0.1:0").expect("bind succeeding DNS server");
        let refused_server = refused_socket.local_addr().expect("refusing DNS address");
        let success_server = success_socket.local_addr().expect("succeeding DNS address");
        for socket in [&refused_socket, &success_socket] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set mock DNS timeout");
        }

        let refused_worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = refused_socket
                .recv_from(&mut buffer)
                .expect("receive refused query");
            let mut response = local_response(&buffer[..length], &[], 0).expect("REFUSED response");
            let flags = u16::from_be_bytes([response[2], response[3]]);
            response[2..4].copy_from_slice(&((flags & !0x000f) | RCODE_REFUSED).to_be_bytes());
            refused_socket
                .send_to(&response, peer)
                .expect("send REFUSED response");
        });
        let success_worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            let (length, peer) = success_socket
                .recv_from(&mut buffer)
                .expect("receive retry query");
            let response = local_response(
                &buffer[..length],
                &[crate::wire::LocalRecord::A(Ipv4Addr::new(192, 0, 2, 77))],
                30,
            )
            .expect("success response");
            success_socket
                .send_to(&response, peer)
                .expect("send success response");
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![refused_server, success_server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 2,
            cache: false,
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        {
            let mut states = resolver.states();
            states
                .entry(ServerKey::new(ScopeKind::Global, refused_server))
                .or_default()
                .metric
                .round_trip_ms = 1.0;
            states
                .entry(ServerKey::new(ScopeKind::Global, success_server))
                .or_default()
                .metric
                .round_trip_ms = 1000.0;
        }

        let query = make_query("refused.example.test", TYPE_A, 0x7300).expect("client query");
        let response = resolver
            .query(&query, QueryMode::Full)
            .expect("retry succeeds");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))]
        );

        refused_worker.join().expect("refusing DNS worker");
        success_worker.join().expect("succeeding DNS worker");
    }
}
