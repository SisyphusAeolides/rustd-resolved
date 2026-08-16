#[cfg(test)]
mod test_16_parallel_address_families {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn unspecified_family_dispatches_a_and_aaaa_together() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        let server_address = socket.local_addr().expect("mock DNS address");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");

        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("parallel DNS query");
                requests.push((buffer[..length].to_vec(), peer));
            }

            for (query, peer) in requests {
                let question = first_question(&query).expect("DNS question");
                let records = match question.rr_type {
                    TYPE_A => vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 40))],
                    TYPE_AAAA => vec![LocalRecord::Aaaa(Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 40,
                    ))],
                    _ => panic!("unexpected address query type"),
                };
                let response = local_response(&query, &records, 30).expect("mock address response");
                let response =
                    edns::add_test_response_opt(&response, 0, false).expect("response OPT");
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
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        let lookup = resolver
            .lookup_name("parallel-family.example", 0)
            .expect("dual-family lookup");

        assert_eq!(
            lookup.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 40)),
            ]
        );
        server.join().expect("mock DNS thread");
    }
}
