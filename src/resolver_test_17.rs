#[cfg(test)]
mod test_17_dns_attempt_budget {
    use super::*;
    use crate::wire::LocalRecord;

    #[test]
    fn upstream_attempt_budget_stops_after_twenty_four_emissions() {
        let mut budget = DnsAttemptBudget::new();
        for expected in 1..=DNS_TRANSACTION_ATTEMPTS_MAX {
            assert!(budget.begin_attempt().is_ok());
            assert_eq!(budget.attempts(), expected);
        }
        let error = budget
            .begin_attempt()
            .expect_err("twenty-fifth DNS emission must be rejected");
        assert_eq!(error.varlink_id(), "io.rustd.Resolve.MaxAttemptsReached");
    }

    #[test]
    fn feature_downgrades_consume_the_shared_attempt_budget() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("mock DNS bind");
        let server_address = socket.local_addr().expect("mock DNS address");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock DNS timeout");

        let server = thread::spawn(move || {
            for exchange_index in 0..3 {
                let mut buffer = [0; 2048];
                let (length, peer) = socket.recv_from(&mut buffer).expect("mock DNS query");
                let query = &buffer[..length];
                let response = match exchange_index {
                    0 => {
                        let opt = edns::inspect_opt(query)
                            .expect("query OPT")
                            .expect("DNSSEC OPT");
                        assert!(opt.dnssec_ok());
                        let response = error_response(query, RCODE_FORMERR);
                        edns::add_test_response_opt(&response, 0, true)
                            .expect("DNSSEC FORMERR response")
                    }
                    1 => {
                        let opt = edns::inspect_opt(query)
                            .expect("query OPT")
                            .expect("EDNS0 OPT");
                        assert!(!opt.dnssec_ok());
                        let response = error_response(query, RCODE_FORMERR);
                        edns::add_test_response_opt(&response, 0, false)
                            .expect("EDNS0 FORMERR response")
                    }
                    2 => {
                        assert!(edns::inspect_opt(query).expect("plain query").is_none());
                        local_response(
                            query,
                            &[LocalRecord::A(Ipv4Addr::new(192, 0, 2, 70))],
                            30,
                        )
                        .expect("plain DNS response")
                    }
                    _ => unreachable!(),
                };
                socket
                    .send_to(&response, peer)
                    .expect("mock DNS response");
            }
        });

        let resolver = Resolver::new(Config {
            upstreams: vec![server_address],
            fallback_upstreams: Vec::new(),
            cache: false,
            query_timeout: Duration::from_millis(500),
            read_etc_hosts: false,
            read_static_records: false,
            dnssec: ValidationMode::AllowDowngrade,
            ..Config::default()
        });
        let query = make_query("budget.example", TYPE_A, 0x7300).expect("client query");
        let mut budget = DnsAttemptBudget::new();
        let response = resolver
            .exchange_with_features(
                ServerKey::new(ScopeKind::Global, server_address),
                &query,
                &mut budget,
            )
            .expect("resolver response");
        let records = extract_address_records(&response, Some(2)).expect("address records");
        assert_eq!(
            records.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70))]
        );
        assert_eq!(budget.attempts(), 3);
        server.join().expect("mock DNS thread");
    }

    fn error_response(query: &[u8], rcode: u16) -> Vec<u8> {
        let end = wire::question_end(query).expect("question end");
        let mut response = query[..end].to_vec();
        let query_flags = u16::from_be_bytes([query[2], query[3]]);
        let flags = (query_flags & 0x0100) | 0x8000 | 0x0080 | rcode;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..12].fill(0);
        response
    }
}
