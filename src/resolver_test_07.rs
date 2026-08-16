#[cfg(test)]
mod test_07_equal_best_scopes_prefer_a_successful_response {
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
    fn equal_best_scopes_prefer_a_successful_response() {
        use crate::wire::question_end;
        use std::thread;

        let negative = UdpSocket::bind("127.0.0.1:0").expect("bind negative DNS server");
        let negative_address = negative.local_addr().expect("negative DNS address");
        let positive = UdpSocket::bind("127.0.0.1:0").expect("bind positive DNS server");
        let positive_address = positive.local_addr().expect("positive DNS address");

        let negative_worker = thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 4096];
                let (length, peer) = negative
                    .recv_from(&mut buffer)
                    .expect("receive negative query");
                let query = &buffer[..length];
                let end = question_end(query).expect("question end");
                let mut response = query[..end].to_vec();
                response[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
                response[6..12].fill(0);
                negative
                    .send_to(&response, peer)
                    .expect("send negative response");
            }
        });
        let positive_worker = thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 4096];
                let (length, peer) = positive
                    .recv_from(&mut buffer)
                    .expect("receive positive query");
                let query = &buffer[..length];
                let end = question_end(query).expect("question end");
                let mut response = query[..end].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response[8..12].fill(0);
                append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 99]);
                positive
                    .send_to(&response, peer)
                    .expect("send positive response");
            }
        });

        let config = Config {
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        for (ifindex, server) in [(7, negative_address), (8, positive_address)] {
            resolver
                .set_link_dns(ifindex, vec![server])
                .expect("set link DNS");
            resolver
                .set_link_domains(
                    ifindex,
                    vec![Domain {
                        name: "corp.example".to_owned(),
                        route_only: true,
                    }],
                )
                .expect("set link domain");
        }

        let lookup = resolver
            .lookup_name("host.corp.example", 2)
            .expect("parallel split DNS lookup");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))]
        );
        assert_eq!(lookup.address_ifindices, vec![Some(8)]);

        let (_, _, answer_ifindex) = resolver
            .resolve_record_on_link_with_request_flags_and_metadata(
                "host.corp.example",
                wire::CLASS_IN,
                TYPE_A,
                None,
                0,
            )
            .expect("record lookup with answering interface");
        assert_eq!(answer_ifindex, Some(8));

        negative_worker.join().expect("negative DNS worker");
        positive_worker.join().expect("positive DNS worker");
    }
}
