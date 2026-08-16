#[cfg(test)]
mod test_05_lookup_name_tries_search_domains_in_order {
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
    fn lookup_name_tries_search_domains_in_order() {
        use crate::wire::question_end;
        use std::thread;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            for (index, expected_name) in ["host.example.test", "host.lab.test"]
                .into_iter()
                .enumerate()
            {
                let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
                let query = &buffer[..length];
                let question = first_question(query).expect("question");
                assert_eq!(question.name.text(), expected_name);
                let end = question_end(query).expect("question end");
                let mut response = query[..end].to_vec();
                let flags = if index == 0 { 0x8183u16 } else { 0x8180u16 };
                response[2..4].copy_from_slice(&flags.to_be_bytes());
                response[6..12].fill(0);
                if index == 1 {
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 77]);
                }
                socket.send_to(&response, peer).expect("send DNS response");
            }
        });

        let config = Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            domains: vec![
                Domain {
                    name: "route.test".to_owned(),
                    route_only: true,
                },
                Domain {
                    name: "example.test".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "lab.test".to_owned(),
                    route_only: false,
                },
            ],
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            resolve_unicast_single_label: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("host", 2)
            .expect("search-domain lookup");
        worker.join().expect("test DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))]
        );
        assert_eq!(lookup.canonical_name, "host.lab.test");
    }

}
