#[cfg(test)]
mod test_06_longest_suffix_routes_to_the_matching_link {
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
    fn longest_suffix_routes_to_the_matching_link() {
        use crate::wire::question_end;
        use std::thread;

        let global = UdpSocket::bind("127.0.0.1:0").expect("bind global DNS server");
        global
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set global timeout");
        let link = UdpSocket::bind("127.0.0.1:0").expect("bind link DNS server");
        link.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set link timeout");
        let link_address = link.local_addr().expect("link DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = link.recv_from(&mut buffer).expect("receive link query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 88]);
            link.send_to(&response, peer).expect("send link response");
        });

        let config = Config {
            upstreams: vec![global.local_addr().expect("global DNS address")],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: true,
            cache_from_localhost: true,
            read_etc_hosts: false,
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        resolver
            .set_link_dns(7, vec![link_address])
            .expect("set link DNS");
        resolver
            .set_link_domains(
                7,
                vec![Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                }],
            )
            .expect("set link domain");

        let lookup = resolver
            .lookup_name("host.corp.example", 2)
            .expect("split DNS lookup");
        worker.join().expect("link DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88))]
        );
        assert_eq!(lookup.address_ifindices, vec![Some(7)]);
        let cached = resolver
            .lookup_name("host.corp.example", 2)
            .expect("cached split DNS lookup");
        assert_eq!(cached.address_ifindices, vec![Some(7)]);
        let mut buffer = [0; 512];
        assert!(global.recv_from(&mut buffer).is_err());
    }

    #[test]
    fn longest_suffix_routes_to_the_matching_delegate() {
        use crate::wire::question_end;
        use std::thread;

        let global = UdpSocket::bind("127.0.0.1:0").expect("bind global DNS server");
        global
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set global timeout");
        let delegate = UdpSocket::bind("127.0.0.1:0").expect("bind delegate DNS server");
        delegate
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set delegate timeout");
        let delegate_address = delegate.local_addr().expect("delegate DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = delegate
                .recv_from(&mut buffer)
                .expect("receive delegate query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 89]);
            delegate
                .send_to(&response, peer)
                .expect("send delegate response");
        });

        let config = Config {
            dns_delegates: vec![crate::dns_delegate::DnsDelegate {
                id: "corp".to_owned(),
                servers: vec![DnsServerSpec {
                    address: delegate_address,
                    interface: None,
                    server_name: None,
                }],
                domains: vec![Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                }],
                default_route: None,
                firewall_mark: 0,
            }],
            upstreams: vec![global.local_addr().expect("global DNS address")],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        };
        let lookup = Resolver::new(config)
            .lookup_name("host.corp.example", 2)
            .expect("delegate split DNS lookup");
        worker.join().expect("delegate DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 89))]
        );
        assert_eq!(lookup.address_ifindices, vec![None]);
        let mut buffer = [0; 512];
        assert!(global.recv_from(&mut buffer).is_err());
    }

}
