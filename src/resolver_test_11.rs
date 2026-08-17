#[cfg(test)]
mod test_11_cross_transaction_redirects {
    use super::*;
    use crate::wire::{TYPE_A, TYPE_CNAME};
    use std::net::UdpSocket;
    use std::thread;

    fn append_answer(packet: &mut Vec<u8>, owner: &[u8], rr_type: u16, rdata: &[u8]) {
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

    fn response(query: &[u8], answer_count: u16) -> Vec<u8> {
        let end = wire::question_end(query).expect("question end");
        let mut response = query[..end].to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());
        response[8..12].fill(0);
        response
    }

    fn receive_query(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0; 4096];
        let (length, peer) = socket.recv_from(&mut buffer).expect("receive DNS query");
        (buffer[..length].to_vec(), peer)
    }

    fn send_redirect(
        socket: &UdpSocket,
        query: &[u8],
        peer: SocketAddr,
        owner: &[u8],
        rr_type: u16,
        target: &str,
    ) {
        let mut reply = response(query, 1);
        let target = wire::encode_name(target).expect("redirect target");
        append_answer(&mut reply, owner, rr_type, &target);
        socket.send_to(&reply, peer).expect("send redirect");
    }

    fn send_error(
        socket: &UdpSocket,
        query: &[u8],
        peer: SocketAddr,
        rcode: u8,
    ) {
        let mut reply = response(query, 0);
        reply[3] = (reply[3] & 0xF0) | (rcode & 0x0f);
        socket.send_to(&reply, peer).expect("send DNS error");
    }

    fn send_a(socket: &UdpSocket, query: &[u8], peer: SocketAddr, address: [u8; 4]) {
        let mut reply = response(query, 1);
        append_answer(&mut reply, &[0xc0, 0x0c], TYPE_A, &address);
        socket.send_to(&reply, peer).expect("send address");
    }

    fn send_redirect_chain(
        socket: &UdpSocket,
        query: &[u8],
        peer: SocketAddr,
        start: u16,
        redirects: usize,
        terminal_has_address: bool,
    ) {
        let mut reply = response(query, u16::try_from(redirects + usize::from(terminal_has_address)).expect("answers"));
        let mut current = start;
        for redirect_index in 0..redirects {
            let owner = if redirect_index == 0 {
                vec![0xc0, 0x0c]
            } else {
                wire::encode_name(&format!("{current}.example")).expect("owner")
            };
            current = current.saturating_add(1);
            let target = wire::encode_name(&format!("{current}.example")).expect("target");
            append_answer(&mut reply, &owner, TYPE_CNAME, &target);
        }
        if terminal_has_address {
            let terminal = format!("{current}.example");
            let terminal_owner = wire::encode_name(&terminal).expect("terminal");
            append_answer(&mut reply, &terminal_owner, TYPE_A, &[192, 0, 2, 100]);
        }
        socket.send_to(&reply, peer).expect("send redirect chain");
    }

    fn resolver_for(server: SocketAddr) -> Resolver {
        Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_millis(500),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        })
    }

    #[test]
    fn cname_redirect_continues_in_a_follow_up_transaction() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first).expect("first question").name.text(),
                "alias.example.test"
            );
            send_redirect(
                &socket,
                &first,
                peer,
                &[0xc0, 0x0c],
                wire::TYPE_CNAME,
                "real.example.test",
            );

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second)
                    .expect("follow-up question")
                    .name
                    .text(),
                "real.example.test"
            );
            send_a(&socket, &second, peer, [192, 0, 2, 71]);
        });

        let lookup = resolver_for(server)
            .lookup_name("alias.example.test", 2)
            .expect("cross-transaction CNAME lookup");
        worker.join().expect("test DNS worker");

        assert_eq!(lookup.canonical_name, "real.example.test");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 71))]
        );
    }

    #[test]
    fn redirect_follow_error_uses_original_question_name() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first).expect("first follow-up query").name.text(),
                "alias.example.test"
            );
            send_redirect(
                &socket,
                &first,
                peer,
                &[0xc0, 0x0c],
                wire::TYPE_CNAME,
                "real.example.test",
            );

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second).expect("follow-up query").name.text(),
                "real.example.test"
            );
            send_error(&socket, &second, peer, 2);
        });

        let error = resolver_for(server)
            .lookup_name("alias.example.test", 2)
            .expect_err("DNSSEC error with redirect");
        worker.join().expect("test DNS worker");
        match error {
            ResolveError::DnsError { query, rcode, .. } => {
                assert_eq!(rcode, 2);
                assert_eq!(query, "alias.example.test");
            }
            other => panic!("expected DNS error, got {other:?}"),
        }
    }

    #[test]
    fn no_cname_stops_before_a_follow_up_transaction() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            send_redirect(
                &socket,
                &first,
                peer,
                &[0xc0, 0x0c],
                wire::TYPE_CNAME,
                "real.example.test",
            );
            let mut buffer = [0; 512];
            assert!(socket.recv_from(&mut buffer).is_err());
        });

        let result = resolver_for(server).resolve_record_on_link_with_request_flags(
            "alias.example.test",
            wire::CLASS_IN,
            TYPE_A,
            None,
            crate::resolve_flags::flags::RUSTD_RESOLVE_NO_CNAME,
        );
        assert!(matches!(
            result,
            Err(ResolveError::Wire(WireError::CnameLoop))
        ));
        worker.join().expect("mock DNS thread");
    }

    #[test]
    fn dname_redirect_continues_in_a_follow_up_transaction() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first).expect("first question").name.text(),
                "host.branch.example.test"
            );
            let owner = wire::encode_name("branch.example.test").expect("DNAME owner");
            send_redirect(
                &socket,
                &first,
                peer,
                &owner,
                wire::TYPE_DNAME,
                "service.example.test",
            );

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second)
                    .expect("follow-up question")
                    .name
                    .text(),
                "host.service.example.test"
            );
            send_a(&socket, &second, peer, [192, 0, 2, 72]);
        });

        let lookup = resolver_for(server)
            .lookup_name("host.branch.example.test", 2)
            .expect("cross-transaction DNAME lookup");
        worker.join().expect("test DNS worker");

        assert_eq!(lookup.canonical_name, "host.service.example.test");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 72))]
        );
    }

    #[test]
    fn cross_transaction_redirect_loop_is_rejected_without_a_third_query() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first).expect("first question").name.text(),
                "loop-a.example.test"
            );
            send_redirect(
                &socket,
                &first,
                peer,
                &[0xc0, 0x0c],
                wire::TYPE_CNAME,
                "loop-b.example.test",
            );

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second)
                    .expect("second question")
                    .name
                    .text(),
                "loop-b.example.test"
            );
            send_redirect(
                &socket,
                &second,
                peer,
                &[0xc0, 0x0c],
                wire::TYPE_CNAME,
                "loop-a.example.test",
            );
        });

        let result = resolver_for(server).lookup_name("loop-a.example.test", 2);
        worker.join().expect("test DNS worker");
        assert!(matches!(
            result,
            Err(ResolveError::Wire(WireError::CnameLoop))
        ));
    }

    #[test]
    fn exactly_sixteen_in_packet_redirects_are_accepted() {
        let query = make_query("n0.example", TYPE_A, 0x4400).expect("query");
        let mut reply = response(&query, 17);
        for index in 0..16 {
            let owner = if index == 0 {
                vec![0xc0, 0x0c]
            } else {
                wire::encode_name(&format!("n{index}.example")).expect("owner")
            };
            let next = index + 1;
            let target = wire::encode_name(&format!("n{next}.example")).expect("target");
            append_answer(&mut reply, &owner, wire::TYPE_CNAME, &target);
        }
        let terminal = wire::encode_name("n16.example").expect("terminal owner");
        append_answer(&mut reply, &terminal, TYPE_A, &[192, 0, 2, 73]);

        assert_eq!(
            wire::classify_redirect_answer(&reply),
            Ok(wire::RedirectAnswer::Direct {
                canonical_name: "n16.example".to_owned(),
                redirects: 16,
            })
        );
    }

    #[test]
    fn seventeenth_in_packet_redirect_is_rejected() {
        let query = make_query("n0.example", TYPE_A, 0x4401).expect("query");
        let mut reply = response(&query, 17);
        for index in 0..17 {
            let owner = if index == 0 {
                vec![0xc0, 0x0c]
            } else {
                wire::encode_name(&format!("n{index}.example")).expect("owner")
            };
            let next = index + 1;
            let target = wire::encode_name(&format!("n{next}.example")).expect("target");
            append_answer(&mut reply, &owner, wire::TYPE_CNAME, &target);
        }

        assert_eq!(
            wire::classify_redirect_answer(&reply),
            Err(WireError::CnameLoop)
        );
    }

    #[test]
    fn redirect_following_across_transactions_accumulates_redirect_limits() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first)
                    .expect("first follow-up query")
                    .name
                    .text(),
                "0.example"
            );
            send_redirect_chain(&socket, &first, peer, 0, 8, false);

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second)
                    .expect("second follow-up query")
                    .name
                    .text(),
                "8.example"
            );
            send_redirect_chain(&socket, &second, peer, 8, 8, true);
        });

        let lookup = resolver_for(server)
            .lookup_name("0.example", 2)
            .expect("cumulative redirects across transactions");
        worker.join().expect("mock DNS thread");

        assert_eq!(
            lookup.canonical_name,
            "16.example",
            "redirect chain should terminate after crossing two transactions"
        );
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100))]
        );
    }

    #[test]
    fn redirect_following_rejects_cumulative_overflow_across_transactions() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");

        let worker = thread::spawn(move || {
            let (first, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&first)
                    .expect("first follow-up query")
                    .name
                    .text(),
                "0.example"
            );
            send_redirect_chain(&socket, &first, peer, 0, 9, false);

            let (second, peer) = receive_query(&socket);
            assert_eq!(
                first_question(&second)
                    .expect("second follow-up query")
                    .name
                    .text(),
                "9.example"
            );
            send_redirect_chain(&socket, &second, peer, 9, 8, false);
        });

        assert!(matches!(
            resolver_for(server).lookup_name("0.example", 2),
            Err(ResolveError::Wire(WireError::CnameLoop))
        ));
        worker.join().expect("mock DNS thread");
    }
}
