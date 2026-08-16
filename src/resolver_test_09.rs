#[cfg(test)]
mod test_09_concurrent_identical_queries_share_one_upstream_transaction {
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
    fn concurrent_identical_queries_share_one_upstream_transaction() {
        use crate::wire::question_end;
        use std::sync::{Arc, Barrier};

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind test DNS server");
        socket
            .set_read_timeout(Some(Duration::from_millis(750)))
            .expect("set test timeout");
        let server = socket.local_addr().expect("test DNS server address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).expect("receive query");
            let query = &buffer[..length];
            thread::sleep(Duration::from_millis(500));
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..12].fill(0);
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            append_test_answer(&mut response, &[0xc0, 0x0c], TYPE_A, &[192, 0, 2, 88]);
            socket.send_to(&response, peer).expect("send DNS response");

            assert!(matches!(
                socket.recv_from(&mut buffer),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    )
            ));
        });

        let resolver = Arc::new(Resolver::new(Config {
            upstreams: vec![server],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(2),
            attempts: 1,
            cache: false,
            read_etc_hosts: false,
            ..Config::default()
        }));
        let barrier = Arc::new(Barrier::new(3));
        let mut clients = Vec::new();
        for id in [101, 202] {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            clients.push(thread::spawn(move || {
                let query = make_query("coalesced.example.test", TYPE_A, id).expect("query");
                barrier.wait();
                resolver
                    .query(&query, QueryMode::Full)
                    .expect("coalesced response")
            }));
        }
        barrier.wait();

        for (client, id) in clients.into_iter().zip([101, 202]) {
            let response = client.join().expect("client thread");
            assert_eq!(Header::parse(&response).expect("header").id, id);
            assert_eq!(
                wire::extract_addresses(&response, Some(2)).expect("address"),
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88))]
            );
        }
        worker.join().expect("test DNS worker");
    }

}
