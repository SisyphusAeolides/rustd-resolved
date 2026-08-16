//! Multi-worker stub DNS data plane — blows single-threaded sd-event away.
#![allow(missing_debug_implementations)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{error, info};

use crate::supremacy::budget::{QueryBudget, QueryClass};
use crate::supremacy::l2_cache::{CKey, L2Cache};

pub struct DataplaneConfig {
    pub bind: SocketAddr, // 127.0.0.53:53
    pub workers: usize,
    pub recvmmsg_batch: usize,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.53:53".parse().unwrap(),
            workers: std::thread::available_parallelism().map_or(4, |n| n.get().clamp(2, 16)),
            recvmmsg_batch: 32,
        }
    }
}

/// Create `SO_REUSEPORT` UDP sockets — one per worker.
pub fn open_reuseport_udp(addr: SocketAddr, n: usize) -> std::io::Result<Vec<std::net::UdpSocket>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        s.set_reuse_port(true)?;
        s.set_nonblocking(true)?;
        s.bind(&addr.into())?;
        out.push(s.into());
    }
    Ok(out)
}

pub struct Dataplane {
    pub cfg: DataplaneConfig,
    pub cache: Arc<L2Cache>,
    pub resolver: Arc<crate::supremacy::resolver::SupremacyResolver>,
}

impl Dataplane {
    pub async fn run(self: Arc<Self>) -> std::io::Result<()> {
        let socks = open_reuseport_udp(self.cfg.bind, self.cfg.workers)?;
        info!(workers = socks.len(), bind = %self.cfg.bind, "dataplane start");
        let mut handles = Vec::new();
        for (i, sock) in socks.into_iter().enumerate() {
            let this = Arc::clone(&self);
            let std_sock = sock;
            handles.push(tokio::spawn(async move {
                if let Err(e) = this.worker_loop(i, std_sock).await {
                    error!(worker = i, error = %e, "worker died");
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }

    async fn worker_loop(&self, id: usize, std_sock: std::net::UdpSocket) -> std::io::Result<()> {
        let sock = UdpSocket::from_std(std_sock)?;
        let _ = id;
        let mut buf = vec![0u8; 1232];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await?;
            let pkt = &buf[..n];
            let budget = QueryBudget::new(QueryClass::Interactive);
            match self.handle_query(pkt, &budget).await {
                Ok(resp) => {
                    let _ = sock.send_to(&resp, peer).await;
                }
                Err(()) => {
                    if let Some(servfail) = make_servfail(pkt) {
                        let _ = sock.send_to(&servfail, peer).await;
                    }
                }
            }
        }
    }

    async fn handle_query(&self, pkt: &[u8], budget: &QueryBudget) -> Result<Vec<u8>, ()> {
        if pkt.len() < 12 || pkt[2] & 0x80 != 0 {
            return Err(());
        }
        let (key, id) = parse_question_key(pkt).ok_or(())?;
        let now = std::time::Instant::now();
        if let Some((val, stale)) = self.cache.get(&key, now) {
            if !stale || budget.allow_stale() {
                return Ok(rewrite_id(&val.answer, id));
            }
        }
        if budget.expired() {
            return Err(());
        }
        let name =
            crate::nss_backend::wire_to_presentation(&key.owner).unwrap_or_else(|_| ".".into());
        match self
            .resolver
            .resolve_name(&name, key.qtype, key.qclass, QueryClass::Interactive)
            .await
        {
            Ok(val) => Ok(rewrite_id(&val.answer, id)),
            Err(_) => Err(()),
        }
    }
}

fn parse_question_key(pkt: &[u8]) -> Option<(CKey, u16)> {
    crate::wire::validate(pkt, false).ok()?;
    let header = crate::wire::Header::parse(pkt).ok()?;
    let question = crate::wire::first_question(pkt).ok()?;
    Some((
        CKey {
            owner: bytes::Bytes::copy_from_slice(question.name.canonical_wire()),
            qtype: question.rr_type,
            qclass: question.class,
            cd: header.checking_disabled(),
        },
        header.id,
    ))
}

fn rewrite_id(answer: &[u8], id: u16) -> Vec<u8> {
    let mut v = answer.to_vec();
    if v.len() >= 2 {
        v[0] = (id >> 8) as u8;
        v[1] = id as u8;
    }
    if v.len() >= 3 {
        v[2] |= 0x80;
    }
    v
}

fn make_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] = 0x80 | (r[2] & 0x01); // QR + keep RD
    r[3] = (r[3] & 0xF0) | 2; // SERVFAIL
    r[6] = 0;
    r[7] = 0;
    r[8] = 0;
    r[9] = 0;
    r[10] = 0;
    r[11] = 0;
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataplane_parses_valid_dns_question() {
        let packet = crate::wire::make_query("ExAmPlE.test", crate::wire::TYPE_A, 0x4242).unwrap();
        let (key, id) = parse_question_key(&packet).unwrap();
        assert_eq!(id, 0x4242);
        assert_eq!(key.qtype, crate::wire::TYPE_A);
        assert_eq!(key.qclass, crate::wire::CLASS_IN);
        assert_eq!(
            crate::nss_backend::wire_to_presentation(&key.owner).unwrap(),
            "example.test"
        );
    }

    #[test]
    fn dataplane_rejects_dns_response_as_query() {
        let query = crate::wire::make_query("example.test", crate::wire::TYPE_A, 7).unwrap();
        let response = crate::wire::local_response(
            &query,
            &[crate::wire::LocalRecord::A("192.0.2.1".parse().unwrap())],
            30,
        )
        .unwrap();
        assert!(parse_question_key(&response).is_none());
    }
}
