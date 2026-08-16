//! LLMNR (RFC 4795) engine: per-link mode, multicast I/O, conflict tracking.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmnrMode {
    No,
    Resolve,
    Yes,
}

impl LlmnrMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Self::Yes,
            "resolve" => Self::Resolve,
            _ => Self::No,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LlmnrLinkCfg {
    pub ifindex: i32,
    pub mode: LlmnrMode,
    pub claim_names: Vec<String>,
    pub addresses_v4: Vec<Ipv4Addr>,
    pub addresses_v6: Vec<Ipv6Addr>,
}

#[derive(Clone, Debug)]
pub struct LlmnrConflict {
    pub name: String,
    pub ifindex: i32,
    pub peer: SocketAddr,
    pub at: Instant,
}

#[derive(Clone, Debug)]
pub struct LlmnrQueryResult {
    pub name: String,
    pub addrs: Vec<std::net::IpAddr>,
    pub from: Vec<SocketAddr>,
}

#[derive(Debug)]
pub struct LlmnrEngine {
    pub links: RwLock<HashMap<i32, LlmnrLinkCfg>>,
    pub conflicts: RwLock<Vec<LlmnrConflict>>,
    /// outstanding id → (name, instant)
    inflight: RwLock<HashMap<u16, (String, Instant)>>,
}

impl LlmnrEngine {
    pub const PORT: u16 = 5355;
    pub const MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            links: RwLock::new(HashMap::new()),
            conflicts: RwLock::new(Vec::new()),
            inflight: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_link(&self, cfg: LlmnrLinkCfg) {
        info!(ifindex = cfg.ifindex, mode = ?cfg.mode, "llmnr link config");
        self.links.write().insert(cfg.ifindex, cfg);
    }

    pub fn clear_link(&self, ifindex: i32) {
        self.links.write().remove(&ifindex);
    }

    fn norm(n: &str) -> String {
        n.trim_end_matches('.').to_ascii_lowercase()
    }

    pub fn we_own(&self, ifindex: i32, name: &str) -> bool {
        let n = Self::norm(name);
        self.links
            .read()
            .get(&ifindex)
            .map(|l| l.mode == LlmnrMode::Yes && l.claim_names.iter().any(|c| Self::norm(c) == n))
            .unwrap_or(false)
    }

    pub fn any_yes(&self) -> bool {
        self.links.read().values().any(|l| l.mode == LlmnrMode::Yes)
    }

    pub async fn run_udp(self: Arc<Self>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "llmnr recv");
                    continue;
                }
            };
            if n < 12 {
                continue;
            }
            let pkt = &buf[..n];
            let qr = pkt[2] & 0x80 != 0;
            if !qr {
                self.handle_query(pkt, peer, &sock).await;
            } else {
                self.handle_response(pkt, peer);
            }
        }
    }

    async fn handle_query(&self, pkt: &[u8], peer: SocketAddr, sock: &UdpSocket) {
        let Some(qname) = parse_qname(pkt) else {
            return;
        };
        let qtype = qtype_at(pkt).unwrap_or(1);
        debug!(%qname, qtype, %peer, "llmnr query");

        // Respond on all Yes links that own the name (ifindex via PKTINFO preferred later)
        let links: Vec<_> = self.links.read().values().cloned().collect();
        for l in links {
            if l.mode != LlmnrMode::Yes || !self.we_own(l.ifindex, &qname) {
                continue;
            }
            let addrs_v4: Vec<[u8; 4]> = if qtype == 1 || qtype == 255 {
                l.addresses_v4.iter().map(|a| a.octets()).collect()
            } else {
                vec![]
            };
            let addrs_v6: Vec<[u8; 16]> = if qtype == 28 || qtype == 255 {
                l.addresses_v6.iter().map(|a| a.octets()).collect()
            } else {
                vec![]
            };
            if let Some(resp) = build_response(pkt, &addrs_v4, &addrs_v6) {
                if let Err(e) = sock.send_to(&resp, peer).await {
                    warn!(error = %e, "llmnr send");
                }
            }
        }
    }

    fn handle_response(&self, pkt: &[u8], peer: SocketAddr) {
        let id = u16::from_be_bytes([pkt[0], pkt[1]]);
        let Some(qname) = parse_qname(pkt) else {
            return;
        };
        let mut inflight = self.inflight.write();
        if let Some((name, _)) = inflight.remove(&id) {
            if Self::norm(&name) != Self::norm(&qname) {
                return;
            }
            // conflict detection: if we also own this name on some link
            for l in self.links.read().values() {
                if self.we_own(l.ifindex, &name) {
                    warn!(%name, %peer, "LLMNR conflict");
                    self.conflicts.write().push(LlmnrConflict {
                        name: name.clone(),
                        ifindex: l.ifindex,
                        peer,
                        at: Instant::now(),
                    });
                }
            }
        }
    }

    pub async fn query(
        &self,
        sock: &UdpSocket,
        name: &str,
        qtype: u16,
        timeout: Duration,
    ) -> Result<LlmnrQueryResult, LlmnrError> {
        let id: u16 = rand_id();
        let q = build_query(id, name, qtype).ok_or(LlmnrError::Wire)?;
        self.inflight
            .write()
            .insert(id, (name.to_string(), Instant::now()));
        let mcast = SocketAddr::from((Self::MCAST_V4, Self::PORT));
        sock.send_to(&q, mcast).await.map_err(LlmnrError::Io)?;

        let deadline = Instant::now() + timeout;
        let mut addrs = Vec::new();
        let mut from = Vec::new();
        let mut buf = vec![0u8; 2048];
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    if n >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id && buf[2] & 0x80 != 0 {
                        extract_addrs(&buf[..n], &mut addrs);
                        from.push(peer);
                    }
                }
                _ => break,
            }
        }
        self.inflight.write().remove(&id);
        if addrs.is_empty() {
            Err(LlmnrError::Timeout)
        } else {
            Ok(LlmnrQueryResult {
                name: name.into(),
                addrs,
                from,
            })
        }
    }
}

#[derive(Debug)]
pub enum LlmnrError {
    Timeout,
    Wire,
    Io(std::io::Error),
    Disabled,
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    (t as u16) ^ 0xA5A5
}

pub fn parse_qname_pub(pkt: &[u8]) -> Option<String> {
    parse_qname(pkt)
}

fn parse_qname(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    loop {
        if i >= pkt.len() {
            return None;
        }
        let l = pkt[i] as usize;
        if l == 0 {
            break;
        }
        if (l & 0xC0) == 0xC0 {
            return None;
        }
        if l > 63 || i + 1 + l > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[i + 1..i + 1 + l]).into_owned());
        i += 1 + l;
    }
    Some(labels.join("."))
}

fn qtype_at(pkt: &[u8]) -> Option<u16> {
    let mut i = 12usize;
    loop {
        if i >= pkt.len() {
            return None;
        }
        let l = pkt[i] as usize;
        if l == 0 {
            i += 1;
            break;
        }
        if (l & 0xC0) == 0xC0 {
            i += 2;
            break;
        }
        i += 1 + l;
    }
    if i + 4 > pkt.len() {
        return None;
    }
    Some(u16::from_be_bytes([pkt[i], pkt[i + 1]]))
}

fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut o = Vec::with_capacity(64);
    o.extend_from_slice(&id.to_be_bytes());
    o.extend_from_slice(&0u16.to_be_bytes()); // flags query
    o.extend_from_slice(&1u16.to_be_bytes());
    o.extend_from_slice(&0u16.to_be_bytes());
    o.extend_from_slice(&0u16.to_be_bytes());
    o.extend_from_slice(&0u16.to_be_bytes());
    for lab in name.trim_end_matches('.').split('.') {
        if lab.is_empty() || lab.len() > 63 {
            return None;
        }
        o.push(lab.len() as u8);
        o.extend_from_slice(lab.as_bytes());
    }
    o.push(0);
    o.extend_from_slice(&qtype.to_be_bytes());
    o.extend_from_slice(&1u16.to_be_bytes());
    Some(o)
}

fn build_response(query: &[u8], v4: &[[u8; 4]], v6: &[[u8; 16]]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] = 0x80; // QR; LLMNR bit 10 is conflict, not DNS AA
    r[3] = 0;
    let an = (v4.len() + v6.len()) as u16;
    r[6] = (an >> 8) as u8;
    r[7] = an as u8;
    r[8] = 0;
    r[9] = 0;
    r[10] = 0;
    r[11] = 0;
    // strip any trailing junk beyond question — keep header+qd only
    let qend = skip_name(query, 12)? + 4;
    r.truncate(qend.max(12));
    for a in v4 {
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&30u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(a);
    }
    for a in v6 {
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&28u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&30u32.to_be_bytes());
        r.extend_from_slice(&16u16.to_be_bytes());
        r.extend_from_slice(a);
    }
    Some(r)
}

fn skip_name(pkt: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= pkt.len() {
            return None;
        }
        let l = pkt[i] as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if (l & 0xC0) == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

pub fn extract_addrs(pkt: &[u8], out: &mut Vec<std::net::IpAddr>) {
    if pkt.len() < 12 {
        return;
    }
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let Some(mut i) = skip_name(pkt, 12) else {
        return;
    };
    i += 4;
    for _ in 0..an {
        let Some(ni) = skip_name(pkt, i) else { return };
        i = ni;
        if i + 10 > pkt.len() {
            return;
        }
        let typ = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
        let rdlen = u16::from_be_bytes([pkt[i + 8], pkt[i + 9]]) as usize;
        i += 10;
        if i + rdlen > pkt.len() {
            return;
        }
        if typ == 1 && rdlen == 4 {
            out.push(std::net::IpAddr::V4(Ipv4Addr::new(
                pkt[i],
                pkt[i + 1],
                pkt[i + 2],
                pkt[i + 3],
            )));
        } else if typ == 28 && rdlen == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[i..i + 16]);
            out.push(std::net::IpAddr::V6(Ipv6Addr::from(a)));
        }
        i += rdlen;
    }
}
