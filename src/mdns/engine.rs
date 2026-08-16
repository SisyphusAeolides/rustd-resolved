//! mDNS (RFC 6762) + DNS-SD (RFC 6763) engine.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdnsMode {
    No,
    Resolve,
    Yes,
}

impl MdnsMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Self::Yes,
            "resolve" => Self::Resolve,
            _ => Self::No,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ServiceType {
    pub kind: String,
    pub domain: String,
}

impl ServiceType {
    pub fn parse(s: &str) -> Self {
        // "_ssh._tcp.local" or "_ssh._tcp"
        let s = s.trim_end_matches('.');
        if let Some((kind, _)) = s.rsplit_once(".local") {
            let kind = kind.trim_end_matches('.');
            return Self {
                kind: kind.to_string(),
                domain: "local".into(),
            };
        }
        Self {
            kind: s.to_string(),
            domain: "local".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceInstance {
    pub instance: String,
    pub service: ServiceType,
    pub port: u16,
    pub target_host: String,
    pub txt: Vec<(String, Vec<u8>)>,
    pub ifindex: i32,
    pub ttl: u32,
    pub priority: u16,
    pub weight: u16,
}

impl ServiceInstance {
    pub fn fqsn(&self) -> String {
        format!(
            "{}.{}.{}",
            self.instance, self.service.kind, self.service.domain
        )
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedService {
    pub instance: ServiceInstance,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub enum BrowseEvent {
    Added(ServiceInstance),
    Removed {
        instance: String,
        service: ServiceType,
    },
}

#[derive(Debug)]
pub struct MdnsEngine {
    pub modes: RwLock<HashMap<i32, MdnsMode>>,
    pub zone_services: RwLock<Vec<ServiceInstance>>,
    pub zone_hosts: RwLock<HashMap<String, Vec<IpAddr>>>,
    browse_tx: broadcast::Sender<BrowseEvent>,
}

impl MdnsEngine {
    pub const PORT: u16 = 5353;
    pub const MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

    pub fn new() -> Arc<Self> {
        let (browse_tx, _) = broadcast::channel(256);
        Arc::new(Self {
            modes: RwLock::new(HashMap::new()),
            zone_services: RwLock::new(Vec::new()),
            zone_hosts: RwLock::new(HashMap::new()),
            browse_tx,
        })
    }

    pub fn set_mode(&self, ifindex: i32, mode: MdnsMode) {
        info!(ifindex, ?mode, "mdns mode");
        self.modes.write().insert(ifindex, mode);
    }

    pub fn register_service(&self, svc: ServiceInstance) {
        info!(fqsn = %svc.fqsn(), port = svc.port, "mdns register");
        let mut g = self.zone_services.write();
        g.retain(|s| s.fqsn() != svc.fqsn() || s.ifindex != svc.ifindex);
        g.push(svc.clone());
        let _ = self.browse_tx.send(BrowseEvent::Added(svc));
    }

    pub fn unregister_service(&self, fqsn: &str, ifindex: i32) {
        let mut g = self.zone_services.write();
        if let Some(pos) = g
            .iter()
            .position(|s| s.fqsn() == fqsn && s.ifindex == ifindex)
        {
            let s = g.remove(pos);
            let _ = self.browse_tx.send(BrowseEvent::Removed {
                instance: s.instance,
                service: s.service,
            });
        }
    }

    pub fn set_host_addrs(&self, host: &str, addrs: Vec<IpAddr>) {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.zone_hosts.write().insert(h, addrs);
    }

    pub fn subscribe_browse(&self) -> broadcast::Receiver<BrowseEvent> {
        self.browse_tx.subscribe()
    }

    pub async fn resolve_service(
        &self,
        name: &str,
        stype: Option<&str>,
        domain: &str,
        ifindex: Option<i32>,
    ) -> Option<ResolvedService> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let g = self.zone_services.read();
        let found = g.iter().find(|s| {
            if let Some(ifi) = ifindex {
                if s.ifindex != ifi {
                    return false;
                }
            }
            s.service.domain.eq_ignore_ascii_case(&domain)
                && (stype.is_none() || s.service.kind.eq_ignore_ascii_case(stype.unwrap_or("")))
                && (s.instance.eq_ignore_ascii_case(name) || s.fqsn().eq_ignore_ascii_case(name))
        })?;
        let host = found.target_host.to_ascii_lowercase();
        let addrs = self
            .zone_hosts
            .read()
            .get(&host)
            .cloned()
            .unwrap_or_default();
        Some(ResolvedService {
            instance: found.clone(),
            addresses: addrs,
        })
    }

    pub fn lookup_local(&self, host: &str, qtype: u16) -> Vec<IpAddr> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if !h.ends_with(".local") {
            return vec![];
        }
        let addrs = self.zone_hosts.read().get(&h).cloned().unwrap_or_default();
        addrs
            .into_iter()
            .filter(|a| match (qtype, a) {
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)) | (255, _) => true,
                _ => false,
            })
            .collect()
    }

    pub async fn run_udp(self: Arc<Self>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 9000];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "mdns recv");
                    continue;
                }
            };
            if n < 12 {
                continue;
            }
            let qr = buf[2] & 0x80 != 0;
            if !qr {
                self.handle_query(&buf[..n], peer, &sock).await;
            } else {
                self.handle_response(&buf[..n], peer);
            }
        }
    }

    async fn handle_query(&self, pkt: &[u8], peer: SocketAddr, sock: &UdpSocket) {
        let Some(qname) = crate::llmnr::parse_qname_pub(pkt).or_else(|| parse_qname(pkt)) else {
            return;
        };
        debug!(%qname, %peer, "mdns query");

        // Clone the matching service while the read lock is held, then release
        // the guard before performing async socket I/O. This prevents a slow
        // or backpressured send from blocking service registration/removal.
        let service = {
            let services = self.zone_services.read();
            services
                .iter()
                .find(|s| s.fqsn().eq_ignore_ascii_case(&qname))
                .cloned()
        };
        if let Some(svc) = service {
            if let Some(resp) = build_service_response(pkt, &svc) {
                let _ = sock
                    .send_to(&resp, SocketAddr::from((Self::MCAST_V4, Self::PORT)))
                    .await;
            }
            return;
        }

        // Host A/AAAA
        let addrs = self.lookup_local(&qname, 255);
        if !addrs.is_empty() {
            if let Some(resp) = build_addr_response(pkt, &addrs) {
                let _ = sock
                    .send_to(&resp, SocketAddr::from((Self::MCAST_V4, Self::PORT)))
                    .await;
            }
        }
    }

    fn handle_response(&self, pkt: &[u8], _peer: SocketAddr) {
        // Cache SRV/TXT/A/AAAA from network for browse/resolve
        let _ = pkt;
        // Full RR parse can reuse wire codec from crate::wire
    }
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

fn build_addr_response(query: &[u8], addrs: &[IpAddr]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] = 0x84;
    r[3] = 0;
    let an = addrs.len() as u16;
    r[6] = (an >> 8) as u8;
    r[7] = an as u8;
    for a in addrs {
        r.extend_from_slice(&[0xC0, 0x0C]);
        match a {
            IpAddr::V4(v) => {
                r.extend_from_slice(&1u16.to_be_bytes());
                r.extend_from_slice(&1u16.to_be_bytes());
                r.extend_from_slice(&120u32.to_be_bytes());
                r.extend_from_slice(&4u16.to_be_bytes());
                r.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                r.extend_from_slice(&28u16.to_be_bytes());
                r.extend_from_slice(&1u16.to_be_bytes());
                r.extend_from_slice(&120u32.to_be_bytes());
                r.extend_from_slice(&16u16.to_be_bytes());
                r.extend_from_slice(&v.octets());
            }
        }
    }
    Some(r)
}

fn build_service_response(query: &[u8], svc: &ServiceInstance) -> Option<Vec<u8>> {
    // PTR + SRV + TXT minimum
    let mut r = query.to_vec();
    r[2] = 0x84;
    r[6] = 0;
    r[7] = 2; // 2 answers simplified
              // SRV
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&33u16.to_be_bytes()); // SRV
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&svc.ttl.to_be_bytes());
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&svc.priority.to_be_bytes());
    rdata.extend_from_slice(&svc.weight.to_be_bytes());
    rdata.extend_from_slice(&svc.port.to_be_bytes());
    for lab in svc.target_host.trim_end_matches('.').split('.') {
        rdata.push(lab.len() as u8);
        rdata.extend_from_slice(lab.as_bytes());
    }
    rdata.push(0);
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(&rdata);
    // TXT
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&16u16.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&svc.ttl.to_be_bytes());
    let mut txt = Vec::new();
    if svc.txt.is_empty() {
        txt.push(0);
    } else {
        for (k, v) in &svc.txt {
            let mut pair = k.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(v);
            if pair.len() > 255 {
                continue;
            }
            txt.push(pair.len() as u8);
            txt.extend_from_slice(&pair);
        }
    }
    r.extend_from_slice(&(txt.len() as u16).to_be_bytes());
    r.extend_from_slice(&txt);
    Some(r)
}
