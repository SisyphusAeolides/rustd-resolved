//! Shared helpers between the daemon (SHM publisher / varlink) and conceptual NSS contract.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// Result of a hostname lookup suitable for NSS / varlink JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NssHostnameResult {
    pub canonical: String,
    pub addrs: Vec<NssAddr>,
    pub ttl: u32,
    pub secure: bool,
    pub from_cache: bool,
    pub rcode: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NssAddr {
    pub ip: IpAddr,
    /// Linux ifindex for link-local scope; 0 if none.
    pub ifindex: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NssReverseResult {
    pub names: Vec<String>,
    pub ttl: u32,
    pub secure: bool,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum NssBackendError {
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("not found")]
    NotFound,
    #[error("no data")]
    NoData,
    #[error("timeout")]
    Timeout,
    #[error("dnssec failure")]
    Dnssec,
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Encode presentation hostname to uncompressed lowercase absolute DNS wire format.
pub fn name_to_wire_lower(name: &str) -> Result<Vec<u8>, NssBackendError> {
    let raw = name.trim();
    if raw.is_empty() {
        return Err(NssBackendError::InvalidName("empty".into()));
    }
    let n = raw.trim_end_matches('.');
    if n.is_empty() {
        return Ok(vec![0]);
    }
    if n.len() > 253 {
        return Err(NssBackendError::InvalidName("too long".into()));
    }
    let mut out = Vec::with_capacity(n.len() + 2);
    for lab in n.split('.') {
        if lab.is_empty() {
            return Err(NssBackendError::InvalidName("empty label".into()));
        }
        if lab.len() > 63 {
            return Err(NssBackendError::InvalidName("label too long".into()));
        }
        if lab.starts_with('-') || lab.ends_with('-') {
            // allow for robustness; strict mode could reject
        }
        out.push(lab.len() as u8);
        for b in lab.bytes() {
            let c = if (b'A'..=b'Z').contains(&b) {
                b + 32
            } else {
                b
            };
            out.push(c);
        }
    }
    out.push(0);
    if out.len() > 255 {
        return Err(NssBackendError::InvalidName("wire too long".into()));
    }
    Ok(out)
}

pub fn wire_to_presentation(wire: &[u8]) -> Result<String, NssBackendError> {
    let mut s = String::new();
    let mut i = 0usize;
    let mut labels = 0usize;
    while i < wire.len() {
        let l = wire[i] as usize;
        if l == 0 {
            if s.is_empty() {
                return Ok(".".into());
            }
            return Ok(s);
        }
        if (l & 0xC0) != 0 {
            return Err(NssBackendError::InvalidName("compressed wire".into()));
        }
        if l > 63 || i + 1 + l > wire.len() {
            return Err(NssBackendError::InvalidName("bad label".into()));
        }
        if !s.is_empty() {
            s.push('.');
        }
        s.push_str(&String::from_utf8_lossy(&wire[i + 1..i + 1 + l]));
        i += 1 + l;
        labels += 1;
        if labels > 128 {
            return Err(NssBackendError::InvalidName("too many labels".into()));
        }
    }
    Err(NssBackendError::InvalidName("truncated wire".into()))
}

/// SHM-friendly address packing: family 4/6, scope_id, 16-byte addr.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ShmAddrPack {
    pub family: u8,
    pub _pad: u8,
    pub scope_id: u16,
    pub addr: [u8; 16],
}

pub fn ip_to_shm(ip: IpAddr, ifindex: i32) -> ShmAddrPack {
    match ip {
        IpAddr::V4(v4) => {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.octets());
            ShmAddrPack {
                family: 4,
                _pad: 0,
                scope_id: ifindex.max(0) as u16,
                addr,
            }
        }
        IpAddr::V6(v6) => ShmAddrPack {
            family: 6,
            _pad: 0,
            scope_id: ifindex.max(0) as u16,
            addr: v6.octets(),
        },
    }
}

pub fn shm_to_ip(a: &ShmAddrPack) -> Option<IpAddr> {
    match a.family {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            a.addr[0], a.addr[1], a.addr[2], a.addr[3],
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(a.addr))),
        _ => None,
    }
}

pub fn parse_ip_list(ss: &[String]) -> Vec<IpAddr> {
    ss.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Build a synthetic DNS answer message (header + question + A/AAAA RRs) for stub/cache.
pub fn build_address_answer(
    id: u16,
    qname_wire: &[u8],
    qtype: u16,
    addrs: &[(IpAddr, i32)],
    ttl: u32,
    aa: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&id.to_be_bytes());
    let mut flags: u16 = 0x8000; // QR
    if aa {
        flags |= 0x0400;
    }
    flags |= 0x0080; // RA
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qd
    let ancount = addrs
        .iter()
        .filter(|(ip, _)| match (qtype, ip) {
            (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)) | (255, _) => true,
            _ => false,
        })
        .count() as u16;
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(qname_wire);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN

    for (ip, _ifi) in addrs {
        let (rtype, rdata): (u16, Vec<u8>) = match (qtype, ip) {
            (1, IpAddr::V4(v)) => (1, v.octets().to_vec()),
            (28, IpAddr::V6(v)) => (28, v.octets().to_vec()),
            (255, IpAddr::V4(v)) => (1, v.octets().to_vec()),
            (255, IpAddr::V6(v)) => (28, v.octets().to_vec()),
            _ => continue,
        };
        // compression pointer to question name at offset 12
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let w = name_to_wire_lower("ExAmPle.CoM").unwrap();
        assert_eq!(wire_to_presentation(&w).unwrap(), "example.com");
        assert_eq!(w.last().copied(), Some(0));
    }

    #[test]
    fn build_a_answer() {
        let w = name_to_wire_lower("a.test").unwrap();
        let pkt = build_address_answer(
            0xABCD,
            &w,
            1,
            &[(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0)],
            60,
            false,
        );
        assert!(pkt.len() > 12);
        assert_eq!(pkt[0], 0xAB);
        assert_eq!(pkt[2] & 0x80, 0x80);
    }
}
