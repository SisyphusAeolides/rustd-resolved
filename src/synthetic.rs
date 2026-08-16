//! Synthetic and special-name resolution (parity with systemd-resolved).
//!
//! Covers: localhost, hostname / pretty hostname, _gateway, _outbound (optional),
//! reverse PTR for loopback, and integration hooks for /etc/hosts.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use tracing::trace;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SynthAnswer {
    Addrs(Vec<IpAddr>),
    Names(Vec<String>),
    NxDomain,
    NoData,
}

#[derive(Clone, Debug, Default)]
pub struct HostsTable {
    /// lowercase name → addresses
    by_name: HashMap<String, Vec<IpAddr>>,
    /// address → names
    by_addr: HashMap<IpAddr, Vec<String>>,
}

impl HostsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_hosts_file(text: &str) -> Self {
        let mut t = Self::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip_s) = parts.next() else { continue };
            let Ok(ip) = IpAddr::from_str(ip_s) else {
                continue;
            };
            let names: Vec<String> = parts
                .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
                .collect();
            if names.is_empty() {
                continue;
            }
            for n in &names {
                t.by_name.entry(n.clone()).or_default().push(ip);
            }
            t.by_addr.entry(ip).or_default().extend(names);
        }
        // dedup
        for v in t.by_name.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        for v in t.by_addr.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        t
    }

    pub fn lookup_name(&self, name: &str, qtype: u16) -> Option<SynthAnswer> {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        let addrs = self.by_name.get(&n)?;
        let filtered: Vec<IpAddr> = addrs
            .iter()
            .copied()
            .filter(|a| match (qtype, a) {
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)) | (255, _) | (0, _) => true,
                _ => false,
            })
            .collect();
        if filtered.is_empty() {
            Some(SynthAnswer::NoData)
        } else {
            Some(SynthAnswer::Addrs(filtered))
        }
    }

    pub fn lookup_addr(&self, ip: IpAddr) -> Option<SynthAnswer> {
        let names = self.by_addr.get(&ip)?;
        Some(SynthAnswer::Names(names.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct SynthContext<'a> {
    pub hostname: &'a str,
    pub pretty_hostname: Option<&'a str>,
    pub gateway_v4: Option<Ipv4Addr>,
    pub gateway_v6: Option<Ipv6Addr>,
    /// Primary outbound interface addresses.
    pub outbound_addrs: &'a [IpAddr],
    pub local_addrs: &'a [IpAddr],
    pub hosts: Option<&'a HostsTable>,
}

fn norm(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn filter_addrs(addrs: impl Iterator<Item = IpAddr>, qtype: u16) -> Vec<IpAddr> {
    addrs
        .filter(|a| match (qtype, a) {
            (1, IpAddr::V4(_)) => true,
            (28, IpAddr::V6(_)) => true,
            (255, _) | (0, _) => true,
            _ => false,
        })
        .collect()
}

pub fn lookup_synthetic(ctx: &SynthContext<'_>, qname: &str, qtype: u16) -> Option<SynthAnswer> {
    let n = norm(qname);
    trace!(%n, qtype, "synthetic lookup");

    // /etc/hosts first (resolved does consult hosts)
    if let Some(h) = ctx.hosts {
        if let Some(a) = h.lookup_name(&n, qtype) {
            return Some(a);
        }
    }

    // localhost
    if n == "localhost" || n == "localhost.localdomain" || n.ends_with(".localhost") {
        return match qtype {
            1 => Some(SynthAnswer::Addrs(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])),
            28 => Some(SynthAnswer::Addrs(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)])),
            255 | 0 => Some(SynthAnswer::Addrs(vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])),
            _ => Some(SynthAnswer::NoData),
        };
    }

    // _gateway / gateway
    if n == "_gateway" || n == "gateway" {
        let mut v = Vec::new();
        if matches!(qtype, 1 | 255 | 0) {
            if let Some(a) = ctx.gateway_v4 {
                v.push(IpAddr::V4(a));
            }
        }
        if matches!(qtype, 28 | 255 | 0) {
            if let Some(a) = ctx.gateway_v6 {
                v.push(IpAddr::V6(a));
            }
        }
        return if v.is_empty() {
            Some(SynthAnswer::NxDomain)
        } else {
            Some(SynthAnswer::Addrs(v))
        };
    }

    // _outbound — addresses of the default route interface
    if n == "_outbound" {
        let v = filter_addrs(ctx.outbound_addrs.iter().copied(), qtype);
        return if v.is_empty() {
            Some(SynthAnswer::NxDomain)
        } else {
            Some(SynthAnswer::Addrs(v))
        };
    }

    // system hostname / pretty hostname
    let host = norm(ctx.hostname);
    let pretty = ctx.pretty_hostname.map(norm);
    if n == host || pretty.as_ref() == Some(&n) {
        let v = filter_addrs(ctx.local_addrs.iter().copied(), qtype);
        if !v.is_empty() {
            return Some(SynthAnswer::Addrs(v));
        }
        // hostname known but no addresses yet
        return Some(SynthAnswer::NoData);
    }

    None
}

pub fn lookup_synthetic_ptr(ctx: &SynthContext<'_>, addr: IpAddr) -> Option<SynthAnswer> {
    if let Some(h) = ctx.hosts {
        if let Some(a) = h.lookup_addr(addr) {
            return Some(a);
        }
    }
    match addr {
        IpAddr::V4(v) if v.octets()[0] == 127 => Some(SynthAnswer::Names(vec!["localhost".into()])),
        IpAddr::V6(v) if v.is_loopback() => Some(SynthAnswer::Names(vec!["localhost".into()])),
        _ => {
            // if addr is one of ours, return hostname
            if ctx.local_addrs.contains(&addr) {
                return Some(SynthAnswer::Names(vec![norm(ctx.hostname)]));
            }
            None
        }
    }
}

/// Map PTR wire-style reverse name to IpAddr if recognizable.
pub fn parse_in_addr_arpa(name: &str) -> Option<IpAddr> {
    let n = norm(name);
    if let Some(rest) = n.strip_suffix(".in-addr.arpa") {
        let mut octs: Vec<u8> = Vec::new();
        for p in rest.split('.') {
            octs.push(p.parse().ok()?);
        }
        if octs.len() != 4 {
            return None;
        }
        octs.reverse();
        return Some(IpAddr::V4(Ipv4Addr::new(
            octs[0], octs[1], octs[2], octs[3],
        )));
    }
    // ip6.arpa nibble-reversed — full parse omitted for brevity in PTR synthesis callers
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_a() {
        let ctx = SynthContext {
            hostname: "box",
            pretty_hostname: None,
            gateway_v4: None,
            gateway_v6: None,
            outbound_addrs: &[],
            local_addrs: &[],
            hosts: None,
        };
        match lookup_synthetic(&ctx, "localhost", 1) {
            Some(SynthAnswer::Addrs(a)) => assert_eq!(a[0], IpAddr::V4(Ipv4Addr::LOCALHOST)),
            _ => panic!(),
        }
    }

    #[test]
    fn hosts_file() {
        let t = HostsTable::parse_hosts_file("10.0.0.1 foo.example foo\n");
        match t.lookup_name("foo", 1) {
            Some(SynthAnswer::Addrs(a)) => assert_eq!(a[0].to_string(), "10.0.0.1"),
            _ => panic!(),
        }
    }
}
