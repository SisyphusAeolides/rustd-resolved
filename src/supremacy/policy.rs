//! Beyond resolved: per-cgroup and per-netns DNS views + no-leak split DNS.
#![allow(missing_debug_implementations)]

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Clone, Debug, Default)]
pub struct DnsView {
    pub name: String,
    pub upstreams: Vec<SocketAddr>,
    pub domains: Vec<DomainRule>,
    pub default_route: bool,
    pub dnssec_mode: u8, // 0 no 1 allow-downgrade 2 yes
    pub dot: u8,         // 0 no 1 opp 2 yes
}

#[derive(Clone, Debug)]
pub struct DomainRule {
    pub suffix: String, // "corp.example" or "."
    pub search: bool,
    pub route_only: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyDb {
    pub by_cgroup: HashMap<String, String>, // cgroup path → view name
    pub by_netns: HashMap<u64, String>,     // inode → view
    pub by_uid: HashMap<u32, String>,
    pub views: HashMap<String, DnsView>,
    pub global: DnsView,
}

impl PolicyDb {
    pub fn resolve_view(
        &self,
        cgroup: Option<&str>,
        netns: Option<u64>,
        uid: Option<u32>,
    ) -> &DnsView {
        if let Some(ns) = netns {
            if let Some(vn) = self.by_netns.get(&ns) {
                if let Some(v) = self.views.get(vn) {
                    return v;
                }
            }
        }
        if let Some(cg) = cgroup {
            // longest prefix match on cgroup path
            let mut best: Option<(&str, &str)> = None;
            for (path, vn) in &self.by_cgroup {
                if cg.starts_with(path) && best.map_or(true, |(p, _)| path.len() > p.len()) {
                    best = Some((path.as_str(), vn.as_str()));
                }
            }
            if let Some((_, vn)) = best {
                if let Some(v) = self.views.get(vn) {
                    return v;
                }
            }
        }
        if let Some(u) = uid {
            if let Some(vn) = self.by_uid.get(&u) {
                if let Some(v) = self.views.get(vn) {
                    return v;
                }
            }
        }
        &self.global
    }
}

pub fn pick_links_for_name(name: &str, rules: &[DomainRule], default_ok: bool) -> Pick {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let mut best = -1isize;
    let mut matched = false;
    for r in rules {
        let d = r.suffix.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() || d == "." {
            continue;
        }
        if n == d || n.ends_with(&format!(".{d}")) {
            let len = d.len() as isize;
            if len > best {
                best = len;
                matched = true;
            }
        }
    }
    if matched {
        Pick::MatchedSuffix
    } else if default_ok {
        Pick::DefaultRoute
    } else {
        Pick::Blackhole // VPN no-leak: do not use global uplink
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    MatchedSuffix,
    DefaultRoute,
    Blackhole,
}
