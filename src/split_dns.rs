//! Split-DNS routing: longest suffix match, search expansion, VPN no-leak.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRule {
    /// DNS suffix without trailing dot. "." means default route domain.
    pub suffix: String,
    pub ifindex: i32,
    /// Participate in search-list expansion.
    pub search: bool,
    /// Routing-only domain (not used as search suffix).
    pub route_only: bool,
    /// Lower is higher priority when suffix lengths tie.
    pub priority: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    /// Query only these interfaces' DNS servers.
    Links(Vec<i32>),
    /// Use links marked default-route.
    DefaultRoute,
    /// Do not fall back to global/uplink (prevent leak).
    Blackhole,
}

#[derive(Clone, Debug)]
pub struct SplitDnsTable {
    pub rules: Vec<DomainRule>,
    pub default_route_ifindices: Vec<i32>,
    /// When false, names that miss suffix rules go Blackhole.
    pub allow_default: bool,
    pub ndots: usize,
    pub search: Vec<String>,
}

impl Default for SplitDnsTable {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_route_ifindices: Vec::new(),
            allow_default: true,
            ndots: 1,
            search: Vec::new(),
        }
    }
}

pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn suffix_match_len(name: &str, suffix: &str) -> Option<usize> {
    let n = normalize_name(name);
    let d = normalize_name(suffix);
    if d.is_empty() || d == "." {
        return None;
    }
    if n == d {
        return Some(d.len());
    }
    let needle = format!(".{}", d);
    if n.ends_with(&needle) {
        Some(d.len())
    } else {
        None
    }
}

impl SplitDnsTable {
    pub fn pick(&self, name: &str) -> Pick {
        pick_links_for_name(
            name,
            &self.rules,
            &self.default_route_ifindices,
            self.allow_default,
        )
    }

    pub fn expand(&self, name: &str) -> Vec<String> {
        expand_search(name, &self.search_list(), self.ndots)
    }

    pub fn search_list(&self) -> Vec<String> {
        let mut s = self.search.clone();
        for r in &self.rules {
            if r.search && !r.route_only {
                s.push(r.suffix.clone());
            }
        }
        s.iter()
            .map(|x| normalize_name(x))
            .filter(|x| !x.is_empty() && x != ".")
            .collect::<Vec<_>>()
            .into_iter()
            .fold(Vec::new(), |mut acc, x| {
                if !acc.contains(&x) {
                    acc.push(x);
                }
                acc
            })
    }

    pub fn upsert_rule(&mut self, rule: DomainRule) {
        if let Some(e) = self.rules.iter_mut().find(|r| {
            r.ifindex == rule.ifindex && normalize_name(&r.suffix) == normalize_name(&rule.suffix)
        }) {
            *e = rule;
        } else {
            self.rules.push(rule);
        }
    }

    pub fn clear_link(&mut self, ifindex: i32) {
        self.rules.retain(|r| r.ifindex != ifindex);
        self.default_route_ifindices.retain(|i| *i != ifindex);
    }
}

pub fn pick_links_for_name(
    name: &str,
    rules: &[DomainRule],
    default_route_links: &[i32],
    allow_default: bool,
) -> Pick {
    let mut best_len: isize = -1;
    let mut best_prio = i32::MAX;
    let mut hits: Vec<(i32, i32)> = Vec::new(); // ifindex, prio

    for r in rules {
        if let Some(len) = suffix_match_len(name, &r.suffix) {
            let len_i = len as isize;
            match len_i.cmp(&best_len) {
                Ordering::Greater => {
                    best_len = len_i;
                    best_prio = r.priority;
                    hits.clear();
                    hits.push((r.ifindex, r.priority));
                }
                Ordering::Equal => {
                    hits.push((r.ifindex, r.priority));
                    if r.priority < best_prio {
                        best_prio = r.priority;
                    }
                }
                Ordering::Less => {}
            }
        }
    }

    if !hits.is_empty() {
        // Prefer best priority among longest matches; keep all with that prio.
        let min_p = hits.iter().map(|h| h.1).min().unwrap_or(0);
        let mut links: Vec<i32> = hits
            .into_iter()
            .filter(|h| h.1 == min_p)
            .map(|h| h.0)
            .collect();
        links.sort_unstable();
        links.dedup();
        return Pick::Links(links);
    }

    if allow_default {
        let _ = default_route_links;
        Pick::DefaultRoute
    } else {
        Pick::Blackhole
    }
}

/// Expand a query name using search domains and ndots (glibc/resolv-like).
pub fn expand_search(name: &str, search: &[String], ndots: usize) -> Vec<String> {
    let raw = name.trim();
    if raw.is_empty() {
        return vec![];
    }
    // Absolute FQDN
    if raw.ends_with('.') {
        return vec![normalize_name(raw)];
    }
    let n = normalize_name(raw);
    let dots = n.chars().filter(|&c| c == '.').count();
    let mut out = Vec::new();

    if dots >= ndots {
        out.push(n.clone());
    }
    for s in search {
        let s = normalize_name(s);
        if s.is_empty() || s == "." {
            continue;
        }
        out.push(format!("{}.{}", n, s));
    }
    if dots < ndots {
        out.push(n);
    }

    let mut seen = std::collections::HashSet::new();
    out.retain(|x| seen.insert(x.clone()));
    out
}

/// True if sending `name` to a global uplink would violate a more-specific route-only domain.
pub fn would_leak_to_uplink(name: &str, rules: &[DomainRule]) -> bool {
    matches!(pick_links_for_name(name, rules, &[], false), Pick::Links(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(sfx: &str, ifi: i32) -> DomainRule {
        DomainRule {
            suffix: sfx.into(),
            ifindex: ifi,
            search: true,
            route_only: false,
            priority: 0,
        }
    }

    #[test]
    fn longest_suffix() {
        let rules = vec![rule("example", 1), rule("corp.example", 2)];
        assert_eq!(
            pick_links_for_name("x.corp.example", &rules, &[1], true),
            Pick::Links(vec![2])
        );
    }

    #[test]
    fn vpn_blackhole() {
        assert_eq!(
            pick_links_for_name("evil.com", &[rule("corp.vpn", 9)], &[], false),
            Pick::Blackhole
        );
    }

    #[test]
    fn search_ndots() {
        let v = expand_search("host", &["lan".into()], 1);
        assert!(v.contains(&"host.lan".into()));
        assert!(v.contains(&"host".into()));
    }
}
