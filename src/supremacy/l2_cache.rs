//! L2 shared daemon cache — sharded, SWR, DNSSEC secure-stable.
#![allow(missing_debug_implementations)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::RwLock;

use crate::supremacy::swr::{SwrConfig, SwrEntry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnssecMark {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct CKey {
    pub owner: Bytes, // lowercase uncompressed wire
    pub qtype: u16,
    pub qclass: u16,
    pub cd: bool,
}

#[derive(Clone, Debug)]
pub struct CVal {
    pub rcode: u8,
    pub answer: Bytes,
    pub dnssec: DnssecMark,
    pub min_ttl: u32,
    pub from_upstream: u32,
}

pub struct Shard {
    map: RwLock<HashMap<CKey, SwrEntry<CVal>>>,
}

pub struct L2Cache {
    shards: Vec<Shard>,
    mask: u64,
    cap: usize,
    swr: SwrConfig,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub stale_hits: AtomicU64,
}

impl L2Cache {
    pub fn new(bits: u32, cap_per: usize, swr: SwrConfig) -> Arc<Self> {
        let n = 1usize << bits;
        Arc::new(Self {
            shards: (0..n)
                .map(|_| Shard {
                    map: RwLock::new(HashMap::with_capacity(cap_per.min(4096))),
                })
                .collect(),
            mask: (n as u64) - 1,
            cap: cap_per,
            swr,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale_hits: AtomicU64::new(0),
        })
    }

    fn idx(&self, k: &CKey) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = seahash::SeaHasher::new();
        k.hash(&mut h);
        (h.finish() & self.mask) as usize
    }

    pub fn get(&self, k: &CKey, now: Instant) -> Option<(CVal, bool /*stale*/)> {
        let g = self.shards[self.idx(k)].map.read();
        let e = g.get(k)?;
        match e.freshness(now, &self.swr) {
            crate::supremacy::swr::CacheFreshness::Fresh => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some((e.value.clone(), false))
            }
            crate::supremacy::swr::CacheFreshness::StaleServable => {
                self.stale_hits.fetch_add(1, Ordering::Relaxed);
                Some((e.value.clone(), true))
            }
            crate::supremacy::swr::CacheFreshness::Dead => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn get_entry(&self, k: &CKey) -> Option<SwrEntry<CVal>> {
        self.shards[self.idx(k)].map.read().get(k).cloned()
    }

    pub fn put(&self, k: CKey, val: CVal, ttl: Duration, now: Instant) {
        if val.dnssec == DnssecMark::Bogus && self.swr.deny_on_bogus {
            // still cache bogosity briefly to avoid hammering
        }
        let ttl = ttl.clamp(Duration::from_secs(1), Duration::from_secs(86400));
        let ent = SwrEntry {
            dnssec_bogus: val.dnssec == DnssecMark::Bogus,
            value: val,
            expires: now + ttl,
            stale_until: now + ttl + self.swr.max_stale,
            refresh_failures: 0,
            last_refresh_attempt: None,
        };
        let mut g = self.shards[self.idx(&k)].map.write();
        if let Some(old) = g.get(&k) {
            // secure-stable
            if old.value.dnssec == DnssecMark::Secure
                && ent.value.dnssec != DnssecMark::Secure
                && now < old.expires
            {
                return;
            }
        }
        if g.len() >= self.cap {
            g.retain(|_, e| now < e.stale_until);
            if g.len() >= self.cap {
                let drop_n = g.len() / 8 + 1;
                let keys: Vec<_> = g.keys().take(drop_n).cloned().collect();
                for key in keys {
                    g.remove(&key);
                }
            }
        }
        g.insert(k, ent);
    }

    pub fn mark_refresh_fail(&self, k: &CKey, now: Instant) {
        if let Some(e) = self.shards[self.idx(k)].map.write().get_mut(k) {
            e.refresh_failures = e.refresh_failures.saturating_add(1);
            e.last_refresh_attempt = Some(now);
        }
    }

    pub fn mark_refresh_ok(&self, k: &CKey, now: Instant) {
        if let Some(e) = self.shards[self.idx(k)].map.write().get_mut(k) {
            e.refresh_failures = 0;
            e.last_refresh_attempt = Some(now);
        }
    }

    pub fn flush(&self) {
        for s in &self.shards {
            s.map.write().clear();
        }
    }
}
