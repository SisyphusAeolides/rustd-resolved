//! Refresh hot names before TTL death; optional CNAME target warm.
#![allow(missing_debug_implementations)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::supremacy::l2_cache::{CKey, L2Cache};

struct Heat {
    hits: u64,
    last: Instant,
}

impl Default for Heat {
    fn default() -> Self {
        Self {
            hits: 0,
            last: Instant::now(),
        }
    }
}

pub struct PrefetchEngine {
    heat: Mutex<HashMap<CKey, Heat>>,
    pub min_hits: u64,
    pub ttl_fraction: f64, // refresh when remaining < fraction
}

impl PrefetchEngine {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            heat: Mutex::new(HashMap::new()),
            min_hits: 3,
            ttl_fraction: 0.10,
        })
    }

    pub fn record_hit(&self, k: &CKey) {
        let mut g = self.heat.lock();
        let h = g.entry(k.clone()).or_insert(Heat {
            hits: 0,
            last: Instant::now(),
        });
        h.hits += 1;
        h.last = Instant::now();
    }

    pub fn candidates(&self, cache: &L2Cache, now: Instant, limit: usize) -> Vec<CKey> {
        let g = self.heat.lock();
        let mut out = Vec::new();
        for (k, h) in g.iter() {
            if h.hits < self.min_hits {
                continue;
            }
            if let Some(ent) = cache.get_entry(k) {
                if now >= ent.expires {
                    continue; // SWR path handles
                }
                let total = ent.expires.saturating_duration_since(
                    ent.expires
                        .checked_sub(Duration::from_secs(u64::from(ent.value.min_ttl)))
                        .unwrap(),
                );
                let rem = ent.expires.saturating_duration_since(now);
                if total.as_secs_f64() > 0.0
                    && (rem.as_secs_f64() / total.as_secs_f64()) < self.ttl_fraction
                {
                    out.push(k.clone());
                }
            }
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}
