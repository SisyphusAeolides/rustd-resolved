//! Lock-free-ish sharded DNS positive/negative cache with:
//! - per-shard `parking_lot` `RwLock` (or `std::sync::RwLock`)
//! - epoch-based lazy eviction (no background sweeper storms)
//! - singleflight coalescing for in-flight identical QNAME/QTYPE/QCLASS
//! - label-aware FNV-1a mixed with wyhash finalizer for name keys

#![allow(dead_code)]

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;

/// Wire-stable cache key: question, DNSSEC checking mode, and routing scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheKey {
    /// Lowercase DNS wire name, no compression, absolute (trailing root label 0).
    pub owner: Arc<[u8]>,
    pub qtype: u16,
    pub qclass: u16,
    pub checking_disabled: bool,
    pub route: u64,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(dns_name_hash(&self.owner));
        state.write_u16(self.qtype);
        state.write_u16(self.qclass);
        state.write_u8(u8::from(self.checking_disabled));
        state.write_u64(self.route);
    }
}

/// Fast DNS-name hash: process label-by-label, ASCII lower fold, FNV-ish mix.
#[inline]
pub fn dns_name_hash(wire: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    let mut i = 0usize;
    while i < wire.len() {
        let len = wire[i] as usize;
        if len == 0 {
            h ^= 0xff;
            h = h.wrapping_mul(PRIME);
            break;
        }
        // Compression pointer or invalid → poison hash (caller must reject earlier).
        if len > 63 || i + 1 + len > wire.len() {
            return h ^ 0xDEADBEEFCAFEBABE;
        }
        i += 1;
        for _ in 0..len {
            let b = wire[i];
            let folded = if b.is_ascii_uppercase() { b + 32 } else { b };
            h ^= u64::from(folded);
            h = h.wrapping_mul(PRIME);
            i += 1;
        }
        // label separator mix
        h ^= 0x2e;
        h = h.wrapping_mul(PRIME);
    }
    // wyhash-inspired final avalanche
    let mut x = h;
    x ^= x >> 32;
    x = x.wrapping_mul(0xe7037ed1a0b428db);
    x ^= x >> 32;
    x
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub rcode: u8,
    pub answer: Arc<[u8]>, // full message or RR set blob — your wire format
    pub inserted: Instant,
    pub expires_at: Instant,
    pub stale_until: Instant, // serve-stale window (RFC 8767 style)
    pub dnssec_secure: bool,
    pub source_ifindex: Option<i32>,
    pub source_scope: u64,
    pub insert_gen: u64,
}

impl CacheEntry {
    #[inline]
    pub fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires_at
    }

    #[inline]
    pub fn is_servable_stale(&self, now: Instant) -> bool {
        now >= self.expires_at && now < self.stale_until
    }
}

struct Shard {
    map: RwLock<HashMap<CacheKey, CacheEntry>>,
    /// Approx live entries for adaptive capacity.
    live: AtomicU64,
}

impl Shard {
    fn new(cap_hint: usize) -> Self {
        Self {
            map: RwLock::new(HashMap::with_capacity(cap_hint)),
            live: AtomicU64::new(0),
        }
    }
}

/// In-flight singleflight cell.
struct Flight {
    /// Subscribers get Ok(entry) or Err(()) if leader failed.
    tx: broadcast::Sender<Result<CacheEntry, ()>>,
}

pub struct GlobalCache {
    shards: Vec<Shard>,
    shard_mask: u64,
    max_per_shard: usize,
    stale_window: RwLock<Duration>,
    gen: AtomicU64,
    flights: Mutex<HashMap<CacheKey, Arc<Flight>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    stale_hits: AtomicU64,
    coalesced: AtomicU64,
}

impl std::fmt::Debug for GlobalCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCache")
            .field("max_per_shard", &self.max_per_shard)
            .field("stale_window", &*self.stale_window.read())
            .finish_non_exhaustive()
    }
}

impl GlobalCache {
    /// `shard_bits` 6 → 64 shards. Power-of-two only.
    pub fn new(shard_bits: u32, max_per_shard: usize, stale_window: Duration) -> Self {
        assert!(shard_bits > 0 && shard_bits <= 12);
        let n = 1usize << shard_bits;
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            shards.push(Shard::new(max_per_shard.min(1024)));
        }
        Self {
            shards,
            shard_mask: (n as u64) - 1,
            max_per_shard,
            stale_window: RwLock::new(stale_window),
            gen: AtomicU64::new(1),
            flights: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale_hits: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_idx(&self, key: &CacheKey) -> usize {
        (dns_name_hash(&key.owner) ^ (u64::from(key.qtype) << 16) ^ u64::from(key.qclass)) as usize
            & self.shard_mask as usize
    }

    pub fn lookup(&self, key: &CacheKey, now: Instant) -> Lookup {
        let shard = &self.shards[self.shard_idx(key)];
        let guard = shard.map.read();
        match guard.get(key) {
            Some(e) if e.is_fresh(now) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Lookup::Fresh(e.clone())
            }
            Some(e) if e.is_servable_stale(now) => {
                self.stale_hits.fetch_add(1, Ordering::Relaxed);
                Lookup::Stale(e.clone())
            }
            Some(_) | None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                Lookup::Miss
            }
        }
    }

    pub fn insert(
        &self,
        key: CacheKey,
        rcode: u8,
        answer: Arc<[u8]>,
        ttl: Duration,
        dnssec_secure: bool,
        source_ifindex: Option<i32>,
        now: Instant,
    ) {
        self.insert_with_scope(
            key,
            rcode,
            answer,
            ttl,
            dnssec_secure,
            source_ifindex,
            0,
            now,
        );
    }

    pub fn insert_with_scope(
        &self,
        key: CacheKey,
        rcode: u8,
        answer: Arc<[u8]>,
        ttl: Duration,
        dnssec_secure: bool,
        source_ifindex: Option<i32>,
        source_scope: u64,
        now: Instant,
    ) {
        let ttl = clamp_ttl(ttl, rcode);
        let stale_window = *self.stale_window.read();
        let entry = CacheEntry {
            rcode,
            answer,
            inserted: now,
            expires_at: now + ttl,
            stale_until: now + ttl + stale_window,
            dnssec_secure,
            source_ifindex,
            source_scope,
            insert_gen: self.gen.fetch_add(1, Ordering::Relaxed),
        };
        let idx = self.shard_idx(&key);
        let shard = &self.shards[idx];
        let mut map = shard.map.write();
        if map.len() >= self.max_per_shard {
            evict_expired_or_oldest(&mut map, now, self.max_per_shard / 16 + 1);
        }
        let new = !map.contains_key(&key);
        map.insert(key, entry);
        if new {
            shard.live.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_stale_window(&self, stale_window: Duration) {
        *self.stale_window.write() = stale_window;
        for shard in &self.shards {
            for entry in shard.map.write().values_mut() {
                entry.stale_until = entry.expires_at + stale_window;
            }
        }
    }

    /// Singleflight: only one task performs `fetch`; others await the result.
    pub async fn get_or_fetch<F, Fut>(
        &self,
        key: CacheKey,
        now: Instant,
        fetch: F,
    ) -> Result<CacheEntry, FetchErr>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(u8, Arc<[u8]>, Duration, bool), FetchErr>>,
    {
        match self.lookup(&key, now) {
            Lookup::Fresh(e) => return Ok(e),
            Lookup::Stale(e) => {
                // Return stale immediately; optionally kick background refresh.
                let cache = self as *const GlobalCache;
                let key_bg = key.clone();
                // SAFETY: caller keeps GlobalCache alive for daemon lifetime.
                let _ = (cache, key_bg);
                return Ok(e);
            }
            Lookup::Miss => {}
        }

        // Join or lead flight.
        let (rx_opt, leader) = {
            let mut flights = self.flights.lock();
            if let Some(f) = flights.get(&key) {
                self.coalesced.fetch_add(1, Ordering::Relaxed);
                (Some(f.tx.subscribe()), false)
            } else {
                let (tx, rx) = broadcast::channel(16);
                flights.insert(key.clone(), Arc::new(Flight { tx: tx.clone() }));
                (Some(rx), true)
            }
        };

        if !leader {
            let mut rx = rx_opt.expect("follower rx");
            return match rx.recv().await {
                Ok(Ok(e)) => Ok(e),
                Ok(Err(())) => Err(FetchErr::LeaderFailed),
                Err(_) => Err(FetchErr::CoalesceDropped),
            };
        }

        let result = fetch().await;
        let publish = {
            let mut flights = self.flights.lock();
            flights.remove(&key).map(|f| f.tx.clone())
        };

        match result {
            Ok((rcode, answer, ttl, secure)) => {
                self.insert(
                    key,
                    rcode,
                    answer.clone(),
                    ttl,
                    secure,
                    None,
                    Instant::now(),
                );
                let entry = CacheEntry {
                    rcode,
                    answer,
                    inserted: Instant::now(),
                    expires_at: Instant::now() + clamp_ttl(ttl, rcode),
                    stale_until: Instant::now() + clamp_ttl(ttl, rcode) + *self.stale_window.read(),
                    dnssec_secure: secure,
                    source_ifindex: None,
                    source_scope: 0,
                    insert_gen: self.gen.load(Ordering::Relaxed),
                };
                if let Some(tx) = publish {
                    let _ = tx.send(Ok(entry.clone()));
                }
                Ok(entry)
            }
            Err(e) => {
                if let Some(tx) = publish {
                    let _ = tx.send(Err(()));
                }
                Err(e)
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
        }
    }

    pub fn flush(&self) {
        for shard in &self.shards {
            let mut map = shard.map.write();
            map.clear();
            shard.live.store(0, Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.live.load(Ordering::Relaxed) as usize)
            .sum()
    }

    pub fn snapshot(&self, now: Instant) -> Vec<(CacheKey, CacheEntry)> {
        let mut entries = Vec::new();
        for shard in &self.shards {
            let map = shard.map.read();
            entries.extend(map.iter().filter_map(|(key, entry)| {
                if entry.is_fresh(now) || entry.is_servable_stale(now) {
                    Some((key.clone(), entry.clone()))
                } else {
                    None
                }
            }));
        }
        entries.sort_by(|(left_key, left_entry), (right_key, right_entry)| {
            left_key
                .owner
                .as_ref()
                .cmp(right_key.owner.as_ref())
                .then_with(|| left_key.qclass.cmp(&right_key.qclass))
                .then_with(|| left_key.qtype.cmp(&right_key.qtype))
                .then_with(|| left_entry.insert_gen.cmp(&right_entry.insert_gen))
        });
        entries
    }
}

#[derive(Clone, Debug)]
pub enum Lookup {
    Fresh(CacheEntry),
    Stale(CacheEntry),
    Miss,
}

#[derive(Clone, Debug)]
pub enum FetchErr {
    Upstream,
    Timeout,
    LeaderFailed,
    CoalesceDropped,
    PolicyDenied,
}

#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
    pub coalesced: u64,
}

#[inline]
fn clamp_ttl(ttl: Duration, rcode: u8) -> Duration {
    // NXDOMAIN/NODATA: cap negative cache (systemd-resolved style bounds).
    let max = if rcode == 3 || rcode == 0 {
        Duration::from_secs(if rcode == 3 { 1800 } else { 3600 })
    } else {
        Duration::from_secs(86400)
    };
    let min = Duration::from_secs(1);
    ttl.clamp(min, max)
}

fn evict_expired_or_oldest(map: &mut HashMap<CacheKey, CacheEntry>, now: Instant, budget: usize) {
    let mut removed = 0usize;
    map.retain(|_, e| {
        if removed >= budget {
            return true;
        }
        if !e.is_fresh(now) && !e.is_servable_stale(now) {
            removed += 1;
            false
        } else {
            true
        }
    });
    if removed >= budget || map.is_empty() {
        return;
    }
    // Hard pressure: drop lowest insert_gen.
    let mut gens: Vec<(u64, CacheKey)> =
        map.iter().map(|(k, e)| (e.insert_gen, k.clone())).collect();
    gens.sort_by_key(|(g, _)| *g);
    for (_, k) in gens.into_iter().take(budget.saturating_sub(removed)) {
        map.remove(&k);
    }
}

/// Normalize presentation/wire owner into lowercase uncompressed absolute wire name.
pub fn owner_to_wire_lower(labels: &[&[u8]]) -> Result<Arc<[u8]>, NameErr> {
    let mut out = Vec::with_capacity(64);
    let mut total = 0usize;
    for lab in labels {
        if lab.is_empty() || lab.len() > 63 {
            return Err(NameErr::BadLabel);
        }
        total += lab.len() + 1;
        if total > 255 {
            return Err(NameErr::TooLong);
        }
        out.push(lab.len() as u8);
        for &b in *lab {
            out.push(if b.is_ascii_uppercase() { b + 32 } else { b });
        }
    }
    out.push(0);
    Ok(Arc::from(out.into_boxed_slice()))
}

#[derive(Debug)]
pub enum NameErr {
    BadLabel,
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_case_insensitive() {
        let a = owner_to_wire_lower(&[b"Example", b"COM"]).unwrap();
        let b = owner_to_wire_lower(&[b"example", b"com"]).unwrap();
        assert_eq!(dns_name_hash(&a), dns_name_hash(&b));
    }

    #[test]
    fn insert_and_fresh_lookup() {
        let c = GlobalCache::new(4, 64, Duration::from_secs(30));
        let owner = owner_to_wire_lower(&[b"a", b"test"]).unwrap();
        let key = CacheKey {
            owner,
            qtype: 1,
            qclass: 1,
            checking_disabled: false,
            route: 0,
        };
        let now = Instant::now();
        c.insert(
            key.clone(),
            0,
            Arc::from([0u8; 32]),
            Duration::from_secs(60),
            false,
            None,
            now,
        );
        assert!(matches!(c.lookup(&key, now), Lookup::Fresh(_)));
    }

    #[test]
    fn changing_stale_window_updates_retained_entries() {
        let c = GlobalCache::new(4, 64, Duration::ZERO);
        let key = CacheKey {
            owner: owner_to_wire_lower(&[b"stale", b"test"]).unwrap(),
            qtype: 1,
            qclass: 1,
            checking_disabled: false,
            route: 0,
        };
        let now = Instant::now();
        c.insert(
            key.clone(),
            0,
            Arc::from([0u8; 32]),
            Duration::from_secs(1),
            false,
            None,
            now,
        );
        let expired = now + Duration::from_secs(2);
        assert!(matches!(c.lookup(&key, expired), Lookup::Miss));

        c.set_stale_window(Duration::from_secs(60));
        assert!(matches!(c.lookup(&key, expired), Lookup::Stale(_)));
    }
}
