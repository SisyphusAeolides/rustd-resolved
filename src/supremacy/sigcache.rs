//! Don't re-verify the same RRSIG/DNSKEY thousands of times.
#![allow(missing_debug_implementations)]

use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct SigCacheKey {
    pub signer: Bytes,
    pub key_tag: u16,
    pub algorithm: u8,
    pub type_covered: u16,
    pub labels: u8,
    pub orig_ttl: u32,
    /// hash of rrset wire canonical form
    pub rrset_hash: u64,
    pub sig_hash: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum VerifyResult {
    Ok,
    Bad,
    Expired,
}

struct Ent {
    result: VerifyResult,
    expires: Instant,
}

pub struct SigCache {
    inner: Mutex<HashMap<SigCacheKey, Ent>>,
    cap: usize,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub verifies: AtomicU64,
}

impl SigCache {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::with_capacity(cap.min(8192))),
            cap,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            verifies: AtomicU64::new(0),
        }
    }

    pub fn get(&self, k: &SigCacheKey, now: Instant) -> Option<VerifyResult> {
        let g = self.inner.lock();
        if let Some(e) = g.get(k) {
            if now < e.expires {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(e.result);
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn put(&self, k: SigCacheKey, result: VerifyResult, ttl: Duration, now: Instant) {
        let mut g = self.inner.lock();
        if g.len() >= self.cap {
            g.retain(|_, e| now < e.expires);
            if g.len() >= self.cap {
                g.clear(); // epoch drop
            }
        }
        g.insert(
            k,
            Ent {
                result,
                expires: now + ttl.min(Duration::from_secs(3600)),
            },
        );
    }

    /// `verify_fn` called only on miss
    pub fn get_or_verify<F>(
        &self,
        k: SigCacheKey,
        ttl: Duration,
        now: Instant,
        verify_fn: F,
    ) -> VerifyResult
    where
        F: FnOnce() -> VerifyResult,
    {
        if let Some(r) = self.get(&k, now) {
            return r;
        }
        self.verifies.fetch_add(1, Ordering::Relaxed);
        let r = verify_fn();
        self.put(k, r, ttl, now);
        r
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct KeyCacheKey {
    pub zone: Bytes,
    pub key_tag: u16,
    pub algorithm: u8,
}

pub struct DnskeyCache {
    inner: Mutex<HashMap<KeyCacheKey, (Bytes, Instant)>>,
    cap: usize,
}

impl DnskeyCache {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cap,
        }
    }

    pub fn get(&self, k: &KeyCacheKey, now: Instant) -> Option<Bytes> {
        let g = self.inner.lock();
        g.get(k).filter(|(_, e)| now < *e).map(|(b, _)| b.clone())
    }

    pub fn put(&self, k: KeyCacheKey, key: Bytes, exp: Instant) {
        let mut g = self.inner.lock();
        if g.len() >= self.cap {
            g.clear();
        }
        g.insert(k, (key, exp));
    }
}
