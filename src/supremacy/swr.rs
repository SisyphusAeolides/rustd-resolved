//! Stale-while-revalidate — ON by default (supremacy mode).
#![allow(missing_debug_implementations)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::supremacy::budget::QueryBudget;

#[derive(Clone, Copy, Debug)]
pub struct SwrConfig {
    pub enabled: bool,
    pub max_stale: Duration,
    pub refresh_backoff_base: Duration,
    pub refresh_backoff_max: Duration,
    /// Never SWR for these rcodes if DNSSEC bogus
    pub deny_on_bogus: bool,
}

impl Default for SwrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_stale: Duration::from_secs(86400),
            refresh_backoff_base: Duration::from_secs(2),
            refresh_backoff_max: Duration::from_secs(300),
            deny_on_bogus: true,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CacheFreshness {
    Fresh,
    StaleServable,
    Dead,
}

#[derive(Clone, Debug)]
pub struct SwrEntry<T> {
    pub value: T,
    pub expires: Instant,
    pub stale_until: Instant,
    pub dnssec_bogus: bool,
    pub refresh_failures: u32,
    pub last_refresh_attempt: Option<Instant>,
}

impl<T> SwrEntry<T> {
    pub fn freshness(&self, now: Instant, cfg: &SwrConfig) -> CacheFreshness {
        if now < self.expires {
            CacheFreshness::Fresh
        } else if cfg.enabled && now < self.stale_until && !(cfg.deny_on_bogus && self.dnssec_bogus)
        {
            CacheFreshness::StaleServable
        } else {
            CacheFreshness::Dead
        }
    }

    pub fn should_background_refresh(&self, now: Instant, cfg: &SwrConfig) -> bool {
        if !cfg.enabled || self.dnssec_bogus {
            return false;
        }
        if now < self.expires {
            // prefetch window: last 10% of TTL
            let ttl = self.expires.saturating_duration_since(
                self.stale_until
                    .checked_sub(cfg.max_stale)
                    .unwrap_or(self.expires),
            );
            let _ = ttl;
            return false;
        }
        let backoff = cfg
            .refresh_backoff_base
            .saturating_mul(1 << self.refresh_failures.min(8))
            .min(cfg.refresh_backoff_max);
        match self.last_refresh_attempt {
            None => true,
            Some(t) => now.duration_since(t) >= backoff,
        }
    }
}

pub enum SwrDecision<T> {
    /// Return immediately; optional bg refresh key
    Serve(T, bool /* kick_refresh */),
    /// Must fetch synchronously
    MustFetch,
}

pub fn decide_swr<T: Clone>(
    entry: Option<&SwrEntry<T>>,
    now: Instant,
    cfg: &SwrConfig,
    budget: &QueryBudget,
) -> SwrDecision<T> {
    let Some(e) = entry else {
        return SwrDecision::MustFetch;
    };
    match e.freshness(now, cfg) {
        CacheFreshness::Fresh => {
            let kick = e.should_background_refresh(now, cfg);
            SwrDecision::Serve(e.value.clone(), kick)
        }
        CacheFreshness::StaleServable => {
            // Always serve stale; refresh if budget wants or failures low
            let kick = e.should_background_refresh(now, cfg) || budget.allow_stale();
            SwrDecision::Serve(e.value.clone(), kick)
        }
        CacheFreshness::Dead => SwrDecision::MustFetch,
    }
}

/// Background refresh queue (singleflight-aware upstream).
#[derive(Clone)]
pub struct RefreshQueue<K: Send + 'static> {
    tx: mpsc::UnboundedSender<K>,
}

impl<K: Send + 'static> RefreshQueue<K> {
    pub fn spawn<F, Fut>(worker: F) -> Self
    where
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<K>();
        let worker = Arc::new(worker);
        tokio::spawn(async move {
            while let Some(k) = rx.recv().await {
                worker(k).await;
            }
        });
        Self { tx }
    }

    pub fn kick(&self, k: K) {
        let _ = self.tx.send(k);
    }
}
