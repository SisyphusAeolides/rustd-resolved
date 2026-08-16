//! Metrics + ring-buffer flight recorder for failed queries.
#![allow(missing_debug_implementations)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Default)]
pub struct Metrics {
    pub queries_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_stale_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub shm_hits: AtomicU64,
    pub coalesce: AtomicU64,
    pub upstream_ok: AtomicU64,
    pub upstream_fail: AtomicU64,
    pub dnssec_verify_us_sum: AtomicU64,
    pub dnssec_verify_count: AtomicU64,
    pub dnssec_bogus: AtomicU64,
    pub nsec_agg_hits: AtomicU64,
    pub swr_served: AtomicU64,
    pub budget_expired: AtomicU64,
    pub latency_us_sum: AtomicU64,
    pub latency_count: AtomicU64,
}

impl Metrics {
    pub fn record_latency(&self, d: Duration) {
        self.latency_us_sum
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn prometheus_text(&self) -> String {
        let mut s = String::with_capacity(4096);
        macro_rules! g {
            ($n:expr, $f:ident) => {
                s.push_str(&format!(
                    "# TYPE {} counter\n{} {}\n",
                    $n,
                    $n,
                    self.$f.load(Ordering::Relaxed)
                ));
            };
        }
        g!("resolvedrs_queries_total", queries_total);
        g!("resolvedrs_cache_hits_total", cache_hits);
        g!("resolvedrs_cache_stale_hits_total", cache_stale_hits);
        g!("resolvedrs_cache_misses_total", cache_misses);
        g!("resolvedrs_shm_hits_total", shm_hits);
        g!("resolvedrs_coalesce_total", coalesce);
        g!("resolvedrs_upstream_ok_total", upstream_ok);
        g!("resolvedrs_upstream_fail_total", upstream_fail);
        g!("resolvedrs_dnssec_bogus_total", dnssec_bogus);
        g!("resolvedrs_nsec_agg_hits_total", nsec_agg_hits);
        g!("resolvedrs_swr_served_total", swr_served);
        g!("resolvedrs_budget_expired_total", budget_expired);
        let lc = self.latency_count.load(Ordering::Relaxed).max(1);
        let avg = self.latency_us_sum.load(Ordering::Relaxed) / lc;
        s.push_str(&format!(
            "# TYPE resolvedrs_query_latency_us gauge\nresolvedrs_query_latency_us {avg}\n"
        ));
        let vc = self.dnssec_verify_count.load(Ordering::Relaxed).max(1);
        let vavg = self.dnssec_verify_us_sum.load(Ordering::Relaxed) / vc;
        s.push_str(&format!(
            "# TYPE resolvedrs_dnssec_verify_us gauge\nresolvedrs_dnssec_verify_us {vavg}\n"
        ));
        s
    }
}

#[derive(Clone, Debug)]
pub struct FlightEvent {
    pub at: Instant,
    pub qname: String,
    pub qtype: u16,
    pub err: String,
    pub upstream: Option<String>,
    pub budget_ms_left: u64,
    pub wire_hex_prefix: String, // first 64B
}

pub struct FlightRecorder {
    q: Mutex<VecDeque<FlightEvent>>,
    cap: usize,
}

impl FlightRecorder {
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            q: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        })
    }

    pub fn push(&self, ev: FlightEvent) {
        let mut g = self.q.lock();
        if g.len() >= self.cap {
            g.pop_front();
        }
        g.push_back(ev);
    }

    pub fn snapshot(&self) -> Vec<FlightEvent> {
        self.q.lock().iter().cloned().collect()
    }
}

/// Tiny HTTP metrics server on 127.0.0.1:9990/metrics
pub async fn serve_metrics(m: Arc<Metrics>, addr: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    let lis = TcpListener::bind(addr).await?;
    loop {
        let (mut sock, _) = lis.accept().await?;
        let body = m.prometheus_text();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes()).await;
    }
}
