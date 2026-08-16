//! Per-server capability memory: EDNS, DNSSEC DO, DoT, cookies, TCP fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerFeatures {
    pub edns: Option<bool>,
    pub do_bit_ok: Option<bool>,
    pub udp_payload: u16,
    pub tcp_required: bool,
    pub dot_ok: Option<bool>,
    pub doh_ok: Option<bool>,
    pub cookie_ok: Option<bool>,
    pub dnssec_validated_ok: Option<bool>,
    #[serde(skip)]
    pub last_probe: Option<Instant>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub rtt_ewma_ms: f64,
    pub reachable: bool,
}

impl Default for ServerFeatures {
    fn default() -> Self {
        Self {
            edns: None,
            do_bit_ok: None,
            udp_payload: 1232,
            tcp_required: false,
            dot_ok: None,
            doh_ok: None,
            cookie_ok: None,
            dnssec_validated_ok: None,
            last_probe: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            rtt_ewma_ms: 50.0,
            reachable: true,
        }
    }
}

impl ServerFeatures {
    pub fn fresh() -> Self {
        Self::default()
    }

    pub fn apply_rtt_sample(&mut self, rtt: Duration, ok: bool) {
        let ms = rtt.as_secs_f64() * 1000.0;
        const A: f64 = 0.25;
        if ok {
            self.rtt_ewma_ms = A * ms + (1.0 - A) * self.rtt_ewma_ms;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            self.consecutive_failures = 0;
            self.reachable = true;
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.consecutive_successes = 0;
            if self.consecutive_failures >= 3 {
                self.tcp_required = true;
            }
            if self.consecutive_failures >= 5 {
                self.reachable = false;
            }
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerId {
    pub addr: SocketAddr,
    pub ifindex: i32,
    pub sni: Option<String>,
    pub doh_url: Option<String>,
}

#[derive(Debug)]
pub struct FeatureTable {
    map: RwLock<HashMap<ServerId, ServerFeatures>>,
    probe_interval: Duration,
}

impl FeatureTable {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            probe_interval: Duration::from_secs(600),
        }
    }

    pub fn with_probe_interval(mut self, d: Duration) -> Self {
        self.probe_interval = d;
        self
    }

    pub fn get(&self, id: &ServerId) -> ServerFeatures {
        self.map.read().get(id).cloned().unwrap_or_default()
    }

    pub fn set(&self, id: ServerId, f: ServerFeatures) {
        self.map.write().insert(id, f);
    }

    pub fn update<F>(&self, id: &ServerId, f: F)
    where
        F: FnOnce(&mut ServerFeatures),
    {
        let mut g = self.map.write();
        let e = g.entry(id.clone()).or_default();
        f(e);
    }

    pub fn reset_all(&self) {
        self.map.write().clear();
    }

    pub fn reset_one(&self, id: &ServerId) {
        self.map.write().remove(id);
    }

    pub fn mark_ok(&self, id: &ServerId, rtt: Duration) {
        self.update(id, |e| e.apply_rtt_sample(rtt, true));
    }

    pub fn mark_fail(&self, id: &ServerId) {
        self.update(id, |e| e.apply_rtt_sample(Duration::from_millis(0), false));
    }

    pub fn needs_probe(&self, id: &ServerId) -> bool {
        match self.get(id).last_probe {
            None => true,
            Some(t) => t.elapsed() >= self.probe_interval,
        }
    }

    pub fn note_probe(&self, id: &ServerId) {
        self.update(id, |e| e.last_probe = Some(Instant::now()));
    }

    pub fn note_formerr_edns(&self, id: &ServerId) {
        self.update(id, |e| {
            e.edns = Some(false);
            e.udp_payload = 512;
        });
    }

    pub fn note_edns_ok(&self, id: &ServerId, payload: u16) {
        self.update(id, |e| {
            e.edns = Some(true);
            e.udp_payload = payload.clamp(512, 4096);
        });
    }

    pub fn note_tc(&self, id: &ServerId) {
        self.update(id, |e| {
            e.tcp_required = true;
            if e.udp_payload > 512 {
                e.udp_payload = e.udp_payload.saturating_sub(128).max(512);
            }
        });
    }

    pub fn snapshot(&self) -> Vec<(ServerId, ServerFeatures)> {
        self.map
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for FeatureTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Probe policy recommendation for the transport layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportChoice {
    Udp,
    Tcp,
    Dot,
    Doh,
}

pub fn prefer_transport(f: &ServerFeatures, dot_mode: DotMode) -> TransportChoice {
    if !f.reachable {
        return TransportChoice::Udp;
    }
    match dot_mode {
        DotMode::No => {
            if f.tcp_required {
                TransportChoice::Tcp
            } else {
                TransportChoice::Udp
            }
        }
        DotMode::Opportunistic => {
            if f.dot_ok == Some(true) {
                TransportChoice::Dot
            } else if f.tcp_required {
                TransportChoice::Tcp
            } else {
                TransportChoice::Udp
            }
        }
        DotMode::Yes => TransportChoice::Dot,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DotMode {
    No,
    Opportunistic,
    Yes,
}
