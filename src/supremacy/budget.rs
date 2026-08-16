//! Per-client query time budget — kills multi-second stall cascades.
#![allow(missing_debug_implementations)]

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum QueryClass {
    Interactive, // browsers, getaddrinfo UX
    Bulk,        // updates, scanners
    Prefetch,    // background
}

#[derive(Clone, Debug)]
pub struct QueryBudget {
    pub class: QueryClass,
    pub start: Instant,
    pub total: Duration,
    pub upstream_slice: Duration,
}

impl QueryBudget {
    pub fn new(class: QueryClass) -> Self {
        let total = match class {
            QueryClass::Interactive => Duration::from_millis(350),
            QueryClass::Bulk => Duration::from_secs(2),
            QueryClass::Prefetch => Duration::from_secs(5),
        };
        Self {
            class,
            start: Instant::now(),
            total,
            upstream_slice: total / 3,
        }
    }

    pub fn from_client_hint(timeout_ms: Option<u64>) -> Self {
        if let Some(ms) = timeout_ms {
            let total = Duration::from_millis(ms.clamp(50, 10_000));
            return Self {
                class: QueryClass::Interactive,
                start: Instant::now(),
                total,
                upstream_slice: total / 3,
            };
        }
        Self::new(QueryClass::Interactive)
    }

    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    #[inline]
    pub fn remaining(&self) -> Duration {
        self.total.saturating_sub(self.elapsed())
    }

    #[inline]
    pub fn expired(&self) -> bool {
        self.elapsed() >= self.total
    }

    /// Timeout for next upstream attempt (Kalman RTT aware).
    pub fn upstream_timeout(&self, ewma_rtt: Duration, tries_left: u32) -> Duration {
        if self.expired() {
            return Duration::from_millis(1);
        }
        let rem = self.remaining();
        let fair = rem / tries_left.max(1);
        let floor = ewma_rtt.saturating_mul(2) + Duration::from_millis(20);
        let cap = self.upstream_slice.max(floor);
        fair.min(cap).min(rem).max(Duration::from_millis(15))
    }

    pub fn allow_stale(&self) -> bool {
        // Interactive: prefer stale over miss when budget half gone
        match self.class {
            QueryClass::Interactive => self.elapsed() > self.total / 2,
            QueryClass::Bulk => self.expired(),
            QueryClass::Prefetch => false,
        }
    }
}
