// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bounded worker pool with admission control, per-peer quotas, and overload metrics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const DEFAULT_WORKERS: usize = 16;
const DEFAULT_QUEUE_DEPTH: usize = 64;
const DEFAULT_PEER_LIMIT: usize = 8;

#[derive(Debug, Default)]
pub struct OverloadMetrics {
    pub admitted: AtomicU64,
    pub completed: AtomicU64,
    pub rejected_queue_full: AtomicU64,
    pub rejected_peer_quota: AtomicU64,
    pub active: AtomicUsize,
}

#[derive(Debug)]
pub struct BoundedExecutor {
    senders: Vec<SyncSender<Job>>,
    round_robin: AtomicUsize,
    metrics: Arc<OverloadMetrics>,
    peer_limit: usize,
    peer_inflight: Arc<Mutex<HashMap<u64, usize>>>,
    _workers: Vec<JoinHandle<()>>,
}

struct Job {
    peer_key: u64,
    work: Box<dyn FnOnce() + Send>,
}

impl BoundedExecutor {
    pub fn new(workers: usize, queue_depth: usize, peer_limit: usize) -> Self {
        let metrics = Arc::new(OverloadMetrics::default());
        let peer_inflight = Arc::new(Mutex::new(HashMap::new()));
        let mut senders = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);

        for index in 0..workers {
            let (sender, receiver) = mpsc::sync_channel(queue_depth);
            senders.push(sender);
            let metrics = Arc::clone(&metrics);
            let peer_inflight = Arc::clone(&peer_inflight);
            handles.push(
                thread::Builder::new()
                    .name(format!("rustd-resolved-worker-{index}"))
                    .spawn(move || worker_loop(&receiver, &metrics, &peer_inflight))
                    .expect("spawn bounded executor worker"),
            );
        }

        Self {
            senders,
            round_robin: AtomicUsize::new(0),
            metrics,
            peer_limit,
            peer_inflight,
            _workers: handles,
        }
    }

    pub fn metrics(&self) -> &OverloadMetrics {
        &self.metrics
    }

    pub fn try_submit<F>(&self, peer_key: u64, work: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.reserve_peer(peer_key) {
            self.metrics
                .rejected_peer_quota
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let job = Job {
            peer_key,
            work: Box::new(work),
        };

        if self.dispatch(job) {
            self.metrics.admitted.fetch_add(1, Ordering::Relaxed);
            self.metrics.active.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.release_peer(peer_key);
            self.metrics
                .rejected_queue_full
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn reserve_peer(&self, peer_key: u64) -> bool {
        let mut peers = self
            .peer_inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = peers.entry(peer_key).or_insert(0);
        if *count >= self.peer_limit {
            return false;
        }
        *count += 1;
        true
    }

    fn release_peer(&self, peer_key: u64) {
        let mut peers = self
            .peer_inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = peers.get_mut(&peer_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                peers.remove(&peer_key);
            }
        }
    }

    fn dispatch(&self, mut job: Job) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let start = self.round_robin.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        for offset in 0..self.senders.len() {
            let index = (start + offset) % self.senders.len();
            match self.senders[index].try_send(job) {
                Ok(()) => return true,
                Err(TrySendError::Full(returned)) => job = returned,
                Err(TrySendError::Disconnected(returned)) => job = returned,
            }
        }
        false
    }
}

fn worker_loop(
    receiver: &mpsc::Receiver<Job>,
    metrics: &OverloadMetrics,
    peer_inflight: &Mutex<HashMap<u64, usize>>,
) {
    loop {
        let job = match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        (job.work)();
        release_peer_key(peer_inflight, job.peer_key);
        metrics.active.fetch_sub(1, Ordering::Relaxed);
        metrics.completed.fetch_add(1, Ordering::Relaxed);
    }
}

fn release_peer_key(peer_inflight: &Mutex<HashMap<u64, usize>>, peer_key: u64) {
    let mut peers = peer_inflight
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(count) = peers.get_mut(&peer_key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            peers.remove(&peer_key);
        }
    }
}

pub fn peer_key_from_u64(value: u64) -> u64 {
    value
}

pub fn peer_key_from_socket_addr(address: std::net::SocketAddr) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    address.hash(&mut hasher);
    hasher.finish()
}

pub fn tcp_executor() -> &'static BoundedExecutor {
    static EXECUTOR: OnceLock<BoundedExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(|| {
        BoundedExecutor::new(DEFAULT_WORKERS, DEFAULT_QUEUE_DEPTH, DEFAULT_PEER_LIMIT)
    })
}

pub fn varlink_executor() -> &'static BoundedExecutor {
    static EXECUTOR: OnceLock<BoundedExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(|| {
        BoundedExecutor::new(DEFAULT_WORKERS, DEFAULT_QUEUE_DEPTH, DEFAULT_PEER_LIMIT)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize as Counter;
    use std::sync::Barrier;

    #[test]
    fn rejects_when_worker_queues_are_full() {
        let executor = BoundedExecutor::new(1, 1, 8);
        let gate = Arc::new(Barrier::new(2));
        let started = Arc::new(Counter::new(0));

        let gate_a = Arc::clone(&gate);
        let started_a = Arc::clone(&started);
        assert!(executor.try_submit(1, move || {
            started_a.fetch_add(1, Ordering::SeqCst);
            gate_a.wait();
        }));

        for _ in 0..4 {
            assert!(
                !executor.try_submit(1, || {}),
                "executor must reject when every queue is full"
            );
        }
        assert_eq!(
            executor
                .metrics()
                .rejected_queue_full
                .load(Ordering::Relaxed),
            4
        );

        gate.wait();
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn enforces_per_peer_concurrency_limit() {
        let executor = BoundedExecutor::new(4, 4, 2);
        let gate = Arc::new(Barrier::new(3));

        let first_gate = Arc::clone(&gate);
        let second_gate = Arc::clone(&gate);
        assert!(executor.try_submit(42, move || {
            first_gate.wait();
        }));
        assert!(executor.try_submit(42, move || {
            second_gate.wait();
        }));
        assert!(
            !executor.try_submit(42, || {}),
            "third concurrent job for the same peer must be rejected"
        );
        assert_eq!(
            executor
                .metrics()
                .rejected_peer_quota
                .load(Ordering::Relaxed),
            1
        );

        gate.wait();
    }
}
