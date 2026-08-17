//! RustD manager notification, watchdog, and signal-driven control flags.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{info, warn};

pub static RELOAD: AtomicBool = AtomicBool::new(false);
pub static FLUSH: AtomicBool = AtomicBool::new(false);
pub static STOP: AtomicBool = AtomicBool::new(false);
pub static DUMP_STATS: AtomicBool = AtomicBool::new(false);

/// Monotonic counter of reload requests (for tests / metrics).
pub static RELOAD_COUNT: AtomicU64 = AtomicU64::new(0);
pub static FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
pub struct LifecycleStats {
    pub ready_at: Option<Instant>,
    pub watchdog_ticks: u64,
}

pub fn rustd_notify_ready() {
    let _ = crate::native::notify("READY=1");
    info!("RustD manager notified READY=1");
}

pub fn rustd_notify_stopping() {
    let _ = crate::native::notify("STOPPING=1");
}

pub fn rustd_notify_watchdog() {
    let _ = crate::native::notify("WATCHDOG=1");
}

pub fn rustd_notify_status(msg: impl AsRef<str>) {
    let _ = crate::native::notify(&format!("STATUS={}", msg.as_ref()));
}

pub fn take_reload() -> bool {
    let v = RELOAD.swap(false, Ordering::SeqCst);
    if v {
        RELOAD_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    v
}

pub fn take_flush() -> bool {
    let v = FLUSH.swap(false, Ordering::SeqCst);
    if v {
        FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    v
}

pub fn take_dump_stats() -> bool {
    DUMP_STATS.swap(false, Ordering::SeqCst)
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// Install async Unix signal handlers. Safe to call once per process.
pub fn install_signal_handlers() {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGHUP handler unavailable");
                    return;
                }
            };
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGTERM handler unavailable");
                    return;
                }
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGINT handler unavailable");
                    return;
                }
            };
            let mut usr1 = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGUSR1 handler unavailable");
                    return;
                }
            };
            let mut usr2 = match signal(SignalKind::user_defined2()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "SIGUSR2 handler unavailable");
                    return;
                }
            };

            loop {
                tokio::select! {
                    Some(()) = hup.recv() => {
                        info!("SIGHUP → reload");
                        RELOAD.store(true, Ordering::SeqCst);
                    }
                    Some(()) = term.recv() => {
                        info!("SIGTERM → stop");
                        STOP.store(true, Ordering::SeqCst);
                    }
                    Some(()) = int.recv() => {
                        info!("SIGINT → stop");
                        STOP.store(true, Ordering::SeqCst);
                    }
                    Some(()) = usr1.recv() => {
                        info!("SIGUSR1 → dump stats");
                        DUMP_STATS.store(true, Ordering::SeqCst);
                    }
                    Some(()) = usr2.recv() => {
                        info!("SIGUSR2 → flush caches");
                        FLUSH.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    });
}

/// Background task: watchdog pet + optional custom interval.
pub fn spawn_watchdog_loop(interval: Duration) {
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(interval);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            iv.tick().await;
            if stop_requested() {
                break;
            }
            rustd_notify_watchdog();
        }
    });
}
