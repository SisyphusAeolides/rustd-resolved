// SPDX-License-Identifier: LGPL-2.1-or-later
//! Shared runtime logging controls exposed through D-Bus and Varlink.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

const LOG_EMERG: i32 = 0;
const LOG_ALERT: i32 = 1;
const LOG_CRIT: i32 = 2;
const LOG_ERR: i32 = 3;
const LOG_WARNING: i32 = 4;
const LOG_NOTICE: i32 = 5;
const LOG_INFO: i32 = 6;
const LOG_DEBUG: i32 = 7;

type FilterHandle = reload::Handle<LevelFilter, Registry>;

static GLOBAL: OnceLock<Arc<LogControlState>> = OnceLock::new();
static FILTER_HANDLE: OnceLock<FilterHandle> = OnceLock::new();

#[derive(Debug)]
pub struct LogControlState {
    level: AtomicI32,
    target: RwLock<String>,
}

impl Default for LogControlState {
    fn default() -> Self {
        Self {
            level: AtomicI32::new(LOG_INFO),
            target: RwLock::new("journal-or-kmsg".to_owned()),
        }
    }
}

impl LogControlState {
    pub fn global() -> Arc<Self> {
        Arc::clone(GLOBAL.get_or_init(|| Arc::new(Self::default())))
    }

    pub fn level(&self) -> i32 {
        self.level.load(Ordering::Relaxed)
    }

    pub fn level_name(&self) -> &'static str {
        level_name(self.level())
    }

    pub fn set_level(&self, level: i32) -> bool {
        if !valid_level(level) {
            return false;
        }
        self.level.store(level, Ordering::Relaxed);
        if let Some(handle) = FILTER_HANDLE.get() {
            let filter = tracing_filter(level);
            let _ = handle.modify(|current| *current = filter);
        }
        true
    }

    pub fn set_level_name(&self, level: &str) -> bool {
        let Some(level) = level_number(level) else {
            return false;
        };
        self.set_level(level)
    }

    pub fn target(&self) -> String {
        self.target
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set_target(&self, target: &str) -> bool {
        if !valid_target(target) {
            return false;
        }
        *self
            .target
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = target.to_owned();
        true
    }
}

/// Install the process-wide tracing subscriber used by runtime log controls.
///
/// Applications embedding the library may install their own subscriber first;
/// in that case the state remains usable and the caller's subscriber is left
/// untouched.
pub fn initialize() {
    if FILTER_HANDLE.get().is_some() {
        return;
    }

    let (filter, handle) = reload::Layer::new(tracing_filter(LogControlState::global().level()));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(false));
    if subscriber.try_init().is_ok() {
        let _ = FILTER_HANDLE.set(handle);
    }
}

fn tracing_filter(level: i32) -> LevelFilter {
    match level {
        LOG_EMERG..=LOG_ERR => LevelFilter::ERROR,
        LOG_WARNING => LevelFilter::WARN,
        LOG_NOTICE | LOG_INFO => LevelFilter::INFO,
        LOG_DEBUG => LevelFilter::DEBUG,
        _ => LevelFilter::OFF,
    }
}

fn valid_level(level: i32) -> bool {
    (LOG_EMERG..=LOG_DEBUG).contains(&level)
}

fn level_number(level: &str) -> Option<i32> {
    Some(match level {
        "emerg" => LOG_EMERG,
        "alert" => LOG_ALERT,
        "crit" => LOG_CRIT,
        "err" => LOG_ERR,
        "warning" => LOG_WARNING,
        "notice" => LOG_NOTICE,
        "info" => LOG_INFO,
        "debug" => LOG_DEBUG,
        _ => return None,
    })
}

fn level_name(level: i32) -> &'static str {
    match level {
        LOG_EMERG => "emerg",
        LOG_ALERT => "alert",
        LOG_CRIT => "crit",
        LOG_ERR => "err",
        LOG_WARNING => "warning",
        LOG_NOTICE => "notice",
        LOG_INFO => "info",
        LOG_DEBUG => "debug",
        _ => "info",
    }
}

fn valid_target(target: &str) -> bool {
    matches!(
        target,
        "console"
            | "console-prefixed"
            | "kmsg"
            | "journal"
            | "journal-or-kmsg"
            | "syslog"
            | "syslog-or-kmsg"
            | "auto"
            | "null"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_levels_have_stable_names_and_validation() {
        assert_eq!(level_name(LOG_INFO), "info");
        assert_eq!(level_number("debug"), Some(LOG_DEBUG));
        assert!(valid_level(LOG_EMERG));
        assert!(valid_level(LOG_DEBUG));
        assert!(!valid_level(-1));
        assert!(!valid_level(LOG_DEBUG + 1));
    }

    #[test]
    fn tracing_filter_preserves_bsd_severity_order() {
        assert_eq!(tracing_filter(LOG_ERR), LevelFilter::ERROR);
        assert_eq!(tracing_filter(LOG_WARNING), LevelFilter::WARN);
        assert_eq!(tracing_filter(LOG_INFO), LevelFilter::INFO);
        assert_eq!(tracing_filter(LOG_DEBUG), LevelFilter::DEBUG);
        assert_eq!(tracing_filter(-1), LevelFilter::OFF);
    }
}
