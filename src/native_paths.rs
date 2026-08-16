// SPDX-License-Identifier: LGPL-2.1-or-later
//! RustD-native runtime and state paths for the resolver.

use std::path::{Path, PathBuf};

pub const RUNTIME_DIR: &str = "/run/rustd/resolve";
pub const STATE_DIR: &str = "/var/lib/rustd/resolved";
pub const LINK_DNS_DIR: &str = "/run/rustd/network/links";
pub const HOOK_DIR: &str = "/run/rustd/resolve.hook";
pub const RFC5011_TRUST_ANCHORS: &str = "/var/lib/rustd/resolved/rfc5011-trust-anchors.bin";

pub fn runtime_directory() -> PathBuf {
    runtime_directory_from_env().unwrap_or_else(|| PathBuf::from(RUNTIME_DIR))
}

pub fn runtime_directory_from_env() -> Option<PathBuf> {
    std::env::var_os("RUSTD_RESOLVED_RUN_DIR").map(PathBuf::from)
}

pub fn link_dns_directory() -> PathBuf {
    std::env::var_os("RUSTD_NETWORK_LINKS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(LINK_DNS_DIR))
}

pub fn varlink_resolve_socket(runtime: &Path) -> PathBuf {
    runtime.join("io.rustd.Resolve")
}

pub fn varlink_monitor_socket(runtime: &Path) -> PathBuf {
    runtime.join("io.rustd.Resolve.Monitor")
}

pub fn dns_delegate_search_dirs() -> Vec<PathBuf> {
    if let Some(value) = std::env::var_os("RUSTD_RESOLVED_DNS_DELEGATE_DIRS") {
        return std::env::split_paths(&value).collect();
    }
    [
        "/etc/rustd/dns-delegate.d",
        "/run/rustd/dns-delegate.d",
        "/usr/local/lib/rustd/dns-delegate.d",
        "/usr/lib/rustd/dns-delegate.d",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

pub fn dnssd_config_directories() -> Vec<PathBuf> {
    [
        "/etc/rustd/dnssd",
        "/run/rustd/dnssd",
        "/usr/local/lib/rustd/dnssd",
        "/usr/lib/rustd/dnssd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

pub fn static_record_directories() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/lib/rustd/resolve/static.d"),
        PathBuf::from("/usr/local/lib/rustd/resolve/static.d"),
        PathBuf::from("/run/rustd/resolve/static.d"),
        PathBuf::from("/etc/rustd/resolve/static.d"),
    ]
}

#[cfg(feature = "systemd-compat-paths")]
pub fn static_record_directories_compat() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/lib/systemd/resolve/static.d"),
        PathBuf::from("/usr/local/lib/systemd/resolve/static.d"),
        PathBuf::from("/run/systemd/resolve/static.d"),
        PathBuf::from("/etc/systemd/resolve/static.d"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_runtime_paths_are_rustd_owned() {
        assert!(RUNTIME_DIR.starts_with("/run/rustd/"));
        assert!(STATE_DIR.starts_with("/var/lib/rustd/"));
        assert!(LINK_DNS_DIR.starts_with("/run/rustd/"));
        assert!(!RUNTIME_DIR.contains("systemd"));
        assert!(!STATE_DIR.contains("systemd"));
    }

    #[test]
    fn default_fallback_upstreams_are_empty() {
        let config = crate::config::Config::default();
        assert!(config.fallback_upstreams.is_empty());
        assert!(config.configured_fallback_upstreams().is_empty());
    }
}
