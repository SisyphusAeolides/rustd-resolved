// src/nss_backend.rs — varlink server handlers nss calls
// Ensure ifindex/scope_id returned for link-local so getaddrinfo works on LAN.
//! Publish the three classic files upstream clients depend on.
//!
//! /run/systemd/resolve/stub-resolv.conf  → nameserver 127.0.0.53
//! /run/systemd/resolve/resolv.conf       → uplink servers flattened
//! /run/systemd/resolve/resolv.conf (search/domain from routing)
//!
//! Admin may symlink /etc/resolv.conf to either. Modes:
//!   Stub  | Uplink | Foreign (don't touch /etc)
#![allow(missing_debug_implementations)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
pub enum ResolvConfMode {
    Stub,
    Uplink,
    Foreign,
}

pub struct ResolvConfPublisher {
    pub run_dir: PathBuf, // /run/systemd/resolve
    pub mode: ResolvConfMode,
}

impl ResolvConfPublisher {
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.run_dir)?;
        fs::create_dir_all(self.run_dir.join("netif"))?;
        // chmod 0755, owner root
        Ok(())
    }

    pub fn write_stub(&self, search: &[String], options: &str) -> std::io::Result<()> {
        let p = self.run_dir.join("stub-resolv.conf");
        let mut tmp = p.clone();
        tmp.set_extension("tmp");
        let mut f = fs::File::create(&tmp)?;
        writeln!(f, "# Written by rustd-resolved")?;
        writeln!(f, "nameserver 127.0.0.53")?;
        writeln!(f, "nameserver 127.0.0.54")?; // some upstream versions document .54
        if !search.is_empty() {
            writeln!(f, "search {}", search.join(" "))?;
        }
        if !options.is_empty() {
            writeln!(f, "options {options}")?;
        }
        f.sync_all()?;
        fs::rename(tmp, p)?;
        Ok(())
    }

    pub fn write_uplink(
        &self,
        servers: &[std::net::IpAddr],
        search: &[String],
    ) -> std::io::Result<()> {
        let p = self.run_dir.join("resolv.conf");
        let mut tmp = p.clone();
        tmp.set_extension("tmp");
        let mut f = fs::File::create(&tmp)?;
        writeln!(f, "# Uplink resolv.conf from rustd-resolved")?;
        for s in servers {
            writeln!(f, "nameserver {s}")?;
        }
        if !search.is_empty() {
            writeln!(f, "search {}", search.join(" "))?;
        }
        f.sync_all()?;
        fs::rename(tmp, p)?;
        Ok(())
    }

    pub fn write_netif(
        &self,
        ifindex: i32,
        servers: &[std::net::IpAddr],
        search: &[String],
    ) -> std::io::Result<()> {
        let p = self.run_dir.join("netif").join(ifindex.to_string());
        let mut tmp = p.clone();
        tmp.set_extension("tmp");
        let mut f = fs::File::create(&tmp)?;
        writeln!(f, "# Link {ifindex} state")?;
        for s in servers {
            writeln!(f, "nameserver {s}")?;
        }
        if !search.is_empty() {
            writeln!(f, "search {}", search.join(" "))?;
        }
        f.sync_all()?;
        fs::rename(tmp, p)?;
        Ok(())
    }

    /// Atomically refresh after link DNS change / Reload.
    pub fn republish(&self, state: &GlobalDnsState) -> std::io::Result<()> {
        self.ensure_dirs()?;
        self.write_stub(&state.search, "edns0 trust-ad")?;
        self.write_uplink(&state.uplink_servers, &state.search)?;
        Ok(())
    }
}

pub struct GlobalDnsState {
    pub search: Vec<String>,
    pub uplink_servers: Vec<std::net::IpAddr>,
}
