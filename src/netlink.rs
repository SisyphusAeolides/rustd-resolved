// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::daemon::{request_stop, stop_requested};
use crate::native;
use crate::resolver::Resolver;
use crate::routing::KernelLinkState;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const RTNL_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub fn synchronize(resolver: &Resolver) -> io::Result<()> {
    let snapshot = native::link_snapshot()?;
    if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
        for link in &snapshot {
            eprintln!(
                "rustd-resolved: kernel link {} ({}) flags={:#x} operstate={} ipv4-global={} ipv6-global={}",
                link.ifindex,
                link.ifname,
                link.flags,
                link.operstate,
                link.has_ipv4_global,
                link.has_ipv6_global
            );
        }
    }
    let links = snapshot
        .into_iter()
        .map(|link| KernelLinkState {
            ifindex: link.ifindex,
            ifname: link.ifname,
            flags: link.flags,
            mtu: link.mtu,
            operstate: link.operstate,
            has_ipv4_global: link.has_ipv4_global,
            has_ipv4_link_local: link.has_ipv4_link_local,
            has_ipv6_global: link.has_ipv6_global,
            has_ipv6_link_local: link.has_ipv6_link_local,
        })
        .collect();
    resolver
        .sync_kernel_links(links)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn spawn(resolver: Arc<Resolver>) -> io::Result<JoinHandle<()>> {
    synchronize(&resolver)?;
    let fd = native::rtnl_open()?;
    // SAFETY: rtnl_open returns a fresh owned descriptor on success.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    thread::Builder::new()
        .name("resolved-rtnl".to_owned())
        .spawn(move || monitor(&resolver, &fd))
}

fn monitor(resolver: &Resolver, fd: &OwnedFd) {
    while !stop_requested() {
        match native::rtnl_wait(fd.as_raw_fd(), RTNL_POLL_INTERVAL) {
            Ok(true) => {
                if let Err(error) = synchronize(resolver) {
                    eprintln!("rustd-resolved: failed to refresh kernel link state: {error}");
                }
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("rustd-resolved: RTNL monitoring failed: {error}");
                request_stop();
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn initial_kernel_snapshot_populates_resolver_links() {
        let resolver = Resolver::new(Config::default());
        synchronize(&resolver).expect("kernel link synchronization");
        assert!(!resolver.links().is_empty());
        assert!(resolver.links().iter().all(|link| link
            .kernel
            .as_ref()
            .is_some_and(|kernel| !kernel.ifname.is_empty())));
    }
}
