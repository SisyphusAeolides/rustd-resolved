use super::dnssd_config::{DnsSdConfigError, ServiceCatalog};
use super::parity::{MdnsAddressFamily, MdnsInterface};
use super::parity_dnssd::DnsSdRecord;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const RELOAD_INTERVAL: Duration = Duration::from_secs(2);
const RETIRED_RETENTION: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct RetiredCatalog {
    expires: Instant,
    catalog: ServiceCatalog,
}

#[derive(Debug)]
struct CatalogState {
    catalog: ServiceCatalog,
    next_reload: Instant,
    retired: Vec<RetiredCatalog>,
}

impl Default for CatalogState {
    fn default() -> Self {
        Self {
            catalog: ServiceCatalog::default(),
            next_reload: Instant::now(),
            retired: Vec::new(),
        }
    }
}

static CATALOG: OnceLock<Mutex<CatalogState>> = OnceLock::new();

fn state() -> MutexGuard<'static, CatalogState> {
    CATALOG
        .get_or_init(|| Mutex::new(CatalogState::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn retire(state: &mut CatalogState, catalog: ServiceCatalog, now: Instant) {
    if catalog.is_empty() {
        return;
    }
    state.retired.push(RetiredCatalog {
        expires: now + RETIRED_RETENTION,
        catalog,
    });
    state.retired.retain(|entry| entry.expires > now);
}

fn reconcile_catalog(state: &mut CatalogState, loaded: ServiceCatalog, now: Instant) -> bool {
    let previous = state.catalog.clone();
    if !state.catalog.reconcile(loaded) {
        state.retired.retain(|entry| entry.expires > now);
        return false;
    }
    retire(state, previous, now);
    true
}

fn refresh(state: &mut CatalogState) -> Result<(), DnsSdConfigError> {
    let now = Instant::now();
    if now < state.next_reload {
        state.retired.retain(|entry| entry.expires > now);
        return Ok(());
    }
    state.next_reload = now + RELOAD_INTERVAL;
    let loaded = ServiceCatalog::load()?;
    reconcile_catalog(state, loaded, now);
    Ok(())
}

fn interface_for(ifindex: u32, addresses: &[IpAddr]) -> MdnsInterface {
    let family = if addresses.iter().any(IpAddr::is_ipv4) {
        MdnsAddressFamily::Ipv4
    } else {
        MdnsAddressFamily::Ipv6
    };
    MdnsInterface::new(ifindex, family)
}

pub fn records_for(
    ifindex: u32,
    addresses: &[IpAddr],
    host_label: &str,
    goodbye: bool,
) -> Result<Vec<DnsSdRecord>, DnsSdConfigError> {
    let mut state = state();
    refresh(&mut state)?;
    state.catalog.records(
        interface_for(ifindex, addresses),
        addresses,
        host_label,
        goodbye,
    )
}

pub fn goodbye_records_for(
    ifindex: u32,
    addresses: &[IpAddr],
    host_label: &str,
) -> Result<Vec<DnsSdRecord>, DnsSdConfigError> {
    let mut state = state();
    refresh(&mut state)?;
    let now = Instant::now();
    state.retired.retain(|entry| entry.expires > now);
    let interface = interface_for(ifindex, addresses);
    let mut output = Vec::new();
    for entry in &state.retired {
        output.extend(entry.catalog.records(
            interface,
            addresses,
            host_label,
            true,
        )?);
    }
    output.sort();
    output.dedup();
    Ok(output)
}

pub fn instance_owners(
    ifindex: u32,
    addresses: &[IpAddr],
    host_label: &str,
) -> Result<BTreeMap<Vec<u8>, String>, DnsSdConfigError> {
    let mut state = state();
    refresh(&mut state)?;
    state
        .catalog
        .instance_owners(interface_for(ifindex, addresses), addresses, host_label)
}

pub fn rename_conflicting_owner(
    owner: &[u8],
    rr_type: u16,
    ifindex: u32,
    addresses: &[IpAddr],
    host_label: &str,
) -> Result<Option<String>, DnsSdConfigError> {
    let mut state = state();
    refresh(&mut state)?;
    let interface = interface_for(ifindex, addresses);
    let owners = state
        .catalog
        .instance_owners(interface, addresses, host_label)?;
    let Some(service) = owners.get(owner).cloned() else {
        return Ok(None);
    };
    if !matches!(rr_type, 16 | 33) {
        return Ok(None);
    }
    let previous = state.catalog.clone();
    if state.catalog.rename_after_conflict(&service) {
        retire(&mut state, previous, Instant::now());
        Ok(Some(service))
    } else {
        Ok(None)
    }
}

pub fn generation() -> u64 {
    let mut state = state();
    if let Err(error) = refresh(&mut state) {
        eprintln!("rustd-resolved: failed to refresh DNS-SD services: {error}");
    }
    state.catalog.generation()
}

pub fn force_reload() -> Result<bool, DnsSdConfigError> {
    let loaded = ServiceCatalog::load()?;
    let mut state = state();
    let changed = reconcile_catalog(&mut state, loaded, Instant::now());
    state.next_reload = Instant::now() + RELOAD_INTERVAL;
    Ok(changed)
}

pub fn flush() {
    let mut state = state();
    let previous = std::mem::take(&mut state.catalog);
    retire(&mut state, previous, Instant::now());
    state.catalog = ServiceCatalog::default();
    state.next_reload = Instant::now();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_catalogs_expire() {
        let mut state = CatalogState::default();
        let now = Instant::now();
        state.retired.push(RetiredCatalog {
            expires: now,
            catalog: ServiceCatalog::default(),
        });
        state.retired.retain(|entry| entry.expires > now);
        assert!(state.retired.is_empty());
    }
}
