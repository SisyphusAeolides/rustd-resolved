// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::{
    parse_server_spec, DnsServerSpec, Domain, SupportMode, TlsMode, ValidationMode,
};
use crate::native;
use crate::native_paths;
use crate::resolver::Resolver;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const NETWORKD_POLL_INTERVAL: Duration = Duration::from_millis(250);
const NETWORKD_REOPEN_INTERVAL: Duration = Duration::from_secs(1);
const NETWORKD_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const NETWORKD_MAX_BACKOFF: Duration = Duration::from_secs(60);

fn links_directory() -> std::path::PathBuf {
    native_paths::link_dns_directory()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalState {
    Missing,
    Off,
    NoCarrier,
    Dormant,
    DegradedCarrier,
    Carrier,
    Degraded,
    Enslaved,
    Routable,
    Unknown,
}

impl OperationalState {
    fn parse(value: Option<&str>) -> Self {
        match value {
            None => Self::Missing,
            Some("off") => Self::Off,
            Some("no-carrier") => Self::NoCarrier,
            Some("dormant") => Self::Dormant,
            Some("degraded-carrier") => Self::DegradedCarrier,
            Some("carrier") => Self::Carrier,
            Some("degraded") => Self::Degraded,
            Some("enslaved") => Self::Enslaved,
            Some("routable") => Self::Routable,
            Some(_) => Self::Unknown,
        }
    }

    pub const fn resolver_relevant(self) -> bool {
        matches!(
            self,
            Self::DegradedCarrier | Self::Degraded | Self::Routable
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkState {
    pub ifindex: i32,
    pub managed: bool,
    pub operstate: OperationalState,
    pub dns_servers: Vec<std::net::SocketAddr>,
    pub dns_server_specs: Vec<DnsServerSpec>,
    pub domains: Vec<Domain>,
    pub default_route: Option<bool>,
    pub llmnr: SupportMode,
    pub multicast_dns: SupportMode,
    pub dns_over_tls: Option<TlsMode>,
    pub dnssec: Option<ValidationMode>,
    pub dnssec_negative_trust_anchors: Vec<String>,
}

impl LinkState {
    pub const fn resolver_relevant(&self) -> bool {
        !self.managed || self.operstate.resolver_relevant()
    }
}

pub fn read_all() -> io::Result<Vec<LinkState>> {
    read_directory(&links_directory())
}

fn read_directory(directory: &Path) -> io::Result<Vec<LinkState>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut states = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(ifindex) = name.parse::<i32>() else {
            continue;
        };
        if ifindex <= 0 {
            continue;
        }
        match fs::read_to_string(entry.path()) {
            Ok(text) => states.push(parse_link_state(ifindex, &text)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    states.sort_by_key(|state| state.ifindex);
    Ok(states)
}

fn parse_link_state(ifindex: i32, text: &str) -> io::Result<LinkState> {
    let values = parse_environment(text);
    let admin_state = values.get("ADMIN_STATE").map(String::as_str);
    let managed = !matches!(
        admin_state,
        None | Some("pending" | "initialized" | "unmanaged")
    );
    let operstate = OperationalState::parse(values.get("OPER_STATE").map(String::as_str));

    if !managed {
        return Ok(LinkState {
            ifindex,
            managed: false,
            operstate,
            dns_servers: Vec::new(),
            dns_server_specs: Vec::new(),
            domains: Vec::new(),
            default_route: None,
            llmnr: SupportMode::Yes,
            multicast_dns: SupportMode::Yes,
            dns_over_tls: None,
            dnssec: None,
            dnssec_negative_trust_anchors: Vec::new(),
        });
    }

    let dns_server_specs = parse_dns_specs(values.get("DNS").map_or("", String::as_str))?;
    let dns_servers = dns_server_specs.iter().map(|spec| spec.address).fold(
        Vec::new(),
        |mut servers, address| {
            if !servers.contains(&address) {
                servers.push(address);
            }
            servers
        },
    );
    let mut domains = parse_domains(values.get("DOMAINS").map_or("", String::as_str), false)?;
    for domain in parse_domains(values.get("ROUTE_DOMAINS").map_or("", String::as_str), true)? {
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }

    Ok(LinkState {
        ifindex,
        managed: true,
        operstate,
        dns_servers,
        dns_server_specs,
        domains,
        default_route: values
            .get("DNS_DEFAULT_ROUTE")
            .map(|value| parse_bool(value))
            .transpose()?,
        llmnr: values
            .get("LLMNR")
            .map(|value| parse_support_mode(value))
            .transpose()?
            .unwrap_or(SupportMode::Yes),
        multicast_dns: values
            .get("MDNS")
            .map(|value| parse_support_mode(value))
            .transpose()?
            .unwrap_or(SupportMode::Yes),
        dns_over_tls: values
            .get("DNS_OVER_TLS")
            .map(|value| parse_tls_mode(value))
            .transpose()?,
        dnssec: values
            .get("DNSSEC")
            .map(|value| parse_validation_mode(value))
            .transpose()?,
        dnssec_negative_trust_anchors: parse_names(
            values.get("DNSSEC_NTA").map_or("", String::as_str),
        )?,
    })
}

fn parse_environment(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_owned(), unquote(value.trim())))
        })
        .collect()
}

fn unquote(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

fn parse_dns_specs(value: &str) -> io::Result<Vec<DnsServerSpec>> {
    let mut output = Vec::new();
    for token in value.split_whitespace() {
        let server = parse_server_spec(token).map_err(invalid_data)?;
        if !output.contains(&server) {
            output.push(server);
        }
    }
    Ok(output)
}

fn parse_domains(value: &str, route_only: bool) -> io::Result<Vec<Domain>> {
    let mut output = Vec::new();
    for token in value.split_whitespace() {
        let name = normalize_name(token)?;
        let domain = Domain { name, route_only };
        if !output.contains(&domain) {
            output.push(domain);
        }
    }
    Ok(output)
}

fn parse_names(value: &str) -> io::Result<Vec<String>> {
    let mut output = Vec::new();
    for token in value.split_whitespace() {
        let name = normalize_name(token)?;
        if !output.contains(&name) {
            output.push(name);
        }
    }
    Ok(output)
}

fn normalize_name(value: &str) -> io::Result<String> {
    let value = value.trim();
    if matches!(value, "." | "~" | "~.") {
        return Ok(".".to_owned());
    }
    let value = value
        .strip_prefix('~')
        .unwrap_or(value)
        .trim_end_matches('.');
    if value.is_empty()
        || !value.is_ascii()
        || value.len() > 253
        || value
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid networkd DNS domain {value}"),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_bool(value: &str) -> io::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid networkd boolean {value}"),
        )),
    }
}

fn parse_support_mode(value: &str) -> io::Result<SupportMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" => Ok(SupportMode::Yes),
        "resolve" => Ok(SupportMode::Resolve),
        "no" => Ok(SupportMode::No),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid networkd resolver support mode {value}"),
        )),
    }
}

fn parse_tls_mode(value: &str) -> io::Result<TlsMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" => Ok(TlsMode::No),
        "opportunistic" => Ok(TlsMode::Opportunistic),
        "yes" => Ok(TlsMode::Yes),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid networkd DNS-over-TLS mode {value}"),
        )),
    }
}

fn parse_validation_mode(value: &str) -> io::Result<ValidationMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" => Ok(ValidationMode::No),
        "allow-downgrade" => Ok(ValidationMode::AllowDowngrade),
        "yes" => Ok(ValidationMode::Yes),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid networkd DNSSEC mode {value}"),
        )),
    }
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub fn synchronize(resolver: &Resolver) -> io::Result<()> {
    let links = read_all()?;
    if std::env::var_os("RUSTD_RESOLVED_QUERY_DIAGNOSTICS").is_some() {
        for link in &links {
            eprintln!(
                "rustd-resolved: networkd link {} managed={} operstate={:?} DNS={:?}",
                link.ifindex, link.managed, link.operstate, link.dns_servers
            );
        }
    }
    resolver.sync_networkd_links(links).map_err(invalid_data)
}

pub fn spawn(resolver: Arc<Resolver>) -> io::Result<JoinHandle<()>> {
    if let Err(error) = synchronize(&resolver) {
        eprintln!("rustd-resolved: initial per-link DNS state unavailable: {error}");
    }
    thread::Builder::new()
        .name("resolved-link-dns".to_owned())
        .spawn(move || monitor(&resolver))
}

fn monitor(resolver: &Resolver) {
    use crate::daemon::stop_requested;

    let mut backoff = NETWORKD_INITIAL_BACKOFF;
    while !stop_requested() {
        let fd = match native::networkd_open() {
            Ok(fd) => fd,
            Err(error) => {
                eprintln!(
                    "rustd-resolved: per-link DNS monitor unavailable, retrying in {:?}: {error}",
                    backoff
                );
                thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(NETWORKD_MAX_BACKOFF);
                continue;
            }
        };
        backoff = NETWORKD_INITIAL_BACKOFF;
        // SAFETY: networkd_open returns a fresh owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let reopen_at = Instant::now() + NETWORKD_REOPEN_INTERVAL;
        loop {
            if stop_requested() {
                return;
            }
            match native::networkd_wait(fd.as_raw_fd(), NETWORKD_POLL_INTERVAL) {
                Ok(true) => {
                    if let Err(error) = synchronize(resolver) {
                        eprintln!("rustd-resolved: failed to refresh per-link DNS state: {error}");
                    }
                    crate::daemon::request_reload();
                }
                Ok(false) if Instant::now() >= reopen_at => {
                    if let Err(error) = synchronize(resolver) {
                        eprintln!("rustd-resolved: failed to refresh per-link DNS state: {error}");
                    }
                    crate::daemon::request_reload();
                    break;
                }
                Ok(false) => {}
                Err(error) => {
                    eprintln!("rustd-resolved: per-link DNS monitor failed, reconnecting: {error}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_managed_networkd_resolver_state() {
        let state = parse_link_state(
            7,
            "ADMIN_STATE=configured\n\
             OPER_STATE=degraded-carrier\n\
             DNS=192.0.2.53 2001:db8::53\n\
             DOMAINS=example.test\n\
             ROUTE_DOMAINS=corp.example\n\
             DNS_DEFAULT_ROUTE=no\n\
             LLMNR=resolve\n\
             MDNS=no\n\
             DNS_OVER_TLS=opportunistic\n\
             DNSSEC=allow-downgrade\n\
             DNSSEC_NTA=private.example.\n",
        )
        .expect("networkd state");
        assert!(state.managed);
        assert!(state.resolver_relevant());
        assert_eq!(state.dns_servers.len(), 2);
        assert_eq!(state.dns_server_specs.len(), 2);
        assert_eq!(
            state.domains,
            vec![
                Domain {
                    name: "example.test".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "corp.example".to_owned(),
                    route_only: true,
                },
            ]
        );
        assert_eq!(state.default_route, Some(false));
        assert_eq!(state.llmnr, SupportMode::Resolve);
        assert_eq!(state.multicast_dns, SupportMode::No);
        assert_eq!(state.dns_over_tls, Some(TlsMode::Opportunistic));
        assert_eq!(state.dnssec, Some(ValidationMode::AllowDowngrade));
        assert_eq!(
            state.dnssec_negative_trust_anchors,
            vec!["private.example".to_owned()]
        );
    }

    #[test]
    fn managed_dns_metadata_is_preserved() {
        let state = parse_link_state(
            7,
            "ADMIN_STATE=configured\nOPER_STATE=routable\nDNS=192.0.2.53:853%vpn0#resolver.example\n",
        )
        .expect("networkd DNS metadata");
        assert_eq!(state.dns_servers.len(), 1);
        assert_eq!(state.dns_server_specs.len(), 1);
        assert_eq!(state.dns_server_specs[0].interface.as_deref(), Some("vpn0"));
        assert_eq!(
            state.dns_server_specs[0].server_name.as_deref(),
            Some("resolver.example")
        );
    }

    #[test]
    fn root_route_domain_is_preserved() {
        let state = parse_link_state(
            7,
            "ADMIN_STATE=configured\nOPER_STATE=routable\nROUTE_DOMAINS=.\n",
        )
        .expect("root route domain");
        assert_eq!(
            state.domains,
            vec![Domain {
                name: ".".to_owned(),
                route_only: true,
            }]
        );
    }

    #[test]
    fn unmanaged_state_ignores_networkd_resolver_values() {
        let state = parse_link_state(
            7,
            "ADMIN_STATE=unmanaged\nOPER_STATE=routable\nDNS=192.0.2.53\nDOMAINS=example.test\n",
        )
        .expect("unmanaged state");
        assert!(!state.managed);
        assert!(state.dns_servers.is_empty());
        assert!(state.domains.is_empty());
    }

    #[test]
    fn managed_operstate_gates_resolver_relevance() {
        let configuring = parse_link_state(7, "ADMIN_STATE=configuring\nOPER_STATE=carrier\n")
            .expect("configuring state");
        assert!(!configuring.resolver_relevant());
        let routable = parse_link_state(7, "ADMIN_STATE=configured\nOPER_STATE=routable\n")
            .expect("routable state");
        assert!(routable.resolver_relevant());
    }

    #[test]
    fn spawn_does_not_require_link_dns_provider() {
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-missing-links-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        let previous = std::env::var_os("RUSTD_NETWORK_LINKS_DIR");
        std::env::set_var("RUSTD_NETWORK_LINKS_DIR", &directory);

        let resolver = Arc::new(crate::resolver::Resolver::new(
            crate::config::Config::default(),
        ));
        spawn(Arc::clone(&resolver)).expect("spawn link DNS monitor without provider");

        if let Some(value) = previous {
            std::env::set_var("RUSTD_NETWORK_LINKS_DIR", value);
        } else {
            std::env::remove_var("RUSTD_NETWORK_LINKS_DIR");
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn quoted_environment_values_are_unwrapped() {
        let values = parse_environment("ADMIN_STATE=\"configured\"\nDNS='192.0.2.53'\n");
        assert_eq!(
            values.get("ADMIN_STATE").map(String::as_str),
            Some("configured")
        );
        assert_eq!(values.get("DNS").map(String::as_str), Some("192.0.2.53"));
    }
}
