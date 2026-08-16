// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::config::{parse_server_spec, DnsServerSpec, Domain};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DNS_DELEGATES_MAX: usize = 4096;
const DNS_SERVERS_MAX: usize = 256;
const SEARCH_DOMAINS_MAX: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDelegate {
    pub id: String,
    pub servers: Vec<DnsServerSpec>,
    pub domains: Vec<Domain>,
    pub default_route: Option<bool>,
    pub firewall_mark: u32,
}

impl DnsDelegate {
    fn new(id: String) -> Self {
        Self {
            id,
            servers: Vec::new(),
            domains: Vec::new(),
            default_route: None,
            firewall_mark: 0,
        }
    }

    pub fn effective_default_route(&self) -> bool {
        self.default_route.unwrap_or(false)
    }

    fn apply_text(&mut self, text: &str) {
        let mut delegate_section = false;
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                delegate_section = &line[1..line.len() - 1] == "Delegate";
                continue;
            }
            if !delegate_section {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            self.apply_setting(key.trim(), value.trim());
        }
    }

    fn apply_setting(&mut self, key: &str, value: &str) {
        match key {
            "DNS" => self.apply_dns(value),
            "Domains" => self.apply_domains(value),
            "DefaultRoute" => {
                if value.is_empty() {
                    self.default_route = None;
                } else if let Some(value) = parse_boolean(value) {
                    self.default_route = Some(value);
                }
            }
            "FirewallMark" => {
                if let Some(value) = parse_unsigned(value) {
                    self.firewall_mark = value;
                }
            }
            _ => {}
        }
    }

    fn apply_dns(&mut self, value: &str) {
        if value.is_empty() {
            self.servers.clear();
            return;
        }
        for token in value.split_whitespace() {
            let Ok(server) = parse_server_spec(token) else {
                continue;
            };
            if invalid_server_address(&server) || self.servers.contains(&server) {
                continue;
            }
            if self.servers.len() < DNS_SERVERS_MAX {
                self.servers.push(server);
            }
        }
    }

    fn apply_domains(&mut self, value: &str) {
        if value.is_empty() {
            self.domains.clear();
            return;
        }
        for token in value.split_whitespace() {
            let route_only = token.starts_with('~');
            let raw_name = token.trim_start_matches('~').trim_end_matches('.');
            let name = if raw_name.is_empty() || raw_name == "*" {
                "."
            } else {
                raw_name
            };
            if !valid_dns_name(name) {
                continue;
            }
            let domain = Domain {
                name: name.to_ascii_lowercase(),
                route_only: route_only || name == ".",
            };
            if !self.domains.contains(&domain) && self.domains.len() < SEARCH_DOMAINS_MAX {
                self.domains.push(domain);
            }
        }
    }
}

pub fn system_search_dirs() -> Vec<PathBuf> {
    crate::native_paths::dns_delegate_search_dirs()
}

pub fn load_system() -> Vec<DnsDelegate> {
    load_from_search_dirs(&system_search_dirs()).unwrap_or_default()
}

pub fn load_from_search_dirs(search_dirs: &[PathBuf]) -> io::Result<Vec<DnsDelegate>> {
    let files = selected_files(search_dirs, "dns-delegate")?;
    let mut delegates = Vec::new();
    for (name, path) in files.into_iter().take(DNS_DELEGATES_MAX) {
        let Some(id) = name.strip_suffix(".dns-delegate") else {
            continue;
        };
        if !safe_id(id) || masked(&path)? {
            continue;
        }
        let mut delegate = DnsDelegate::new(id.to_owned());
        if let Ok(text) = fs::read_to_string(&path) {
            delegate.apply_text(&text);
        } else {
            continue;
        }
        let drop_in = format!("{id}.dns-delegate.d");
        for path in selected_drop_ins(search_dirs, &drop_in)? {
            if masked(&path)? {
                continue;
            }
            if let Ok(text) = fs::read_to_string(path) {
                delegate.apply_text(&text);
            }
        }
        delegates.push(delegate);
    }
    Ok(delegates)
}

fn selected_files(
    search_dirs: &[PathBuf],
    extension: &str,
) -> io::Result<BTreeMap<String, PathBuf>> {
    let mut selected = BTreeMap::new();
    for directory in search_dirs {
        for path in directory_entries(directory)? {
            if path.extension().and_then(|value| value.to_str()) != Some(extension) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            selected.entry(name.to_owned()).or_insert(path);
        }
    }
    Ok(selected)
}

fn selected_drop_ins(search_dirs: &[PathBuf], dirname: &str) -> io::Result<Vec<PathBuf>> {
    let mut selected = BTreeMap::new();
    for directory in search_dirs {
        for path in directory_entries(&directory.join(dirname))? {
            if path.extension().and_then(|value| value.to_str()) != Some("conf") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            selected.entry(name.to_owned()).or_insert(path);
        }
    }
    Ok(selected.into_values().collect())
}

fn directory_entries(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect()
}

fn masked(path: &Path) -> io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_symlink()
        && fs::canonicalize(path).is_ok_and(|target| target == Path::new("/dev/null")))
}

fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id.is_ascii()
        && id != "."
        && id != ".."
        && !id
            .chars()
            .any(|character| character.is_control() || character == '/')
}

fn valid_dns_name(name: &str) -> bool {
    name == "."
        || (!name.is_empty()
            && name.is_ascii()
            && name.len() <= 253
            && name
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63))
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn parse_unsigned(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

fn invalid_server_address(server: &DnsServerSpec) -> bool {
    match server.address.ip() {
        std::net::IpAddr::V4(address) => {
            address.is_unspecified()
                || address.octets() == [127, 0, 0, 53]
                || address.octets() == [127, 0, 0, 54]
        }
        std::net::IpAddr::V6(address) => address.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loads_main_file_drop_ins_and_priority() {
        let root = TempDir::new().expect("temporary directory");
        let high = root.path().join("etc");
        let low = root.path().join("usr");
        fs::create_dir_all(high.join("corp.dns-delegate.d")).expect("high drop-in");
        fs::create_dir_all(low.join("corp.dns-delegate.d")).expect("low drop-in");
        fs::write(
            low.join("corp.dns-delegate"),
            "[Delegate]\nDNS=192.0.2.1\nDomains=~old.example\n",
        )
        .expect("low main");
        fs::write(
            high.join("corp.dns-delegate"),
            "[Delegate]\nDNS=192.0.2.53#resolver.example\nDomains=~corp.example\n",
        )
        .expect("high main");
        fs::write(
            low.join("corp.dns-delegate.d/10-route.conf"),
            "[Delegate]\nDefaultRoute=no\nFirewallMark=7\n",
        )
        .expect("low drop-in");
        fs::write(
            high.join("corp.dns-delegate.d/10-route.conf"),
            "[Delegate]\nDefaultRoute=yes\nFirewallMark=0x2a\n",
        )
        .expect("high drop-in");

        let delegates = load_from_search_dirs(&[high, low]).expect("delegates");
        assert_eq!(delegates.len(), 1);
        let delegate = &delegates[0];
        assert_eq!(delegate.id, "corp");
        assert_eq!(
            delegate.servers[0].address,
            "192.0.2.53:53".parse().unwrap()
        );
        assert_eq!(delegate.domains[0].name, "corp.example");
        assert_eq!(delegate.default_route, Some(true));
        assert_eq!(delegate.firewall_mark, 42);
    }

    #[test]
    fn empty_assignments_clear_lists_and_root_is_route_only() {
        let mut delegate = DnsDelegate::new("test".to_owned());
        delegate.apply_text(
            "[Delegate]\nDNS=192.0.2.1 192.0.2.2\nDNS=\nDNS=192.0.2.3\nDomains=example ~corp *\nDomains=\nDomains=.\nDefaultRoute=yes\nDefaultRoute=\n",
        );
        assert_eq!(delegate.servers.len(), 1);
        assert_eq!(delegate.servers[0].address, "192.0.2.3:53".parse().unwrap());
        assert_eq!(
            delegate.domains,
            vec![Domain {
                name: ".".to_owned(),
                route_only: true,
            }]
        );
        assert_eq!(delegate.default_route, None);
    }

    #[test]
    fn filters_only_unset_and_local_stub_addresses() {
        let mut delegate = DnsDelegate::new("test".to_owned());
        delegate.apply_text("[Delegate]\nDNS=0.0.0.0 :: 127.0.0.53 127.0.0.54 127.0.0.1 ::1\n");
        assert_eq!(
            delegate
                .servers
                .iter()
                .map(|server| server.address.ip())
                .collect::<Vec<_>>(),
            vec![
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
                "::1".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
    }
}
