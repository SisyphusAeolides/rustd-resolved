// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::wire::{
    parse_reverse_name, LocalRecord, Question, CLASS_ANY, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_PTR,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct Hosts {
    by_name: HashMap<String, Vec<IpAddr>>,
    by_address: HashMap<IpAddr, Vec<String>>,
    canonical_by_address: HashMap<IpAddr, String>,
    no_address: HashSet<String>,
}

impl Hosts {
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut hosts = Self::default();
        for raw_line in text.lines() {
            let line = raw_line.split_once('#').map_or(raw_line, |(head, _)| head);
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next().and_then(|field| field.parse::<IpAddr>().ok()) else {
                continue;
            };
            for name in fields {
                let canonical = canonical_name(name);
                if !valid_ldh_name(&canonical) {
                    continue;
                }
                if address.is_unspecified() {
                    hosts.no_address.insert(canonical);
                    continue;
                }
                let addresses = hosts.by_name.entry(canonical.clone()).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                hosts
                    .canonical_by_address
                    .entry(address)
                    .or_insert_with(|| canonical.clone());
                let names = hosts.by_address.entry(address).or_default();
                if !names.contains(&canonical) {
                    names.push(canonical);
                }
            }
        }
        hosts.strip_redundant_localhost();
        hosts
    }

    pub fn lookup(&self, question: &Question) -> Option<Vec<LocalRecord>> {
        self.lookup_with_synthetic(question, true)
    }

    pub fn lookup_file(&self, question: &Question) -> Option<Vec<LocalRecord>> {
        self.lookup_with_synthetic(question, false)
    }

    fn lookup_with_synthetic(
        &self,
        question: &Question,
        include_synthetic: bool,
    ) -> Option<Vec<LocalRecord>> {
        if question.class != CLASS_IN && question.class != CLASS_ANY {
            return None;
        }
        match question.rr_type {
            TYPE_A | TYPE_AAAA | 255 => self.lookup_forward(question, include_synthetic),
            TYPE_PTR => self.lookup_reverse(question, include_synthetic),
            _ => self
                .known_name(question.name.text(), include_synthetic)
                .then(Vec::new),
        }
    }

    fn lookup_forward(
        &self,
        question: &Question,
        include_synthetic: bool,
    ) -> Option<Vec<LocalRecord>> {
        let name = canonical_name(question.name.text());
        let synthetic = if include_synthetic {
            synthetic_addresses(&name)
        } else {
            Vec::new()
        };
        let mut addresses = synthetic.clone();
        if include_synthetic {
            if let Ok(address) = name.parse::<IpAddr>() {
                addresses.push(address);
            }
        }
        if let Some(host_addresses) = self.by_name.get(&name) {
            for address in host_addresses {
                if !addresses.contains(address) {
                    addresses.push(*address);
                }
            }
        }
        if addresses.is_empty() {
            return self.no_address.contains(&name).then(Vec::new);
        }

        let mut records = Vec::new();
        for address in addresses {
            if !matches!(
                (question.rr_type, address),
                (TYPE_A | 255, IpAddr::V4(_)) | (TYPE_AAAA | 255, IpAddr::V6(_))
            ) {
                continue;
            }
            let canonical = (!synthetic.contains(&address))
                .then(|| {
                    self.canonical_by_address
                        .get(&address)
                        .filter(|canonical| canonical.as_str() != name)
                })
                .flatten();
            if let Some(canonical) = canonical {
                let cname = LocalRecord::Cname(canonical.clone());
                if !records.contains(&cname) {
                    records.push(cname);
                }
            }
            let record = match (address, canonical) {
                (IpAddr::V4(address), Some(canonical)) => {
                    LocalRecord::NamedA(canonical.clone(), address)
                }
                (IpAddr::V6(address), Some(canonical)) => {
                    LocalRecord::NamedAaaa(canonical.clone(), address)
                }
                (IpAddr::V4(address), None) => LocalRecord::A(address),
                (IpAddr::V6(address), None) => LocalRecord::Aaaa(address),
            };
            records.push(record);
        }
        Some(records)
    }

    fn lookup_reverse(
        &self,
        question: &Question,
        include_synthetic: bool,
    ) -> Option<Vec<LocalRecord>> {
        let address = parse_reverse_name(question.name.text())?;
        let mut names = if include_synthetic {
            synthetic_names(address)
        } else {
            Vec::new()
        };
        if let Some(host_names) = self.by_address.get(&address) {
            for name in host_names {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        if names.is_empty() {
            return None;
        }
        Some(names.into_iter().map(LocalRecord::Ptr).collect())
    }

    fn known_name(&self, name: &str, include_synthetic: bool) -> bool {
        let name = canonical_name(name);
        self.by_name.contains_key(&name)
            || self.no_address.contains(&name)
            || (include_synthetic
                && (!synthetic_addresses(&name).is_empty() || name.parse::<IpAddr>().is_ok()))
    }

    fn strip_redundant_localhost(&mut self) {
        let candidates = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let removable = candidates
            .into_iter()
            .filter(|address| {
                let Some(names) = self.by_address.get(address) else {
                    return false;
                };
                names.iter().all(|name| is_localhost_name(name))
                    && names.iter().all(|name| {
                        self.by_name
                            .get(name)
                            .is_some_and(|addresses| addresses.iter().all(is_loopback_address))
                    })
            })
            .collect::<Vec<_>>();

        for address in removable {
            if let Some(names) = self.by_address.remove(&address) {
                for name in names {
                    self.by_name.remove(&name);
                }
            }
            self.canonical_by_address.remove(&address);
        }
    }
}

fn canonical_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn valid_ldh_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn is_loopback_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}

fn is_localhost_name(name: &str) -> bool {
    name == "localhost"
        || name == "localhost.localdomain"
        || name == "localhost4"
        || name == "localhost4.localdomain4"
        || name == "localhost6"
        || name == "localhost6.localdomain6"
        || name.ends_with(".localhost")
        || name.ends_with(".localhost.localdomain")
}

fn synthetic_addresses(name: &str) -> Vec<IpAddr> {
    if is_localhost_name(name) {
        return vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
    }
    match name {
        "localhost4" | "localhost4.localdomain4" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "localhost6" | "localhost6.localdomain6" => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        "_localdnsstub" => vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))],
        "_localdnsproxy" => vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54))],
        _ => Vec::new(),
    }
}

fn synthetic_names(address: IpAddr) -> Vec<String> {
    match address {
        IpAddr::V4(address) if address == Ipv4Addr::LOCALHOST => vec!["localhost".to_owned()],
        IpAddr::V6(address) if address == Ipv6Addr::LOCALHOST => vec!["localhost".to_owned()],
        IpAddr::V4(address) if address == Ipv4Addr::new(127, 0, 0, 53) => {
            vec!["_localdnsstub".to_owned()]
        }
        IpAddr::V4(address) if address == Ipv4Addr::new(127, 0, 0, 54) => {
            vec!["_localdnsproxy".to_owned()]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{first_question, make_query};

    #[test]
    fn parses_aliases_and_reverse_entries() {
        let hosts = Hosts::parse("192.0.2.10 host.example alias.example\n");
        let query = make_query("alias.example", TYPE_A, 1).expect("query");
        let records = hosts
            .lookup(&first_question(&query).expect("question"))
            .expect("local answer");
        assert_eq!(
            records,
            vec![
                LocalRecord::Cname("host.example".to_owned()),
                LocalRecord::NamedA("host.example".to_owned(), Ipv4Addr::new(192, 0, 2, 10)),
            ]
        );

        let reverse = make_query("10.2.0.192.in-addr.arpa", TYPE_PTR, 2).expect("query");
        assert_eq!(
            hosts
                .lookup(&first_question(&reverse).expect("question"))
                .expect("local answer"),
            vec![
                LocalRecord::Ptr("host.example".to_owned()),
                LocalRecord::Ptr("alias.example".to_owned()),
            ]
        );
    }

    #[test]
    fn canonical_name_has_a_direct_address_record() {
        let hosts = Hosts::parse("192.0.2.10 host.example alias.example\n");
        let query = make_query("host.example", TYPE_A, 1).expect("query");
        assert_eq!(
            hosts
                .lookup(&first_question(&query).expect("question"))
                .expect("local answer"),
            vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn numeric_address_is_answered_locally() {
        let hosts = Hosts::default();
        let query = make_query("192.0.2.15", TYPE_A, 1).expect("query");
        let records = hosts
            .lookup(&first_question(&query).expect("question"))
            .expect("local answer");
        assert_eq!(records, vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 15))]);
    }

    #[test]
    fn synthesizes_stub_address() {
        let hosts = Hosts::default();
        let query = make_query("_localdnsstub", TYPE_A, 1).expect("query");
        assert!(hosts
            .lookup(&first_question(&query).expect("question"))
            .is_some());
    }

    #[test]
    fn zero_addresses_make_names_authoritative_without_records() {
        let hosts = Hosts::parse("0.0.0.0 deny.listed\n::0 deny6.listed\n");
        for name in ["deny.listed", "deny6.listed"] {
            let query = make_query(name, TYPE_A, 1).expect("query");
            assert_eq!(
                hosts.lookup(&first_question(&query).expect("question")),
                Some(Vec::new())
            );
        }
    }

    #[test]
    fn invalid_ldh_names_are_ignored() {
        let hosts = Hosts::parse(
            "192.0.2.10 valid-name bad-dash- -bad-dash bad_underscore nonascii-\u{e4}\n",
        );
        for name in [
            "bad-dash-",
            "-bad-dash",
            "bad_underscore",
            "nonascii-\u{e4}",
        ] {
            assert!(!hosts.by_name.contains_key(name));
        }
        let query = make_query("valid-name", TYPE_A, 1).expect("query");
        assert!(hosts
            .lookup(&first_question(&query).expect("question"))
            .is_some());
    }

    #[test]
    fn strips_only_equivalent_localhost_entries() {
        let redundant = Hosts::parse("127.0.0.1 localhost localhost.localdomain\n::1 localhost\n");
        assert!(redundant.by_name.is_empty());
        assert!(redundant.by_address.is_empty());

        let distribution_defaults = Hosts::parse(
            "127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n\
             ::1 localhost localhost.localdomain localhost6 localhost6.localdomain6\n",
        );
        assert!(distribution_defaults.by_name.is_empty());
        assert!(distribution_defaults.by_address.is_empty());

        let custom = Hosts::parse("127.0.0.1 localhost custom-name\n");
        assert!(custom.by_name.contains_key("localhost"));
        assert!(custom.by_name.contains_key("custom-name"));

        let mixed = Hosts::parse("127.0.0.1 localhost\n192.0.2.10 localhost\n");
        assert!(mixed.by_name.contains_key("localhost"));
        assert!(mixed
            .by_address
            .contains_key(&IpAddr::V4(Ipv4Addr::LOCALHOST)));

        let subdomain = Hosts::parse("127.0.0.1 service.localhost\n");
        let query = make_query("service.localhost", TYPE_A, 1).expect("query");
        assert_eq!(
            subdomain.lookup(&first_question(&query).expect("question")),
            Some(vec![LocalRecord::A(Ipv4Addr::LOCALHOST)])
        );
    }

    #[test]
    fn file_lookup_excludes_synthetic_names() {
        let hosts = Hosts::parse("192.0.2.10 host.example\n");
        let local = make_query("localhost", TYPE_A, 1).expect("localhost query");
        assert!(hosts
            .lookup_file(&first_question(&local).expect("localhost question"))
            .is_none());

        let file = make_query("host.example", TYPE_A, 2).expect("hosts query");
        assert_eq!(
            hosts
                .lookup_file(&first_question(&file).expect("hosts question"))
                .expect("hosts answer"),
            vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }
}
