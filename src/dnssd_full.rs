// SPDX-License-Identifier: LGPL-2.1-or-later
use super::parity::{canonical_wire_name, MdnsAddressFamily, MdnsInterface, MdnsNameError};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;

pub const DNS_SD_CLASS_IN: u16 = 1;
pub const DNS_SD_TYPE_A: u16 = 1;
pub const DNS_SD_TYPE_PTR: u16 = 12;
pub const DNS_SD_TYPE_TXT: u16 = 16;
pub const DNS_SD_TYPE_AAAA: u16 = 28;
pub const DNS_SD_TYPE_SRV: u16 = 33;
pub const DNS_SD_DEFAULT_TTL: u32 = 120;
pub const DNS_SD_ADDRESS_TTL: u32 = 120;
pub const DNS_SD_MAX_TXT_TOTAL: usize = 1300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsSdError {
    EmptyInstance,
    InstanceTooLong,
    InvalidInstance,
    InvalidServiceType,
    InvalidDomain,
    InvalidHost,
    InvalidTxtItem,
    TxtTooLarge,
    InvalidSubtype,
    DuplicateRegistration,
    UnknownRegistration,
    Name(MdnsNameError),
}

impl fmt::Display for DnsSdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyInstance => "DNS-SD instance name is empty",
            Self::InstanceTooLong => "DNS-SD instance name exceeds one DNS label",
            Self::InvalidInstance => "DNS-SD instance name is invalid",
            Self::InvalidServiceType => "DNS-SD service type is invalid",
            Self::InvalidDomain => "DNS-SD domain is invalid",
            Self::InvalidHost => "DNS-SD host name is invalid",
            Self::InvalidTxtItem => "DNS-SD TXT item exceeds 255 octets",
            Self::TxtTooLarge => "DNS-SD TXT record exceeds the configured limit",
            Self::InvalidSubtype => "DNS-SD subtype is invalid",
            Self::DuplicateRegistration => "DNS-SD service is already registered",
            Self::UnknownRegistration => "DNS-SD registration does not exist",
            Self::Name(error) => return error.fmt(formatter),
        })
    }
}

impl Error for DnsSdError {}

impl From<MdnsNameError> for DnsSdError {
    fn from(error: MdnsNameError) -> Self {
        Self::Name(error)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdServiceType {
    service: String,
    protocol: String,
}

impl DnsSdServiceType {
    pub fn parse(value: &str) -> Result<Self, DnsSdError> {
        let value = value.trim_end_matches('.');
        let mut labels = value.split('.');
        let Some(service) = labels.next() else {
            return Err(DnsSdError::InvalidServiceType);
        };
        let Some(protocol) = labels.next() else {
            return Err(DnsSdError::InvalidServiceType);
        };
        if labels.next().is_some()
            || !service_label_is_valid(service)
            || !matches!(protocol.to_ascii_lowercase().as_str(), "_tcp" | "_udp")
        {
            return Err(DnsSdError::InvalidServiceType);
        }
        Ok(Self {
            service: service.to_ascii_lowercase(),
            protocol: protocol.to_ascii_lowercase(),
        })
    }

    pub fn presentation(&self) -> String {
        format!("{}.{}", self.service, self.protocol)
    }

    fn labels(&self) -> [&str; 2] {
        [&self.service, &self.protocol]
    }
}

fn service_label_is_valid(value: &str) -> bool {
    value.starts_with('_')
        && value.len() >= 2
        && value.len() <= 16
        && value.is_ascii()
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.as_bytes()[1] != b'-'
        && value.as_bytes()[value.len() - 1] != b'-'
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdDomain(Vec<String>);

impl DnsSdDomain {
    pub fn parse(value: &str) -> Result<Self, DnsSdError> {
        let value = value.trim_end_matches('.');
        if value.is_empty() {
            return Err(DnsSdError::InvalidDomain);
        }
        let labels = value
            .split('.')
            .map(validate_domain_label)
            .collect::<Result<Vec<_>, _>>()?;
        let wire = encode_labels(labels.iter().map(String::as_bytes))?;
        canonical_wire_name(&wire)?;
        Ok(Self(labels))
    }

    pub fn local() -> Self {
        Self(vec!["local".to_owned()])
    }

    pub fn presentation(&self) -> String {
        self.0.join(".")
    }

    fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(String::as_bytes)
    }
}

fn validate_domain_label(value: &str) -> Result<String, DnsSdError> {
    if value.is_empty()
        || value.len() > 63
        || !value.is_ascii()
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(DnsSdError::InvalidDomain);
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdInstance(Vec<u8>);

impl DnsSdInstance {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, DnsSdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DnsSdError::EmptyInstance);
        }
        if value.len() > 63 {
            return Err(DnsSdError::InstanceTooLong);
        }
        if value.contains(&0) {
            return Err(DnsSdError::InvalidInstance);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn display_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdHost(Vec<String>);

impl DnsSdHost {
    pub fn parse(value: &str) -> Result<Self, DnsSdError> {
        let value = value.trim_end_matches('.');
        if value.is_empty() {
            return Err(DnsSdError::InvalidHost);
        }
        let labels = value
            .split('.')
            .map(|label| validate_domain_label(label).map_err(|_| DnsSdError::InvalidHost))
            .collect::<Result<Vec<_>, _>>()?;
        let wire = encode_labels(labels.iter().map(String::as_bytes))?;
        canonical_wire_name(&wire)?;
        Ok(Self(labels))
    }

    pub fn local(label: &str) -> Result<Self, DnsSdError> {
        let label = validate_domain_label(label).map_err(|_| DnsSdError::InvalidHost)?;
        Ok(Self(vec![label, "local".to_owned()]))
    }

    pub fn presentation(&self) -> String {
        self.0.join(".")
    }

    fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(String::as_bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSdRegistration {
    pub instance: DnsSdInstance,
    pub service_type: DnsSdServiceType,
    pub domain: DnsSdDomain,
    pub host: DnsSdHost,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub txt: Vec<Vec<u8>>,
    pub subtypes: BTreeSet<String>,
    pub addresses: BTreeSet<IpAddr>,
    pub interface: MdnsInterface,
    pub ttl: u32,
}

impl DnsSdRegistration {
    pub fn validate(&self) -> Result<(), DnsSdError> {
        if self.instance.as_bytes().is_empty() {
            return Err(DnsSdError::EmptyInstance);
        }
        validate_txt(&self.txt)?;
        for subtype in &self.subtypes {
            if !subtype_is_valid(subtype) {
                return Err(DnsSdError::InvalidSubtype);
            }
        }
        for address in &self.addresses {
            match (self.interface.family, address) {
                (MdnsAddressFamily::Ipv4, IpAddr::V4(_))
                | (MdnsAddressFamily::Ipv6, IpAddr::V6(_)) => {}
                _ => return Err(DnsSdError::InvalidHost),
            }
        }
        Ok(())
    }

    pub fn browse_owner(&self) -> Result<Vec<u8>, DnsSdError> {
        encode_service_owner(&self.service_type, &self.domain)
    }

    pub fn instance_owner(&self) -> Result<Vec<u8>, DnsSdError> {
        let service = self.service_type.labels();
        encode_labels(
            std::iter::once(self.instance.as_bytes())
                .chain(service.iter().map(|label| label.as_bytes()))
                .chain(self.domain.labels()),
        )
    }

    pub fn host_owner(&self) -> Result<Vec<u8>, DnsSdError> {
        encode_labels(self.host.labels())
    }

    pub fn records(&self, goodbye: bool) -> Result<Vec<DnsSdRecord>, DnsSdError> {
        self.validate()?;
        let ttl = if goodbye { 0 } else { self.ttl.max(1) };
        let browse_owner = self.browse_owner()?;
        let instance_owner = self.instance_owner()?;
        let host_owner = self.host_owner()?;
        let mut records = vec![
            DnsSdRecord {
                owner: browse_owner,
                rr_type: DNS_SD_TYPE_PTR,
                class: DNS_SD_CLASS_IN,
                ttl,
                cache_flush: false,
                rdata: instance_owner.clone(),
                interface: self.interface,
            },
            DnsSdRecord {
                owner: instance_owner.clone(),
                rr_type: DNS_SD_TYPE_SRV,
                class: DNS_SD_CLASS_IN,
                ttl,
                cache_flush: true,
                rdata: srv_rdata(self.priority, self.weight, self.port, &host_owner),
                interface: self.interface,
            },
            DnsSdRecord {
                owner: instance_owner.clone(),
                rr_type: DNS_SD_TYPE_TXT,
                class: DNS_SD_CLASS_IN,
                ttl,
                cache_flush: true,
                rdata: txt_rdata(&self.txt)?,
                interface: self.interface,
            },
        ];

        for subtype in &self.subtypes {
            records.push(DnsSdRecord {
                owner: encode_subtype_owner(subtype, &self.service_type, &self.domain)?,
                rr_type: DNS_SD_TYPE_PTR,
                class: DNS_SD_CLASS_IN,
                ttl,
                cache_flush: false,
                rdata: instance_owner.clone(),
                interface: self.interface,
            });
        }

        for address in &self.addresses {
            let (rr_type, rdata) = match address {
                IpAddr::V4(address) => (DNS_SD_TYPE_A, address.octets().to_vec()),
                IpAddr::V6(address) => (DNS_SD_TYPE_AAAA, address.octets().to_vec()),
            };
            records.push(DnsSdRecord {
                owner: host_owner.clone(),
                rr_type,
                class: DNS_SD_CLASS_IN,
                ttl: if goodbye { 0 } else { DNS_SD_ADDRESS_TTL },
                cache_flush: true,
                rdata,
                interface: self.interface,
            });
        }
        records.sort();
        Ok(records)
    }
}

fn subtype_is_valid(value: &str) -> bool {
    service_label_is_valid(value)
}

fn validate_txt(items: &[Vec<u8>]) -> Result<(), DnsSdError> {
    let mut total = 0usize;
    for item in items {
        if item.len() > u8::MAX as usize {
            return Err(DnsSdError::InvalidTxtItem);
        }
        total = total
            .checked_add(1 + item.len())
            .ok_or(DnsSdError::TxtTooLarge)?;
        if total > DNS_SD_MAX_TXT_TOTAL {
            return Err(DnsSdError::TxtTooLarge);
        }
    }
    Ok(())
}

fn txt_rdata(items: &[Vec<u8>]) -> Result<Vec<u8>, DnsSdError> {
    validate_txt(items)?;
    if items.is_empty() {
        return Ok(vec![0]);
    }
    let mut output = Vec::new();
    for item in items {
        output.push(u8::try_from(item.len()).map_err(|_| DnsSdError::InvalidTxtItem)?);
        output.extend_from_slice(item);
    }
    Ok(output)
}

fn srv_rdata(priority: u16, weight: u16, port: u16, target: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(6 + target.len());
    output.extend_from_slice(&priority.to_be_bytes());
    output.extend_from_slice(&weight.to_be_bytes());
    output.extend_from_slice(&port.to_be_bytes());
    output.extend_from_slice(target);
    output
}

fn encode_service_owner(
    service_type: &DnsSdServiceType,
    domain: &DnsSdDomain,
) -> Result<Vec<u8>, DnsSdError> {
    let service = service_type.labels();
    encode_labels(
        service
            .iter()
            .map(|label| label.as_bytes())
            .chain(domain.labels()),
    )
}

fn encode_subtype_owner(
    subtype: &str,
    service_type: &DnsSdServiceType,
    domain: &DnsSdDomain,
) -> Result<Vec<u8>, DnsSdError> {
    if !subtype_is_valid(subtype) {
        return Err(DnsSdError::InvalidSubtype);
    }
    let service = service_type.labels();
    encode_labels(
        std::iter::once(subtype.as_bytes())
            .chain(std::iter::once(b"_sub".as_slice()))
            .chain(service.iter().map(|label| label.as_bytes()))
            .chain(domain.labels()),
    )
}

fn encode_labels<'a>(labels: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>, DnsSdError> {
    let mut output = Vec::new();
    for label in labels {
        if label.is_empty() || label.len() > 63 || label.contains(&0) {
            return Err(DnsSdError::InvalidDomain);
        }
        output.push(u8::try_from(label.len()).map_err(|_| DnsSdError::InvalidDomain)?);
        output.extend_from_slice(label);
    }
    output.push(0);
    if output.len() > 255 {
        return Err(DnsSdError::InvalidDomain);
    }
    canonical_wire_name(&output)?;
    Ok(output)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdRecord {
    pub owner: Vec<u8>,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub cache_flush: bool,
    pub rdata: Vec<u8>,
    pub interface: MdnsInterface,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RegistrationKey {
    interface: MdnsInterface,
    instance: Vec<u8>,
    service_type: DnsSdServiceType,
    domain: DnsSdDomain,
}

impl RegistrationKey {
    fn from_registration(registration: &DnsSdRegistration) -> Self {
        Self {
            interface: registration.interface,
            instance: registration.instance.as_bytes().to_vec(),
            service_type: registration.service_type.clone(),
            domain: registration.domain.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsSdBrowseUpdateKind {
    Added,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSdBrowseUpdate {
    pub kind: DnsSdBrowseUpdateKind,
    pub registration_id: u64,
    pub instance: DnsSdInstance,
    pub service_type: DnsSdServiceType,
    pub domain: DnsSdDomain,
    pub interface: MdnsInterface,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsSdBrowseFilter {
    pub service_type: DnsSdServiceType,
    pub domain: DnsSdDomain,
    pub interface: Option<MdnsInterface>,
}

impl DnsSdBrowseFilter {
    fn matches(&self, registration: &DnsSdRegistration) -> bool {
        self.service_type == registration.service_type
            && self.domain == registration.domain
            && self
                .interface
                .map_or(true, |interface| interface == registration.interface)
    }
}

#[derive(Debug, Default)]
pub struct DnsSdRegistry {
    next_registration_id: u64,
    next_subscription_id: u64,
    registrations: BTreeMap<u64, DnsSdRegistration>,
    keys: BTreeMap<RegistrationKey, u64>,
    subscriptions: BTreeMap<u64, DnsSdBrowseFilter>,
    pending: BTreeMap<u64, Vec<DnsSdBrowseUpdate>>,
}

impl DnsSdRegistry {
    pub fn register(&mut self, registration: DnsSdRegistration) -> Result<u64, DnsSdError> {
        registration.validate()?;
        let key = RegistrationKey::from_registration(&registration);
        if self.keys.contains_key(&key) {
            return Err(DnsSdError::DuplicateRegistration);
        }
        self.next_registration_id = self.next_registration_id.wrapping_add(1).max(1);
        let id = self.next_registration_id;
        self.notify(DnsSdBrowseUpdateKind::Added, id, &registration);
        self.keys.insert(key, id);
        self.registrations.insert(id, registration);
        Ok(id)
    }

    pub fn register_with_automatic_rename(
        &mut self,
        mut registration: DnsSdRegistration,
    ) -> Result<(u64, DnsSdInstance), DnsSdError> {
        let base = registration.instance.clone();
        for ordinal in 1..=9999u32 {
            let candidate = if ordinal == 1 {
                base.clone()
            } else {
                renamed_instance(&base, ordinal)?
            };
            registration.instance = candidate.clone();
            let key = RegistrationKey::from_registration(&registration);
            if self.keys.contains_key(&key) {
                continue;
            }
            let id = self.register(registration)?;
            return Ok((id, candidate));
        }
        Err(DnsSdError::DuplicateRegistration)
    }

    pub fn update(&mut self, id: u64, registration: DnsSdRegistration) -> Result<(), DnsSdError> {
        registration.validate()?;
        let previous = self
            .registrations
            .get(&id)
            .cloned()
            .ok_or(DnsSdError::UnknownRegistration)?;
        let previous_key = RegistrationKey::from_registration(&previous);
        let new_key = RegistrationKey::from_registration(&registration);
        if previous_key != new_key && self.keys.contains_key(&new_key) {
            return Err(DnsSdError::DuplicateRegistration);
        }
        self.notify(DnsSdBrowseUpdateKind::Removed, id, &previous);
        self.keys.remove(&previous_key);
        self.keys.insert(new_key, id);
        self.notify(DnsSdBrowseUpdateKind::Added, id, &registration);
        self.registrations.insert(id, registration);
        Ok(())
    }

    pub fn unregister(&mut self, id: u64) -> Result<DnsSdRegistration, DnsSdError> {
        let registration = self
            .registrations
            .remove(&id)
            .ok_or(DnsSdError::UnknownRegistration)?;
        self.keys
            .remove(&RegistrationKey::from_registration(&registration));
        self.notify(DnsSdBrowseUpdateKind::Removed, id, &registration);
        Ok(registration)
    }

    pub fn registration(&self, id: u64) -> Option<&DnsSdRegistration> {
        self.registrations.get(&id)
    }

    pub fn subscribe(&mut self, filter: DnsSdBrowseFilter) -> u64 {
        self.next_subscription_id = self.next_subscription_id.wrapping_add(1).max(1);
        let id = self.next_subscription_id;
        let initial = self
            .registrations
            .iter()
            .filter(|(_, registration)| filter.matches(registration))
            .map(|(&registration_id, registration)| DnsSdBrowseUpdate {
                kind: DnsSdBrowseUpdateKind::Added,
                registration_id,
                instance: registration.instance.clone(),
                service_type: registration.service_type.clone(),
                domain: registration.domain.clone(),
                interface: registration.interface,
            })
            .collect();
        self.subscriptions.insert(id, filter);
        self.pending.insert(id, initial);
        id
    }

    pub fn unsubscribe(&mut self, id: u64) {
        self.subscriptions.remove(&id);
        self.pending.remove(&id);
    }

    pub fn take_updates(&mut self, id: u64) -> Vec<DnsSdBrowseUpdate> {
        self.pending
            .get_mut(&id)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    pub fn goodbye_records(&self, id: u64) -> Result<Vec<DnsSdRecord>, DnsSdError> {
        self.registrations
            .get(&id)
            .ok_or(DnsSdError::UnknownRegistration)?
            .records(true)
    }

    pub fn remove_interface(&mut self, interface: MdnsInterface) -> Vec<DnsSdRegistration> {
        let ids = self
            .registrations
            .iter()
            .filter(|(_, registration)| registration.interface == interface)
            .map(|(&id, _)| id)
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.unregister(id).ok())
            .collect()
    }

    fn notify(
        &mut self,
        kind: DnsSdBrowseUpdateKind,
        registration_id: u64,
        registration: &DnsSdRegistration,
    ) {
        for (&subscription_id, filter) in &self.subscriptions {
            if !filter.matches(registration) {
                continue;
            }
            self.pending
                .entry(subscription_id)
                .or_default()
                .push(DnsSdBrowseUpdate {
                    kind: kind.clone(),
                    registration_id,
                    instance: registration.instance.clone(),
                    service_type: registration.service_type.clone(),
                    domain: registration.domain.clone(),
                    interface: registration.interface,
                });
        }
    }
}

fn renamed_instance(base: &DnsSdInstance, ordinal: u32) -> Result<DnsSdInstance, DnsSdError> {
    let suffix = format!(" ({ordinal})");
    if suffix.len() >= 63 {
        return Err(DnsSdError::InstanceTooLong);
    }
    let maximum = 63 - suffix.len();
    let mut prefix = base.as_bytes();
    if prefix.len() > maximum {
        prefix = &prefix[..maximum];
        while std::str::from_utf8(prefix).is_err() && !prefix.is_empty() {
            prefix = &prefix[..prefix.len() - 1];
        }
    }
    let mut output = prefix.to_vec();
    output.extend_from_slice(suffix.as_bytes());
    DnsSdInstance::new(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn registration(interface: MdnsInterface) -> DnsSdRegistration {
        let addresses = match interface.family {
            MdnsAddressFamily::Ipv4 => BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
            MdnsAddressFamily::Ipv6 => {
                BTreeSet::from([IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 10))])
            }
        };
        DnsSdRegistration {
            instance: DnsSdInstance::new(b"Office Printer".to_vec()).expect("instance"),
            service_type: DnsSdServiceType::parse("_ipp._tcp").expect("service type"),
            domain: DnsSdDomain::local(),
            host: DnsSdHost::local("printer").expect("host"),
            port: 631,
            priority: 0,
            weight: 0,
            txt: vec![b"txtvers=1".to_vec(), b"qtotal=1".to_vec()],
            subtypes: BTreeSet::from(["_universal".to_owned()]),
            addresses,
            interface,
            ttl: DNS_SD_DEFAULT_TTL,
        }
    }

    #[test]
    fn validates_service_types() {
        assert!(DnsSdServiceType::parse("_http._tcp").is_ok());
        assert!(DnsSdServiceType::parse("_http._sctp").is_err());
        assert!(DnsSdServiceType::parse("http._tcp").is_err());
        assert!(DnsSdServiceType::parse("_this-service-name-is-too-long._tcp").is_err());
    }

    #[test]
    fn instance_is_encoded_as_one_label_even_with_dots() {
        let mut registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        registration.instance = DnsSdInstance::new(b"A.B".to_vec()).expect("instance");
        let owner = registration.instance_owner().expect("instance owner");
        assert_eq!(owner[0], 3);
        assert_eq!(&owner[1..4], b"A.B");
    }

    #[test]
    fn complete_record_set_contains_ptr_srv_txt_subtype_and_address() {
        let registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        let records = registration.records(false).expect("records");
        assert_eq!(records.len(), 5);
        assert!(records
            .iter()
            .any(|record| record.rr_type == DNS_SD_TYPE_PTR));
        assert!(records
            .iter()
            .any(|record| record.rr_type == DNS_SD_TYPE_SRV));
        assert!(records
            .iter()
            .any(|record| record.rr_type == DNS_SD_TYPE_TXT));
        assert!(records.iter().any(|record| record.rr_type == DNS_SD_TYPE_A));
        assert_eq!(
            records
                .iter()
                .filter(|record| record.rr_type == DNS_SD_TYPE_PTR)
                .count(),
            2
        );
    }

    #[test]
    fn goodbye_records_use_zero_ttl() {
        let registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        assert!(registration
            .records(true)
            .expect("goodbye records")
            .iter()
            .all(|record| record.ttl == 0));
    }

    #[test]
    fn txt_items_and_total_are_bounded() {
        let mut registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        registration.txt = vec![vec![0; 256]];
        assert_eq!(registration.validate(), Err(DnsSdError::InvalidTxtItem));
        registration.txt = (0..6).map(|_| vec![0; 255]).collect();
        assert_eq!(registration.validate(), Err(DnsSdError::TxtTooLarge));
    }

    #[test]
    fn registry_rejects_exact_duplicate() {
        let registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        let mut registry = DnsSdRegistry::default();
        registry
            .register(registration.clone())
            .expect("registration");
        assert_eq!(
            registry.register(registration),
            Err(DnsSdError::DuplicateRegistration)
        );
    }

    #[test]
    fn automatic_rename_is_deterministic_and_label_bounded() {
        let registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        let mut registry = DnsSdRegistry::default();
        registry
            .register(registration.clone())
            .expect("registration");
        let (_, renamed) = registry
            .register_with_automatic_rename(registration)
            .expect("renamed registration");
        assert_eq!(renamed.display_lossy(), "Office Printer (2)");
        assert!(renamed.as_bytes().len() <= 63);
    }

    #[test]
    fn browse_subscription_gets_initial_add_and_remove() {
        let registration = registration(MdnsInterface::new(2, MdnsAddressFamily::Ipv4));
        let filter = DnsSdBrowseFilter {
            service_type: registration.service_type.clone(),
            domain: registration.domain.clone(),
            interface: None,
        };
        let mut registry = DnsSdRegistry::default();
        let id = registry.register(registration).expect("registration");
        let subscription = registry.subscribe(filter);
        let initial = registry.take_updates(subscription);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].kind, DnsSdBrowseUpdateKind::Added);
        registry.unregister(id).expect("unregister");
        let removed = registry.take_updates(subscription);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].kind, DnsSdBrowseUpdateKind::Removed);
    }

    #[test]
    fn browse_filter_is_scoped_to_interface() {
        let first_interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let second_interface = MdnsInterface::new(3, MdnsAddressFamily::Ipv4);
        let first = registration(first_interface);
        let mut second = registration(second_interface);
        second.instance = DnsSdInstance::new(b"Second Printer".to_vec()).expect("instance");
        let filter = DnsSdBrowseFilter {
            service_type: first.service_type.clone(),
            domain: first.domain.clone(),
            interface: Some(first_interface),
        };
        let mut registry = DnsSdRegistry::default();
        let subscription = registry.subscribe(filter);
        registry.register(first).expect("first registration");
        registry.register(second).expect("second registration");
        let updates = registry.take_updates(subscription);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].interface, first_interface);
    }

    #[test]
    fn removing_interface_produces_removals() {
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let registration = registration(interface);
        let filter = DnsSdBrowseFilter {
            service_type: registration.service_type.clone(),
            domain: registration.domain.clone(),
            interface: Some(interface),
        };
        let mut registry = DnsSdRegistry::default();
        let subscription = registry.subscribe(filter);
        registry.register(registration).expect("registration");
        registry.take_updates(subscription);
        assert_eq!(registry.remove_interface(interface).len(), 1);
        let updates = registry.take_updates(subscription);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].kind, DnsSdBrowseUpdateKind::Removed);
    }
}
