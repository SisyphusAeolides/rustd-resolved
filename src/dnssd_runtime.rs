// SPDX-License-Identifier: LGPL-2.1-or-later
use super::dnssd_config::{DnsSdConfigError, ServiceCatalog};
use super::parity::MdnsInterface;
use super::parity_dnssd::{
    DnsSdDomain, DnsSdError, DnsSdHost, DnsSdInstance, DnsSdRecord, DnsSdRegistration,
    DnsSdServiceType, DNS_SD_CLASS_IN, DNS_SD_DEFAULT_TTL, DNS_SD_TYPE_PTR,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const RELOAD_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum DnsSdRuntimeError {
    Configuration(DnsSdConfigError),
    Service(DnsSdError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicServiceError {
    InvalidIdentifier,
    InvalidNameTemplate,
    InvalidTxtKey,
    AlreadyExists,
    NotFound,
    Service(DnsSdError),
}

impl fmt::Display for DynamicServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "DNS-SD service identifier is invalid",
            Self::InvalidNameTemplate => "DNS-SD service name template is invalid",
            Self::InvalidTxtKey => "DNS-SD TXT key is invalid",
            Self::AlreadyExists => "DNS-SD service already exists",
            Self::NotFound => "DNS-SD service does not exist",
            Self::Service(error) => return error.fmt(formatter),
        })
    }
}

impl Error for DynamicServiceError {}

impl From<DnsSdError> for DynamicServiceError {
    fn from(error: DnsSdError) -> Self {
        Self::Service(error)
    }
}

#[derive(Clone, Debug)]
pub struct DynamicServiceSpec {
    pub id: String,
    pub name_template: String,
    pub service_type: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub txt_data: Vec<HashMap<String, Vec<u8>>>,
}

#[derive(Clone, Debug)]
struct DynamicService {
    id: String,
    owner: String,
    originator_uid: u32,
    name_template: String,
    service_type: DnsSdServiceType,
    port: u16,
    priority: u16,
    weight: u16,
    txt_records: Vec<Vec<Vec<u8>>>,
    withdrawn: bool,
}

impl DynamicService {
    fn new(
        spec: DynamicServiceSpec,
        owner: String,
        originator_uid: u32,
    ) -> Result<Self, DynamicServiceError> {
        if !valid_identifier(&spec.id) {
            return Err(DynamicServiceError::InvalidIdentifier);
        }
        let service_type = DnsSdServiceType::parse(&spec.service_type)?;
        validate_name_template(&spec.name_template)?;
        let mut txt_records = Vec::new();
        for data in spec.txt_data {
            if data.is_empty() {
                continue;
            }
            let mut entries = data.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut record = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                if key.is_empty()
                    || !key.is_ascii()
                    || key.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(DynamicServiceError::InvalidTxtKey);
                }
                let mut item = key.into_bytes();
                if !value.is_empty() {
                    item.push(b'=');
                    item.extend_from_slice(&value);
                }
                record.push(item);
            }
            txt_records.push(record);
        }
        if txt_records.is_empty() {
            txt_records.push(Vec::new());
        }
        let service = Self {
            id: spec.id,
            owner,
            originator_uid,
            name_template: spec.name_template,
            service_type,
            port: spec.port,
            priority: spec.priority,
            weight: spec.weight,
            txt_records,
            withdrawn: false,
        };
        for txt in &service.txt_records {
            service
                .registration(
                    MdnsInterface::new(1, super::parity::MdnsAddressFamily::Ipv4),
                    &BTreeSet::new(),
                    "localhost",
                    txt.clone(),
                )?
                .validate()?;
        }
        Ok(service)
    }

    fn registration(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
        txt: Vec<Vec<u8>>,
    ) -> Result<DnsSdRegistration, DynamicServiceError> {
        Ok(DnsSdRegistration {
            instance: DnsSdInstance::new(render_name_template(&self.name_template, host_label)?)?,
            service_type: self.service_type.clone(),
            domain: DnsSdDomain::local(),
            host: DnsSdHost::local(host_label)?,
            port: self.port,
            priority: self.priority,
            weight: self.weight,
            txt,
            subtypes: BTreeSet::new(),
            addresses: addresses.iter().copied().collect(),
            interface,
            ttl: DNS_SD_DEFAULT_TTL,
        })
    }

    fn records(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
        goodbye: bool,
    ) -> Result<Vec<DnsSdRecord>, DynamicServiceError> {
        if self.withdrawn {
            return Ok(Vec::new());
        }
        let mut records = BTreeSet::new();
        for txt in &self.txt_records {
            records.extend(
                self.registration(interface, addresses, host_label, txt.clone())?
                    .records(goodbye)?,
            );
        }
        let browse_owner = self
            .registration(interface, addresses, host_label, Vec::new())?
            .browse_owner()?;
        records.insert(DnsSdRecord {
            owner: b"\x09_services\x07_dns-sd\x04_udp\x05local\0".to_vec(),
            rr_type: DNS_SD_TYPE_PTR,
            class: DNS_SD_CLASS_IN,
            ttl: if goodbye { 0 } else { DNS_SD_DEFAULT_TTL },
            cache_flush: false,
            rdata: browse_owner,
            interface,
        });
        Ok(records.into_iter().collect())
    }

    fn instance_owner(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
    ) -> Result<Vec<u8>, DynamicServiceError> {
        Ok(self
            .registration(interface, addresses, host_label, Vec::new())?
            .instance_owner()?)
    }
}

impl fmt::Display for DnsSdRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(formatter),
            Self::Service(error) => error.fmt(formatter),
        }
    }
}

impl Error for DnsSdRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Service(error) => Some(error),
        }
    }
}

impl From<DnsSdConfigError> for DnsSdRuntimeError {
    fn from(error: DnsSdConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<DnsSdError> for DnsSdRuntimeError {
    fn from(error: DnsSdError) -> Self {
        Self::Service(error)
    }
}

#[derive(Debug)]
struct CatalogState {
    catalog: ServiceCatalog,
    dynamic: BTreeMap<String, DynamicService>,
    dynamic_generation: u64,
    conflicts: Vec<String>,
    next_reload: Instant,
    last_error: Option<String>,
}

impl CatalogState {
    fn new() -> Self {
        match ServiceCatalog::load() {
            Ok(catalog) => Self {
                catalog,
                dynamic: BTreeMap::new(),
                dynamic_generation: 1,
                conflicts: Vec::new(),
                next_reload: Instant::now() + RELOAD_INTERVAL,
                last_error: None,
            },
            Err(error) => Self {
                catalog: ServiceCatalog::default(),
                dynamic: BTreeMap::new(),
                dynamic_generation: 1,
                conflicts: Vec::new(),
                next_reload: Instant::now() + RELOAD_INTERVAL,
                last_error: Some(error.to_string()),
            },
        }
    }

    fn refresh(&mut self, now: Instant) {
        if now < self.next_reload {
            return;
        }
        self.next_reload = now + RELOAD_INTERVAL;
        match ServiceCatalog::load() {
            Ok(loaded) => {
                self.catalog.reconcile(loaded);
                self.last_error = None;
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_error.as_deref() != Some(&message) {
                    eprintln!("rustd-resolved: DNS-SD reload failed: {message}");
                }
                self.last_error = Some(message);
            }
        }
    }
}

static CATALOG: OnceLock<Mutex<CatalogState>> = OnceLock::new();

fn state() -> MutexGuard<'static, CatalogState> {
    CATALOG
        .get_or_init(|| Mutex::new(CatalogState::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn records_for(
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
    goodbye: bool,
) -> Result<Vec<DnsSdRecord>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    let mut records = state
        .catalog
        .records_for(interface, addresses, host_label, goodbye)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for service in state.dynamic.values() {
        records.extend(
            service
                .records(interface, addresses, host_label, goodbye)
                .map_err(|error| DnsSdRuntimeError::Service(dynamic_service_error(error)))?,
        );
    }
    Ok(records.into_iter().collect())
}

pub fn instance_owners(
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
) -> Result<BTreeMap<Vec<u8>, String>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    let mut owners = state
        .catalog
        .instance_owners(interface, addresses, host_label)?;
    for service in state.dynamic.values().filter(|service| !service.withdrawn) {
        let owner = service
            .instance_owner(interface, addresses, host_label)
            .map_err(|error| DnsSdRuntimeError::Service(dynamic_service_error(error)))?;
        owners.insert(owner, service.id.clone());
    }
    Ok(owners)
}

pub fn rename_conflicting_owner(
    owner: &[u8],
    rr_type: u16,
    interface: MdnsInterface,
    addresses: &BTreeSet<IpAddr>,
    host_label: &str,
) -> Result<Option<String>, DnsSdRuntimeError> {
    let mut state = state();
    state.refresh(Instant::now());
    if let Some(id) = state
        .catalog
        .rename_conflicting_owner(owner, rr_type, interface, addresses, host_label)?
    {
        return Ok(Some(id));
    }
    let conflicting = state
        .dynamic
        .iter()
        .filter(|(_, service)| !service.withdrawn)
        .find_map(|(id, service)| {
            service
                .instance_owner(interface, addresses, host_label)
                .ok()
                .filter(|candidate| candidate == owner)
                .map(|_| id.clone())
        });
    if let Some(id) = conflicting {
        if let Some(service) = state.dynamic.get_mut(&id) {
            service.withdrawn = true;
        }
        state.dynamic_generation = state.dynamic_generation.wrapping_add(1).max(1);
        state.conflicts.push(id.clone());
        return Ok(Some(id));
    }
    Ok(None)
}

pub fn generation() -> u64 {
    let mut state = state();
    state.refresh(Instant::now());
    state.catalog.generation() ^ state.dynamic_generation.rotate_left(17)
}

pub fn force_reload() -> Result<bool, DnsSdRuntimeError> {
    let loaded = ServiceCatalog::load()?;
    let mut state = state();
    state.next_reload = Instant::now() + RELOAD_INTERVAL;
    state.last_error = None;
    Ok(state.catalog.reconcile(loaded))
}

pub fn flush() {
    let mut state = state();
    state.catalog = ServiceCatalog::default();
    state.dynamic.clear();
    state.dynamic_generation = state.dynamic_generation.wrapping_add(1).max(1);
    state.conflicts.clear();
    state.next_reload = Instant::now();
    state.last_error = None;
}

pub fn register_dynamic(
    spec: DynamicServiceSpec,
    owner: String,
    originator_uid: u32,
) -> Result<(), DynamicServiceError> {
    let service = DynamicService::new(spec, owner, originator_uid)?;
    let mut state = state();
    if state.catalog.contains_id(&service.id) || state.dynamic.contains_key(&service.id) {
        return Err(DynamicServiceError::AlreadyExists);
    }
    state.dynamic.insert(service.id.clone(), service);
    state.dynamic_generation = state.dynamic_generation.wrapping_add(1).max(1);
    Ok(())
}

/// Validate a D-Bus DNS-SD registration before it reaches authorization.
///
/// The upstream Manager implementation rejects malformed and duplicate
/// registrations before it performs a PolicyKit check.  Keep that observable
/// ordering while leaving insertion to `register_dynamic` after authorization.
pub fn validate_dynamic_registration(spec: &DynamicServiceSpec) -> Result<(), DynamicServiceError> {
    let service = DynamicService::new(spec.clone(), String::new(), 0)?;
    let state = state();
    if state.catalog.contains_id(&service.id) || state.dynamic.contains_key(&service.id) {
        return Err(DynamicServiceError::AlreadyExists);
    }
    Ok(())
}

pub fn unregister_dynamic(id: &str) -> Result<(), DynamicServiceError> {
    let mut state = state();
    if state.dynamic.remove(id).is_none() {
        return Err(DynamicServiceError::NotFound);
    }
    state.dynamic_generation = state.dynamic_generation.wrapping_add(1).max(1);
    Ok(())
}

pub fn dynamic_ids() -> BTreeSet<String> {
    state().dynamic.keys().cloned().collect()
}

pub fn dynamic_owners() -> BTreeSet<String> {
    state()
        .dynamic
        .values()
        .map(|service| service.owner.clone())
        .collect()
}

pub fn dynamic_originator(id: &str) -> Option<u32> {
    state()
        .dynamic
        .get(id)
        .map(|service| service.originator_uid)
}

pub fn unregister_dynamic_owner(owner: &str) -> Vec<String> {
    let mut state = state();
    let ids = state
        .dynamic
        .iter()
        .filter(|(_, service)| service.owner == owner)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in &ids {
        state.dynamic.remove(id);
    }
    if !ids.is_empty() {
        state.dynamic_generation = state.dynamic_generation.wrapping_add(1).max(1);
    }
    ids
}

pub fn take_conflicts() -> Vec<String> {
    std::mem::take(&mut state().conflicts)
}

fn valid_identifier(id: &str) -> bool {
    !id.is_empty() && id.len() <= 255 && !matches!(id, "." | "..") && !id.contains('/')
}

fn validate_name_template(template: &str) -> Result<(), DynamicServiceError> {
    let rendered = render_name_template(template, "localhost")?;
    DnsSdInstance::new(rendered)?;
    Ok(())
}

fn render_name_template(template: &str, host_label: &str) -> Result<Vec<u8>, DynamicServiceError> {
    let os_release = read_os_release();
    let machine_id = read_trimmed("/etc/machine-id");
    let boot_id = read_trimmed("/proc/sys/kernel/random/boot_id");
    let kernel_release = read_trimmed("/proc/sys/kernel/osrelease");
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86-64",
        "aarch64" => "arm64",
        other => other,
    };
    let mut output = String::new();
    let mut characters = template.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        let Some(specifier) = characters.next() else {
            return Err(DynamicServiceError::InvalidNameTemplate);
        };
        match specifier {
            '%' => output.push('%'),
            'a' => output.push_str(architecture),
            'b' => output.push_str(&boot_id),
            'B' => output.push_str(os_release.get("BUILD_ID").map_or("", String::as_str)),
            'H' => output.push_str(host_label),
            'm' => output.push_str(&machine_id),
            'o' => output.push_str(os_release.get("ID").map_or("", String::as_str)),
            'v' => output.push_str(&kernel_release),
            'w' => output.push_str(os_release.get("VERSION_ID").map_or("", String::as_str)),
            'W' => output.push_str(os_release.get("VARIANT_ID").map_or("", String::as_str)),
            _ => return Err(DynamicServiceError::InvalidNameTemplate),
        }
    }
    if output.is_empty() || output.as_bytes().len() > 63 || output.chars().any(char::is_control) {
        return Err(DynamicServiceError::InvalidNameTemplate);
    }
    Ok(output.into_bytes())
}

fn read_trimmed(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

fn read_os_release() -> BTreeMap<String, String> {
    let contents = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    contents
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = value.trim().trim_matches('"').trim_matches('\'');
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn dynamic_service_error(error: DynamicServiceError) -> DnsSdError {
    match error {
        DynamicServiceError::Service(error) => error,
        DynamicServiceError::InvalidIdentifier
        | DynamicServiceError::InvalidNameTemplate
        | DynamicServiceError::InvalidTxtKey => DnsSdError::InvalidInstance,
        DynamicServiceError::AlreadyExists => DnsSdError::DuplicateRegistration,
        DynamicServiceError::NotFound => DnsSdError::UnknownRegistration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    static GLOBAL_CATALOG_TEST: Mutex<()> = Mutex::new(());

    fn lock_global_catalog() -> MutexGuard<'static, ()> {
        GLOBAL_CATALOG_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn dynamic_service() -> DynamicService {
        DynamicService::new(
            DynamicServiceSpec {
                id: "web.service".to_owned(),
                name_template: "%H Web".to_owned(),
                service_type: "_http._tcp".to_owned(),
                port: 8080,
                priority: 1,
                weight: 2,
                txt_data: vec![
                    HashMap::from([("path".to_owned(), b"/".to_vec())]),
                    HashMap::from([("version".to_owned(), b"1".to_vec())]),
                ],
            },
            ":1.40".to_owned(),
            1000,
        )
        .expect("dynamic service")
    }

    #[test]
    fn empty_global_catalog_is_safe() {
        let _guard = lock_global_catalog();
        flush();
        let interface = MdnsInterface::new(2, super::super::parity::MdnsAddressFamily::Ipv4);
        assert!(records_for(interface, &BTreeSet::new(), "host", false)
            .expect("empty records")
            .is_empty());
    }

    #[test]
    fn dynamic_service_renders_hostname_and_multiple_txt_records() {
        let service = dynamic_service();
        let interface = MdnsInterface::new(2, super::super::parity::MdnsAddressFamily::Ipv4);
        let addresses = BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let records = service
            .records(interface, &addresses, "candidate", false)
            .expect("records");
        let txt = records
            .iter()
            .filter(|record| record.rr_type == super::super::parity_dnssd::DNS_SD_TYPE_TXT)
            .collect::<Vec<_>>();
        assert_eq!(txt.len(), 2);
        let owner = service
            .instance_owner(interface, &addresses, "candidate")
            .expect("owner");
        assert_eq!(&owner[1..14], b"candidate Web");
    }

    #[test]
    fn dynamic_service_rejects_non_ascii_txt_keys() {
        let error = DynamicService::new(
            DynamicServiceSpec {
                id: "bad.service".to_owned(),
                name_template: "Bad".to_owned(),
                service_type: "_http._tcp".to_owned(),
                port: 80,
                priority: 0,
                weight: 0,
                txt_data: vec![HashMap::from([("clé".to_owned(), Vec::new())])],
            },
            ":1.41".to_owned(),
            1000,
        )
        .expect_err("invalid TXT key");
        assert_eq!(error, DynamicServiceError::InvalidTxtKey);
    }

    #[test]
    fn dbus_registration_validation_checks_type_before_name_template() {
        let error = validate_dynamic_registration(&DynamicServiceSpec {
            id: "order.service".to_owned(),
            name_template: "%Q".to_owned(),
            service_type: "not-a-service".to_owned(),
            port: 80,
            priority: 0,
            weight: 0,
            txt_data: Vec::new(),
        })
        .expect_err("invalid type must be reported first");
        assert_eq!(
            error,
            DynamicServiceError::Service(DnsSdError::InvalidServiceType)
        );
    }

    #[test]
    fn dbus_registration_validation_rejects_existing_dynamic_id() {
        let _guard = lock_global_catalog();
        flush();
        let spec = DynamicServiceSpec {
            id: "existing.service".to_owned(),
            name_template: "Existing".to_owned(),
            service_type: "_http._tcp".to_owned(),
            port: 80,
            priority: 0,
            weight: 0,
            txt_data: Vec::new(),
        };
        register_dynamic(spec.clone(), ":1.4243".to_owned(), 1000)
            .expect("register existing service");
        assert_eq!(
            validate_dynamic_registration(&spec),
            Err(DynamicServiceError::AlreadyExists)
        );
        flush();
    }

    #[test]
    fn withdrawn_dynamic_service_stops_publishing() {
        let mut service = dynamic_service();
        service.withdrawn = true;
        let interface = MdnsInterface::new(2, super::super::parity::MdnsAddressFamily::Ipv4);
        assert!(service
            .records(interface, &BTreeSet::new(), "candidate", false)
            .expect("withdrawn records")
            .is_empty());
    }

    #[test]
    fn unregistering_an_owner_removes_all_of_its_services() {
        let _guard = lock_global_catalog();
        flush();
        let owner = ":1.4242";
        for id in ["owner-web.service", "owner-printer.service"] {
            register_dynamic(
                DynamicServiceSpec {
                    id: id.to_owned(),
                    name_template: "Owned service".to_owned(),
                    service_type: "_http._tcp".to_owned(),
                    port: 8080,
                    priority: 0,
                    weight: 0,
                    txt_data: Vec::new(),
                },
                owner.to_owned(),
                1000,
            )
            .expect("register owner service");
        }
        assert!(dynamic_owners().contains(owner));
        assert_eq!(unregister_dynamic_owner(owner).len(), 2);
        assert!(!dynamic_owners().contains(owner));
    }
}
