// SPDX-License-Identifier: LGPL-2.1-or-later
use super::parity::{canonical_wire_name, MdnsAddressFamily, MdnsInterface};
use super::parity_dnssd::{
    DnsSdDomain, DnsSdError, DnsSdHost, DnsSdInstance, DnsSdRecord, DnsSdRegistration,
    DnsSdServiceType, DNS_SD_CLASS_IN, DNS_SD_DEFAULT_TTL, DNS_SD_TYPE_PTR,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const MAX_SERVICE_FILE_SIZE: u64 = 1024 * 1024;
const DEFAULT_DIRECTORIES: [&str; 4] = [
    "/etc/rustd/dnssd",
    "/run/rustd/dnssd",
    "/usr/local/lib/rustd/dnssd",
    "/usr/lib/rustd/dnssd",
];

#[derive(Debug)]
pub enum DnsSdConfigError {
    Io(io::Error),
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },
    Service {
        path: PathBuf,
        error: DnsSdError,
    },
    FileTooLarge(PathBuf),
    InvalidUtf8(PathBuf),
}

impl fmt::Display for DnsSdConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Parse {
                path,
                line,
                message,
            } => {
                write!(formatter, "{}:{line}: {message}", path.display())
            }
            Self::Service { path, error } => write!(formatter, "{}: {error}", path.display()),
            Self::FileTooLarge(path) => write!(formatter, "{} exceeds one MiB", path.display()),
            Self::InvalidUtf8(path) => write!(formatter, "{} is not valid UTF-8", path.display()),
        }
    }
}

impl Error for DnsSdConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Service { error, .. } => Some(error),
            Self::Parse { .. } | Self::FileTooLarge(_) | Self::InvalidUtf8(_) => None,
        }
    }
}

impl From<io::Error> for DnsSdConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceTemplate {
    id: String,
    base_instance: DnsSdInstance,
    ordinal: u32,
    service_type: DnsSdServiceType,
    port: u16,
    priority: u16,
    weight: u16,
    txt: Vec<Vec<u8>>,
    subtypes: BTreeSet<String>,
}

impl ServiceTemplate {
    fn instance(&self) -> Result<DnsSdInstance, DnsSdError> {
        if self.ordinal <= 1 {
            return Ok(self.base_instance.clone());
        }
        let suffix = format!(" ({})", self.ordinal);
        let maximum = 63usize.saturating_sub(suffix.len());
        let mut prefix = self.base_instance.as_bytes();
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

    fn registration(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
    ) -> Result<DnsSdRegistration, DnsSdError> {
        let addresses = addresses
            .iter()
            .copied()
            .filter(|address| {
                matches!(
                    (interface.family, address),
                    (MdnsAddressFamily::Ipv4, IpAddr::V4(_))
                        | (MdnsAddressFamily::Ipv6, IpAddr::V6(_))
                )
            })
            .collect();
        Ok(DnsSdRegistration {
            instance: self.instance()?,
            service_type: self.service_type.clone(),
            domain: DnsSdDomain::local(),
            host: DnsSdHost::local(host_label)?,
            port: self.port,
            priority: self.priority,
            weight: self.weight,
            txt: self.txt.clone(),
            subtypes: self.subtypes.clone(),
            addresses,
            interface,
            ttl: DNS_SD_DEFAULT_TTL,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServiceCatalog {
    templates: BTreeMap<String, ServiceTemplate>,
    configuration: BTreeMap<String, Vec<u8>>,
    generation: u64,
}

impl ServiceCatalog {
    pub fn load() -> Result<Self, DnsSdConfigError> {
        let directories = std::env::var_os("RUSTD_RESOLVED_DNSSD_PATH").map_or_else(
            || {
                DEFAULT_DIRECTORIES
                    .iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            },
            |path| vec![PathBuf::from(path)],
        );
        Self::load_from_directories(&directories)
    }

    pub fn load_from_directories(directories: &[PathBuf]) -> Result<Self, DnsSdConfigError> {
        let selected = selected_files(directories)?;
        let specifiers = Specifiers::load();
        let mut templates = BTreeMap::new();
        let mut configuration = BTreeMap::new();
        for (basename, path) in selected {
            let loaded = (|| {
                let bytes = bounded_read(&path)?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| DnsSdConfigError::InvalidUtf8(path.clone()))?;
                let template = parse_service(&path, &basename, text, &specifiers)?;
                Ok::<_, DnsSdConfigError>((bytes, template))
            })();
            if let Ok((bytes, template)) = loaded {
                configuration.insert(basename.clone(), bytes);
                templates.insert(basename, template);
            }
        }
        Ok(Self {
            templates,
            configuration,
            generation: 1,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.templates.contains_key(id)
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn reconcile(&mut self, mut loaded: Self) -> bool {
        if self.configuration == loaded.configuration {
            return false;
        }
        for (id, template) in &mut loaded.templates {
            if let Some(previous) = self.templates.get(id) {
                if previous.base_instance == template.base_instance
                    && previous.service_type == template.service_type
                {
                    template.ordinal = previous.ordinal;
                }
            }
        }
        loaded.generation = self.generation.wrapping_add(1).max(1);
        *self = loaded;
        true
    }

    pub fn records_for(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
        goodbye: bool,
    ) -> Result<Vec<DnsSdRecord>, DnsSdError> {
        let mut output = BTreeSet::new();
        let enumeration_owner = enumeration_owner();
        for template in self.templates.values() {
            let registration = template.registration(interface, addresses, host_label)?;
            let browse_owner = registration.browse_owner()?;
            output.insert(DnsSdRecord {
                owner: enumeration_owner.clone(),
                rr_type: DNS_SD_TYPE_PTR,
                class: DNS_SD_CLASS_IN,
                ttl: if goodbye { 0 } else { DNS_SD_DEFAULT_TTL },
                cache_flush: false,
                rdata: browse_owner,
                interface,
            });
            output.extend(registration.records(goodbye)?);
        }
        Ok(output.into_iter().collect())
    }

    pub fn rename_conflicting_owner(
        &mut self,
        owner: &[u8],
        rr_type: u16,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
    ) -> Result<Option<String>, DnsSdError> {
        if !matches!(rr_type, 16 | 33) {
            return Ok(None);
        }
        for (id, template) in &mut self.templates {
            let registration = template.registration(interface, addresses, host_label)?;
            if registration.instance_owner()? == owner {
                template.ordinal = template.ordinal.saturating_add(1).max(2);
                self.generation = self.generation.wrapping_add(1).max(1);
                return Ok(Some(id.clone()));
            }
        }
        Ok(None)
    }

    pub fn instance_owners(
        &self,
        interface: MdnsInterface,
        addresses: &BTreeSet<IpAddr>,
        host_label: &str,
    ) -> Result<BTreeMap<Vec<u8>, String>, DnsSdError> {
        let mut output = BTreeMap::new();
        for (id, template) in &self.templates {
            let registration = template.registration(interface, addresses, host_label)?;
            output.insert(registration.instance_owner()?, id.clone());
        }
        Ok(output)
    }
}

fn enumeration_owner() -> Vec<u8> {
    canonical_wire_name(b"\x09_services\x07_dns-sd\x04_udp\x05local\0").unwrap_or_else(|_| vec![0])
}

fn selected_files(directories: &[PathBuf]) -> Result<BTreeMap<String, PathBuf>, DnsSdConfigError> {
    let mut output = BTreeMap::new();
    let mut masked = BTreeSet::new();
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("dnssd")
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let Some(basename) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if output.contains_key(basename) || masked.contains(basename) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path)?;
                if target == Path::new("/dev/null") {
                    masked.insert(basename.to_owned());
                    continue;
                }
            }
            if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                output.insert(basename.to_owned(), path);
            }
        }
    }
    Ok(output)
}

fn bounded_read(path: &Path) -> Result<Vec<u8>, DnsSdConfigError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_SERVICE_FILE_SIZE {
        return Err(DnsSdConfigError::FileTooLarge(path.to_owned()));
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > MAX_SERVICE_FILE_SIZE {
        return Err(DnsSdConfigError::FileTooLarge(path.to_owned()));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Default)]
struct ParsedService {
    name: Option<String>,
    service_type: Option<String>,
    port: u16,
    priority: u16,
    weight: u16,
    txt: Vec<Vec<u8>>,
    subtypes: BTreeSet<String>,
}

fn parse_service(
    path: &Path,
    id: &str,
    text: &str,
    specifiers: &Specifiers,
) -> Result<ServiceTemplate, DnsSdConfigError> {
    let mut service = ParsedService::default();
    let mut section = String::new();
    for (line, logical) in logical_lines(text) {
        let value = strip_comment(&logical).trim();
        if value.is_empty() {
            continue;
        }
        if value.starts_with('[') && value.ends_with(']') {
            section = value[1..value.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        if section != "service" {
            continue;
        }
        let Some((key, raw_value)) = value.split_once('=') else {
            return Err(parse_error(path, line, "expected KEY=VALUE"));
        };
        let key = key.trim().to_ascii_lowercase();
        let raw_value = raw_value.trim();
        match key.as_str() {
            "name" => service.name = Some(expand_specifiers(raw_value, specifiers, path, line)?),
            "type" => {
                service.service_type = Some(expand_specifiers(raw_value, specifiers, path, line)?)
            }
            "port" => {
                if raw_value.is_empty() {
                    service.port = 0;
                } else if let Ok(value) = parse_u16(raw_value, path, line, false) {
                    service.port = value;
                }
            }
            "priority" => {
                if let Ok(value) = parse_u16(raw_value, path, line, true) {
                    service.priority = value;
                }
            }
            "weight" => {
                if let Ok(value) = parse_u16(raw_value, path, line, true) {
                    service.weight = value;
                }
            }
            "subtype" => {
                for subtype in split_words(raw_value, path, line)? {
                    service.subtypes.insert(subtype.to_ascii_lowercase());
                }
            }
            "txttext" => service.txt.push(
                unescape_text(
                    &expand_specifiers(raw_value, specifiers, path, line)?,
                    path,
                    line,
                )?
                .into_bytes(),
            ),
            "txtdata" => service.txt.push(decode_base64(raw_value, path, line)?),
            _ => {}
        }
    }

    let name = service
        .name
        .ok_or_else(|| parse_error(path, 0, "Service.Name= is required"))?;
    let service_type = service
        .service_type
        .ok_or_else(|| parse_error(path, 0, "Service.Type= is required"))?;
    let base_instance =
        DnsSdInstance::new(name.into_bytes()).map_err(|error| DnsSdConfigError::Service {
            path: path.to_owned(),
            error,
        })?;
    let service_type =
        DnsSdServiceType::parse(&service_type).map_err(|error| DnsSdConfigError::Service {
            path: path.to_owned(),
            error,
        })?;

    let template = ServiceTemplate {
        id: id.to_owned(),
        base_instance,
        ordinal: 1,
        service_type,
        port: service.port,
        priority: service.priority,
        weight: service.weight,
        txt: service.txt,
        subtypes: service.subtypes,
    };
    template
        .registration(
            MdnsInterface::new(1, MdnsAddressFamily::Ipv4),
            &BTreeSet::new(),
            "localhost",
        )
        .and_then(|registration| registration.validate())
        .map_err(|error| DnsSdConfigError::Service {
            path: path.to_owned(),
            error,
        })?;
    Ok(template)
}

fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut output = Vec::new();
    let mut pending = String::new();
    let mut start = 0usize;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let continued = raw.ends_with('\\') && !raw.ends_with("\\\\");
        let fragment = if continued {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        if pending.is_empty() {
            start = line;
        }
        pending.push_str(fragment);
        if continued {
            continue;
        }
        output.push((start, std::mem::take(&mut pending)));
    }
    if !pending.is_empty() {
        output.push((start, pending));
    }
    output
}

fn strip_comment(value: &str) -> &str {
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
        } else if character == '#' || character == ';' {
            return &value[..index];
        }
    }
    value
}

fn split_words(value: &str, path: &Path, line: usize) -> Result<Vec<String>, DnsSdConfigError> {
    let mut output = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !current.is_empty() {
                output.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err(parse_error(path, line, "unterminated quote or escape"));
    }
    if !current.is_empty() {
        output.push(current);
    }
    Ok(output)
}

fn parse_u16(
    value: &str,
    path: &Path,
    line: usize,
    allow_zero: bool,
) -> Result<u16, DnsSdConfigError> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| parse_error(path, line, "expected a 16-bit unsigned integer"))?;
    if !allow_zero && parsed == 0 {
        return Err(parse_error(path, line, "value must not be zero"));
    }
    Ok(parsed)
}

fn unescape_text(value: &str, path: &Path, line: usize) -> Result<String, DnsSdConfigError> {
    let mut output = String::new();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            return Err(parse_error(path, line, "trailing escape"));
        };
        match escaped {
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            's' => output.push(' '),
            '\\' => output.push('\\'),
            '"' => output.push('"'),
            '\'' => output.push('\''),
            'x' => {
                let high = characters
                    .next()
                    .and_then(|value| value.to_digit(16))
                    .ok_or_else(|| parse_error(path, line, "invalid hexadecimal escape"))?;
                let low = characters
                    .next()
                    .and_then(|value| value.to_digit(16))
                    .ok_or_else(|| parse_error(path, line, "invalid hexadecimal escape"))?;
                let byte = u8::try_from(high * 16 + low)
                    .map_err(|_| parse_error(path, line, "invalid hexadecimal escape"))?;
                output.push(char::from(byte));
            }
            other => output.push(other),
        }
    }
    Ok(output)
}

#[derive(Clone, Debug)]
struct Specifiers {
    hostname: String,
    machine_id: String,
    boot_id: String,
}

impl Specifiers {
    fn load() -> Self {
        Self {
            hostname: crate::native::kernel_hostname().unwrap_or_else(|| "localhost".to_owned()),
            machine_id: fs::read_to_string("/etc/machine-id")
                .map(|value| value.trim().to_owned())
                .unwrap_or_default(),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map(|value| value.trim().to_owned())
                .unwrap_or_default(),
        }
    }
}

fn expand_specifiers(
    value: &str,
    specifiers: &Specifiers,
    path: &Path,
    line: usize,
) -> Result<String, DnsSdConfigError> {
    let mut output = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        let Some(specifier) = characters.next() else {
            return Err(parse_error(path, line, "trailing percent specifier"));
        };
        match specifier {
            '%' => output.push('%'),
            'H' => output.push_str(&specifiers.hostname),
            'm' => output.push_str(&specifiers.machine_id),
            'b' => output.push_str(&specifiers.boot_id),
            other => {
                return Err(parse_error(
                    path,
                    line,
                    format!("unsupported percent specifier %{other}"),
                ))
            }
        }
    }
    Ok(output)
}

fn decode_base64(value: &str, path: &Path, line: usize) -> Result<Vec<u8>, DnsSdConfigError> {
    let mut output = Vec::new();
    let mut quartet = [0u8; 4];
    let mut count = 0usize;
    let mut padding = 0usize;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            quartet[count] = 0;
            count += 1;
            padding += 1;
        } else {
            if padding != 0 {
                return Err(parse_error(path, line, "base64 data follows padding"));
            }
            quartet[count] =
                base64_value(byte).ok_or_else(|| parse_error(path, line, "invalid base64 data"))?;
            count += 1;
        }
        if count == 4 {
            output.push((quartet[0] << 2) | (quartet[1] >> 4));
            if padding < 2 {
                output.push((quartet[1] << 4) | (quartet[2] >> 2));
            }
            if padding == 0 {
                output.push((quartet[2] << 6) | quartet[3]);
            }
            count = 0;
            padding = 0;
        }
    }
    if count != 0 {
        return Err(parse_error(path, line, "incomplete base64 quartet"));
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn parse_error(path: &Path, line: usize, message: impl Into<String>) -> DnsSdConfigError {
    DnsSdConfigError::Parse {
        path: path.to_owned(),
        line,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustd-resolved-{name}-{nonce}"));
        fs::create_dir_all(&path).expect("temporary directory");
        path
    }

    #[test]
    fn higher_priority_directory_wins() {
        let high = temporary_directory("dnssd-high");
        let low = temporary_directory("dnssd-low");
        fs::write(
            high.join("web.dnssd"),
            "[Service]\nName=High\nType=_http._tcp\nPort=80\n",
        )
        .expect("high file");
        fs::write(
            low.join("web.dnssd"),
            "[Service]\nName=Low\nType=_http._tcp\nPort=8080\n",
        )
        .expect("low file");
        let catalog =
            ServiceCatalog::load_from_directories(&[high.clone(), low.clone()]).expect("catalog");
        assert_eq!(catalog.len(), 1);
        let template = catalog.templates.get("web.dnssd").expect("template");
        assert_eq!(template.base_instance.as_bytes(), b"High");
        assert_eq!(template.port, 80);
        fs::remove_dir_all(high).expect("remove high");
        fs::remove_dir_all(low).expect("remove low");
    }

    #[test]
    fn dev_null_masks_lower_priority_file() {
        let high = temporary_directory("dnssd-mask-high");
        let low = temporary_directory("dnssd-mask-low");
        symlink("/dev/null", high.join("web.dnssd")).expect("mask");
        fs::write(
            low.join("web.dnssd"),
            "[Service]\nName=Low\nType=_http._tcp\nPort=8080\n",
        )
        .expect("low file");
        let catalog =
            ServiceCatalog::load_from_directories(&[high.clone(), low.clone()]).expect("catalog");
        assert!(catalog.is_empty());
        fs::remove_dir_all(high).expect("remove high");
        fs::remove_dir_all(low).expect("remove low");
    }

    #[test]
    fn parses_text_data_subtype_and_numeric_fields() {
        let directory = temporary_directory("dnssd-fields");
        fs::write(
            directory.join("printer.dnssd"),
            "[Service]\nName=Printer\nType=_ipp._tcp\nSubtype=_universal\nPort=631\nPriority=2\nWeight=3\nTxtText=txtvers=1\nTxtData=cXRvdGFsPTE=\n",
        )
        .expect("service file");
        let catalog = ServiceCatalog::load_from_directories(std::slice::from_ref(&directory))
            .expect("catalog");
        let template = catalog.templates.get("printer.dnssd").expect("template");
        assert_eq!(template.priority, 2);
        assert_eq!(template.weight, 3);
        assert_eq!(
            template.txt,
            vec![b"txtvers=1".to_vec(), b"qtotal=1".to_vec()]
        );
        assert!(template.subtypes.contains("_universal"));
        fs::remove_dir_all(directory).expect("remove directory");
    }

    #[test]
    fn invalid_port_and_broken_peer_match_pinned_load_boundaries() {
        let directory = temporary_directory("dnssd-invalid-port");
        fs::write(
            directory.join("published.dnssd"),
            "[Service]\nName=Published\nType=_test._udp\nPort=98010\n",
        )
        .expect("published service file");
        fs::write(
            directory.join("broken.dnssd"),
            "[Service]\nName=Broken\nType=not-a-service-type\nPort=80\n",
        )
        .expect("broken service file");

        let catalog = ServiceCatalog::load_from_directories(std::slice::from_ref(&directory))
            .expect("catalog survives one broken file");
        assert_eq!(catalog.len(), 1);
        assert_eq!(
            catalog
                .templates
                .get("published.dnssd")
                .expect("published service")
                .port,
            0
        );
        fs::remove_dir_all(directory).expect("remove directory");
    }

    #[test]
    fn produces_enumeration_and_service_records() {
        let directory = temporary_directory("dnssd-records");
        fs::write(
            directory.join("web.dnssd"),
            "[Service]\nName=Web\nType=_http._tcp\nPort=80\n",
        )
        .expect("service file");
        let catalog = ServiceCatalog::load_from_directories(std::slice::from_ref(&directory))
            .expect("catalog");
        let records = catalog
            .records_for(
                MdnsInterface::new(2, MdnsAddressFamily::Ipv4),
                &BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
                "host",
                false,
            )
            .expect("records");
        assert!(records
            .iter()
            .any(|record| record.owner == enumeration_owner()));
        assert!(records.iter().any(|record| record.rr_type == 33));
        assert!(records.iter().any(|record| record.rr_type == 16));
        assert!(records.iter().any(|record| record.rr_type == 1));
        fs::remove_dir_all(directory).expect("remove directory");
    }

    #[test]
    fn renames_only_the_conflicting_service_instance() {
        let directory = temporary_directory("dnssd-rename");
        fs::write(
            directory.join("web.dnssd"),
            "[Service]\nName=Web\nType=_http._tcp\nPort=80\n",
        )
        .expect("service file");
        let mut catalog = ServiceCatalog::load_from_directories(std::slice::from_ref(&directory))
            .expect("catalog");
        let interface = MdnsInterface::new(2, MdnsAddressFamily::Ipv4);
        let addresses = BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        let owner = catalog
            .instance_owners(interface, &addresses, "host")
            .expect("owners")
            .into_keys()
            .next()
            .expect("owner");
        assert_eq!(
            catalog
                .rename_conflicting_owner(&owner, 33, interface, &addresses, "host")
                .expect("rename")
                .as_deref(),
            Some("web.dnssd")
        );
        let renamed = catalog
            .instance_owners(interface, &addresses, "host")
            .expect("renamed owners")
            .into_keys()
            .next()
            .expect("renamed owner");
        assert_ne!(owner, renamed);
        fs::remove_dir_all(directory).expect("remove directory");
    }
}
