// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    InvalidServer(String),
    InvalidValue(String),
    Line { line: usize, message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::InvalidServer(server) => write!(formatter, "invalid DNS server: {server}"),
            Self::InvalidValue(value) => write!(formatter, "invalid value: {value}"),
            Self::Line { line, message } => write!(formatter, "line {line}: {message}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Io(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn apply_optional_file(
    config: &mut Config,
    path: &Path,
) -> Result<ConfigAssignments, ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(config.apply_file_text_tracking(&text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ConfigAssignments::default()),
        Err(error) => Err(ConfigError::Io(error)),
    }
}

const MAX_CREDENTIAL_SIZE: usize = 1024 * 1024;
const MAX_CREDENTIAL_READ: u64 = 1024 * 1024 + 1;

fn apply_credentials_from_environment(config: &mut Config) -> bool {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return false;
    };
    let directory = PathBuf::from(directory);
    if !directory.is_absolute() {
        return false;
    }
    apply_credentials(config, &directory)
}

fn apply_credentials(config: &mut Config, directory: &Path) -> bool {
    let dns = read_credential(&directory.join("network.dns"));
    let domains = read_credential(&directory.join("network.search_domains"));
    let present = dns.is_some() || domains.is_some();

    if let Some(dns) = dns {
        let _ = apply_server_spec_assignment(
            &mut config.upstreams,
            &mut config.upstream_specs,
            dns.trim(),
        );
    }
    if let Some(domains) = domains {
        let _ = apply_domain_assignment(&mut config.domains, domains.trim());
    }
    present
}

fn read_credential(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_READ)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_CREDENTIAL_SIZE {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn discover_drop_ins(main: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let mut selected = BTreeMap::<String, PathBuf>::new();
    let mut directories = Vec::new();
    if main == Path::new("/etc/rustd/resolved.conf") {
        directories.extend([
            PathBuf::from("/usr/lib/rustd/resolved.conf.d"),
            PathBuf::from("/usr/local/lib/rustd/resolved.conf.d"),
            PathBuf::from("/run/rustd/resolved.conf.d"),
            PathBuf::from("/etc/rustd/resolved.conf.d"),
        ]);
    } else if let Some(parent) = main.parent() {
        directories.push(parent.join("resolved.conf.d"));
    }

    for directory in directories {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ConfigError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("conf") {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                selected.insert(name.to_owned(), path);
            }
        }
    }
    Ok(selected.into_values().collect())
}

fn apply_domain_assignment(destination: &mut Vec<Domain>, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        destination.clear();
        return Ok(());
    }
    for token in value.split_whitespace() {
        let mut route_only = token.starts_with('~');
        let name = token.trim_start_matches('~').trim_end_matches('.');
        let name = if name.is_empty() || name == "*" {
            route_only = true;
            "."
        } else {
            name
        };
        if !name.is_ascii() || name.split('.').any(|label| label.len() > 63) {
            return Err(ConfigError::InvalidValue(token.to_owned()));
        }
        let domain = Domain {
            name: name.to_ascii_lowercase(),
            route_only,
        };
        if !destination.contains(&domain) {
            destination.push(domain);
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidValue(value.to_owned())),
    }
}

fn parse_cache_size(value: &str) -> Result<usize, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue(value.to_owned()))
}

fn parse_cache_mode(value: &str) -> Result<(bool, bool), ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Ok((true, true)),
        "no-negative" => Ok((true, false)),
        "no" | "false" | "off" | "0" => Ok((false, false)),
        _ => Err(ConfigError::InvalidValue(value.to_owned())),
    }
}

fn parse_duration(value: &str) -> Result<Duration, ConfigError> {
    let value = value.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = value.strip_suffix("min") {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3600.0)
    } else if let Some(number) = value.strip_suffix('d') {
        (number, 86_400.0)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };
    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue(value.to_owned()))?;
    if !number.is_finite() || number < 0.0 {
        return Err(ConfigError::InvalidValue(value.to_owned()));
    }
    Duration::try_from_secs_f64(number * multiplier)
        .map_err(|_| ConfigError::InvalidValue(value.to_owned()))
}

pub fn parse_server(value: &str) -> Result<SocketAddr, ConfigError> {
    Ok(parse_server_spec(value)?.address)
}

#[derive(Debug, Default)]
struct ResolvConf {
    servers: Vec<SocketAddr>,
    domains: Vec<Domain>,
}

fn discover_resolv_conf_state(path: &Path) -> Result<ResolvConf, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ResolvConf::default()),
        Err(error) => return Err(ConfigError::Io(error)),
    };
    let mut output = ResolvConf::default();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("nameserver") => {
                let Some(value) = fields.next() else {
                    continue;
                };
                let Ok(server) = parse_server(value) else {
                    continue;
                };
                if !is_local_stub(server) && !output.servers.contains(&server) {
                    output.servers.push(server);
                }
            }
            Some("domain" | "search") => {
                let value = fields.collect::<Vec<_>>().join(" ");
                if value.is_empty() {
                    continue;
                }
                let _ = apply_domain_assignment(&mut output.domains, &value);
            }
            _ => {}
        }
    }
    Ok(output)
}

pub fn discover_resolv_conf(path: &Path) -> Result<Vec<SocketAddr>, ConfigError> {
    Ok(discover_resolv_conf_state(path)?.servers)
}

fn filtered_servers(servers: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut output = Vec::new();
    for server in servers {
        if !is_local_stub(*server) && !output.contains(server) {
            output.push(*server);
        }
    }
    output
}

fn is_local_stub(server: SocketAddr) -> bool {
    match server.ip() {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(127, 0, 0, 53) || address == Ipv4Addr::new(127, 0, 0, 54)
        }
        IpAddr::V6(address) => address.is_loopback(),
    }
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), ConfigError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)?;
    Ok(())
}
