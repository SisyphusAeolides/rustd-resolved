// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportMode {
    No,
    Resolve,
    Yes,
}

impl SupportMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "resolve" => Ok(Self::Resolve),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    No,
    AllowDowngrade,
    Yes,
}

impl ValidationMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "allow-downgrade" => Ok(Self::AllowDowngrade),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    No,
    Opportunistic,
    Yes,
}

impl TlsMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "opportunistic" => Ok(Self::Opportunistic),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServerSpec {
    pub address: SocketAddr,
    pub interface: Option<String>,
    pub server_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsStubListenerMode {
    No,
    Udp,
    Tcp,
    Yes,
}

impl DnsStubListenerMode {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "no" | "false" | "off" | "0" => Ok(Self::No),
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "yes" | "true" | "on" | "1" => Ok(Self::Yes),
            other => Err(ConfigError::InvalidValue(other.to_owned())),
        }
    }

    pub const fn udp_enabled(self) -> bool {
        matches!(self, Self::Udp | Self::Yes)
    }

    pub const fn tcp_enabled(self) -> bool {
        matches!(self, Self::Tcp | Self::Yes)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Yes => "yes",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsStubListenerExtra {
    address: SocketAddr,
    mode: DnsStubListenerMode,
}

impl DnsStubListenerExtra {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let value = value.trim();
        let (mode, address) = if let Some(address) = value.strip_prefix("udp:") {
            (DnsStubListenerMode::Udp, address)
        } else if let Some(address) = value.strip_prefix("tcp:") {
            (DnsStubListenerMode::Tcp, address)
        } else {
            (DnsStubListenerMode::Yes, value)
        };
        if address.is_empty() {
            return Err(ConfigError::InvalidValue(value.to_owned()));
        }
        let address = if let Ok(address) = address.parse::<SocketAddr>() {
            address
        } else if let Ok(address) = address.parse::<IpAddr>() {
            SocketAddr::new(address, 53)
        } else {
            return Err(ConfigError::InvalidValue(value.to_owned()));
        };
        Ok(Self { address, mode })
    }

    pub const fn address(self) -> SocketAddr {
        self.address
    }

    pub const fn udp_enabled(self) -> bool {
        self.mode.udp_enabled()
    }

    pub const fn tcp_enabled(self) -> bool {
        self.mode.tcp_enabled()
    }

    pub const fn mode(self) -> DnsStubListenerMode {
        self.mode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub name: String,
    pub route_only: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConfigAssignments {
    dns: bool,
    fallback_dns: bool,
    domains: bool,
}

impl ConfigAssignments {
    fn merge(&mut self, other: Self) {
        self.dns |= other.dns;
        self.fallback_dns |= other.fallback_dns;
        self.domains |= other.domains;
    }
}

#[derive(Clone, Debug)]
#[allow(unknown_lints)]
#[allow(clippy::struct_excessive_bools, clippy::struct_field_names)]
pub struct Config {
    pub dns_delegates: Vec<crate::dns_delegate::DnsDelegate>,
    pub upstreams: Vec<SocketAddr>,
    pub upstream_specs: Vec<DnsServerSpec>,
    pub fallback_upstreams: Vec<SocketAddr>,
    pub fallback_upstream_specs: Vec<DnsServerSpec>,
    pub listeners: Vec<SocketAddr>,
    pub proxy_listeners: Vec<SocketAddr>,
    pub dns_stub_listener: DnsStubListenerMode,
    pub dns_stub_listener_extra: Vec<DnsStubListenerExtra>,
    pub domains: Vec<Domain>,
    pub refuse_record_types: BTreeSet<u16>,
    pub varlink_path: PathBuf,
    pub runtime_directory: PathBuf,
    pub hosts_path: PathBuf,
    pub cache: bool,
    pub cache_negative: bool,
    pub cache_from_localhost: bool,
    pub cache_size: usize,
    pub llmnr_cache_size: usize,
    pub multicast_dns_cache_size: usize,
    pub cache_max_ttl: Duration,
    pub stale_retention: Duration,
    pub query_timeout: Duration,
    pub attempts: usize,
    pub workers: usize,
    pub read_etc_hosts: bool,
    pub read_static_records: bool,
    pub resolve_unicast_single_label: bool,
    pub llmnr: SupportMode,
    pub multicast_dns: SupportMode,
    pub dnssec: ValidationMode,
    pub dns_over_tls: TlsMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_delegates: Vec::new(),
            upstreams: Vec::new(),
            upstream_specs: Vec::new(),
            fallback_upstreams: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                    53,
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                    53,
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
                    53,
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
                    53,
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
                    53,
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 9)),
                    53,
                ),
            ],
            fallback_upstream_specs: Vec::new(),
            listeners: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
                53,
            )],
            proxy_listeners: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54)),
                53,
            )],
            dns_stub_listener: DnsStubListenerMode::Yes,
            dns_stub_listener_extra: Vec::new(),
            domains: Vec::new(),
            refuse_record_types: BTreeSet::new(),
            varlink_path: PathBuf::from("/run/rustd/resolve/io.rustd.Resolve"),
            runtime_directory: PathBuf::from("/run/rustd/resolve"),
            hosts_path: PathBuf::from("/etc/hosts"),
            cache: true,
            cache_negative: true,
            cache_from_localhost: false,
            cache_size: 4096,
            llmnr_cache_size: 4096,
            multicast_dns_cache_size: 4096,
            cache_max_ttl: Duration::from_secs(2 * 60 * 60),
            stale_retention: Duration::ZERO,
            query_timeout: Duration::from_secs(5),
            attempts: 24,
            workers: 4,
            read_etc_hosts: true,
            read_static_records: true,
            resolve_unicast_single_label: false,
            llmnr: SupportMode::Yes,
            multicast_dns: SupportMode::Yes,
            dnssec: ValidationMode::AllowDowngrade,
            dns_over_tls: TlsMode::No,
        }
    }
}
