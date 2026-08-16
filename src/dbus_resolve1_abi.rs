//! Complete org.freedesktop.resolve1 Manager/Link contract types and async trait.

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub const BUS_NAME: &str = "org.freedesktop.resolve1";
pub const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
pub const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
pub const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

pub const MANAGER_METHODS: &[&str] = &[
    "ResolveHostname",
    "ResolveAddress",
    "ResolveRecord",
    "ResolveService",
    "GetLink",
    "SetLinkDNS",
    "SetLinkDNSEx",
    "SetLinkDomains",
    "SetLinkDefaultRoute",
    "SetLinkLLMNR",
    "SetLinkMulticastDNS",
    "SetLinkDNSOverTLS",
    "SetLinkDNSSEC",
    "SetLinkDNSSECNegativeTrustAnchors",
    "RevertLink",
    "RegisterService",
    "UnregisterService",
    "GetDelegate",
    "ListDelegates",
    "ResetStatistics",
    "FlushCaches",
    "ResetServerFeatures",
];

pub const MANAGER_PROPERTIES: &[&str] = &[
    "LLMNRHostname",
    "LLMNR",
    "MulticastDNS",
    "DNSOverTLS",
    "DNS",
    "DNSEx",
    "FallbackDNS",
    "FallbackDNSEx",
    "CurrentDNSServer",
    "CurrentDNSServerEx",
    "Domains",
    "TransactionStatistics",
    "CacheStatistics",
    "DNSSECStatistics",
    "DNSSECSupported",
    "DNSSECNegativeTrustAnchors",
    "DNSSEC",
    "DNSStubListener",
    "ResolvConfMode",
];

pub const LINK_METHODS: &[&str] = &[
    "SetDNS",
    "SetDNSEx",
    "SetDomains",
    "SetDefaultRoute",
    "SetLLMNR",
    "SetMulticastDNS",
    "SetDNSOverTLS",
    "SetDNSSEC",
    "SetDNSSECNegativeTrustAnchors",
    "Revert",
];

pub const LINK_PROPERTIES: &[&str] = &[
    "ScopesMask",
    "DNS",
    "DNSEx",
    "CurrentDNSServer",
    "CurrentDNSServerEx",
    "Domains",
    "DefaultRoute",
    "LLMNR",
    "MulticastDNS",
    "DNSOverTLS",
    "DNSSEC",
    "DNSSECNegativeTrustAnchors",
    "DNSSECSupported",
];

/// Flags subset from sd-resolve / resolve1
pub mod flags {
    pub const SD_RESOLVED_DNS: u64 = 1 << 0;
    pub const SD_RESOLVED_LLMNR_IPV4: u64 = 1 << 1;
    pub const SD_RESOLVED_LLMNR_IPV6: u64 = 1 << 2;
    pub const SD_RESOLVED_MDNS_IPV4: u64 = 1 << 3;
    pub const SD_RESOLVED_MDNS_IPV6: u64 = 1 << 4;
    pub const SD_RESOLVED_NO_CNAME: u64 = 1 << 5;
    pub const SD_RESOLVED_NO_TXT: u64 = 1 << 6;
    pub const SD_RESOLVED_NO_ADDRESS: u64 = 1 << 7;
    pub const SD_RESOLVED_NO_SEARCH: u64 = 1 << 8;
    pub const SD_RESOLVED_AUTHENTICATED: u64 = 1 << 9;
    pub const SD_RESOLVED_NO_VALIDATE: u64 = 1 << 10;
    pub const SD_RESOLVED_NO_SYNTHESIZE: u64 = 1 << 11;
    pub const SD_RESOLVED_NO_CACHE: u64 = 1 << 12;
    pub const SD_RESOLVED_NO_ZONE: u64 = 1 << 13;
    pub const SD_RESOLVED_NO_TRUST_ANCHOR: u64 = 1 << 14;
    pub const SD_RESOLVED_NO_NETWORK: u64 = 1 << 15;
    pub const SD_RESOLVED_REQUIRE_PRIMARY: u64 = 1 << 16;
    pub const SD_RESOLVED_CLAMP_TTL: u64 = 1 << 17;
    pub const SD_RESOLVED_CONFIDENTIAL: u64 = 1 << 18;
    pub const SD_RESOLVED_SYNTHETIC: u64 = 1 << 19;
    pub const SD_RESOLVED_FROM_CACHE: u64 = 1 << 20;
    pub const SD_RESOLVED_FROM_ZONE: u64 = 1 << 21;
    pub const SD_RESOLVED_FROM_TRUST_ANCHOR: u64 = 1 << 22;
    pub const SD_RESOLVED_FROM_NETWORK: u64 = 1 << 23;
    pub const SD_RESOLVED_NO_STALE: u64 = 1 << 24;
    pub const SD_RESOLVED_RELAX_SINGLE_LABEL: u64 = 1 << 25;
    pub const SD_RESOLVED_QUERY_CONTINUOUS: u64 = 1 << 26;
    pub const SD_RESOLVED_FROM_HOOK: u64 = 1 << 27;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Resolve1Error {
    Success = 0,
    NoName = 1,
    NoAddress = 2,
    Resource = 3,
    DnsTimeout = 4,
    DnsNoServer = 5,
    DnssecFailed = 6,
    NoSuchLink = 7,
    NotSupported = 8,
    Invalid = 9,
    DnsNoAnswer = 10,
}

#[derive(Clone, Debug)]
pub struct ResolveHostnameArgs {
    pub ifindex: i32,
    pub name: String,
    /// AF_UNSPEC=0, AF_INET=2, AF_INET6=10
    pub family: i32,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolvedAddress {
    pub ifindex: i32,
    pub family: i32,
    pub address: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ResolveHostnameResult {
    pub addresses: Vec<ResolvedAddress>,
    pub canonical: String,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveAddressArgs {
    pub ifindex: i32,
    pub family: i32,
    pub address: Vec<u8>,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveAddressResult {
    pub names: Vec<(i32, String)>,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveRecordArgs {
    pub ifindex: i32,
    pub name: String,
    pub class: u16,
    pub type_: u16,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveRecordResult {
    pub records: Vec<(u16, u16, u32, Vec<u8>)>, // class, type, ttl? rr wire varies
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveServiceArgs {
    pub ifindex: i32,
    pub name: String,
    pub type_: String,
    pub domain: String,
    pub family: i32,
    pub flags: u64,
}

#[derive(Clone, Debug)]
pub struct ResolveServiceResult {
    pub srv: Vec<(u16, u16, u16, String)>, // priority weight port host
    pub txt: Vec<Vec<u8>>,
    pub addresses: Vec<ResolvedAddress>,
    pub canonical_name: String,
    pub canonical_type: String,
    pub canonical_domain: String,
    pub flags: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkDnsServer {
    pub family: i32,
    pub address: Vec<u8>,
    pub port: u16,
    pub ifindex: i32,
    pub server_name: String,
}

#[derive(Clone, Debug)]
pub struct LinkDomain {
    pub domain: String,
    pub route_only: bool,
}

#[async_trait]
pub trait Resolve1Manager: Send + Sync {
    async fn resolve_hostname(
        &self,
        a: ResolveHostnameArgs,
    ) -> Result<ResolveHostnameResult, Resolve1Error>;

    async fn resolve_address(
        &self,
        a: ResolveAddressArgs,
    ) -> Result<ResolveAddressResult, Resolve1Error>;

    async fn resolve_record(
        &self,
        a: ResolveRecordArgs,
    ) -> Result<ResolveRecordResult, Resolve1Error>;

    async fn resolve_service(
        &self,
        a: ResolveServiceArgs,
    ) -> Result<ResolveServiceResult, Resolve1Error>;

    async fn flush_caches(&self);
    async fn reset_statistics(&self);
    async fn reset_server_features(&self);
    async fn reload(&self);

    async fn set_link_dns(&self, ifindex: i32, addrs: Vec<IpAddr>) -> Result<(), Resolve1Error>;
    async fn set_link_domains(
        &self,
        ifindex: i32,
        domains: Vec<LinkDomain>,
    ) -> Result<(), Resolve1Error>;
    async fn set_link_default_route(&self, ifindex: i32, enable: bool)
        -> Result<(), Resolve1Error>;
    async fn set_link_llmnr(&self, ifindex: i32, mode: &str) -> Result<(), Resolve1Error>;
    async fn set_link_mdns(&self, ifindex: i32, mode: &str) -> Result<(), Resolve1Error>;
    async fn set_link_dot(&self, ifindex: i32, mode: &str) -> Result<(), Resolve1Error>;
    async fn set_link_dnssec(&self, ifindex: i32, mode: &str) -> Result<(), Resolve1Error>;
    async fn revert_link(&self, ifindex: i32) -> Result<(), Resolve1Error>;
}

/// Bridge DaemonState → Resolve1Manager (implement in dbus_manager.rs).
#[derive(Debug)]
pub struct ManagerFacade {
    // pub state: Arc<crate::landing_glue::DaemonState>,
    pub _marker: u8,
}

/// Helper: IpAddr → resolve1 address bytes + family
pub fn ip_to_resolve1(ip: IpAddr, ifindex: i32) -> ResolvedAddress {
    match ip {
        IpAddr::V4(v) => ResolvedAddress {
            ifindex,
            family: 2, // AF_INET
            address: v.octets().to_vec(),
        },
        IpAddr::V6(v) => ResolvedAddress {
            ifindex,
            family: 10, // AF_INET6
            address: v.octets().to_vec(),
        },
    }
}

pub fn method_supported(name: &str) -> bool {
    MANAGER_METHODS.contains(&name)
}

pub fn manager_property_supported(name: &str) -> bool {
    MANAGER_PROPERTIES.contains(&name)
}

pub fn link_method_supported(name: &str) -> bool {
    LINK_METHODS.contains(&name)
}

pub fn link_property_supported(name: &str) -> bool {
    LINK_PROPERTIES.contains(&name)
}
