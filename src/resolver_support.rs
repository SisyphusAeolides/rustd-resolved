fn lookup_candidates(
    name: &str,
    domains: &[Domain],
    resolve_unicast_single_label: bool,
) -> Vec<String> {
    let relative = name.trim_end_matches('.');
    if relative.is_empty() || name.ends_with('.') || relative.contains('.') {
        return vec![name.to_owned()];
    }

    let mut candidates = Vec::new();
    for domain in domains {
        if domain.route_only || domain.name == "." {
            continue;
        }
        let candidate = format!("{relative}.{}", domain.name);
        if !candidates
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&candidate))
        {
            candidates.push(candidate);
        }
    }
    if resolve_unicast_single_label
        && !candidates
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(relative))
    {
        candidates.push(relative.to_owned());
    }
    candidates
}

fn normalize_shared_response(response: &[u8], ifindex: Option<i32>) -> Option<SharedResponse> {
    let mut response = response.to_vec();
    wire::rewrite_id(&mut response, 0).ok()?;
    Some(SharedResponse {
        packet: response,
        ifindex,
    })
}

fn response_is_success(response: &[u8]) -> bool {
    response_full_rcode(response)
        .map(|(rcode, _, _)| rcode == 0)
        .unwrap_or(false)
}

pub(crate) fn response_full_rcode(
    response: &[u8],
) -> Result<(u16, Option<u16>, Option<String>), ResolveError> {
    let opt = edns::inspect_opt(response).map_err(ResolveError::from)?;
    let rcode = edns::full_rcode(response, opt.as_ref()).map_err(ResolveError::from)?;
    let extended_dns_error = opt
        .as_ref()
        .map(edns::extended_error)
        .transpose()?
        .flatten()
        .map(|(extended_dns_error_code, extended_dns_error_message)| {
            (Some(extended_dns_error_code), extended_dns_error_message)
        })
        .unwrap_or((None, None));
    Ok((rcode, extended_dns_error.0, extended_dns_error.1))
}

pub const fn request_protocol_enabled(flags: u64, protocol: u64) -> bool {
    if (flags & crate::dbus_resolve1_abi::flags::SD_RESOLVED_NO_ZONE != 0)
        && (protocol & (llmnr_protocol_mask() | mdns_protocol_mask()) != 0)
    {
        return false;
    }
    let configured = flags & resolver_protocol_mask();
    configured == 0 || configured & protocol != 0
}

const fn resolver_protocol_mask() -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_DNS, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4,
        SD_RESOLVED_MDNS_IPV6,
    };
    SD_RESOLVED_DNS
        | SD_RESOLVED_LLMNR_IPV4
        | SD_RESOLVED_LLMNR_IPV6
        | SD_RESOLVED_MDNS_IPV4
        | SD_RESOLVED_MDNS_IPV6
}

const fn llmnr_protocol_mask() -> u64 {
    crate::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV4
        | crate::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV6
}

const fn mdns_protocol_mask() -> u64 {
    crate::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV4
        | crate::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV6
}

pub const fn query_flags_are_valid(flags: u64, method_flags: u64) -> bool {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_AUTHENTICATED, SD_RESOLVED_CONFIDENTIAL,
        SD_RESOLVED_NO_CACHE, SD_RESOLVED_NO_CNAME, SD_RESOLVED_NO_NETWORK, SD_RESOLVED_NO_STALE,
        SD_RESOLVED_NO_SYNTHESIZE, SD_RESOLVED_NO_TRUST_ANCHOR, SD_RESOLVED_NO_VALIDATE,
        SD_RESOLVED_NO_ZONE, SD_RESOLVED_RELAX_SINGLE_LABEL,
        SD_RESOLVED_SYNTHETIC,
    };
    let common = resolver_protocol_mask()
        | SD_RESOLVED_NO_CNAME
        | SD_RESOLVED_NO_VALIDATE
        | SD_RESOLVED_NO_SYNTHESIZE
        | SD_RESOLVED_NO_CACHE
        | SD_RESOLVED_NO_ZONE
        | SD_RESOLVED_NO_TRUST_ANCHOR
        | SD_RESOLVED_NO_NETWORK
        | SD_RESOLVED_NO_STALE
        | SD_RESOLVED_RELAX_SINGLE_LABEL
        | SD_RESOLVED_AUTHENTICATED
        | SD_RESOLVED_CONFIDENTIAL
        | SD_RESOLVED_SYNTHETIC;
    flags & !(common | method_flags) == 0
}

fn route_cache_id(generation: u64, ifindex: Option<i32>) -> u64 {
    let ifindex = ifindex
        .and_then(|value| u32::try_from(value).ok())
        .map_or(0, u64::from);
    generation.rotate_left(32) ^ ifindex
}

fn duration_milliseconds(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameLookup {
    pub addresses: Vec<IpAddr>,
    pub address_ifindices: Vec<Option<i32>>,
    pub canonical_name: String,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressLookup {
    pub names: Vec<String>,
    pub name_ifindices: Vec<Option<i32>>,
    pub flags: u64,
}

pub fn response_protocol_flags(response: &[u8]) -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_DNS, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4,
        SD_RESOLVED_MDNS_IPV6,
    };

    let Ok(header) = Header::parse(response) else {
        return SD_RESOLVED_DNS;
    };
    if header.flags & 0x0080 != 0 {
        return SD_RESOLVED_DNS;
    }
    let Ok(question) = first_question(response) else {
        return SD_RESOLVED_DNS;
    };
    let name = question.name.text().to_ascii_lowercase();
    if crate::mdns::runtime::should_handle_name(&name) {
        return response_family_protocol_flags(
            response,
            SD_RESOLVED_MDNS_IPV4,
            SD_RESOLVED_MDNS_IPV6,
        );
    }
    if !name.contains('.') || name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa") {
        return response_family_protocol_flags(
            response,
            SD_RESOLVED_LLMNR_IPV4,
            SD_RESOLVED_LLMNR_IPV6,
        );
    }
    SD_RESOLVED_DNS
}

fn response_family_protocol_flags(packet: &[u8], ipv4_flag: u64, ipv6_flag: u64) -> u64 {
    let Ok(question) = first_question(packet) else {
        return ipv4_flag | ipv6_flag;
    };
    let name = question.name.text().to_ascii_lowercase();
    let ipv6 = question.rr_type == TYPE_AAAA || name.ends_with(".ip6.arpa");
    let ipv4 = question.rr_type == TYPE_A || name.ends_with(".in-addr.arpa");
    match (ipv4, ipv6) {
        (true, false) => ipv4_flag,
        (false, true) => ipv6_flag,
        _ => ipv4_flag | ipv6_flag,
    }
}

fn synthetic_response_flags(request_flags: u64, query: &[u8]) -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_AUTHENTICATED, SD_RESOLVED_CONFIDENTIAL, SD_RESOLVED_SYNTHETIC,
    };

    synthesized_protocol_flags(request_flags, query)
        | SD_RESOLVED_AUTHENTICATED
        | SD_RESOLVED_CONFIDENTIAL
        | SD_RESOLVED_SYNTHETIC
}

const fn dns_response_flags() -> u64 {
    crate::dbus_resolve1_abi::flags::SD_RESOLVED_DNS
}

fn hook_response_flags(request_flags: u64, query: &[u8]) -> u64 {
    synthesized_protocol_flags(request_flags, query)
        | crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_HOOK
}

fn synthesized_protocol_flags(request_flags: u64, query: &[u8]) -> u64 {
    if request_protocol_enabled(
        request_flags,
        crate::dbus_resolve1_abi::flags::SD_RESOLVED_DNS,
    ) {
        return dns_response_flags();
    }
    if request_flags & llmnr_protocol_mask() != 0 {
        return response_family_protocol_flags(
            query,
            crate::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV4,
            crate::dbus_resolve1_abi::flags::SD_RESOLVED_LLMNR_IPV6,
        );
    }
    response_family_protocol_flags(
        query,
        crate::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV4,
        crate::dbus_resolve1_abi::flags::SD_RESOLVED_MDNS_IPV6,
    )
}

fn cache_response_flags(response: &[u8]) -> u64 {
    authenticated_response_flag(response)
        | dns_response_flags()
        | crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_CACHE
}

fn dns_network_response_flags(response: &[u8]) -> u64 {
    authenticated_response_flag(response)
        | dns_response_flags()
        | crate::dbus_resolve1_abi::flags::SD_RESOLVED_FROM_NETWORK
}

fn authenticated_response_flag(response: &[u8]) -> u64 {
    if matches!(Header::parse(response), Ok(header) if header.authentic_data()) {
        crate::dbus_resolve1_abi::flags::SD_RESOLVED_AUTHENTICATED
    } else {
        0
    }
}

fn mdns_response_flags(query: &[u8], from_cache: bool) -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_FROM_CACHE, SD_RESOLVED_FROM_NETWORK, SD_RESOLVED_MDNS_IPV4,
        SD_RESOLVED_MDNS_IPV6,
    };

    response_family_protocol_flags(query, SD_RESOLVED_MDNS_IPV4, SD_RESOLVED_MDNS_IPV6)
        | if from_cache {
            SD_RESOLVED_FROM_CACHE
        } else {
            SD_RESOLVED_FROM_NETWORK
        }
}

fn llmnr_response_flags(query: &[u8], from_cache: bool) -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_FROM_CACHE, SD_RESOLVED_FROM_NETWORK, SD_RESOLVED_LLMNR_IPV4,
        SD_RESOLVED_LLMNR_IPV6,
    };

    response_family_protocol_flags(query, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_LLMNR_IPV6)
        | if from_cache {
            SD_RESOLVED_FROM_CACHE
        } else {
            SD_RESOLVED_FROM_NETWORK
        }
}

fn merge_redirect_response_flags(previous: Option<u64>, current: u64) -> u64 {
    merge_response_flags(previous, current, false)
}

pub(crate) fn merge_parallel_response_flags(previous: Option<u64>, current: u64) -> u64 {
    merge_response_flags(previous, current, true)
}

fn merge_response_flags(previous: Option<u64>, current: u64, union_protocols: bool) -> u64 {
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_AUTHENTICATED, SD_RESOLVED_CONFIDENTIAL, SD_RESOLVED_DNS,
        SD_RESOLVED_FROM_CACHE, SD_RESOLVED_FROM_HOOK, SD_RESOLVED_FROM_NETWORK,
        SD_RESOLVED_FROM_TRUST_ANCHOR, SD_RESOLVED_FROM_ZONE, SD_RESOLVED_LLMNR_IPV4,
        SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4, SD_RESOLVED_MDNS_IPV6,
        SD_RESOLVED_SYNTHETIC,
    };

    let Some(previous) = previous else {
        return current;
    };
    let protocols = SD_RESOLVED_DNS
        | SD_RESOLVED_LLMNR_IPV4
        | SD_RESOLVED_LLMNR_IPV6
        | SD_RESOLVED_MDNS_IPV4
        | SD_RESOLVED_MDNS_IPV6;
    let sources = SD_RESOLVED_FROM_CACHE
        | SD_RESOLVED_FROM_ZONE
        | SD_RESOLVED_FROM_TRUST_ANCHOR
        | SD_RESOLVED_FROM_NETWORK
        | SD_RESOLVED_FROM_HOOK;
    let qualities = SD_RESOLVED_AUTHENTICATED | SD_RESOLVED_CONFIDENTIAL | SD_RESOLVED_SYNTHETIC;
    let protocol_flags = if union_protocols {
        (previous | current) & protocols
    } else {
        current & protocols
    };
    protocol_flags | ((previous | current) & sources) | ((previous & current) & qualities)
}

#[cfg(test)]
mod response_protocol_flag_tests {
    use super::*;
    use crate::dbus_resolve1_abi::flags::{
        SD_RESOLVED_DNS, SD_RESOLVED_FROM_CACHE, SD_RESOLVED_FROM_NETWORK, SD_RESOLVED_LLMNR_IPV4,
        SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV4, SD_RESOLVED_MDNS_IPV6,
    };
    use crate::wire::LocalRecord;

    fn response(name: &str, rr_type: u16, flags: u16) -> Vec<u8> {
        let query = make_query(name, rr_type, 17).unwrap();
        let record = if rr_type == TYPE_AAAA {
            LocalRecord::Aaaa(Ipv6Addr::LOCALHOST)
        } else {
            LocalRecord::A(Ipv4Addr::LOCALHOST)
        };
        let mut response = local_response(&query, &[record], 30).unwrap();
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    #[test]
    fn identifies_dns_llmnr_and_mdns_protocols() {
        assert_eq!(
            response_protocol_flags(&response("example.test", TYPE_A, 0x8080)),
            SD_RESOLVED_DNS
        );
        assert_eq!(
            response_protocol_flags(&response("example.test", TYPE_A, 0x80a0)),
            SD_RESOLVED_DNS
        );
        assert_eq!(
            response_protocol_flags(&response("printer", TYPE_A, 0x8000)),
            SD_RESOLVED_LLMNR_IPV4
        );
        assert_eq!(
            response_protocol_flags(&response("printer", TYPE_AAAA, 0x8000)),
            SD_RESOLVED_LLMNR_IPV6
        );
        assert_eq!(
            response_protocol_flags(&response("printer.local", TYPE_A, 0x8400)),
            SD_RESOLVED_MDNS_IPV4
        );
        let reverse = response("1.0.0.127.in-addr.arpa", TYPE_PTR, 0x8400);
        assert_eq!(
            mdns_response_flags(&reverse, false),
            SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_FROM_NETWORK
        );
        assert_eq!(
            mdns_response_flags(&reverse, true),
            SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_FROM_CACHE
        );
        assert_eq!(
            llmnr_response_flags(&reverse, false),
            SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_FROM_NETWORK
        );
        assert_eq!(
            llmnr_response_flags(&reverse, true),
            SD_RESOLVED_LLMNR_IPV4 | SD_RESOLVED_FROM_CACHE
        );
        let service = response("_ipp._tcp.local", 12, 0x8400);
        assert_eq!(
            mdns_response_flags(&service, false),
            SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6 | SD_RESOLVED_FROM_NETWORK
        );
    }

    #[test]
    fn merges_sources_without_overclaiming_answer_quality() {
        use crate::dbus_resolve1_abi::flags::{
            SD_RESOLVED_AUTHENTICATED, SD_RESOLVED_CONFIDENTIAL, SD_RESOLVED_FROM_CACHE,
            SD_RESOLVED_SYNTHETIC,
        };

        let query = make_query("localhost", TYPE_A, 7).expect("query");
        let synthetic = synthetic_response_flags(0, &query);
        let network = dns_network_response_flags(&response("example.test", TYPE_A, 0));
        let redirected = merge_redirect_response_flags(Some(synthetic), network);
        assert_eq!(redirected, network);

        let cached = SD_RESOLVED_DNS | SD_RESOLVED_FROM_CACHE;
        let mixed = merge_redirect_response_flags(Some(cached), network);
        assert_eq!(
            mixed,
            SD_RESOLVED_DNS | SD_RESOLVED_FROM_CACHE | SD_RESOLVED_FROM_NETWORK
        );

        let mdns_v4 = SD_RESOLVED_MDNS_IPV4
            | SD_RESOLVED_FROM_NETWORK
            | SD_RESOLVED_AUTHENTICATED
            | SD_RESOLVED_CONFIDENTIAL
            | SD_RESOLVED_SYNTHETIC;
        let mdns_v6 = SD_RESOLVED_MDNS_IPV6 | SD_RESOLVED_FROM_NETWORK;
        assert_eq!(
            merge_parallel_response_flags(Some(mdns_v4), mdns_v6),
            SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6 | SD_RESOLVED_FROM_NETWORK
        );
    }
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    Wire(WireError),
    Link(LinkError),
    NoNameServers,
    NoSuchResourceRecord,
    DnsError {
        rcode: u16,
        query: String,
        extended_dns_error_code: Option<u16>,
        extended_dns_error_message: Option<String>,
    },
    DnssecValidationFailed {
        result: String,
        extended_dns_error_code: Option<u16>,
        extended_dns_error_message: Option<String>,
    },
    NoTrustAnchor,
    QueryAborted,
    QueryRefused,
    MaxAttemptsReached,
    ResourceRecordTypeUnsupported,
    ResourceRecordTypeObsolete,
    InconsistentServiceRecords,
    StubLoop,
    UnsupportedFamily(i32),
    Protocol(&'static str),
}

impl ResolveError {
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Self::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                )
        )
    }

    pub fn varlink_id(&self) -> &'static str {
        match self {
            Self::NoNameServers => "io.rustd.Resolve.NoNameServers",
            Self::NoSuchResourceRecord => "io.rustd.Resolve.NoSuchResourceRecord",
            Self::DnsError { .. } => "io.rustd.Resolve.DNSError",
            Self::DnssecValidationFailed { .. } => "io.rustd.Resolve.DNSSECValidationFailed",
            Self::NoTrustAnchor => "io.rustd.Resolve.NoTrustAnchor",
            Self::QueryAborted => "io.rustd.Resolve.QueryAborted",
            Self::QueryRefused => "io.rustd.Resolve.QueryRefused",
            Self::MaxAttemptsReached => "io.rustd.Resolve.MaxAttemptsReached",
            Self::ResourceRecordTypeUnsupported => {
                "io.rustd.Resolve.ResourceRecordTypeUnsupported"
            }
            Self::ResourceRecordTypeObsolete => "io.rustd.Resolve.ResourceRecordTypeObsolete",
            Self::InconsistentServiceRecords => "io.rustd.Resolve.InconsistentServiceRecords",
            Self::StubLoop => "io.rustd.Resolve.StubLoop",
            Self::UnsupportedFamily(_) => "io.rustd.Resolve.BadAddressSize",
            Self::Link(_) => "io.rustd.Resolve.NoSource",
            Self::Wire(WireError::CnameLoop) => "io.rustd.Resolve.CNAMELoop",
            Self::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                "io.rustd.Resolve.QueryTimedOut"
            }
            Self::Io(_) => "io.rustd.Resolve.NetworkDown",
            Self::Wire(_) | Self::Protocol(_) => "io.rustd.Resolve.InvalidReply",
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Link(error) => write!(formatter, "{error}"),
            Self::NoNameServers => formatter.write_str("no DNS name servers are configured"),
            Self::NoSuchResourceRecord => formatter.write_str("no such DNS resource record"),
            Self::DnsError { rcode, query, .. } => {
                write!(formatter, "DNS response code {rcode} for {query}")
            }
            Self::DnssecValidationFailed { result, .. } => {
                write!(formatter, "DNSSEC validation failed: {result}")
            }
            Self::NoTrustAnchor => formatter.write_str("no DNSSEC trust anchor"),
            Self::QueryAborted => formatter.write_str("DNS query aborted"),
            Self::QueryRefused => formatter.write_str("DNS query refused"),
            Self::MaxAttemptsReached => {
                formatter.write_str("maximum DNS transaction attempts reached")
            }
            Self::ResourceRecordTypeUnsupported => formatter
                .write_str("DNS server does not support the requested resource record type"),
            Self::ResourceRecordTypeObsolete => {
                formatter.write_str("DNS resource record type is obsolete")
            }
            Self::InconsistentServiceRecords => {
                formatter.write_str("DNS service records are inconsistent")
            }
            Self::StubLoop => formatter.write_str("DNS stub loop detected"),
            Self::UnsupportedFamily(family) => {
                write!(formatter, "unsupported address family {family}")
            }
            Self::Protocol(message) => write!(formatter, "DNS protocol error: {message}"),
        }
    }
}

impl Error for ResolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Link(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for ResolveError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<LinkError> for ResolveError {
    fn from(error: LinkError) -> Self {
        Self::Link(error)
    }
}
