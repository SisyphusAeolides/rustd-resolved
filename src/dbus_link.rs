// SPDX-License-Identifier: LGPL-2.1-or-later
#[derive(Debug)]
struct LinkObject {
    resolver: Arc<Resolver>,
    authorization: Arc<DbusAuthorization>,
    ifindex: i32,
}

#[dbus_interface(name = "org.freedesktop.resolve1.Link")]
impl LinkObject {
    #[dbus_interface(name = "SetDNS")]
    fn set_dns(
        &self,
        addresses: Vec<(i32, Vec<u8>)>,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let servers = decode_dns_servers(addresses, DNS_PORT)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-dns-servers")?;
        self.resolver
            .set_link_dns(self.ifindex, servers)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSEx")]
    fn set_dns_ex(
        &self,
        addresses: Vec<(i32, Vec<u8>, u16, String)>,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let servers = validate_dns_server_specs(decode_dns_server_specs(addresses)?)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-dns-servers")?;
        self.resolver
            .set_link_dns_specs(self.ifindex, servers)
            .map_err(map_link_error)
    }

    fn set_domains(
        &self,
        domains: Vec<(String, bool)>,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorize(&header, "org.freedesktop.resolve1.set-domains")?;
        self.resolver
            .set_link_domains(
                self.ifindex,
                domains
                    .into_iter()
                    .map(|(name, route_only)| Domain { name, route_only })
                    .collect(),
            )
            .map_err(map_link_error)
    }

    fn set_default_route(
        &self,
        enable: bool,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorize(&header, "org.freedesktop.resolve1.set-default-route")?;
        self.resolver
            .set_link_default_route(self.ifindex, Some(enable))
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetLLMNR")]
    fn set_llmnr(
        &self,
        mode: &str,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_support_mode(mode)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-llmnr")?;
        self.resolver
            .set_link_llmnr(self.ifindex, mode)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetMulticastDNS")]
    fn set_multicast_dns(
        &self,
        mode: &str,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_support_mode(mode)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-mdns")?;
        self.resolver
            .set_link_multicast_dns(self.ifindex, mode)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSOverTLS")]
    fn set_dns_over_tls(
        &self,
        mode: &str,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_tls_mode(mode)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-dns-over-tls")?;
        self.resolver
            .set_link_dns_over_tls_override(self.ifindex, mode)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSSEC")]
    fn set_dnssec(
        &self,
        mode: &str,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        let mode = parse_validation_mode(mode)?;
        self.authorize(&header, "org.freedesktop.resolve1.set-dnssec")?;
        self.resolver
            .set_link_dnssec_override(self.ifindex, mode)
            .map_err(map_link_error)
    }

    #[dbus_interface(name = "SetDNSSECNegativeTrustAnchors")]
    fn set_dnssec_negative_trust_anchors(
        &self,
        names: Vec<String>,
        #[zbus(header)] header: MessageHeader<'_>,
    ) -> Result<(), DbusError> {
        self.authorize(
            &header,
            "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors",
        )?;
        self.resolver
            .set_link_dnssec_negative_trust_anchors(self.ifindex, names)
            .map_err(map_link_error)
    }

    fn revert(&self, #[zbus(header)] header: MessageHeader<'_>) -> Result<(), DbusError> {
        self.authorize(&header, "org.freedesktop.resolve1.revert")?;
        self.resolver
            .revert_link(self.ifindex)
            .map_err(map_link_error)
    }

    #[dbus_interface(property, name = "ScopesMask")]
    fn scopes_mask(&self) -> Result<u64, zbus::fdo::Error> {
        let link = self.state()?;
        Ok(link_scopes_mask(&self.resolver, &link))
    }

    #[dbus_interface(property, name = "DNS")]
    fn dns(&self) -> Result<Vec<(i32, Vec<u8>)>, zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .into_iter()
            .map(link_dns_entry)
            .collect())
    }

    #[dbus_interface(property, name = "DNSEx")]
    fn dns_ex(&self) -> Vec<(i32, Vec<u8>, u16, String)> {
        self.resolver
            .link_dns_specs(self.ifindex)
            .into_iter()
            .map(link_dns_ex_entry)
            .collect()
    }

    #[dbus_interface(property, name = "CurrentDNSServer")]
    fn current_dns_server(&self) -> Result<(i32, Vec<u8>), zbus::fdo::Error> {
        Ok(self
            .state()?
            .dns_servers
            .first()
            .copied()
            .map_or((AF_UNSPEC, Vec::new()), link_dns_entry))
    }

    #[dbus_interface(property, name = "CurrentDNSServerEx")]
    fn current_dns_server_ex(&self) -> (i32, Vec<u8>, u16, String) {
        self.resolver
            .link_dns_specs(self.ifindex)
            .into_iter()
            .next()
            .map_or((AF_UNSPEC, Vec::new(), 0, String::new()), link_dns_ex_entry)
    }

    #[dbus_interface(property, name = "Domains")]
    fn domains(&self) -> Result<Vec<(String, bool)>, zbus::fdo::Error> {
        Ok(self
            .state()?
            .domains
            .into_iter()
            .map(|domain| (domain.name, domain.route_only))
            .collect())
    }

    #[dbus_interface(property, name = "DefaultRoute")]
    fn default_route(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(self.state()?.effective_default_route())
    }

    #[dbus_interface(property, name = "LLMNR")]
    fn llmnr(&self) -> Result<String, zbus::fdo::Error> {
        self.state()?;
        Ok(support_mode_string(self.resolver.llmnr_mode_for_link(Some(self.ifindex))).to_owned())
    }

    #[dbus_interface(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> Result<String, zbus::fdo::Error> {
        self.state()?;
        Ok(support_mode_string(
            self.resolver
                .multicast_dns_mode_for_link(Some(self.ifindex)),
        )
        .to_owned())
    }

    #[dbus_interface(property, name = "DNSOverTLS")]
    fn dns_over_tls(&self) -> Result<String, zbus::fdo::Error> {
        Ok(tls_mode_string(self.state()?.dns_over_tls).to_owned())
    }

    #[dbus_interface(property, name = "DNSSEC")]
    fn dnssec(&self) -> Result<String, zbus::fdo::Error> {
        Ok(validation_mode_string(self.state()?.dnssec).to_owned())
    }

    #[dbus_interface(property, name = "DNSSECNegativeTrustAnchors")]
    fn dnssec_negative_trust_anchors(&self) -> Result<Vec<String>, zbus::fdo::Error> {
        Ok(self.state()?.dnssec_negative_trust_anchors)
    }

    #[dbus_interface(property, name = "DNSSECSupported")]
    fn dnssec_supported(&self) -> Result<bool, zbus::fdo::Error> {
        self.state()?;
        Ok(self.resolver.link_dnssec_supported(self.ifindex))
    }
}

fn link_scopes_mask(resolver: &Resolver, link: &LinkState) -> u64 {
    let networkd_relevant = resolver.networkd_link_relevant(link.ifindex);
    let mut mask = if link.dns_servers.is_empty()
        || !link.kernel_relevant_unicast()
        || !networkd_relevant
    {
        0
    } else {
        SD_RESOLVED_DNS
    };
    if let Some(kernel) = &link.kernel {
        for (family, llmnr_flag, mdns_flag) in [
            (2, SD_RESOLVED_LLMNR_IPV4, SD_RESOLVED_MDNS_IPV4),
            (10, SD_RESOLVED_LLMNR_IPV6, SD_RESOLVED_MDNS_IPV6),
        ] {
            if !networkd_relevant || !kernel.relevant_multicast(family) {
                continue;
            }
            if resolver.llmnr_mode_for_link(Some(link.ifindex)) != SupportMode::No {
                mask |= llmnr_flag;
            }
            if resolver.multicast_dns_mode_for_link(Some(link.ifindex)) != SupportMode::No {
                mask |= mdns_flag;
            }
        }
    }
    mask
}

impl LinkObject {
    fn authorize(&self, header: &MessageHeader<'_>, action: &str) -> Result<(), DbusError> {
        self.authorization.authorize(
            header,
            action,
            interface_details(&self.resolver, self.ifindex),
        )
    }

    fn state(&self) -> Result<LinkState, DbusError> {
        self.resolver.link(self.ifindex).ok_or_else(|| {
            DbusError::NoSuchLink(format!("no state exists for interface {}", self.ifindex))
        })
    }
}

async fn ensure_link_object_registered(
    object_server: &zbus::ObjectServer,
    resolver: &Arc<Resolver>,
    authorization: &Arc<DbusAuthorization>,
    ifindex: i32,
) -> Result<(), DbusError> {
    let path = link_object_path(ifindex)?;
    object_server
        .at(
            path,
            LinkObject {
                resolver: Arc::clone(resolver),
                authorization: Arc::clone(authorization),
                ifindex,
            },
        )
        .await?;
    Ok(())
}

fn synchronize_link_objects(
    connection: &Connection,
    resolver: &Arc<Resolver>,
    authorization: &Arc<DbusAuthorization>,
    registered: &mut BTreeSet<i32>,
) -> zbus::Result<()> {
    let current = resolver
        .links()
        .into_iter()
        .map(|link| link.ifindex)
        .collect::<BTreeSet<_>>();
    for ifindex in current.difference(registered).copied() {
        let path =
            link_object_path(ifindex).map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection.object_server().at(
            path.as_str(),
            LinkObject {
                resolver: Arc::clone(resolver),
                authorization: Arc::clone(authorization),
                ifindex,
            },
        )?;
    }
    for ifindex in registered.difference(&current).copied().collect::<Vec<_>>() {
        let path =
            link_object_path(ifindex).map_err(|error| zbus::Error::Failure(error.to_string()))?;
        connection
            .object_server()
            .remove::<LinkObject, _>(path.as_str())?;
    }
    *registered = current;
    Ok(())
}

fn link_object_path(ifindex: i32) -> Result<OwnedObjectPath, DbusError> {
    if ifindex <= 0 {
        return Err(DbusError::NoSuchLink(format!(
            "invalid interface index {ifindex}"
        )));
    }
    let encoded = encode_bus_label(&ifindex.to_string());
    OwnedObjectPath::try_from(format!("{LINK_PATH_PREFIX}/{encoded}"))
        .map_err(|error| DbusError::InvalidArgs(error.to_string()))
}

fn encode_bus_label(value: &str) -> String {
    if value.is_empty() {
        return "_".to_owned();
    }
    let mut output = String::with_capacity(value.len() * 3);
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()) {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "_{byte:02x}");
        }
    }
    output
}

fn validate_lookup_ifindex(ifindex: i32) -> Result<(), DbusError> {
    if ifindex < 0 {
        Err(DbusError::InvalidArgs(format!(
            "invalid interface index {ifindex}"
        )))
    } else {
        Ok(())
    }
}

fn positive_ifindex(ifindex: i32) -> Option<i32> {
    (ifindex > 0).then_some(ifindex)
}

fn validate_family(family: i32) -> Result<(), DbusError> {
    if matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        Ok(())
    } else {
        Err(DbusError::InvalidArgs(format!(
            "unsupported address family {family}"
        )))
    }
}

fn decode_address(family: i32, address: &[u8]) -> Result<IpAddr, DbusError> {
    match (family, address) {
        (AF_INET, [a, b, c, d]) => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        (AF_INET6, bytes) if bytes.len() == 16 => {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
                DbusError::InvalidArgs("IPv6 address must contain 16 octets".to_owned())
            })?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err(DbusError::InvalidArgs(format!(
            "address length does not match family {family}"
        ))),
    }
}

fn validate_dns_server_address(address: IpAddr) -> Result<IpAddr, DbusError> {
    let invalid = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || matches!(address.octets(), [127, 0, 0, 53] | [127, 0, 0, 54])
        }
        IpAddr::V6(address) => address.is_unspecified(),
    };
    if invalid {
        Err(DbusError::InvalidArgs(
            "invalid DNS server address".to_owned(),
        ))
    } else {
        Ok(address)
    }
}

fn validate_dns_server_specs(
    servers: Vec<DnsServerSpec>,
) -> Result<Vec<DnsServerSpec>, DbusError> {
    for server in &servers {
        validate_dns_server_address(server.address.ip())?;
    }
    Ok(servers)
}

fn decode_dns_server_address(family: i32, address: &[u8]) -> Result<IpAddr, DbusError> {
    validate_dns_server_address(decode_address(family, address)?)
}

fn decode_dns_servers(
    addresses: Vec<(i32, Vec<u8>)>,
    port: u16,
) -> Result<Vec<SocketAddr>, DbusError> {
    addresses
        .into_iter()
        .map(|(family, address)| {
            decode_dns_server_address(family, &address)
                .map(|address| SocketAddr::new(address, port))
        })
        .collect()
}

fn address_bytes(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (AF_INET, address.octets().to_vec()),
        IpAddr::V6(address) => (AF_INET6, address.octets().to_vec()),
    }
}

fn manager_dns(servers: &[SocketAddr], ifindex: i32) -> Vec<(i32, i32, Vec<u8>)> {
    servers
        .iter()
        .copied()
        .map(|server| manager_dns_entry(ifindex, server))
        .collect()
}

#[cfg(test)]
mod dns_server_validation_tests {
    use super::*;

    #[test]
    fn rejects_upstream_invalid_dns_server_addresses() {
        for address in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ] {
            assert!(validate_dns_server_address(address).is_err());
        }
    }

    #[test]
    fn accepts_other_loopback_dns_server_addresses() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            validate_dns_server_address(address).expect("valid DNS server address"),
            address,
        );
    }

    #[test]
    fn validates_dns_ex_server_specs() {
        let invalid = DnsServerSpec {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), DNS_PORT),
            interface: None,
            server_name: Some("dns.example".to_owned()),
        };
        assert!(validate_dns_server_specs(vec![invalid]).is_err());
    }
}
