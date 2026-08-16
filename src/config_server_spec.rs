// SPDX-License-Identifier: LGPL-2.1-or-later
pub fn parse_server_spec(value: &str) -> Result<DnsServerSpec, ConfigError> {
    let original = value.trim();
    if original.is_empty() {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    }

    let (address_and_interface, server_name) = match original.split_once('#') {
        Some((address, name)) if valid_server_name(name) => (address, Some(name.to_owned())),
        Some(_) => return Err(ConfigError::InvalidServer(value.to_owned())),
        None => (original, None),
    };
    let (address, interface) = match address_and_interface.split_once('%') {
        Some((address, interface)) if valid_interface(interface) => {
            (address, Some(interface.to_owned()))
        }
        Some(_) => return Err(ConfigError::InvalidServer(value.to_owned())),
        None => (address_and_interface, None),
    };
    if address.contains('#') || address.contains('%') {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    }

    let address = if let Ok(address) = address.parse::<SocketAddr>() {
        address
    } else if let Ok(address) = address.parse::<IpAddr>() {
        SocketAddr::new(address, 53)
    } else {
        return Err(ConfigError::InvalidServer(value.to_owned()));
    };

    Ok(DnsServerSpec {
        address,
        interface,
        server_name,
    })
}

fn apply_server_spec_assignment(
    addresses: &mut Vec<SocketAddr>,
    specs: &mut Vec<DnsServerSpec>,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty() {
        addresses.clear();
        specs.clear();
        return Ok(());
    }
    for token in value.split_whitespace() {
        let spec = parse_server_spec(token)?;
        if !addresses.contains(&spec.address) {
            addresses.push(spec.address);
        }
        if !specs.contains(&spec) {
            specs.push(spec);
        }
    }
    Ok(())
}

fn filtered_server_specs(
    addresses: &[SocketAddr],
    specs: &[DnsServerSpec],
) -> Vec<DnsServerSpec> {
    let addresses = filtered_servers(addresses);
    let mut output = Vec::new();
    for address in addresses {
        let mut matched = false;
        for spec in specs.iter().filter(|spec| spec.address == address) {
            matched = true;
            if !output.contains(spec) {
                output.push(spec.clone());
            }
        }
        if !matched {
            output.push(DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            });
        }
    }
    output
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.chars().any(char::is_whitespace)
        && !value.contains('%')
        && !value.contains('#')
}

fn valid_server_name(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.is_ascii()
        && value.len() <= 253
        && !value.contains('%')
        && !value.contains('#')
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
}

#[cfg(test)]
mod server_spec_tests {
    use super::*;

    #[test]
    fn parses_address_port_interface_and_server_name() {
        let spec = parse_server_spec("1.1.1.1:853%2#one.one.one.one").expect("server spec");
        assert_eq!(spec.address, "1.1.1.1:853".parse().expect("address"));
        assert_eq!(spec.interface.as_deref(), Some("2"));
        assert_eq!(spec.server_name.as_deref(), Some("one.one.one.one"));

        let spec = parse_server_spec("[2001:db8::53]:853%eth0#resolver.example")
            .expect("IPv6 server spec");
        assert_eq!(
            spec.address,
            "[2001:db8::53]:853".parse().expect("IPv6 address")
        );
        assert_eq!(spec.interface.as_deref(), Some("eth0"));
        assert_eq!(spec.server_name.as_deref(), Some("resolver.example"));
    }

    #[test]
    fn raw_addresses_keep_default_dns_port() {
        let ipv4 = parse_server_spec("192.0.2.53").expect("IPv4 server");
        assert_eq!(ipv4.address, "192.0.2.53:53".parse().expect("IPv4 address"));

        let ipv6 = parse_server_spec("2001:db8::53%7#resolver.example")
            .expect("IPv6 server with metadata");
        assert_eq!(
            ipv6.address,
            "[2001:db8::53]:53".parse().expect("IPv6 address")
        );
        assert_eq!(ipv6.interface.as_deref(), Some("7"));
        assert_eq!(ipv6.server_name.as_deref(), Some("resolver.example"));
    }

    #[test]
    fn server_spec_assignment_preserves_same_address_metadata() {
        let mut addresses = Vec::new();
        let mut specs = Vec::new();
        apply_server_spec_assignment(
            &mut addresses,
            &mut specs,
            "1.1.1.1#one.example 1.1.1.1#two.example",
        )
        .expect("server specs");
        assert_eq!(addresses.len(), 1);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].server_name.as_deref(), Some("one.example"));
        assert_eq!(specs[1].server_name.as_deref(), Some("two.example"));
    }

    #[test]
    fn server_spec_projection_tracks_legacy_address_mutation() {
        let old = "192.0.2.53:53".parse().expect("old address");
        let new = "192.0.2.54:53".parse().expect("new address");
        let specs = [parse_server_spec("192.0.2.53#old.example").expect("old spec")];
        let projected = filtered_server_specs(&[new], &specs);
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].address, new);
        assert_eq!(projected[0].server_name, None);
        assert_ne!(projected[0].address, old);
    }

    #[test]
    fn server_spec_assignment_clears_both_views() {
        let mut addresses = vec!["192.0.2.53:53".parse().expect("address")];
        let mut specs = vec![parse_server_spec("192.0.2.53#resolver.example").expect("spec")];
        apply_server_spec_assignment(&mut addresses, &mut specs, "").expect("clear specs");
        assert!(addresses.is_empty());
        assert!(specs.is_empty());
    }

    #[test]
    fn rejects_malformed_metadata() {
        for value in [
            "",
            "1.1.1.1%",
            "1.1.1.1#",
            "1.1.1.1%eth0%eth1",
            "1.1.1.1#resolver.example#other.example",
            "1.1.1.1%eth 0",
            "1.1.1.1#bad..name",
        ] {
            assert!(parse_server_spec(value).is_err(), "{value}");
        }
    }
}
