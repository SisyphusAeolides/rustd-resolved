// SPDX-License-Identifier: LGPL-2.1-or-later
impl Resolver {
    fn server_spec_for_key(&self, server: ServerKey) -> DnsServerSpec {
        let specs = self.server_specs_for_scope(server.scope_kind(), &[server.server()]);
        specs
            .into_iter()
            .filter(|spec| spec.address == server.server())
            .nth(server.slot())
            .unwrap_or(DnsServerSpec {
                address: server.server(),
                interface: None,
                server_name: None,
            })
    }

    fn server_transport_ifindex(&self, server: ServerKey) -> Result<Option<i32>, ResolveError> {
        let spec = self.server_spec_for_key(server);
        match spec.interface.as_deref() {
            Some(interface) => Ok(Some(crate::interface::resolve_ifindex(interface)?)),
            None => Ok(server.ifindex()),
        }
    }

    fn server_dns_over_tls_mode(&self, server: ServerKey) -> TlsMode {
        let config = self.config();
        match server.scope_kind() {
            ScopeKind::Link(ifindex) => self
                .link(ifindex)
                .map_or(config.dns_over_tls, |link| link.dns_over_tls),
            ScopeKind::Global | ScopeKind::Delegate(_) | ScopeKind::Fallback => {
                config.dns_over_tls
            }
        }
    }

    fn server_firewall_mark(&self, server: ServerKey) -> u32 {
        let config = self.config();
        server.delegate_index().map_or(0, |index| {
            config
                .dns_delegates
                .get(index)
                .map_or(0, |delegate| delegate.firewall_mark)
        })
    }

    fn server_dnssec_mode(&self, server: ServerKey) -> ValidationMode {
        let config = self.config();
        match server.scope_kind() {
            ScopeKind::Link(ifindex) => self
                .link(ifindex)
                .map_or(config.dnssec, |link| link.dnssec),
            ScopeKind::Global | ScopeKind::Delegate(_) | ScopeKind::Fallback => config.dnssec,
        }
    }

    fn server_tls_endpoint(&self, server: ServerKey) -> (SocketAddr, Option<String>) {
        let spec = self.server_spec_for_key(server);
        let mut endpoint = spec.address;
        if matches!(endpoint.port(), 53 | 853) {
            endpoint.set_port(853);
        }
        (endpoint, spec.server_name)
    }
}

#[cfg(test)]
mod server_identity_tests {
    use super::*;
    use crate::routing::KernelLinkState;

    fn kernel_link(ifindex: i32) -> KernelLinkState {
        KernelLinkState {
            ifindex,
            ifname: format!("test{ifindex}"),
            flags: 0x0001 | 0x0040 | 0x1_0000,
            mtu: 1500,
            operstate: 0,
            has_ipv4_global: true,
            has_ipv4_link_local: false,
            has_ipv6_global: false,
            has_ipv6_link_local: false,
        }
    }

    #[test]
    fn global_numeric_interface_becomes_transport_ifindex() {
        let loopback = crate::interface::resolve_ifindex("lo").expect("loopback ifindex");
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let config = Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: Some(loopback.to_string()),
                server_name: Some("resolver.example".to_owned()),
            }],
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        let key = ServerKey::new(ScopeKind::Global, address);

        assert_eq!(
            resolver.server_transport_ifindex(key).expect("ifindex"),
            Some(loopback)
        );
        assert_eq!(
            resolver.server_spec_for_key(key).server_name.as_deref(),
            Some("resolver.example")
        );
    }

    #[test]
    fn global_named_interface_becomes_transport_ifindex() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let config = Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: Some("lo".to_owned()),
                server_name: None,
            }],
            ..Config::default()
        };
        let resolver = Resolver::new(config);
        let key = ServerKey::new(ScopeKind::Global, address);

        assert!(resolver
            .server_transport_ifindex(key)
            .expect("loopback ifindex")
            .is_some_and(|ifindex| ifindex > 0));
    }

    #[test]
    fn link_scope_remains_default_transport_interface() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let resolver = Resolver::new(Config::default());
        let key = ServerKey::new(ScopeKind::Link(9), address);

        assert_eq!(resolver.server_transport_ifindex(key).expect("ifindex"), Some(9));
    }

    #[test]
    fn default_dns_port_becomes_default_tls_port() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let resolver = Resolver::new(Config {
            upstreams: vec![address],
            upstream_specs: vec![DnsServerSpec {
                address,
                interface: None,
                server_name: Some("resolver.example".to_owned()),
            }],
            ..Config::default()
        });
        let key = ServerKey::new(ScopeKind::Global, address);
        let (endpoint, server_name) = resolver.server_tls_endpoint(key);

        assert_eq!(endpoint.port(), 853);
        assert_eq!(server_name.as_deref(), Some("resolver.example"));
    }

    #[test]
    fn link_dns_over_tls_mode_overrides_global_policy() {
        let resolver = Resolver::new(Config {
            dns_over_tls: TlsMode::No,
            ..Config::default()
        });
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link");
        resolver
            .set_link_dns_over_tls(7, TlsMode::Yes)
            .expect("link TLS mode");
        let key = ServerKey::new(
            ScopeKind::Link(7),
            "192.0.2.53:53".parse().expect("DNS server"),
        );

        assert_eq!(resolver.server_dns_over_tls_mode(key), TlsMode::Yes);
    }

    #[test]
    fn link_dnssec_mode_overrides_global_policy() {
        let resolver = Resolver::new(Config {
            dnssec: ValidationMode::No,
            ..Config::default()
        });
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link");
        resolver
            .set_link_dnssec(7, ValidationMode::Yes)
            .expect("link DNSSEC mode");
        let key = ServerKey::new(
            ScopeKind::Link(7),
            "192.0.2.53:53".parse().expect("DNS server"),
        );

        assert_eq!(resolver.server_dnssec_mode(key), ValidationMode::Yes);
    }

    #[test]
    fn delegate_firewall_mark_is_bound_to_its_transport_scope() {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        let resolver = Resolver::new(Config {
            dns_delegates: vec![crate::dns_delegate::DnsDelegate {
                id: "marked".to_owned(),
                servers: vec![DnsServerSpec {
                    address,
                    interface: None,
                    server_name: None,
                }],
                domains: Vec::new(),
                default_route: None,
                firewall_mark: 42,
            }],
            ..Config::default()
        });
        assert_eq!(
            resolver.server_firewall_mark(ServerKey::new(ScopeKind::Delegate(0), address)),
            42
        );
        assert_eq!(
            resolver.server_firewall_mark(ServerKey::new(ScopeKind::Global, address)),
            0
        );
    }
}
