// SPDX-License-Identifier: LGPL-2.1-or-later
impl Resolver {
    fn link_server_specs(&self) -> RwLockReadGuard<'_, HashMap<i32, Vec<DnsServerSpec>>> {
        self.link_server_specs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn link_server_specs_mut(&self) -> RwLockWriteGuard<'_, HashMap<i32, Vec<DnsServerSpec>>> {
        self.link_server_specs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn link_dns_specs(&self, ifindex: i32) -> Vec<DnsServerSpec> {
        let Some(link) = self.link(ifindex) else {
            return Vec::new();
        };
        let stored = self.link_server_specs();
        project_link_specs(&link.dns_servers, stored.get(&ifindex).map(Vec::as_slice))
    }

    pub fn set_link_dns_specs(
        &self,
        ifindex: i32,
        specs: Vec<DnsServerSpec>,
    ) -> Result<(), LinkError> {
        self.ensure_link_writable(ifindex)?;
        let addresses = specs.iter().map(|spec| spec.address).collect::<Vec<_>>();
        let mut routing = self.routing_mut();
        let route_changed = routing.set_dns(ifindex, addresses)?;
        let normalized_addresses = routing
            .link(ifindex)
            .map(|link| link.dns_servers)
            .unwrap_or_default();
        drop(routing);

        let normalized_specs = normalize_link_specs(&normalized_addresses, specs);
        let spec_changed = self.replace_link_server_specs(ifindex, normalized_specs);
        self.finish_routing_change(route_changed || spec_changed);
        Ok(())
    }

    fn replace_link_server_specs(&self, ifindex: i32, specs: Vec<DnsServerSpec>) -> bool {
        let mut stored = self.link_server_specs_mut();
        if specs.is_empty() {
            return stored.remove(&ifindex).is_some();
        }
        if stored.get(&ifindex) == Some(&specs) {
            return false;
        }
        stored.insert(ifindex, specs);
        true
    }

    fn remove_link_server_specs(&self, ifindex: i32) -> bool {
        self.link_server_specs_mut().remove(&ifindex).is_some()
    }
}

fn project_link_specs(
    addresses: &[SocketAddr],
    specs: Option<&[DnsServerSpec]>,
) -> Vec<DnsServerSpec> {
    let mut output = Vec::new();
    for &address in addresses {
        let before = output.len();
        if let Some(specs) = specs {
            for spec in specs
                .iter()
                .filter(|spec| same_dns_endpoint(spec.address, address))
            {
                let mut spec = spec.clone();
                spec.address = address;
                if !output.contains(&spec) {
                    output.push(spec);
                }
            }
        }
        if output.len() == before {
            output.push(DnsServerSpec {
                address,
                interface: None,
                server_name: None,
            });
        }
    }
    output
}

fn normalize_link_specs(addresses: &[SocketAddr], specs: Vec<DnsServerSpec>) -> Vec<DnsServerSpec> {
    let mut output = Vec::new();
    for mut spec in specs {
        if let Some(address) = addresses
            .iter()
            .copied()
            .find(|address| same_dns_endpoint(spec.address, *address))
        {
            spec.address = address;
        }
        if !output.contains(&spec) {
            output.push(spec);
        }
    }
    output
}

fn same_dns_endpoint(left: SocketAddr, right: SocketAddr) -> bool {
    left.ip() == right.ip() && left.port() == right.port()
}

#[cfg(test)]
mod link_server_spec_tests {
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
            has_ipv6_link_local: true,
        }
    }

    #[test]
    fn link_specs_preserve_same_address_tls_names() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link");
        let address = "192.0.2.53:853".parse().expect("DNS server");
        resolver
            .set_link_dns_specs(
                7,
                vec![
                    DnsServerSpec {
                        address,
                        interface: None,
                        server_name: Some("one.example".to_owned()),
                    },
                    DnsServerSpec {
                        address,
                        interface: None,
                        server_name: Some("two.example".to_owned()),
                    },
                ],
            )
            .expect("link DNS specs");

        let specs = resolver.link_dns_specs(7);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].server_name.as_deref(), Some("one.example"));
        assert_eq!(specs[1].server_name.as_deref(), Some("two.example"));
        assert_eq!(resolver.link(7).expect("link").dns_servers, vec![address]);
    }

    #[test]
    fn link_local_scope_projection_retains_server_name() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link");
        let address = "[fe80::53]:853".parse().expect("link-local DNS server");
        resolver
            .set_link_dns_specs(
                7,
                vec![DnsServerSpec {
                    address,
                    interface: None,
                    server_name: Some("resolver.example".to_owned()),
                }],
            )
            .expect("link DNS spec");

        let specs = resolver.link_dns_specs(7);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].server_name.as_deref(), Some("resolver.example"));
        match specs[0].address {
            SocketAddr::V6(address) => assert_eq!(address.scope_id(), 7),
            SocketAddr::V4(_) => panic!("expected IPv6 server"),
        }
    }
}
