#[cfg(test)]
mod test_21_networkd_link_state {
    use super::*;
    use crate::networkd::OperationalState;
    use crate::routing::KernelLinkState;

    fn kernel_link(ifindex: i32) -> KernelLinkState {
        KernelLinkState {
            ifindex,
            ifname: format!("test{ifindex}"),
            flags: 0x0083,
            mtu: 1500,
            operstate: 0,
            has_ipv4_global: true,
            has_ipv4_link_local: false,
            has_ipv6_global: false,
            has_ipv6_link_local: false,
        }
    }

    fn networkd_link(ifindex: i32, operstate: OperationalState) -> NetworkdLinkState {
        let address = "192.0.2.53:53".parse().expect("DNS server");
        NetworkdLinkState {
            ifindex,
            managed: true,
            operstate,
            dns_servers: vec![address],
            dns_server_specs: vec![DnsServerSpec {
                address,
                interface: Some(format!("test{ifindex}")),
                server_name: Some("resolver.example".to_owned()),
            }],
            domains: vec![Domain {
                name: "corp.example".to_owned(),
                route_only: true,
            }],
            default_route: Some(false),
            llmnr: SupportMode::Resolve,
            multicast_dns: SupportMode::No,
            dns_over_tls: Some(TlsMode::Opportunistic),
            dnssec: Some(ValidationMode::No),
            dnssec_negative_trust_anchors: vec!["private.example".to_owned()],
        }
    }

    #[test]
    fn networkd_route_only_link_resolves_without_global_dns_leak() {
        use crate::wire::question_end;
        use std::net::{IpAddr, Ipv4Addr, UdpSocket};
        use std::thread;

        let global = UdpSocket::bind("127.0.0.1:0").expect("bind global DNS server");
        global
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("set global timeout");
        let link = UdpSocket::bind("127.0.0.1:0").expect("bind networkd DNS server");
        link.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set link timeout");
        let link_address = link.local_addr().expect("networkd DNS address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = link.recv_from(&mut buffer).expect("receive link query");
            let query = &buffer[..length];
            let end = question_end(query).expect("question end");
            let mut response = query[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[8..12].fill(0);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&TYPE_A.to_be_bytes());
            response.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[192, 0, 2, 121]);
            link.send_to(&response, peer).expect("send link response");
        });

        let ifindex = 7;
        let resolver = Resolver::new(Config {
            upstreams: vec![global.local_addr().expect("global DNS address")],
            fallback_upstreams: Vec::new(),
            query_timeout: Duration::from_secs(1),
            attempts: 1,
            cache: false,
            cache_from_localhost: true,
            read_etc_hosts: false,
            ..Config::default()
        });
        resolver
            .set_link_dns(ifindex, vec![link_address])
            .expect("create link transport state");
        let mut state = networkd_link(ifindex, OperationalState::Routable);
        state.dns_servers = vec![link_address];
        state.dns_server_specs = vec![DnsServerSpec {
            address: link_address,
            interface: None,
            server_name: None,
        }];
        state.dns_over_tls = Some(TlsMode::No);
        resolver
            .sync_networkd_links(vec![state])
            .expect("networkd link state");

        let lookup = resolver
            .lookup_name("host.corp.example", 2)
            .expect("networkd split DNS lookup");
        worker.join().expect("networkd DNS worker");
        assert_eq!(
            lookup.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 121))]
        );
        assert_eq!(lookup.address_ifindices, vec![Some(ifindex)]);
        let mut leaked = [0; 512];
        assert!(
            global.recv_from(&mut leaked).is_err(),
            "route-only networkd query leaked to the global DNS server"
        );
    }

    #[test]
    fn managed_networkd_state_populates_effective_link_and_blocks_mutation() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("networkd link state");

        let link = resolver.link(7).expect("link state");
        assert_eq!(link.dns_servers.len(), 1);
        assert_eq!(link.domains.len(), 1);
        assert_eq!(link.default_route, Some(false));
        assert_eq!(link.llmnr, SupportMode::Resolve);
        assert_eq!(link.multicast_dns, SupportMode::No);
        assert_eq!(link.dns_over_tls, TlsMode::Opportunistic);
        assert_eq!(link.dnssec, ValidationMode::No);
        assert_eq!(
            link.dnssec_negative_trust_anchors,
            vec!["private.example".to_owned()]
        );
        let specs = resolver.link_dns_specs(7);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].interface.as_deref(), Some("test7"));
        assert_eq!(specs[0].server_name.as_deref(), Some("resolver.example"));
        assert!(resolver.link_is_managed(7));
        assert_eq!(
            resolver.set_link_dns(7, vec!["198.51.100.53:53".parse().expect("DNS server")]),
            Err(LinkError::ManagedLink(7))
        );
    }

    #[test]
    fn late_kernel_link_applies_already_published_networkd_state() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(Vec::new())
            .expect("initial empty kernel state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("early networkd link state");
        assert!(resolver.link(7).is_none());

        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("late kernel link state");

        let link = resolver.link(7).expect("reconciled link state");
        assert_eq!(link.dns_servers, vec!["192.0.2.53:53".parse().unwrap()]);
        assert_eq!(link.domains[0].name, "corp.example");
        assert!(resolver.link_is_managed(7));
    }

    #[test]
    fn networkd_operstate_controls_link_scope_relevance() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Carrier)])
            .expect("carrier state");
        assert!(!resolver.networkd_link_relevant(7));

        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("routable state");
        assert!(resolver.networkd_link_relevant(7));
    }

    #[test]
    fn managed_to_unmanaged_transition_reverts_resolver_state_only() {
        let resolver = Resolver::new(Config {
            dns_over_tls: TlsMode::Yes,
            dnssec: ValidationMode::Yes,
            ..Config::default()
        });
        resolver
            .sync_kernel_links(vec![kernel_link(7)])
            .expect("kernel link state");
        resolver
            .sync_networkd_links(vec![networkd_link(7, OperationalState::Routable)])
            .expect("managed state");

        let mut unmanaged = networkd_link(7, OperationalState::Routable);
        unmanaged.managed = false;
        unmanaged.dns_servers.clear();
        unmanaged.dns_server_specs.clear();
        unmanaged.domains.clear();
        resolver
            .sync_networkd_links(vec![unmanaged])
            .expect("unmanaged state");

        let link = resolver.link(7).expect("kernel link survives");
        assert!(!resolver.link_is_managed(7));
        assert!(link.dns_servers.is_empty());
        assert!(resolver.link_dns_specs(7).is_empty());
        assert!(link.domains.is_empty());
        assert!(link.kernel.is_some());
        assert_eq!(link.dns_over_tls, TlsMode::Yes);
        assert_eq!(link.dnssec, ValidationMode::Yes);
    }

    #[test]
    fn networkd_policy_inherits_manager_defaults_only_when_unset() {
        let resolver = Resolver::new(Config::default());
        resolver
            .sync_kernel_links(vec![kernel_link(7), kernel_link(8)])
            .expect("kernel link state");
        let explicit = networkd_link(7, OperationalState::Routable);
        let mut inherited = networkd_link(8, OperationalState::Routable);
        inherited.dns_over_tls = None;
        inherited.dnssec = None;
        resolver
            .sync_networkd_links(vec![explicit.clone(), inherited.clone()])
            .expect("networkd link state");

        let reloaded = Config {
            dns_over_tls: TlsMode::Yes,
            dnssec: ValidationMode::Yes,
            ..Config::default()
        };
        assert!(resolver.reload_config(reloaded));

        let explicit_link = resolver.link(7).expect("explicit link state");
        assert_eq!(explicit_link.dns_over_tls, TlsMode::Opportunistic);
        assert_eq!(explicit_link.dnssec, ValidationMode::No);
        let inherited_link = resolver.link(8).expect("inherited link state");
        assert_eq!(inherited_link.dns_over_tls, TlsMode::Yes);
        assert_eq!(inherited_link.dnssec, ValidationMode::Yes);
    }
}
