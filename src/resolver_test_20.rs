// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod test_20_scope_transport_isolation {
    use super::*;

    #[test]
    fn identical_server_addresses_keep_independent_link_state() {
        let resolver = Resolver::new(Config::default());
        let address: SocketAddr = "127.0.0.1:53".parse().expect("server address");
        let link_two = ServerKey::new(ScopeKind::Link(2), address);
        let link_three = ServerKey::new(ScopeKind::Link(3), address);
        assert_ne!(link_two, link_three);
        assert_eq!(link_two.ifindex(), Some(2));
        assert_eq!(link_three.ifindex(), Some(3));

        resolver.record_failure(link_two, Duration::from_millis(25));
        let mut states = resolver.states();
        let first_failures = states
            .get(&link_two)
            .expect("link two state")
            .metric
            .failures;
        let second_failures = states.entry(link_three).or_default().metric.failures;
        assert_eq!(first_failures, 1);
        assert_eq!(second_failures, 0);
    }

    #[test]
    fn identical_server_addresses_keep_independent_udp_pools() {
        let resolver = Resolver::new(Config::default());
        let address: SocketAddr = "127.0.0.1:53".parse().expect("server address");
        let link_two = ServerKey::new(ScopeKind::Link(2), address);
        let link_three = ServerKey::new(ScopeKind::Link(3), address);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("UDP socket");
        resolver.recycle_udp_socket(link_two, socket);

        let pools = resolver
            .udp_sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(pools.get(&link_two).map(Vec::len), Some(1));
        assert!(pools.get(&link_three).is_none());
    }

    #[test]
    fn global_and_fallback_instances_do_not_share_state() {
        let resolver = Resolver::new(Config::default());
        let address: SocketAddr = "192.0.2.53:53".parse().expect("server address");
        let global = ServerKey::new(ScopeKind::Global, address);
        let fallback = ServerKey::new(ScopeKind::Fallback, address);
        assert_ne!(global, fallback);

        resolver.record_transport_failure(global, TransportMode::Udp);
        let mut states = resolver.states();
        let global_failures = states
            .get(&global)
            .expect("global state")
            .transport
            .failures(TransportMode::Udp);
        let fallback_failures = states
            .entry(fallback)
            .or_default()
            .transport
            .failures(TransportMode::Udp);
        assert_eq!(global_failures, 1);
        assert_eq!(fallback_failures, 0);
    }
}
