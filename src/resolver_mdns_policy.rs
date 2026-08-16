impl Resolver {
    pub fn multicast_dns_mode_for_link(&self, ifindex: Option<i32>) -> SupportMode {
        let global_mode = self.global_multicast_dns_mode();
        let link_mode = ifindex
            .and_then(|ifindex| self.link(ifindex))
            .map_or(SupportMode::Yes, |link| link.multicast_dns);
        match (global_mode, link_mode) {
            (_, SupportMode::No) | (SupportMode::No, _) => SupportMode::No,
            (SupportMode::Resolve, _) | (_, SupportMode::Resolve) => SupportMode::Resolve,
            (SupportMode::Yes, SupportMode::Yes) => SupportMode::Yes,
        }
    }

    pub fn multicast_dns_resolve_enabled(&self, ifindex: Option<i32>) -> bool {
        !matches!(self.multicast_dns_mode_for_link(ifindex), SupportMode::No)
    }

    pub fn multicast_dns_respond_enabled(&self, ifindex: i32) -> bool {
        matches!(
            self.multicast_dns_mode_for_link(Some(ifindex)),
            SupportMode::Yes
        )
    }
}

#[cfg(test)]
mod mdns_policy_tests {
    use super::*;

    #[test]
    fn global_mdns_policy_controls_unknown_links() {
        let mut config = Config::default();
        config.multicast_dns = SupportMode::No;
        let resolver = Resolver::new(config);
        assert!(!resolver.multicast_dns_resolve_enabled(None));
        assert!(!resolver.multicast_dns_respond_enabled(42));
    }

    #[test]
    fn reloaded_global_mode_clamps_per_link_modes() {
        let resolver = Resolver::new(Config::default());
        let mut reloaded = Config::default();
        reloaded.multicast_dns = SupportMode::Resolve;
        reloaded.llmnr = SupportMode::No;
        assert!(resolver.reload_protocol_modes(&reloaded));
        assert_eq!(
            resolver.multicast_dns_mode_for_link(Some(42)),
            SupportMode::Resolve
        );
        assert_eq!(resolver.llmnr_mode_for_link(Some(42)), SupportMode::No);
    }
}
