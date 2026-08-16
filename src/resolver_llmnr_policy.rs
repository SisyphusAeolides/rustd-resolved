// SPDX-License-Identifier: LGPL-2.1-or-later
impl Resolver {
    pub fn llmnr_mode_for_link(&self, ifindex: Option<i32>) -> SupportMode {
        let global_mode = self.global_llmnr_mode();
        if matches!(global_mode, SupportMode::No) {
            return SupportMode::No;
        }
        let link_mode = ifindex
            .and_then(|ifindex| self.link(ifindex))
            .map_or(SupportMode::Yes, |link| link.llmnr);
        match (global_mode, link_mode) {
            (_, SupportMode::No) | (SupportMode::No, _) => SupportMode::No,
            (SupportMode::Resolve, _) | (_, SupportMode::Resolve) => SupportMode::Resolve,
            (SupportMode::Yes, SupportMode::Yes) => SupportMode::Yes,
        }
    }

    pub fn llmnr_resolve_enabled(&self, ifindex: Option<i32>) -> bool {
        !matches!(self.llmnr_mode_for_link(ifindex), SupportMode::No)
    }

    pub fn llmnr_respond_enabled(&self, ifindex: i32) -> bool {
        matches!(self.llmnr_mode_for_link(Some(ifindex)), SupportMode::Yes)
    }

    pub fn llmnr_hostname(&self) -> String {
        crate::llmnr::runtime::hostname()
    }

    pub fn install_llmnr_client(&self, client: crate::llmnr::LlmnrClient) {
        *self
            .llmnr_client
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(client);
    }

    fn llmnr_query_raw(
        &self,
        query: &[u8],
        ifindex: Option<i32>,
        bypass_cache: bool,
        network_allowed: bool,
    ) -> io::Result<Option<(Vec<u8>, bool)>> {
        let client = self
            .llmnr_client
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match client {
            Some(client) => client.query_raw(
                query,
                ifindex,
                self.config().query_timeout,
                bypass_cache,
                network_allowed,
            ),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod llmnr_policy_tests {
    use super::*;

    #[test]
    fn global_resolve_mode_prevents_responder_mode() {
        let mut config = Config::default();
        config.llmnr = SupportMode::Resolve;
        let resolver = Resolver::new(config);
        assert!(resolver.llmnr_resolve_enabled(None));
        assert!(!resolver.llmnr_respond_enabled(42));
    }

    #[test]
    fn global_no_mode_disables_link_override() {
        let mut config = Config::default();
        config.llmnr = SupportMode::No;
        let resolver = Resolver::new(config);
        assert!(!resolver.llmnr_resolve_enabled(Some(42)));
        assert!(!resolver.llmnr_respond_enabled(42));
    }
}
