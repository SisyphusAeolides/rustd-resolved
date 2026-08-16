// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod server_spec_config_tests {
    use super::*;

    #[test]
    fn resolved_conf_retains_interface_and_tls_name() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 DNS=1.1.1.1:853%eth0#one.one.one.one 1.1.1.1:853%eth1#two.example\n\
                 FallbackDNS=[2001:db8::53]:853%7#fallback.example\n",
            )
            .expect("metadata-aware DNS configuration");

        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstream_specs.len(), 2);
        assert_eq!(config.upstream_specs[0].interface.as_deref(), Some("eth0"));
        assert_eq!(
            config.upstream_specs[0].server_name.as_deref(),
            Some("one.one.one.one")
        );
        assert_eq!(config.upstream_specs[1].interface.as_deref(), Some("eth1"));
        assert_eq!(
            config.upstream_specs[1].server_name.as_deref(),
            Some("two.example")
        );
        assert_eq!(config.fallback_upstream_specs.len(), 1);
        assert_eq!(
            config.fallback_upstream_specs[0].server_name.as_deref(),
            Some("fallback.example")
        );

        let effective = config.effective_upstream_specs();
        assert_eq!(effective.len(), 2);
        assert_eq!(effective[0].interface.as_deref(), Some("eth0"));
        assert_eq!(effective[1].interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn dns_credential_retains_tls_identity_metadata() {
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-server-spec-credentials-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(
            directory.join("network.dns"),
            "9.9.9.9:853%vpn0#dns.quad9.net\n",
        )
        .expect("DNS credential");

        let mut config = Config::default();
        config.upstreams.clear();
        assert!(apply_credentials(&mut config, &directory));
        assert_eq!(config.upstream_specs.len(), 1);
        assert_eq!(config.upstream_specs[0].interface.as_deref(), Some("vpn0"));
        assert_eq!(
            config.upstream_specs[0].server_name.as_deref(),
            Some("dns.quad9.net")
        );
        assert_eq!(
            config.upstreams,
            vec!["9.9.9.9:853".parse().expect("credential address")]
        );

        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn legacy_address_replacement_drops_stale_metadata() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nDNS=1.1.1.1#one.one.one.one\n")
            .expect("DNS configuration");
        config.upstreams = vec!["9.9.9.9:53".parse().expect("replacement server")];

        let effective = config.effective_upstream_specs();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].address, config.upstreams[0]);
        assert_eq!(effective[0].interface, None);
        assert_eq!(effective[0].server_name, None);
    }
}
