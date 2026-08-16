// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fallback_dns_is_empty() {
        let config = Config::default();
        assert!(config.fallback_upstreams.is_empty());
        assert!(config.configured_fallback_upstreams().is_empty());
    }

    #[test]
    fn default_cache_matches_upstream_policy() {
        let config = Config::default();
        assert!(config.cache);
        assert!(config.cache_negative);
        assert!(!config.cache_from_localhost);
        assert_eq!(config.cache_size, 4096);
        assert_eq!(config.llmnr_cache_size, 4096);
        assert_eq!(config.multicast_dns_cache_size, 4096);
        assert_eq!(config.cache_max_ttl, Duration::from_secs(2 * 60 * 60));
    }

    #[test]
    fn parses_core_resolved_settings() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 DNS=192.0.2.53 2001:db8::53\n\
                 Domains=example.test ~corp.test\n\
                 Cache=no\n\
                 DNSCacheSize=128\n\
                 LLMNRCacheSize=64\n\
                 MulticastDNSCacheSize=256\n\
                 ReadEtcHosts=no\n\
                 ReadStaticRecords=no\n",
            )
            .expect("configuration");
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.domains.len(), 2);
        assert!(!config.cache);
        assert!(!config.cache_negative);
        assert_eq!(config.cache_size, 128);
        assert_eq!(config.llmnr_cache_size, 64);
        assert_eq!(config.multicast_dns_cache_size, 256);
        assert!(!config.read_etc_hosts);
        assert!(!config.read_static_records);
    }

    #[test]
    fn parses_no_negative_cache_mode() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nCache=no-negative\n")
            .expect("configuration");
        assert!(config.cache);
        assert!(!config.cache_negative);
    }

    #[test]
    fn parses_cache_from_localhost() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nCacheFromLocalhost=yes\n")
            .expect("configuration");
        assert!(config.cache_from_localhost);
    }

    #[test]
    fn rejects_oversized_dns_cache() {
        for key in ["DNSCacheSize", "LLMNRCacheSize", "MulticastDNSCacheSize"] {
            let mut config = Config::default();
            assert!(config
                .apply_text(&format!("[Resolve]\n{key}=16777217\n"))
                .is_err());
        }
    }

    #[test]
    fn empty_assignment_resets_a_list() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nDNS=192.0.2.53\nDNS=\n")
            .expect("configuration");
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn local_stub_is_not_an_upstream() {
        let config = Config {
            upstreams: vec![
                "127.0.0.53:53".parse().expect("stub"),
                "192.0.2.53:53".parse().expect("uplink"),
            ],
            ..Config::default()
        };
        assert_eq!(config.effective_upstreams().len(), 1);
    }

    #[test]
    fn tracks_explicit_dns_and_domain_assignments() {
        let mut config = Config::default();
        let assignments = config
            .apply_text_tracking("[Resolve]\nDNS=\nDomains=example.test\n")
            .expect("tracked configuration");
        assert_eq!(
            assignments,
            ConfigAssignments {
                dns: true,
                fallback_dns: false,
                domains: true,
            }
        );
    }

    #[test]
    fn reads_dns_and_search_domain_credentials() {
        let directory = temporary_credential_directory("reads");
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(directory.join("network.dns"), "192.0.2.53 2001:db8::53\n")
            .expect("DNS credential");
        fs::write(
            directory.join("network.search_domains"),
            "example.test ~corp.test\n",
        )
        .expect("domain credential");

        let mut config = Config::default();
        config.upstreams.clear();
        assert!(apply_credentials(&mut config, &directory));
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(
            config.domains,
            vec![
                Domain {
                    name: "example.test".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "corp.test".to_owned(),
                    route_only: true,
                },
            ]
        );
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn one_credential_is_enough_to_close_the_external_config_gate() {
        let directory = temporary_credential_directory("one-present");
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(directory.join("network.dns"), "192.0.2.53\n").expect("DNS credential");

        let mut config = Config::default();
        config.upstreams.clear();
        assert!(apply_credentials(&mut config, &directory));
        assert_eq!(
            config.upstreams,
            vec!["192.0.2.53:53".parse().expect("credential DNS")]
        );
        assert!(config.domains.is_empty());
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn empty_credentials_are_present_and_reset_lists() {
        let directory = temporary_credential_directory("empty");
        fs::create_dir_all(&directory).expect("credential directory");
        fs::write(directory.join("network.dns"), "").expect("empty DNS credential");
        fs::write(directory.join("network.search_domains"), "")
            .expect("empty domain credential");

        let mut config = Config::default();
        config.upstreams.push("192.0.2.53:53".parse().expect("server"));
        config.domains.push(Domain {
            name: "example.test".to_owned(),
            route_only: false,
        });
        assert!(apply_credentials(&mut config, &directory));
        assert!(config.upstreams.is_empty());
        assert!(config.domains.is_empty());
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn missing_credentials_do_not_suppress_resolv_conf_discovery() {
        let directory = temporary_credential_directory("missing");
        fs::create_dir_all(&directory).expect("credential directory");
        let mut config = Config::default();
        assert!(!apply_credentials(&mut config, &directory));
        fs::remove_dir_all(directory).expect("remove credential directory");
    }

    #[test]
    fn resolv_conf_discovers_dns_search_and_domain_lines() {
        let directory = temporary_credential_directory("resolv-conf");
        fs::create_dir_all(&directory).expect("resolv.conf directory");
        let path = directory.join("resolv.conf");
        fs::write(
            &path,
            "nameserver 192.0.2.53\n\
             search search.example corp.example\n\
             domain legacy.example\n",
        )
        .expect("resolv.conf");

        let discovered = discover_resolv_conf_state(&path).expect("resolv.conf discovery");
        assert_eq!(
            discovered.servers,
            vec!["192.0.2.53:53".parse().expect("DNS server")]
        );
        assert_eq!(
            discovered.domains,
            vec![
                Domain {
                    name: "search.example".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "corp.example".to_owned(),
                    route_only: false,
                },
                Domain {
                    name: "legacy.example".to_owned(),
                    route_only: false,
                },
            ]
        );
        fs::remove_dir_all(directory).expect("remove resolv.conf directory");
    }

    #[test]
    fn invalid_resolv_conf_nameserver_does_not_hide_valid_entries() {
        let directory = temporary_credential_directory("invalid-resolv-conf");
        fs::create_dir_all(&directory).expect("resolv.conf directory");
        let path = directory.join("resolv.conf");
        fs::write(
            &path,
            "nameserver invalid\n\
             nameserver 192.0.2.54\n",
        )
        .expect("resolv.conf");

        let discovered = discover_resolv_conf_state(&path).expect("resolv.conf discovery");
        assert_eq!(
            discovered.servers,
            vec!["192.0.2.54:53".parse().expect("DNS server")]
        );
        fs::remove_dir_all(directory).expect("remove resolv.conf directory");
    }

    #[test]
    fn file_loading_ignores_bad_assignments_and_keeps_later_valid_settings() {
        let directory = temporary_credential_directory("lenient-file");
        fs::create_dir_all(&directory).expect("configuration directory");
        let path = directory.join("resolved.conf");
        fs::write(
            &path,
            "[Resolve]\n\
             DNS=192.0.2.53 invalid 192.0.2.54\n\
             FallbackDNS=198.51.100.53 invalid 198.51.100.54\n\
             DNSSEC=invalid\n\
             DNSCacheSize=16777217\n\
             MissingEquals\n\
             DNSOverTLS=yes\n\
             LLMNR=no\n",
        )
        .expect("configuration file");

        let config = Config::load(&path).expect("lenient configuration load");

        assert_eq!(
            config.upstreams,
            vec![
                "192.0.2.53:53".parse().expect("first DNS server"),
                "192.0.2.54:53".parse().expect("second DNS server"),
            ]
        );
        assert_eq!(
            config.fallback_upstreams,
            vec![
                "198.51.100.53:53".parse().expect("first fallback server"),
                "198.51.100.54:53".parse().expect("second fallback server"),
            ]
        );
        assert_eq!(config.dnssec, ValidationMode::AllowDowngrade);
        assert_eq!(config.dns_over_tls, TlsMode::Yes);
        assert_eq!(config.cache_size, 4096);
        assert_eq!(config.llmnr, SupportMode::No);
        fs::remove_dir_all(directory).expect("remove configuration directory");
    }

    #[test]
    fn explicit_fallback_dns_replaces_builtins_and_accumulates() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 FallbackDNS=192.0.2.53\n\
                 FallbackDNS=192.0.2.54\n",
            )
            .expect("fallback configuration");

        assert_eq!(
            config.fallback_upstreams,
            vec![
                "192.0.2.53:53".parse().expect("first fallback server"),
                "192.0.2.54:53".parse().expect("second fallback server"),
            ]
        );
    }

    #[test]
    fn wildcard_domain_is_the_root_route_domain() {
        let mut config = Config::default();
        config
            .apply_text("[Resolve]\nDomains=*\n")
            .expect("wildcard domain");

        assert_eq!(
            config.domains,
            vec![Domain {
                name: ".".to_owned(),
                route_only: true,
            }]
        );
    }

    fn temporary_credential_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "rustd-resolved-credentials-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        directory
    }
}
