// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod stub_listener_tests {
    use super::*;

    #[test]
    fn default_stub_listener_matches_upstream() {
        let config = Config::default();
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        assert!(config.dns_stub_listener.udp_enabled());
        assert!(config.dns_stub_listener.tcp_enabled());
        assert_eq!(config.dns_stub_listener.as_str(), "yes");
        assert!(config.dns_stub_listener_extra.is_empty());
    }

    #[test]
    fn modes_preserve_listener_addresses() {
        let mut config = Config::default();
        let listeners = config.listeners.clone();
        let proxy_listeners = config.proxy_listeners.clone();

        config
            .apply_text("[Resolve]\nDNSStubListener=no\n")
            .expect("disabled stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::No);
        assert!(!config.dns_stub_listener.udp_enabled());
        assert!(!config.dns_stub_listener.tcp_enabled());
        assert_eq!(config.listeners, listeners);
        assert_eq!(config.proxy_listeners, proxy_listeners);

        config
            .apply_text("[Resolve]\nDNSStubListener=udp\n")
            .expect("UDP stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Udp);
        assert!(config.dns_stub_listener.udp_enabled());
        assert!(!config.dns_stub_listener.tcp_enabled());

        config
            .apply_text("[Resolve]\nDNSStubListener=tcp\n")
            .expect("TCP stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Tcp);
        assert!(!config.dns_stub_listener.udp_enabled());
        assert!(config.dns_stub_listener.tcp_enabled());

        config
            .apply_text("[Resolve]\nDNSStubListener=yes\n")
            .expect("enabled stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        assert_eq!(config.listeners, listeners);
        assert_eq!(config.proxy_listeners, proxy_listeners);
    }

    #[test]
    fn boolean_spellings_match_upstream_yes_no_aliases() {
        for value in ["yes", "true", "on", "1"] {
            let mut config = Config::default();
            config
                .apply_text(&format!("[Resolve]\nDNSStubListener={value}\n"))
                .expect("enabled alias");
            assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        }
        for value in ["no", "false", "off", "0"] {
            let mut config = Config::default();
            config
                .apply_text(&format!("[Resolve]\nDNSStubListener={value}\n"))
                .expect("disabled alias");
            assert_eq!(config.dns_stub_listener, DnsStubListenerMode::No);
        }
    }

    #[test]
    fn extra_listener_examples_match_upstream_syntax() {
        let cases = [
            ("192.168.10.10", "192.168.10.10:53", DnsStubListenerMode::Yes),
            (
                "2001:db8:0:f102::10",
                "[2001:db8:0:f102::10]:53",
                DnsStubListenerMode::Yes,
            ),
            (
                "192.168.10.11:9953",
                "192.168.10.11:9953",
                DnsStubListenerMode::Yes,
            ),
            (
                "[2001:db8:0:f102::11]:9953",
                "[2001:db8:0:f102::11]:9953",
                DnsStubListenerMode::Yes,
            ),
            (
                "tcp:192.168.10.12",
                "192.168.10.12:53",
                DnsStubListenerMode::Tcp,
            ),
            (
                "udp:2001:db8:0:f102::12",
                "[2001:db8:0:f102::12]:53",
                DnsStubListenerMode::Udp,
            ),
            (
                "tcp:192.168.10.13:9953",
                "192.168.10.13:9953",
                DnsStubListenerMode::Tcp,
            ),
            (
                "udp:[2001:db8:0:f102::13]:9953",
                "[2001:db8:0:f102::13]:9953",
                DnsStubListenerMode::Udp,
            ),
        ];

        for (value, address, mode) in cases {
            let listener = DnsStubListenerExtra::parse(value).expect("extra stub listener");
            assert_eq!(listener.address(), address.parse().expect("socket address"));
            assert_eq!(listener.mode(), mode);
        }
    }

    #[test]
    fn extra_listener_assignments_accumulate_deduplicate_and_clear() {
        let mut config = Config::default();
        config
            .apply_text(
                "[Resolve]\n\
                 DNSStubListenerExtra=tcp:192.0.2.53:9953\n\
                 DNSStubListenerExtra=udp:[2001:db8::53]:9953\n\
                 DNSStubListenerExtra=tcp:192.0.2.53:9953\n",
            )
            .expect("extra stub listeners");
        assert_eq!(config.dns_stub_listener_extra.len(), 2);
        assert_eq!(
            config.dns_stub_listener_extra[0].mode(),
            DnsStubListenerMode::Tcp
        );
        assert_eq!(
            config.dns_stub_listener_extra[1].mode(),
            DnsStubListenerMode::Udp
        );

        config
            .apply_text("[Resolve]\nDNSStubListenerExtra=\n")
            .expect("clear extra stub listeners");
        assert!(config.dns_stub_listener_extra.is_empty());
    }

    #[test]
    fn extra_listener_rejects_invalid_protocol_or_address() {
        for value in ["udp:", "tcp:", "sctp:192.0.2.53", "not-an-address"] {
            assert!(DnsStubListenerExtra::parse(value).is_err(), "{value}");
        }
    }
}
