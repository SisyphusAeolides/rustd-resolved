// SPDX-License-Identifier: LGPL-2.1-or-later

use std::borrow::Cow;

const MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const LINK_PATH: &str = "/org/freedesktop/resolve1/link";
const DNSSD_PATH: &str = "/org/freedesktop/resolve1/dnssd";
const DELEGATE_PATH: &str = "/org/freedesktop/resolve1/dns_delegate";
const LOG_CONTROL_PATH: &str = "/org/freedesktop/LogControl1";

const MANAGER_INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_INTERFACE: &str = "org.freedesktop.resolve1.Link";
const DNSSD_INTERFACE: &str = "org.freedesktop.resolve1.DnssdService";
const DELEGATE_INTERFACE: &str = "org.freedesktop.resolve1.DnsDelegate";
const LOG_CONTROL_INTERFACE: &str = "org.freedesktop.LogControl1";

const IMPLEMENTATIONS: &[(&str, &str, &str)] = &[
    (
        MANAGER_PATH,
        MANAGER_INTERFACE,
        include_str!("../compat/org.freedesktop.resolve1.Manager.xml"),
    ),
    (
        LINK_PATH,
        LINK_INTERFACE,
        include_str!("../compat/org.freedesktop.resolve1.Link.xml"),
    ),
    (
        DNSSD_PATH,
        DNSSD_INTERFACE,
        include_str!("../compat/org.freedesktop.resolve1.DnssdService.xml"),
    ),
    (
        DELEGATE_PATH,
        DELEGATE_INTERFACE,
        include_str!("../compat/org.freedesktop.resolve1.DnsDelegate.xml"),
    ),
    (
        LOG_CONTROL_PATH,
        LOG_CONTROL_INTERFACE,
        include_str!("../compat/org.freedesktop.LogControl1.xml"),
    ),
];

#[derive(Debug, thiserror::Error)]
#[error("{kind} {pattern} not found")]
pub struct IntrospectionError {
    kind: &'static str,
    pattern: String,
}

pub fn render(pattern: &str) -> Result<Cow<'static, str>, IntrospectionError> {
    if pattern == "list" {
        let mut output = String::new();
        for (path, interface, _) in IMPLEMENTATIONS {
            output.push_str(path);
            output.push('\t');
            output.push_str(interface);
            output.push('\n');
        }
        return Ok(Cow::Owned(output));
    }

    IMPLEMENTATIONS
        .iter()
        .find(|(path, interface, _)| pattern == *path || pattern == *interface)
        .map(|(_, _, xml)| Cow::Borrowed(*xml))
        .ok_or_else(|| IntrospectionError {
            kind: if pattern.starts_with('/') {
                "Object path"
            } else {
                "Interface"
            },
            pattern: pattern.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_matches_the_pinned_implementation_tree() {
        assert_eq!(
            render("list").expect("implementation list"),
            concat!(
                "/org/freedesktop/resolve1\torg.freedesktop.resolve1.Manager\n",
                "/org/freedesktop/resolve1/link\torg.freedesktop.resolve1.Link\n",
                "/org/freedesktop/resolve1/dnssd\torg.freedesktop.resolve1.DnssdService\n",
                "/org/freedesktop/resolve1/dns_delegate\t",
                "org.freedesktop.resolve1.DnsDelegate\n",
                "/org/freedesktop/LogControl1\torg.freedesktop.LogControl1\n",
            )
        );
    }

    #[test]
    fn paths_and_interfaces_select_the_same_manifest() {
        for (path, interface, _) in IMPLEMENTATIONS {
            assert_eq!(
                render(path).expect("path manifest"),
                render(interface).expect("interface manifest")
            );
        }
    }

    #[test]
    fn missing_patterns_preserve_upstream_error_context() {
        assert_eq!(
            render("org.example.Missing")
                .expect_err("missing interface")
                .to_string(),
            "Interface org.example.Missing not found"
        );
        assert_eq!(
            render("/org/example/Missing")
                .expect_err("missing path")
                .to_string(),
            "Object path /org/example/Missing not found"
        );
    }
}
