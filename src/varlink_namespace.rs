// SPDX-License-Identifier: LGPL-2.1-or-later
//! Namespace translation for the RustD resolver Varlink API.
//!
//! The resolver core uses RustD-native interface names canonically. Legacy
//! interface names, when accepted for application interoperability, are
//! translated only at the transport boundary.

use std::borrow::Cow;

pub const NATIVE_ROOT_INTERFACE: &str = "io.rustd";
pub const NATIVE_RESOLVE_INTERFACE: &str = "io.rustd.Resolve";
pub const NATIVE_MONITOR_INTERFACE: &str = "io.rustd.Resolve.Monitor";
pub const NATIVE_SERVICE_INTERFACE: &str = "io.rustd.service";
pub const COMPAT_ROOT_INTERFACE: &str = "io.systemd";
pub const COMPAT_RESOLVE_INTERFACE: &str = "io.systemd.Resolve";
pub const COMPAT_MONITOR_INTERFACE: &str = "io.systemd.Resolve.Monitor";
pub const COMPAT_SERVICE_INTERFACE: &str = "io.systemd.service";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveNamespace {
    Native,
    Compatibility,
    Other,
}

pub fn method_namespace(method: &str) -> ResolveNamespace {
    if has_interface_prefix(method, NATIVE_RESOLVE_INTERFACE) {
        ResolveNamespace::Native
    } else if has_interface_prefix(method, COMPAT_RESOLVE_INTERFACE) {
        ResolveNamespace::Compatibility
    } else {
        ResolveNamespace::Other
    }
}

/// Normalize an interface or method name to the native vocabulary used by the
/// shared resolver core.
pub fn canonical_method(value: &str) -> Cow<'_, str> {
    if value == COMPAT_ROOT_INTERFACE {
        return Cow::Borrowed(NATIVE_ROOT_INTERFACE);
    }
    translate_interface(
        value,
        &[
            (COMPAT_RESOLVE_INTERFACE, NATIVE_RESOLVE_INTERFACE),
            (COMPAT_SERVICE_INTERFACE, NATIVE_SERVICE_INTERFACE),
        ],
    )
}

/// Normalize a value to the native RustD namespace.
pub fn native_method(value: &str) -> Cow<'_, str> {
    canonical_method(value)
}

/// Translate a native interface or method to the legacy interoperability
/// namespace for a caller that explicitly used that namespace.
pub fn compatibility_method(value: &str) -> Cow<'_, str> {
    if value == NATIVE_ROOT_INTERFACE {
        return Cow::Borrowed(COMPAT_ROOT_INTERFACE);
    }
    translate_interface(
        value,
        &[
            (NATIVE_RESOLVE_INTERFACE, COMPAT_RESOLVE_INTERFACE),
            (NATIVE_SERVICE_INTERFACE, COMPAT_SERVICE_INTERFACE),
        ],
    )
}

pub fn error_for_namespace(error: &str, namespace: ResolveNamespace) -> Cow<'_, str> {
    match namespace {
        ResolveNamespace::Native => native_method(error),
        ResolveNamespace::Compatibility => compatibility_method(error),
        ResolveNamespace::Other => Cow::Borrowed(error),
    }
}

pub fn native_description(description: &str) -> Cow<'_, str> {
    if !description.contains(COMPAT_ROOT_INTERFACE) {
        return Cow::Borrowed(description);
    }
    Cow::Owned(
        description
            .replace(COMPAT_RESOLVE_INTERFACE, NATIVE_RESOLVE_INTERFACE)
            .replace(COMPAT_SERVICE_INTERFACE, NATIVE_SERVICE_INTERFACE)
            .replace(COMPAT_ROOT_INTERFACE, NATIVE_ROOT_INTERFACE),
    )
}

pub fn compatibility_description(description: &str) -> Cow<'_, str> {
    if !description.contains(NATIVE_ROOT_INTERFACE) {
        return Cow::Borrowed(description);
    }
    Cow::Owned(
        description
            .replace(NATIVE_RESOLVE_INTERFACE, COMPAT_RESOLVE_INTERFACE)
            .replace(NATIVE_SERVICE_INTERFACE, COMPAT_SERVICE_INTERFACE)
            .replace(NATIVE_ROOT_INTERFACE, COMPAT_ROOT_INTERFACE),
    )
}

fn translate_interface<'a>(value: &'a str, mappings: &[(&str, &str)]) -> Cow<'a, str> {
    for (from, to) in mappings {
        if let Some(suffix) = interface_suffix(value, from) {
            return Cow::Owned(format!("{to}{suffix}"));
        }
    }
    Cow::Borrowed(value)
}

fn has_interface_prefix(value: &str, interface: &str) -> bool {
    interface_suffix(value, interface).is_some()
}

fn interface_suffix<'a>(value: &'a str, interface: &str) -> Option<&'a str> {
    let suffix = value.strip_prefix(interface)?;
    if suffix.is_empty() || suffix.starts_with('.') {
        Some(suffix)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_methods_normalize_to_native_core_names() {
        assert_eq!(
            canonical_method("io.systemd.Resolve.ResolveHostname"),
            "io.rustd.Resolve.ResolveHostname"
        );
        assert_eq!(
            canonical_method("io.systemd.Resolve.Monitor.SubscribeQueryResults"),
            "io.rustd.Resolve.Monitor.SubscribeQueryResults"
        );
        assert_eq!(
            canonical_method("io.systemd.service.Ping"),
            "io.rustd.service.Ping"
        );
        assert_eq!(canonical_method("io.systemd"), "io.rustd");
    }

    #[test]
    fn native_and_unrelated_methods_are_left_unchanged() {
        assert_eq!(
            canonical_method("io.rustd.Resolve.ResolveAddress"),
            "io.rustd.Resolve.ResolveAddress"
        );
        assert_eq!(
            canonical_method("org.varlink.service.GetInfo"),
            "org.varlink.service.GetInfo"
        );
    }

    #[test]
    fn similar_but_different_interface_names_are_not_rewritten() {
        for value in [
            "io.rustd.ResolveExtra.ResolveHostname",
            "io.rustd.serviceExtra.Ping",
            "io.rustd.other.Method",
        ] {
            assert_eq!(canonical_method(value), value);
        }
        assert_eq!(
            method_namespace("io.rustd.ResolveExtra.ResolveHostname"),
            ResolveNamespace::Other
        );
    }

    #[test]
    fn resolver_errors_follow_the_callers_namespace() {
        assert_eq!(
            error_for_namespace("io.rustd.Resolve.DNSError", ResolveNamespace::Native),
            "io.rustd.Resolve.DNSError"
        );
        assert_eq!(
            error_for_namespace("io.rustd.Resolve.DNSError", ResolveNamespace::Compatibility),
            "io.systemd.Resolve.DNSError"
        );
        assert_eq!(
            error_for_namespace(
                "org.varlink.service.InvalidParameter",
                ResolveNamespace::Compatibility
            ),
            "org.varlink.service.InvalidParameter"
        );
    }

    #[test]
    fn native_and_compatibility_names_round_trip() {
        for native in [
            "io.rustd.Resolve.Monitor.SubscribeServerState",
            "io.rustd.Resolve.ResolveHostname",
            "io.rustd.service.Reload",
            "io.rustd",
        ] {
            let compatibility = compatibility_method(native);
            assert_eq!(canonical_method(&compatibility), native);
        }
    }

    #[test]
    fn descriptions_translate_only_protocol_metadata() {
        let compatibility = "interface io.systemd.Resolve\\nerror io.systemd.Resolve.DNSError()\\n";
        assert_eq!(
            native_description(compatibility),
            "interface io.rustd.Resolve\\nerror io.rustd.Resolve.DNSError()\\n"
        );
        let native = "interface io.rustd.Resolve\\nerror io.rustd.Resolve.DNSError()\\n";
        assert_eq!(
            compatibility_description(native),
            "interface io.systemd.Resolve\\nerror io.systemd.Resolve.DNSError()\\n"
        );
    }
}
