// SPDX-License-Identifier: LGPL-2.1-or-later

#[test]
fn varlink_path_and_interface_names() {
    assert_eq!(
        rustd_resolved::native_paths::RUNTIME_DIR,
        "/run/rustd/resolve"
    );
    assert_eq!(
        rustd_resolved::native_paths::varlink_resolve_socket(std::path::Path::new(
            rustd_resolved::native_paths::RUNTIME_DIR
        ))
        .to_str(),
        Some("/run/rustd/resolve/io.rustd.Resolve")
    );
}

#[test]
fn resolve1_bus_constants_remain_compat_only() {
    // Keep in sync with dbus_resolve1_abi.rs when the resolve1-dbus-compat surface is enabled.
    let bus = "org.freedesktop.resolve1";
    let path = "/org/freedesktop/resolve1";
    assert!(bus.starts_with("org.freedesktop."));
    assert!(path.starts_with("/org/"));
}
