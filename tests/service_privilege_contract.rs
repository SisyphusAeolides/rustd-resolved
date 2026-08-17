// SPDX-License-Identifier: LGPL-2.1-or-later

#[test]
fn installed_service_uses_daemon_owned_privilege_drop() {
    let unit = include_str!("../packaging/rustd/rustd-resolved.service");
    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("ExecStart=/usr/lib/rustd/rustd-resolved"));
    assert!(
        !unit.lines().any(|line| line.trim_start().starts_with("User=")),
        "the daemon must start privileged enough to bind DNS sockets and execute its audited internal drop path"
    );

    let drop_test = include_str!("direct-root-privilege-drop.sh");
    assert!(drop_test.contains("rustd-resolve"));
    assert!(drop_test.contains("CapEff:"));
    assert!(drop_test.contains("CapBnd:"));
    assert!(drop_test.contains("1 << 10 | 1 << 13"));
}

#[test]
fn service_exposes_only_native_varlink_control() {
    let unit = include_str!("../packaging/rustd/rustd-resolved.service");
    assert!(!unit.contains("--dbus"));
    assert!(!unit.contains("org.freedesktop"));
    assert!(
        include_str!("../packaging/rustd/rustd-resolved-varlink.socket")
            .contains("/run/rustd/resolve/io.rustd.Resolve")
    );
    assert!(
        include_str!("../packaging/rustd/rustd-resolved-monitor.socket")
            .contains("/run/rustd/resolve/io.rustd.Resolve.Monitor")
    );
}
