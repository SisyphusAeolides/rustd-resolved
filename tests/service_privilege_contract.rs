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
fn dbus_activation_and_policy_are_rustd_native() {
    let activation = include_str!("../packaging/dbus/org.freedesktop.resolve1.service");
    assert!(activation.contains("Name=org.freedesktop.resolve1"));
    assert!(activation.contains("Exec=/usr/bin/rustctl start rustd-resolved.service"));
    assert!(activation.contains("User=root"));
    assert!(!activation.contains("SystemdService="));
    assert!(!activation.contains("/bin/false"));

    let policy = include_str!("../packaging/dbus/org.freedesktop.resolve1.conf");
    assert!(policy.contains("<policy user=\"rustd-resolve\">"));
    assert!(!policy.contains("systemd-resolve"));
}
