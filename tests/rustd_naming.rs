// SPDX-License-Identifier: LGPL-2.1-or-later

use std::path::Path;

#[test]
fn native_resolver_targets_use_rustd_names() {
    for target in [
        env!("CARGO_BIN_EXE_rustd-resolved"),
        env!("CARGO_BIN_EXE_rustd-resolvectl"),
    ] {
        let file_name = Path::new(target)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("native resolver target must have a UTF-8 file name");
        assert!(
            file_name.starts_with("rustd-"),
            "unexpected native resolver target name: {file_name}"
        );
    }
}

#[test]
fn install_surface_is_rustd_native_only() {
    let makefile = include_str!("../Makefile");

    for required in [
        "RUSTD_LIBEXECDIR ?= $(PREFIX)/lib/rustd",
        "target/release/rustd-resolved $(DESTDIR)$(RUSTD_LIBEXECDIR)/rustd-resolved",
        "target/release/rustd-resolvectl $(DESTDIR)$(BINDIR)/rustd-resolvectl",
        "$(LIBDIR)/libnss_resolve.so.2",
        "packaging/rustd/rustd-resolved.service",
        "packaging/rustd/rustd-resolved-varlink.socket",
        "packaging/rustd/rustd-resolved-monitor.socket",
        "packaging/sysusers/rustd-resolve.conf",
        "certify: release boot-smoke",
    ] {
        assert!(
            makefile.contains(required),
            "native installation contract is missing {required}"
        );
    }

    let install_recipe = makefile
        .split_once("\ninstall: build nss\n")
        .and_then(|(_, remainder)| remainder.split_once("\nclean:\n"))
        .map(|(recipe, _)| recipe)
        .expect("Makefile must contain a bounded install recipe");

    for forbidden in [
        "$(LIBEXECDIR)/systemd-resolved",
        "$(BINDIR)/resolvectl",
        "$(BINDIR)/systemd-resolve",
        "systemd-resolved.service",
        "/run/systemd/resolve",
    ] {
        assert!(
            !install_recipe.contains(forbidden),
            "legacy compatibility install surface remains: {forbidden}"
        );
    }
}

#[test]
fn installed_certificate_is_rustd_native() {
    let smoke = include_str!("../scripts/boot-smoke.sh");

    for required in [
        "/usr/bin/rustctl",
        "/usr/bin/rustd-resolvectl",
        "/usr/lib/rustd/rustd-resolved",
        "/run/rustd/resolve",
        "io.rustd.Resolve",
        "rustd-resolved.service",
    ] {
        assert!(
            smoke.contains(required),
            "native boot certificate is missing {required}"
        );
    }

    for forbidden in [
        "systemctl",
        "systemd-resolved",
        "/run/systemd/resolve",
        "resolvectl-rs",
    ] {
        assert!(
            !smoke.contains(forbidden),
            "legacy boot-certificate surface remains: {forbidden}"
        );
    }
}

#[test]
fn replacement_and_parity_release_tools_do_not_return() {
    let makefile = include_str!("../Makefile");
    let mdns_workflow = include_str!("../.github/workflows/mdns-live.yml");

    for forbidden in [
        "capture-replacement-state.sh",
        "uninstall-restore.sh",
        "rollback_roundtrip.sh",
        "REPLACEMENT-CERTIFICATION.md",
        "run-upstream-test-75.sh",
        "systemd_service_replace.sh",
    ] {
        assert!(
            !makefile.contains(forbidden),
            "replacement-era release dependency returned: {forbidden}"
        );
    }

    assert!(mdns_workflow.contains("tests/live-avahi-interop.sh"));
    assert!(!mdns_workflow.contains("tests/parity/"));
    assert!(!mdns_workflow.contains("systemctl"));
}
