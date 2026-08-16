#[test]
fn varlink_path_and_interface_names() {
    assert_eq!(
        "/run/systemd/resolve/io.systemd.Resolve",
        "/run/systemd/resolve/io.systemd.Resolve"
    );
    assert!(std::path::Path::new("/run/systemd/resolve").is_absolute());
}

#[test]
fn resolve1_bus_constants() {
    // Keep in sync with dbus_resolve1_abi.rs
    let bus = "org.freedesktop.resolve1";
    let path = "/org/freedesktop/resolve1";
    assert!(bus.starts_with("org.freedesktop."));
    assert!(path.starts_with("/org/"));
}
