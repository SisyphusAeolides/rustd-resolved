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
