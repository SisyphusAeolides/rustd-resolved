// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const NATIVE_SOCKET_ARGUMENT: &str = "--socket=/run/rustd/resolve/io.rustd.Resolve";
const NATIVE_SOCKET_DEFAULTED: &str = "RUSTD_RESOLVECTL_NATIVE_SOCKET_DEFAULTED";
const LEGACY_INVOKED_AS: &str = "SYSTEMD_INVOKED_AS";

mod implementation {
    include!("rustd_resolvectl_impl.rs");

    #[cfg(test)]
    #[allow(private_interfaces)]
    pub(super) type TestLookupOptions<'a> = LookupOptions<'a>;

    #[cfg(test)]
    #[allow(private_interfaces)]
    pub(super) type TestRawMode = RawMode;

    pub(super) fn entrypoint() -> std::process::ExitCode {
        main()
    }
}

#[cfg(test)]
use implementation::{TestLookupOptions as LookupOptions, TestRawMode as RawMode};

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let program = arguments
        .first()
        .map_or_else(|| OsStr::new("rustd-resolvectl"), OsString::as_os_str);
    let invoked_as = std::env::var_os(LEGACY_INVOKED_AS);
    let compatibility = is_compatibility_invocation(invoked_as.as_deref());
    let native = is_native_program(program) && !compatibility;
    let socket_defaulted = std::env::var_os(NATIVE_SOCKET_DEFAULTED).is_some();

    if native && requests_version(&arguments[1..]) {
        println!("rustd-resolvectl {}", rustd_resolved::VERSION);
        return ExitCode::SUCCESS;
    }

    if needs_native_socket_reexec(
        native,
        has_explicit_socket(&arguments[1..]),
        socket_defaulted,
    ) {
        let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(program));
        let mut command = Command::new(executable);
        command.arg0(program);
        command.env_remove(LEGACY_INVOKED_AS);
        command.env(NATIVE_SOCKET_DEFAULTED, "1");
        command.arg(NATIVE_SOCKET_ARGUMENT);
        command.args(arguments.iter().skip(1));
        let error = command.exec();
        eprintln!("rustd-resolvectl: failed to apply the native socket default: {error}");
        return ExitCode::FAILURE;
    }

    if native {
        std::env::remove_var(LEGACY_INVOKED_AS);
        std::env::remove_var(NATIVE_SOCKET_DEFAULTED);
    }

    implementation::entrypoint()
}

fn needs_native_socket_reexec(native: bool, explicit_socket: bool, socket_defaulted: bool) -> bool {
    native && !explicit_socket && !socket_defaulted
}

fn has_explicit_socket(arguments: &[OsString]) -> bool {
    arguments.iter().any(|argument| {
        argument == OsStr::new("--socket")
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with("--socket="))
    })
}

fn requests_version(arguments: &[OsString]) -> bool {
    arguments
        .iter()
        .any(|argument| argument == OsStr::new("--version"))
}

fn is_native_program(program: &OsStr) -> bool {
    Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name == "rustd-resolvectl")
}

fn is_compatibility_invocation(invoked_as: Option<&OsStr>) -> bool {
    let Some(invoked_as) = invoked_as.filter(|name| !name.is_empty()) else {
        return false;
    };
    let name = Path::new(invoked_as)
        .file_name()
        .unwrap_or(invoked_as)
        .to_string_lossy();
    name.contains("resolvconf") || name.contains("systemd-resolve")
}

#[cfg(test)]
mod entrypoint_tests {
    use super::*;

    #[test]
    fn native_invocation_receives_the_rustd_socket_default_once() {
        assert!(is_native_program(OsStr::new("/usr/bin/rustd-resolvectl")));
        assert_eq!(
            NATIVE_SOCKET_ARGUMENT,
            "--socket=/run/rustd/resolve/io.rustd.Resolve"
        );
        assert!(needs_native_socket_reexec(true, false, false));
        assert!(!needs_native_socket_reexec(true, false, true));
    }

    #[test]
    fn native_version_is_detected_before_compatibility_code() {
        assert!(requests_version(&[OsString::from("--version")]));
        assert!(!requests_version(&[OsString::from("status")]));
    }

    #[test]
    fn explicit_socket_is_preserved() {
        assert!(has_explicit_socket(&[
            OsString::from("--socket"),
            OsString::from("/tmp/resolve.sock")
        ]));
        assert!(has_explicit_socket(&[OsString::from(
            "--socket=/tmp/resolve.sock"
        )]));
        assert!(!needs_native_socket_reexec(true, true, false));
    }

    #[test]
    fn compatibility_override_takes_precedence_over_native_program_name() {
        assert!(is_compatibility_invocation(Some(OsStr::new("resolvconf"))));
        assert!(is_compatibility_invocation(Some(OsStr::new(
            "/usr/bin/systemd-resolve"
        ))));
        assert!(!is_compatibility_invocation(None));
        assert!(!is_compatibility_invocation(Some(OsStr::new(
            "rustd-resolvectl"
        ))));
        assert!(!needs_native_socket_reexec(false, false, false));
    }

    #[test]
    fn legacy_alias_name_is_not_the_native_program() {
        assert!(!is_native_program(OsStr::new("/usr/bin/systemd-resolve")));
        assert!(!is_native_program(OsStr::new("/usr/bin/resolvconf")));
        assert!(!needs_native_socket_reexec(false, false, false));
    }
}
