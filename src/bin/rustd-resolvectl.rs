// SPDX-License-Identifier: LGPL-2.1-or-later

use std::process::ExitCode;

mod implementation {
    #[cfg(test)]
    #[allow(private_interfaces)]
    pub(super) type TestLookupOptions<'a> = LookupOptions<'a>;

    #[cfg(test)]
    #[allow(private_interfaces)]
    pub(super) type TestRawMode = RawMode;

    pub(super) fn entrypoint() -> std::process::ExitCode {
        main()
    }

    include!("rustd_resolvectl_impl.rs");
}

#[cfg(test)]
use implementation::{TestLookupOptions as LookupOptions, TestRawMode as RawMode};

fn main() -> ExitCode {
    implementation::entrypoint()
}
