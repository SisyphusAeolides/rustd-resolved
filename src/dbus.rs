// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(
    clippy::if_not_else,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::unused_self,
    clippy::used_underscore_binding
)]
include!("dbus_core.rs");
include!("dbus_polkit.rs");
include!("dbus_manager.rs");
include!("dbus_link.rs");
include!("dbus_dnssd.rs");
include!("dbus_delegate.rs");
include!("dbus_helpers.rs");
include!("dbus_tests.rs");
