// SPDX-License-Identifier: LGPL-2.1-or-later
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

extern crate self as rustd_resolved;

pub mod bounded_executor;
pub mod cache;
pub mod cache_x;
pub mod config;
pub mod daemon;
pub mod dbus;
pub mod dbus_resolve1_abi;
pub mod dns_delegate;
pub mod dnssec;
pub mod dnssec_rfc5011;
pub mod edns;
pub mod hook;
pub mod hosts;
#[cfg(feature = "hyper")]
pub mod hyper_resolver;
pub mod idna_name;
pub mod interface;
pub mod json;
pub mod lifecycle;
pub mod llmnr;
pub mod log_control;
pub mod mdns;
pub mod native;
pub mod native_paths;
pub mod netlink;
pub mod networkd;
pub mod nss_backend;
pub mod policy;
pub(crate) mod query_cancel;
pub mod resolv_conf;
pub mod resolvconf_publish;
pub mod resolve_flags;
pub mod resolvectl_dbus;
pub mod resolver;
pub mod routing;
pub mod server_features;
pub mod service_introspection;
pub mod split_dns;
pub mod static_records;
#[cfg(feature = "supremacy")]
pub mod supremacy;
pub mod synthetic;
pub mod tls;
pub mod transport;
#[cfg_attr(test, allow(unused_imports))]
pub mod varlink;
pub(crate) mod varlink_polkit;
pub mod wire;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
