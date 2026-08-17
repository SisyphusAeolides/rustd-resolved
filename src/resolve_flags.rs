// SPDX-License-Identifier: LGPL-2.1-or-later
//! Request and result flags for the native RustD resolver protocol.

pub mod flags {
    pub const RUSTD_RESOLVE_DNS: u64 = 1 << 0;
    pub const RUSTD_RESOLVE_LLMNR_IPV4: u64 = 1 << 1;
    pub const RUSTD_RESOLVE_LLMNR_IPV6: u64 = 1 << 2;
    pub const RUSTD_RESOLVE_MDNS_IPV4: u64 = 1 << 3;
    pub const RUSTD_RESOLVE_MDNS_IPV6: u64 = 1 << 4;
    pub const RUSTD_RESOLVE_NO_CNAME: u64 = 1 << 5;
    pub const RUSTD_RESOLVE_NO_TXT: u64 = 1 << 6;
    pub const RUSTD_RESOLVE_NO_ADDRESS: u64 = 1 << 7;
    pub const RUSTD_RESOLVE_NO_SEARCH: u64 = 1 << 8;
    pub const RUSTD_RESOLVE_AUTHENTICATED: u64 = 1 << 9;
    pub const RUSTD_RESOLVE_NO_VALIDATE: u64 = 1 << 10;
    pub const RUSTD_RESOLVE_NO_SYNTHESIZE: u64 = 1 << 11;
    pub const RUSTD_RESOLVE_NO_CACHE: u64 = 1 << 12;
    pub const RUSTD_RESOLVE_NO_ZONE: u64 = 1 << 13;
    pub const RUSTD_RESOLVE_NO_TRUST_ANCHOR: u64 = 1 << 14;
    pub const RUSTD_RESOLVE_NO_NETWORK: u64 = 1 << 15;
    pub const RUSTD_RESOLVE_REQUIRE_PRIMARY: u64 = 1 << 16;
    pub const RUSTD_RESOLVE_CLAMP_TTL: u64 = 1 << 17;
    pub const RUSTD_RESOLVE_CONFIDENTIAL: u64 = 1 << 18;
    pub const RUSTD_RESOLVE_SYNTHETIC: u64 = 1 << 19;
    pub const RUSTD_RESOLVE_FROM_CACHE: u64 = 1 << 20;
    pub const RUSTD_RESOLVE_FROM_ZONE: u64 = 1 << 21;
    pub const RUSTD_RESOLVE_FROM_TRUST_ANCHOR: u64 = 1 << 22;
    pub const RUSTD_RESOLVE_FROM_NETWORK: u64 = 1 << 23;
    pub const RUSTD_RESOLVE_NO_STALE: u64 = 1 << 24;
    pub const RUSTD_RESOLVE_RELAX_SINGLE_LABEL: u64 = 1 << 25;
    pub const RUSTD_RESOLVE_QUERY_CONTINUOUS: u64 = 1 << 26;
    pub const RUSTD_RESOLVE_FROM_HOOK: u64 = 1 << 27;
}
