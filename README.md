# RustD Resolved (`rustd-resolved`)

`rustd-resolved` is the native network name resolver for RustD. Its authoritative executables are `rustd-resolved` and `rustd-resolvectl`; its authoritative runtime and control-plane identity is RustD.

The resolver is built from Rust, C, Fortran, Idris, and Agda. It owns DNS stub service, upstream transports, cache, split-DNS routing, DNSSEC, DNS-over-TLS, LLMNR, mDNS, DNS-SD, NSS integration, lifecycle handling, and the RustD resolver control plane.

## Native identity

The native resolver contract is:

- daemon: `/usr/lib/rustd/rustd-resolved`;
- CLI: `/usr/bin/rustd-resolvectl`;
- runtime root: `/run/rustd/resolve`;
- configuration: `/etc/rustd/resolved.conf` plus RustD `resolved.conf.d` roots;
- service account: `rustd-resolve`;
- public and canonical Varlink namespace: `io.rustd`, `io.rustd.service`, `io.rustd.Resolve`, and `io.rustd.Resolve.Monitor`;
- native NSS resolver socket: `/run/rustd/resolve/io.rustd.Resolve`;
- RustD-specific NSS controls: `RUSTD_NSS_DNS_*`.

The shared resolver dispatcher now uses `io.rustd.*` canonically. Native requests remain native through the core. Only `io.rustd.*` Varlink identifiers are accepted; no namespace translation is performed.

## Installation surface

The supported installation does not ship `systemd-resolved`, `systemd-resolve`, or `resolvectl` as authoritative executable aliases. RustD packaging lives under `packaging/rustd`, and `/run/systemd/resolve` is not a native runtime root.

Native service/socket definitions include:

- `packaging/rustd/rustd-resolved.service`;
- `packaging/rustd/rustd-resolved-varlink.socket`;
- `packaging/rustd/rustd-resolved-monitor.socket`;
- `packaging/sysusers/rustd-resolve.conf`.

## Resolver foundation

The implementation includes:

- bounded DNS packet, compression-pointer, question, and RR parsing;
- UDP and TCP stub service plus proxy-stub operation;
- `/etc/hosts`, localhost, numeric-address, and local-stub synthesis;
- positive and RFC 2308 negative caching, TTL aging, bounded eviction, stale retention, transaction-ID isolation, and TSIG exclusion;
- UDP upstream queries with response identity validation and TCP retry after truncation;
- per-link state and split-DNS routing;
- DNS-over-TLS and DNSSEC;
- dual-stack LLMNR and mDNS resolver/responder behavior plus DNS-SD;
- glibc NSS integration through `libnss_rustd_dns.so.2`;
- Fortran routing-domain scoring, Idris resolver-policy models, and Agda wire/bound invariants.

These are RustD resolver capabilities, not an upstream parity score.

## Build and verification

Rust 1.74 is the minimum supported Rust version. The normal production matrix also tests current stable Rust.

```sh
make check-native
make check-packaging
make check-nss
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo build --release --locked
python3 tests/live-dns.py \
  target/release/rustd-resolved \
  target/release/rustd-resolvectl
bash tests/dbus-introspection.sh \
  target/release/rustd-resolved \
  target/release/rustd-resolvectl
make check-formal
bash scripts/build-reproducible-release.sh
```

The production CI separately exercises Rust 1.74, current stable, native C/Fortran ABI, packaging, NSS, formatting, production and all-feature Clippy, the full test suite, repeated DNS regression tests, release builds, direct-root privilege drop, live native DNS/Varlink, live D-Bus interoperability, formal verification, restart-soak behavior, fuzz smoke tests, and reproducible release builds.

## Native development run

```sh
cargo run --bin rustd-resolved -- \
  --port 1053 \
  --runtime-directory /tmp/rustd-resolved \
  --varlink /tmp/rustd-resolved/io.rustd.Resolve \
  --no-dbus

cargo run --bin rustd-resolvectl -- \
  --socket /tmp/rustd-resolved/io.rustd.Resolve \
  query example.com
```

## Interoperability rule

Compatibility adapters are allowed only at explicit external boundaries. They must not become the canonical core again. A compatibility surface must be regression-tested and must leave RustD-native package names, executable names, private protocol vocabulary, runtime paths, configuration roots, NSS defaults, service account, and diagnostics authoritative.

This means legacy D-Bus or Varlink application clients can be supported without making another resolver implementation RustD's reference architecture.

## Production-release boundary

A resolver release is not judged by source CI alone. Before labeling a candidate production-ready on a machine's only resolver path, it must also pass installed-system campaigns that exercise sustained query load, upstream and interface changes, DNSSEC/DNS-over-TLS policy, reload/restart/watchdog/shutdown, crash recovery, malformed input, resource pressure, bounded memory, NSS behavior, privilege dropping, RustD-managed boot, and long-running soak/fault tests.

The source/build baseline is intentionally strict so those installed-system campaigns begin from a tree with no known compiler, unit-test, live-protocol, ABI, packaging, NSS, or reproducibility failures.

## Supported platform

Arch Linux and compatible Arch-based distributions are the initial supported release and maintenance targets. The intended RustD stack does not require a host installation of another init system.

## License

GNU Lesser General Public License 2.1 or later.
