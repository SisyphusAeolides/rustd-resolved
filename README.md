# RustD Resolved (`rustd-resolved`)

`rustd-resolved` is the native network name resolver for RustD. Its authoritative executables are `rustd-resolved` and `rustd-resolvectl`; its authoritative runtime and control-plane identity is RustD.

The resolver is built from Rust, C, Fortran, Idris, and Agda. It owns DNS stub service, upstream transports, cache, split-DNS routing, DNSSEC, DNS-over-TLS, LLMNR, mDNS, DNS-SD, NSS integration, lifecycle handling, and the RustD resolver control plane.

In ArachOS, RustD-resolved is the native resolver managed by RustD on Arach
Kernel. ArachOS owns the release, pacman repository, and ArchISO/Calamares
installer composition. The integration is complete only after the native daemon, NSS
module, Varlink, D-Bus, NetworkManager, DNSSEC, and DNS-over-TLS paths pass on
the installed Arach-Kernel system; source tests alone do not certify that
runtime.

Upstream selection includes a deterministic bounded controller composed from
Lorenz, Mandelbrot, Rössler, logistic-map, Lyapunov, and Duffing dynamics. It
can adjust server tie-breaking by no more than 12 ms and keeps failure
cooldowns between 100 ms and 60 seconds. DNS correctness, validation, routing,
and configured policy remain authoritative.

> **Current status (2026-08-31):** the native resolver, packaging, NSS, and
> compatibility-boundary gates are passing. The pinned pacman package build
> completed its test suite, and the resulting package passed ArachOS
> candidate-repository validation. The bounded nonlinear server policy also
> passes its determinism, limits, and policy-ordering tests. Final runtime
> certification on Arach Kernel remains an open gate.
>
> **Production boundary:** this is not a claim that `rustd-resolved` is a 100%
> certified, drop-in replacement for `systemd-resolved`. The paired ArachOS
> installation still requires repeated installed-system VM validation
> covering boot under RustD PID 1, resolver startup/restart, NSS and pacman name
> resolution, NetworkManager changes, DNSSEC/DNS-over-TLS policy, crash/fault
> recovery, privilege boundaries, and long-running soak tests after the
> `systemd*` package stack is removed. Keep a recovery path until that exact
> release image passes.

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

The shared resolver dispatcher uses `io.rustd.*` canonically. Native requests remain native through the core. Only `io.rustd.*` Varlink identifiers are accepted; no namespace translation is performed.

## Installation surface

The supported installation does not ship `systemd-resolved`, `systemd-resolve`, or `resolvectl` as authoritative executable aliases. RustD packaging lives under `packaging/rustd`, and `/run/systemd/resolve` is not a native runtime root.

Native service/socket definitions include:

- `packaging/rustd/rustd-resolved.service`;
- `packaging/rustd/rustd-resolved-varlink.socket`;
- `packaging/rustd/rustd-resolved-monitor.socket`;
- `packaging/sysusers/rustd-resolve.conf`.

For application interoperability, the production service starts the resolver with `--dbus` and owns the bounded `org.freedesktop.resolve1` D-Bus compatibility ABI. Activation is routed through `/usr/bin/rustctl`, bus ownership is assigned to `rustd-resolve`, and no `SystemdService=` activation or `/run/systemd/resolve` runtime ownership is used. Direct development/test runs can disable this compatibility endpoint with `--no-dbus`.

`rustd-resolvectl` keeps native Varlink as its normal query/control transport while exposing the tested link-management compatibility verbs (`dns`, `domain`, `default-route`, `llmnr`, `mdns`, `dnsovertls`, `dnssec`, `nta`, and `revert`) through the bounded D-Bus adapter when arguments request a link mutation. The resolvconf invocation mode is similarly isolated at the CLI boundary.

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

## Production feature boundary

The production Cargo feature set is deliberately smaller than the research
surface. `tests/release_feature_boundary.sh` requires the default feature set to
be exactly `fortran-routing` plus `idna-name` and rejects `supremacy` or `hyper`
from replacement-certification artifacts.

Experimental features must still compile cleanly in the all-features CI matrix,
but incomplete research-only transports are not silently promoted into the
ArachOS production resolver. Moving an experimental feature into the default set
requires its own runtime and failure-mode certification first.

## Build and verification

Rust 1.74 is the minimum supported Rust version. The normal production matrix also tests current stable Rust.

```sh
make check-native
make check-packaging
make check-nss
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
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

The formal Idris2 compiler is built from the pinned upstream Idris2 checkout;
no distro or AUR Idris2 package is part of this project. Install Chez Scheme,
Agda, and the normal build tools from the host distribution, then bootstrap
the compiler from the official source before running the formal gate:

```sh
sudo pacman -S chez-scheme agda git base-devel
git clone --branch v0.8.0 https://github.com/idris-lang/Idris2.git "$HOME/src/Idris2"
make -C "$HOME/src/Idris2" bootstrap SCHEME=chez PREFIX="$HOME/.local"
make -C "$HOME/src/Idris2" install PREFIX="$HOME/.local"
PATH="$HOME/.local/bin:$PATH" make check-formal
```

Set `IDRIS2` or `AGDA` when a tool is installed outside `PATH`.

The production CI separately exercises Rust 1.74, current stable, native C/Fortran ABI, packaging, NSS, formatting, production and all-feature Clippy, the full test suite, repeated DNS regression tests, release builds, direct-root privilege drop, live native DNS/Varlink, live D-Bus interoperability, formal verification, restart-soak behavior, fuzz smoke tests, reproducible release builds, and native plus AArch64 release compilation with TLS, io_uring, and Fortran enabled.

Reload coverage is part of the live contract. A SIGHUP re-reads configuration files while preserving launch-time environment and CLI overrides for listeners, proxy listeners, upstreams, runtime/Varlink paths, workers, ports, and stub-disable mode. The live D-Bus regression suite re-queries the deterministic upstream after HUP and rejects listener-rebind or configuration-publication permission failures after the daemon has dropped privileges.

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

The `org.freedesktop.resolve1` endpoint is such a boundary: it exists for third-party clients that speak the established D-Bus ABI, while resolver execution, RustD Varlink, NSS, configuration, packaging, service ownership, and runtime state remain native RustD interfaces.

## ArachOS zero-systemd integration

The ArachOS release is a zero-systemd compatibility campaign together with the
`rustd` repository. RustD pins an exact RustD-Resolved commit in
`scripts/rustd-resolved-revision.txt`, and ArachOS packages are built from that
immutable source pair before disposable-VM installation.

The resolver side of a successful ArachOS certificate requires:

- the `rustd-resolved` package to conflict with and replace the bootstrap resolver
  package rather than coexisting as an untested second resolver;
- `libnss_rustd_dns.so.2` to service the active authselect-generated hosts NSS
  path after removed NSS backends are deleted;
- `/etc/resolv.conf` and the stub resolver runtime to resolve under
  `/run/rustd/resolve`;
- `rustd-resolved.service` to start under RustD PID 1 and remain active after
  repeated cold boots;
- `getent` name resolution, `rustd-resolvectl status`, NetworkManager, and pacman
  metadata refresh to continue working after every conflicting package has been
  removed;
- no old resolver executable or runtime tree to survive in the certified
  filesystem or rebuilt initramfs.

A resolver source-tree pass is necessary but not sufficient for that claim. The
paired ArachOS full-VM certificate is the installed-system authority.

## Production-release boundary

A resolver release is not judged by source CI alone. Before labeling a candidate production-ready on a machine's only resolver path, it must also pass installed-system campaigns that exercise sustained query load, upstream and interface changes, DNSSEC/DNS-over-TLS policy, reload/restart/watchdog/shutdown, crash recovery, malformed input, resource pressure, bounded memory, NSS behavior, privilege dropping, RustD-managed boot, and long-running soak/fault tests.

The source/build baseline is intentionally strict so those installed-system campaigns begin from a tree with no known compiler, unit-test, live-protocol, ABI, packaging, NSS, or reproducibility failures.

## Supported platform

ArachOS is the current installed-system certification target. Arch Linux plus
compatible Arch-based distributions remain supported build and native-install
targets. No platform is considered production-certified merely because the
source compiles; its installed-system gates must pass for the exact release
candidate.

## License

GNU Lesser General Public License 2.1 or later.
