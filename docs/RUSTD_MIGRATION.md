# RustD Resolved native migration

RustD Resolved is an independent RustD subsystem. The migration target is a
self-contained daemon, CLI, runtime tree, service graph, and private control
protocol owned by RustD rather than a drop-in replacement for another resolver.

## Completed cuts

1. The shipped daemon and CLI are `rustd-resolved` and `rustd-resolvectl`.
2. Installed units live under `/usr/lib/rustd/system` and runtime state under
   `/run/rustd/resolve`.
3. Public native Varlink endpoints use `io.rustd.Resolve` and
   `io.rustd.Resolve.Monitor`.
4. Packaging rejects systemd-owned executable and runtime roots.
5. The release gate includes Rust/native/NSS/formal/live/reproducibility checks.
6. CI includes native DNS/Varlink integration, parser fuzzing, restart
   soak, and live mDNS/Avahi interoperability.
7. Installed-system certification uses `rustctl`, the RustD service identity,
   RustD runtime paths, and `rustd-resolvectl`.
8. Host-replacement, rollback, pinned-upstream, and parity certification tooling
   are not part of the supported release architecture.

## Remaining internal conversion

The native daemon now dispatches `io.rustd.*` directly and installs no D-Bus
activation, policy, or service files. The former D-Bus implementation remains
as unexported source pending a later source-tree deletion; it is not compiled,
started, installed, or part of the supported control protocol.

## Production boundary

Migration is complete only when:

- no shipped command, service, runtime path, package rule, or operational
  procedure depends on systemd-owned names;
- `rustd-resolvectl` is natively identified throughout its implementation;
- sustained load, resource-exhaustion, network-reconfiguration, fault, and
  target-host RustD boot campaigns are green;
- `make release` and installed `make certify` both pass from the same locked
  source revision and release artifacts.

Until those conditions are met, the repository should describe itself as active
native migration rather than claim final production readiness.
