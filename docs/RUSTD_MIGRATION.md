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
6. CI includes native DNS/Varlink/D-Bus integration, parser fuzzing, restart
   soak, and live mDNS/Avahi interoperability.
7. Installed-system certification uses `rustctl`, the RustD service identity,
   RustD runtime paths, and `rustd-resolvectl`.
8. Host-replacement, rollback, pinned-upstream, and parity certification tooling
   are not part of the supported release architecture.

## Remaining internal conversion

The private shared Varlink dispatcher and parts of the CLI implementation still
carry `io.systemd.*` identifiers inherited from the earlier compatibility core.
Those identifiers must move to RustD ownership atomically with their interface
definitions, dispatcher methods, monitor path, NSS client, CLI calls, tests, and
error mapping. The public `io.rustd.*` frontend remains the supported native
surface during that conversion.

The `org.freedesktop.resolve1` D-Bus API is a separate interoperability surface
for Linux applications. Keeping that public freedesktop contract does not make
systemd the resolver architecture or release oracle.

## Production boundary

Migration is complete only when:

- the private dispatcher no longer canonicalizes through `io.systemd.*`;
- no shipped command, service, runtime path, package rule, or operational
  procedure depends on systemd-owned names;
- `rustd-resolvectl` is natively identified throughout its implementation;
- sustained load, resource-exhaustion, network-reconfiguration, fault, and
  target-host RustD boot campaigns are green;
- `make release` and installed `make certify` both pass from the same locked
  source revision and release artifacts.

Until those conditions are met, the repository should describe itself as active
native migration rather than claim final production readiness.
