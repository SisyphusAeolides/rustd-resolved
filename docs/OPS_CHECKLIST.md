# RustD Resolved operations checklist

Use this checklist for native RustD deployments. The authoritative service is
`rustd-resolved.service`, controlled by `rustctl`, with runtime state under
`/run/rustd/resolve` and configuration under `/etc/rustd`.

## Identity and privilege boundary

- [x] The packaged service runs as the `rustd-resolve` account after the daemon
  completes its privileged startup work.
- [x] The packaged unit grants only the bounded directory/identity transition
  set plus `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`; the native drop path
  removes the transition capabilities before serving DNS.
- [x] `tests/direct-root-privilege-drop.sh` verifies the direct-root privilege
  transition, runtime-directory ownership, and retained/bounding capabilities.
- [x] The native sysusers definition creates the `rustd-resolve` identity.
- [ ] Revalidate the effective capability set on every target kernel/distro
  combination before promoting a release artifact.

## Runtime and resource bounds

- [x] Resolver runtime state belongs under `/run/rustd/resolve`.
- [x] The packaged service carries `LimitNOFILE=524288`; the runtime contract
  test verifies the packaged limit.
- [x] DNS packet, DNS record, and Varlink request parsers have a CI fuzz-smoke
  gate.
- [x] Production binaries pass a repeated deterministic restart/lifecycle soak
  in CI.
- [ ] Record long-duration memory, descriptor, queue-depth, and CPU bounds under
  sustained cached and uncached load before release promotion.
- [ ] Keep hot-path diagnostics bounded; prefer counters/metrics over verbose
  per-query logging.

## DNSSEC and time

- [x] Packaged units order after `time-sync.target` so DNSSEC validation does not
  begin against an obviously unsynchronized boot clock.
- [ ] Verify the target host reaches a sane clock before treating DNSSEC failures
  as authoritative.
- [ ] Do not place DNSSEC private material or other secrets in optional shared
  caches. Resolver caches must contain only data safe for the configured trust
  boundary.

## Resolver ownership

Exactly one component should own the host resolver path and local stub.

- [ ] Point `/etc/resolv.conf` at `/run/rustd/resolve/stub-resolv.conf` only when
  RustD Resolved owns the host stub.
- [ ] Do not simultaneously configure another resolver manager to rewrite
  `/etc/resolv.conf`.
- [ ] Verify `/run/rustd/resolve/stub-resolv.conf` and
  `/run/rustd/resolve/resolv.conf` are current after network changes.
- [ ] When a network manager supplies per-link DNS data, integrate it through
  the RustD resolver/network control path rather than a competing resolver
  plugin.

## Containers and network namespaces

If a container shares a network namespace where another process already owns
`127.0.0.53:53`, do not start a second full stub on the same address. Configure
an explicit listener/upstream appropriate to that namespace and verify the
result before enabling the service.

Native configuration belongs in:

```text
/etc/rustd/resolved.conf
/etc/rustd/resolved.conf.d/
```

## Installed-system certification

On the installed candidate, with RustD actually managing the service, run:

```sh
rustctl status rustd-resolved.service
rustd-resolvectl status
make certify-smoke
make certify
```

The native boot certificate verifies the live RustD unit, the daemon PID and
executable, the `io.rustd.Resolve` Varlink socket, generated resolver files,
UDP/TCP stub operation, a native Varlink query, NSS resolution, and localhost.
`certify-smoke` records unavailable network-emulation gates as pending.
The release-mode `certify` target fails while any of those gates remain pending,
so a smoke result cannot be promoted as release certification.

## Recovery boundary

RustD Resolved no longer ships host-replacement scripts that capture and restore
another resolver implementation. Until the native resolver has completed the
full target-host fault/boot campaign, perform release promotion in a
snapshot-backed VM or another environment with an independently tested recovery
path. Recovery evidence is separate from the resolver's production artifact and
must not depend on the resolver daemon itself remaining healthy.

## Release evidence

Before calling a build production-ready, retain evidence for:

- `make release` passing from the locked source tree;
- the reproducible-release workflow producing byte-identical native artifacts;
- stable and Rust 1.74 validation;
- formal Idris/Agda verification;
- native DNS/Varlink, D-Bus bridge, NSS, and privilege-drop integration;
- fuzz-smoke and restart-soak gates;
- `make certify` on the installed RustD-managed target;
- sustained load, resource-exhaustion, network-reconfiguration, crash, and
  fault-injection campaigns on the supported deployment image.
