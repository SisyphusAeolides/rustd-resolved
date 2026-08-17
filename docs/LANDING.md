# RustD Resolved release promotion

Use this sequence to validate a candidate from locked source through an installed
RustD-managed system. Release promotion is native RustD work; it does not
replace another resolver in place or depend on a stock resolver baseline.

## Source and release gates

```sh
make release
```

`make release` requires the native C/Fortran checks, Rust formatting/Clippy/test
suite, packaging contract, NSS integration, Idris/Agda formal models, live
DNS/Varlink checks, and reproducible release artifacts.

CI additionally requires the parser fuzz-smoke gate, deterministic restart soak,
live mDNS/Avahi interoperability, D-Bus application bridge, privilege-drop
checks, and the stable/Rust-1.74 build matrix.

## Installed-system certification

Promote the exact release artifact into a snapshot-backed RustD VM or another
target with an independently tested recovery path. Boot the target with RustD
managing `rustd-resolved.service`, then run:

```sh
rustctl status rustd-resolved.service
rustd-resolvectl status
make certify-smoke
make certify
```

`make certify` reruns the release gate and then checks the installed native
service, daemon PID/executable, `io.rustd.Resolve` socket, resolver runtime files,
UDP/TCP stub, native Varlink query, NSS, and localhost. It also runs installed certification in release mode,
which fails if network-emulation gates are still pending. Use
`make certify-smoke` for an installed smoke pass that records those gates as
pending without treating the smoke run as release evidence.

## Performance evidence

Run performance comparisons only from controlled, reproducible environments.
Keep hardware/VM image, kernel, network path, DNS fixtures, warm-up count, and
measured iteration count fixed. Preserve raw results for p50/p95/p99 latency,
throughput, memory, CPU, descriptor counts, and cache state.

```sh
make bench
```

A release must not claim a performance advantage unless the retained benchmark
evidence supports it.

## Promotion boundary

Do not promote a candidate solely because host-side CI is green. The production
boundary also requires repeated target-host boot/reboot/shutdown testing,
network reconfiguration, sustained load, resource exhaustion, malformed-input,
crash/restart, and fault-injection campaigns. Until those campaigns are complete,
keep the target recoverable through VM snapshots or an independent boot/recovery
path.
