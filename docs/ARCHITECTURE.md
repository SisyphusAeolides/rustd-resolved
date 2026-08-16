# Architecture

This project is one resolver assembled from five implementation languages.
Language boundaries are narrow, explicit, and versioned through stable files or
the C ABI. A language component is not considered part of runtime policy until
the Rust orchestration layer calls it and a differential test covers the call.

## Rust

Rust owns the daemon lifecycle, DNS wire parser, cache, hosts database, upstream
transports, local stub listeners, generated resolver files, Varlink server, and
command-line programs. The current runtime uses only the standard library.

## C

C owns Linux ABI details that are awkward to express without an external libc
crate: signal installation, systemd notification datagrams, inherited descriptor
metadata, Unix peer credentials, and future netlink and capability operations.
All calls use the stable declarations in `ffi/native.h`; unsafe Rust is confined
to `src/native.rs`.

## Fortran

Fortran provides a deterministic DNS routing-domain scoring function with a C
ABI. It performs case-insensitive suffix matching and stable tie breaking. The
object is built with the default Cargo feature. Full runtime use remains blocked
on the per-link scope model, because selecting a domain without associating it
with a link and server set would not implement split DNS correctly.

## Idris

Idris defines a total resolver-policy model for legal query classes and types,
single-label routing, `.local` routing, and TTL aging witnesses. It is a checked
specification source; generated runtime policy tables are a later parity gate.

## Agda

Agda carries proof-oriented wire invariants. The current module expresses DNS
label-count bounds, decreasing compression-pointer steps, and non-increasing TTL
results. Packet-cursor, cache, routing-maximality, and extraction proofs remain
planned.

## Current runtime flow

1. Parse `resolved.conf` and selected drop-ins.
2. Discover non-stub uplinks from `/etc/resolv.conf` when needed.
3. Load `/etc/hosts` and synthetic local records.
4. Bind full and proxy UDP/TCP stubs.
5. Parse and validate each request before local processing.
6. Answer full-stub synthetic and hosts records.
7. Consult the bounded, TTL-aware global cache.
8. Select a global upstream using failure cooldown and smoothed latency.
9. Forward over UDP and retry over TCP after truncation.
10. Validate response identity and question before returning or caching it.
11. Serve the implemented Varlink methods from a bounded local socket.

## Target runtime flow

Drop-in parity additionally requires live netlink link state, per-link DNS
servers and routing domains, maximal-suffix scope selection, parallel equivalent
scopes, LLMNR and mDNS scopes, DNSSEC validation, DNS-over-TLS transport state,
DNS-SD, D-Bus objects, monitor streams, and upstream-compatible authorization.
Those components must share one transaction graph rather than operate as
independent forwarding paths.
