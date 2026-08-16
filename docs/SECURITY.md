# Security model

The resolver processes attacker-controlled datagrams while holding permission
to bind privileged ports. The current implementation follows these rules:

- packet cursors and section lengths are bounds checked;
- DNS labels are limited to 63 octets and expanded names to 255 wire octets;
- compression pointers must move backward and pointer traversal is bounded;
- upstream replies must match the transaction identifier and complete question;
- TCP frames are bounded by the DNS two-byte length field;
- cached packets are transaction-ID neutral and receive the client ID only on lookup;
- cached TTLs can only decrease, and stale answers carry zero TTLs;
- TSIG-bearing and truncated responses are not cached;
- local stub addresses are excluded from discovered upstream servers;
- Varlink messages have a one-megabyte limit;
- Varlink peer identity comes from kernel `SO_PEERCRED` credentials;
- non-root Varlink control calls use action-specific PolicyKit checks with pidfd and UID subjects;
- mutating D-Bus calls use the pinned PolicyKit actions and fail closed;
- mDNS and LLMNR datagrams are interface scoped and require hop limit 255;
- an existing non-socket path is never replaced when creating the Varlink endpoint.

The Rust parser remains the authoritative packet validator in this milestone.
C is restricted to narrow Linux ABI operations, and unsafe Rust is isolated in
that boundary module.

The production resolver performs DNSSEC trust-chain validation, including
DNSKEY/DS delegation, NSEC/NSEC3 denial, wildcard proofs, trust-anchor
precedence, authenticated-data marking, and strict/allow-downgrade policy. It
also drops privileges when launched directly as root, and the packaged service
runs as `systemd-resolve` with a bounded capability set.

Independent DNSSEC edge-case coverage, the full pinned upstream differential
corpus, and the remaining protocol, lifecycle, installation, and security
release gates are still open in `docs/COMPATIBILITY.md`. Until every required
gate closes against one immutable commit, run it only on a recoverable test
system and do not rely on it as a security boundary.
