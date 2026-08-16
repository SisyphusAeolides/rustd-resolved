# Contributing

Changes should close a specific item in `docs/COMPATIBILITY.md` and include a
reproducible test. Interface compatibility claims require a comparison against
the pinned upstream baseline.

Run before committing:

```sh
make check-native
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features --locked
make check-formal
```

Keep unsafe code isolated at the C ABI boundary. Packet parsing, cache state,
and control authorization changes require adversarial tests.
