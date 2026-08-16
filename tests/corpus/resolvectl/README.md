# resolvectl Golden Output Corpus

This directory contains golden output files for `resolvectl` command testing. 

## How to add golden outputs

When adding a new test case, please include:
- The command arguments used
- The expected standard output (`stdout`)
- The expected standard error (`stderr`)
- The expected exit code

These outputs are compared against both the upstream C `resolvectl` and our Rust implementation to ensure drop-in parity.
