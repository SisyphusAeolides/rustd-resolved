#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Keep research-only Cargo features out of replacement certification.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d -t rustd-feature-boundary-XXXXXX)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

cargo metadata \
    --manifest-path "$ROOT/Cargo.toml" \
    --no-deps \
    --locked \
    --format-version 1 >"$WORK/metadata.json"

python3 - "$WORK/metadata.json" <<'PY'
import json
import sys

metadata = json.load(open(sys.argv[1], encoding="utf-8"))
package = next(
    package for package in metadata["packages"] if package["name"] == "rustd-resolved"
)
default = set(package["features"]["default"])
expected = {"fortran-routing", "idna-name"}
if default != expected:
    raise SystemExit(f"unexpected production feature set: {sorted(default)}")
if "supremacy" in default or "hyper" in default:
    raise SystemExit("research feature leaked into the production default")
PY

for script in "$ROOT/scripts/certify-replacement.sh" \
    "$ROOT/scripts/certify-replacement-v2.sh"; do
    if grep -Eq -- '--all-features' "$script"; then
        printf 'research feature flag appears in replacement certification: %s\n' "$script" >&2
        exit 1
    fi
done

if grep -Eq -- '-march=native|-mcpu=native|target-cpu[=[:space:]]+native' \
    "$ROOT/build.rs"; then
    printf '%s\n' 'host-native compiler tuning appears in the release build' >&2
    exit 1
fi

grep -Fq 'replacement-certification artifacts' "$ROOT/README.md"
printf '%s\n' 'PASS release_feature_boundary: certification uses only production features'
