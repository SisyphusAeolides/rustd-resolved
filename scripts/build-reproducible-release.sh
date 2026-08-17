#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUTPUT="$ROOT/target/reproducible-release"

usage() {
    cat <<'USAGE'
Usage: scripts/build-reproducible-release.sh [--output PATH]

Build the native RustD resolver release twice and require byte-identical
binaries, NSS module, staged installation trees, and deterministic tarballs.
No systemd-resolved/resolvectl compatibility aliases or systemd-owned install
roots are emitted.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            [[ $# -ge 2 ]] || { echo "--output requires a path" >&2; exit 64; }
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

case "$OUTPUT" in
    "$ROOT"/target/*|/tmp/*) ;;
    *)
        echo "output must be beneath $ROOT/target or /tmp" >&2
        exit 64
        ;;
esac
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || {
    echo "refusing to replace existing output: $OUTPUT" >&2
    exit 64
}

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_STRIP=symbols
export LC_ALL=C
export TZ=UTC

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rustd-resolved-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$OUTPUT"

build_nss() {
    local destination="$1"
    make -C "$ROOT/nss" clean >/dev/null
    make -C "$ROOT/nss" all >/dev/null
    install -Dm0755 "$ROOT/nss/libnss_rustd_dns.so.2" "$destination"
}

stage_release() {
    local target_dir="$1"
    local nss_module="$2"
    local stage="$3"

    install -Dm0755 "$target_dir/release/rustd-resolved" \
        "$stage/usr/lib/rustd/rustd-resolved"
    install -Dm0755 "$target_dir/release/rustd-resolvectl" \
        "$stage/usr/bin/rustd-resolvectl"
    install -Dm0755 "$nss_module" \
        "$stage/usr/lib/libnss_rustd_dns.so.2"

    for file in "$ROOT"/packaging/rustd/*; do
        install -Dm0644 "$file" \
            "$stage/usr/lib/rustd/system/$(basename "$file")"
    done
    install -Dm0644 "$ROOT/packaging/tmpfiles/rustd-resolved.conf" \
        "$stage/usr/lib/tmpfiles.d/rustd-resolved.conf"
    install -Dm0644 "$ROOT/packaging/sysusers/rustd-resolve.conf" \
        "$stage/usr/lib/sysusers.d/rustd-resolve.conf"
}

build_once() {
    local label="$1"
    local target_dir="$WORK/target-$label"
    local stage="$WORK/stage-$label"
    local nss_module="$WORK/libnss_rustd_dns-$label.so.2"

    CARGO_TARGET_DIR="$target_dir" cargo build \
        --manifest-path "$ROOT/Cargo.toml" \
        --release --locked \
        --bin rustd-resolved --bin rustd-resolvectl >/dev/null
    build_nss "$nss_module"
    stage_release "$target_dir" "$nss_module" "$stage"

    if grep -R -Il -E '(^|/)(systemd-resolved|resolvectl)([^[:alnum:]_-]|$)|/run/systemd/resolve|/usr/lib/systemd' \
        "$stage/usr/lib/rustd" "$stage/usr/bin" "$stage/usr/lib/tmpfiles.d" "$stage/usr/lib/sysusers.d" \
        >/dev/null 2>&1; then
        echo "native release staging contains a forbidden systemd resolver surface" >&2
        exit 1
    fi

    tar --sort=name \
        --mtime="@$SOURCE_DATE_EPOCH" \
        --owner=0 --group=0 --numeric-owner \
        -C "$stage" -cf "$WORK/rustd-resolved-$label.tar" .
    gzip -n -9 "$WORK/rustd-resolved-$label.tar"
}

build_once a
build_once b

for relative in \
    usr/lib/rustd/rustd-resolved \
    usr/bin/rustd-resolvectl \
    usr/lib/libnss_rustd_dns.so.2; do
    cmp "$WORK/stage-a/$relative" "$WORK/stage-b/$relative"
done

diff -ruN "$WORK/stage-a" "$WORK/stage-b"
cmp "$WORK/rustd-resolved-a.tar.gz" "$WORK/rustd-resolved-b.tar.gz"

install -Dm0644 "$WORK/rustd-resolved-a.tar.gz" \
    "$OUTPUT/rustd-resolved-native.tar.gz"
(
    cd "$OUTPUT"
    sha256sum rustd-resolved-native.tar.gz > SHA256SUMS
)

python3 - "$OUTPUT/manifest.json" <<PY
import json
import pathlib
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "schema": 1,
    "project": "rustd-resolved",
    "release_surface": "native-rustd",
    "source_commit": "$SOURCE_COMMIT",
    "source_tree": "$SOURCE_TREE",
    "source_date_epoch": int("$SOURCE_DATE_EPOCH"),
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
    "artifacts": ["rustd-resolved-native.tar.gz", "SHA256SUMS"],
    "forbidden_aliases": ["systemd-resolved", "systemd-resolve", "resolvectl"],
    "unit_root": "/usr/lib/rustd/system",
    "runtime_root": "/run/rustd/resolve",
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

make -C "$ROOT/nss" clean >/dev/null
printf 'reproducible native RustD resolver release: %s\n' "$OUTPUT"
