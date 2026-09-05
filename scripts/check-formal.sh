#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IDRIS2_CMD=${IDRIS2:-idris2}
AGDA_CMD=${AGDA:-agda}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rustd-resolved-formal.XXXXXXXX")

cleanup() {
    local status=$?
    find "$WORK" -depth -delete 2>/dev/null || true
    trap - EXIT HUP INT TERM
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

command -v "$IDRIS2_CMD" >/dev/null 2>&1 || {
    printf 'formal check: missing Idris2 compiler: %s\n' "$IDRIS2_CMD" >&2
    exit 1
}
command -v "$AGDA_CMD" >/dev/null 2>&1 || {
    printf 'formal check: missing Agda compiler: %s\n' "$AGDA_CMD" >&2
    exit 1
}

# Keep Idris build output beside the disposable copy of the package.  This
# prevents a failed check from leaving stale interfaces in the source tree.
mkdir -p "$WORK/idris" "$WORK/agda" "$WORK/agda-data" "$WORK/agda-config"
cp -a "$ROOT/formal/idris/." "$WORK/idris/"
(
    cd "$WORK/idris"
    "$IDRIS2_CMD" --build resolved-policy.ipkg
)

cp -a "$ROOT/formal/agda/." "$WORK/agda/"
Agda_datadir="$WORK/agda-data" "$AGDA_CMD" --setup >/dev/null 2>&1
run_agda() {
    Agda_datadir="$WORK/agda-data" \
    XDG_DATA_HOME="$WORK/agda-data" \
    XDG_CONFIG_HOME="$WORK/agda-config" \
        "$AGDA_CMD" --safe --no-libraries -i "$WORK/agda" "$1"
}
run_agda "$WORK/agda/Resolved/DNS/Name.agda"
run_agda "$WORK/agda/Resolved/DNS/Transaction.agda"

printf '%s\n' 'formal check passed: Idris2 and Agda'
