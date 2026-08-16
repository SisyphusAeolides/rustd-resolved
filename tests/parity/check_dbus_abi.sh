#!/usr/bin/env bash
set -euo pipefail
LIST="$(dirname "$0")/dbus_abi_list.txt"
INTROSPECT=$(busctl introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager 2>/dev/null || true)
if [[ -z "$INTROSPECT" ]]; then
  echo "FAIL cannot introspect resolve1"
  exit 1
fi
FAIL=0
while read -r m; do
  [[ -z "$m" || "$m" =~ ^# ]] && continue
  if grep -q "$m" <<<"$INTROSPECT"; then
    echo "OK  $m"
  else
    echo "MISSING $m"
    FAIL=1
  fi
done < "$LIST"
exit $FAIL
