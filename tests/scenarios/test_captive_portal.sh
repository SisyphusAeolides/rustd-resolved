#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -euo pipefail

NS="testns_$$"
VETH0="veth0_$$"
VETH1="veth1_$$"

cleanup() {
    echo "Cleaning up..."
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH0" 2>/dev/null || true
}

trap cleanup EXIT

# Set up netns
ip netns add "$NS"

# Set up veth pair
ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH1" netns "$NS"

# Bring interfaces up
ip link set "$VETH0" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$VETH1" up

# Set up base nftables filter
ip netns exec "$NS" nft add table inet filter
ip netns exec "$NS" nft add chain inet filter input '{ type filter hook input priority 0 ; policy accept ; }'
ip netns exec "$NS" nft add chain inet filter forward '{ type filter hook forward priority 0 ; policy accept ; }'
ip netns exec "$NS" nft add chain inet filter output '{ type filter hook output priority 0 ; policy accept ; }'

echo "Environment initialized. Running scenario..."
# Scenario specific code goes here
