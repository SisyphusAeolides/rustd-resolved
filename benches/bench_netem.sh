#!/usr/bin/env bash
# Requires root: netem loss on uplink iface
IFACE="${1:-eth0}"
sudo tc qdisc add dev "$IFACE" root netem loss 2% delay 40ms 20ms || true
# run dnsperf; collect p99
sudo tc qdisc del dev "$IFACE" root || true
