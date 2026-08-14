#!/bin/sh
# Sets the firewall policy at container-START time, in the real runtime
# network namespace — NOT at `docker build` time. iptables/netfilter state
# is kernel/namespace state, not filesystem state, so it does not persist
# across build layers, and build-time containers usually lack NET_ADMIN
# anyway. This container MUST be run with --cap-add=NET_ADMIN (see
# WORKPLAN.md §4 Person A) or the line below fails and CIS-3.5.1 will
# spuriously resolve UNKNOWN — that's a docker-run flag issue, not a bug
# in the audit agent.
iptables -P INPUT DROP 2>/dev/null || echo "WARNING: could not set iptables policy — was --cap-add=NET_ADMIN passed to docker run?" >&2
exec sleep infinity
