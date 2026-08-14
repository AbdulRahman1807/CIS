#!/bin/sh
# Deliberately does NOT set an iptables policy or add any rules — the
# default INPUT policy is ACCEPT with an empty ruleset, which is the FAIL
# evidence for CIS-3.5.1. This container still needs --cap-add=NET_ADMIN so
# `iptables -L` itself can run (without it you get a capability error, which
# is a transport problem, not firewall evidence — see WORKPLAN.md §3).
exec sleep infinity
