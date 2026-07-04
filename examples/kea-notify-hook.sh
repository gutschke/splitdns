#!/bin/sh
# Kea libdhcp_run_script hook: on a committed DHCPv4 lease, hand "<host> <ip>" to the
# splitdns-notify relay so the host resolves promptly. Runs as Kea's user with NO announce
# privileges (no TSIG key, no resolver access) — the relay does the signed send. Uses only
# splitdns-notify itself (no socat/nc), so there is nothing extra to install.
#
# Kea config (add to "Dhcp4"):
#   "hooks-libraries": [
#     { "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_run_script.so",
#       "parameters": { "name": "/etc/kea/kea-notify-hook.sh", "sync": false } } ]
# Then add Kea's service user to the relay's group, e.g.:  usermod -aG splitdns-notify _kea
# The cron reconcile remains the source of truth and fallback.
set -u
SOCK=/run/splitdns-notify/lease-relay.sock
NOTIFY=/usr/bin/splitdns-notify
[ "${1:-}" = "leases4_committed" ] || exit 0     # post-commit only; never lease4_select

n="${LEASES4_SIZE:-0}"                            # NOTE: no KEA_ prefix; STATE is a NAME
i=0
while [ "$i" -lt "$n" ]; do
    eval "ip=\${LEASES4_AT${i}_ADDRESS:-}"
    eval "host=\${LEASES4_AT${i}_HOSTNAME:-}"
    eval "state=\${LEASES4_AT${i}_STATE:-}"
    if [ "$state" = "default" ] && [ -n "$ip" ] && [ -n "$host" ]; then
        "$NOTIFY" --relay "$SOCK" "${host%%.*}" "$ip" 2>/dev/null || true
    fi
    i=$((i + 1))
done
exit 0
