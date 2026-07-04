# Troubleshooting & operations

## Diagnostics endpoint

`splitdnsd` serves a read-only HTTP endpoint (default `127.0.0.1:8080`, set by
`[diag].addr`):

- **`/healthz`** — liveness/readiness (also what the systemd watchdog uses internally).
- **`/diag.json`** — machine-readable snapshot: mirrored zones, reverse/stub zones, the
  vhost set, the mDNS view, recent queries, cache/backend/worker health, and whether
  Cloudflare is currently healthy.
- **`/`** — the live diagnostics console (see [diagnostics.md](diagnostics.md)).

```sh
curl -s localhost:8080/diag.json | jq .
curl -s localhost:8080/healthz
```

It is read-only and bound to loopback by default; keep it off untrusted interfaces.

## Logs

```sh
journalctl -u splitdnsd -f
```

Look for: `splitdnsd serving` (startup, with the resolved listen set), mirror build
messages, `forwarder: …` audit lines (e.g. a cleartext downgrade), `ddns: …` outcomes,
and any supervisor restart notices.

## Common problems

**Fails to bind `:53`.** Another resolver holds the port (`systemd-resolved`,
`unbound`, `dnsmasq`). Stop/disable it, or use `[listen] mode="explicit"` on a
different address. The unit has `CAP_NET_BIND_SERVICE`; if you run the binary by hand,
it needs the capability or root.

**A name returns SERVFAIL.** It was forwarded and the upstream failed. With
`cleartext_fallback=false` (default), DoT must reach the upstreams — check egress to
:853 and that the configured servers are correct. The per-request budget is ~2s, so a
dead upstream fails fast rather than hanging.

**A mirrored zone forwards instead of being served authoritatively.** The mirror is not
built: the Cloudflare **read token** is missing/unreadable, the zone is not in the
account, or the mirror has not finished its first build yet. `journalctl` shows the CF
mirror status; `/diag.json` lists the zones actually mirrored. This is fail-static by
design — the daemon forwards rather than NXDOMAIN.

**A zone apex returns the reverse-proxy address instead of its real record.** That apex is
subject to the vhost redirect. Add it to `[vhost].exclude_zones` to serve it
authoritatively.

**Local (`.lan` / `.local`) names do not resolve.** mDNS is best-effort: the listener may
have failed to bind `:5353` (another responder like avahi), or no announcement has been
seen — check the mDNS view on the [diagnostics console](diagnostics.md). A quiet device is
normally found on the first query via on-demand resolution; if you disabled it
(`[mdns] resolve_on_demand = false`), an un-announced host stays NXDOMAIN. A just-booted
host may NXDOMAIN for up to ~30s until it announces itself. Local names are never forwarded.

**Dynamic-DNS makes no changes.** Expected unless fully armed: `enabled=true`,
`dry_run=false`, a **non-empty** `eligible` allowlist (empty = deny-all → forced
dry-run), a readable `DNS:Edit` token, and an authenticated trigger. The audit lines in
the log explain each outcome (`dry-run`, `not-eligible`, `rate-limited`, `applied`).

**The service keeps restarting.** The supervisor restarts a wedged worker or a stale
snapshot, and systemd restarts the process if liveness fails. Check the logs for the
underlying cause (usually a misconfiguration caught at startup — run `-check-config`).

## Validating configuration

```sh
splitdnsd -config /etc/splitdns/splitdnsd.toml -check-config
```

Prints the resolved listen set, access policy, and reverse zones, and exits non-zero on
a bad config. The packaged unit runs this as `ExecStartPre`, so a bad edit fails loudly
instead of crash-looping.
