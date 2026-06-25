# Architecture

`splitdnsd` is built around one invariant: **the query-answering hot path performs
no external I/O and takes no locks.** Everything that can be slow or fail — Cloudflare
API calls, SOA polling, mDNS, the vhost feed, dynamic-DNS writes — happens on
background workers that publish immutable snapshots. The hot path reads those
snapshots through a single atomic pointer load. A slow or unreachable dependency can
degrade freshness but can never wedge resolution.

## Three planes

```
            ┌──────────────────────── data plane (hot) ────────────────────────┐
  :53  ───► │  access control → inbound limiter → pure resolver → reply/forward │
            └──────────────────────────────▲───────────────────────────────────┘
                                            │ atomic snapshot load (no lock, no I/O)
            ┌───────────────────────────────┴──────────────── control plane (cold) ──┐
            │  CF mirror + SOA poller · mDNS source · vhost feed · warm cache         │
            │  supervisor (panic recovery, stall detection, systemd watchdog)         │
            └────────────────────────────────────────────────────────────────────────┘
            ┌──────────────────────── writer plane (isolated) ─────────────────────┐
            │  dynamic-DNS writer — the ONLY component that mutates Cloudflare       │
            └───────────────────────────────────────────────────────────────────────┘
```

### Data plane (hot, `internal/server` + `internal/resolver`)

For each query the front end enforces client access control and a global inbound
concurrency limiter, then calls a **pure** resolver function over the two immutable
snapshots (the zone `Snapshot` and the mDNS `View`). The resolver classifies the
query in a fixed precedence order — static specials, reverse PTR, `*.local`,
stub/forward zones, vhost redirect, authoritative zone, else forward — and either
produces the answer directly or signals the handler to forward it. EDNS0/OPT echo and
TC truncation are applied at the write boundary; forwarded answers pass through the
DNS-rebinding filter.

### Control plane (cold, `internal/mirror`, `internal/mdns`, `internal/vhost`)

Background workers build new snapshots and publish them by storing an
`atomic.Pointer`:

- **Cloudflare mirror** lists each configured zone's records, flattens
  tunnel/proxy indirection to real addresses, derives wildcards and empty
  non-terminals, synthesizes the apex SOA, and assembles a complete snapshot. A
  **SOA-serial poller** drives refreshes; a **persistent warm cache** lets a cold
  start serve last-known data immediately (fail-static).
- **mDNS source** maintains the `*.local` view from received announcements (LRU +
  TTL bounded) and republishes on change.
- **vhost feed** fetches the internal reverse proxy's redirect set.

All of these run under a **supervisor** that provides panic recovery with capped
backoff, progress-based stall detection (it restarts a worker that deadlocks without
panicking), and a systemd watchdog gated on an **in-process liveness probe** — the
daemon pings the watchdog only while it can actually answer a synthetic query from
the current snapshot, so a wedge becomes a controlled restart.

### Writer plane (isolated, `internal/ddns`)

Dynamic-DNS write-back is the only path that mutates Cloudflare, and it is fenced off
from everything else. It is **opt-in and double-guarded** (disabled and in dry-run by
default), holds the only `DNS:Edit` token, and is driven exclusively by authenticated
triggers:

- an **authenticated local socket** that `splitdns-notify(8)` connects to, with a
  `SO_PEERCRED` check on the peer uid; and/or
- mDNS announcements whose **source address** falls in a configured trusted set.

Writes are further gated by a required per-host eligibility allowlist, per-host and
global rate limits, and a hash-chained audit log. An empty allowlist is treated as
deny-all (forced dry-run).

## Snapshots

A `Snapshot` is an immutable value: authoritative zones (records, wildcards, ENTs,
SOA, flattened tunnel addresses), reverse zones, stub zones, the vhost redirect set,
the redirect exclusion set, static specials, and the rebind allow-suffixes. The
control plane builds a fresh one and `Store`s it; the hot path `Load`s it. Published
snapshots are never mutated. The mDNS `View` is a second, independently published
snapshot for `*.local`.

## Reliability properties

- **Fail-static**: with every dependency unreachable, the daemon still serves the
  warm-cached (or cold base) snapshot with a valid SOA serial.
- **Bounded**: the inbound limiter caps concurrent work; the mDNS cache is size- and
  TTL-bounded; forwards carry a per-request deadline and a per-upstream breaker.
- **Supervised**: panics, stalls, and stale snapshots escalate to controlled restarts
  rather than silent failure.

## Testing

The design is exercised by unit and integration tests (race-enabled), native fuzz
targets for every untrusted parser, a **network-namespace e2e harness** that runs the
real components with egress structurally impossible, an **adversarial chaos suite**
(hung-upstream, all-dependencies-down, flood + goroutine-leak checks), and a
**golden-parity harness** that pins answer-for-answer behavior through the real
mirror→resolver pipeline. A shared mock fabric (`internal/mockedge`) provides a
faithful Cloudflare API (pagination, fault injection), DNS, mDNS, and vhost edges.

## Source layout

```
cmd/splitdnsd        the daemon
cmd/splitdns-notify  the dynamic-DNS announcement helper
internal/server      :53 front end (UDP/TCP, access control, EDNS/TC, rebind)
internal/resolver    pure query classifier + authoritative assembler
internal/mirror      Cloudflare mirror, SOA poller, warm cache, snapshot builder
internal/mdns        mDNS source/cache + authenticated notify socket
internal/vhost       reverse-proxy redirect feed
internal/ddns        isolated dynamic-DNS writer + audit
internal/forwarder   DoT/cleartext forwarder + per-upstream circuit breaker
internal/supervisor  worker supervision + sd_notify watchdog
internal/config      TOML config + validation
internal/netmatch    CIDR/scope matching   internal/revzone  reverse-zone derivation
internal/cfapi       Cloudflare REST client   internal/model  immutable snapshot types
```
