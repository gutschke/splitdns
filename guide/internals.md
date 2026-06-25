# Internals

A deeper dive than [ARCHITECTURE.md](../ARCHITECTURE.md), for operators who want to
reason about behavior and for contributors. All examples use placeholders.

## Query precedence

The resolver is a pure function of the published snapshot and the mDNS view. For each
query it walks a fixed precedence order and either answers directly or signals a
forward:

1. **Malformed** (not exactly one question) → FORMERR.
2. **Static specials / seeded hosts** — exact-match table (includes the internal
   liveness record). Authoritative; never forwarded.
3. **Reverse PTR** — authoritative only under a configured reverse zone; PTRs outside
   any managed reverse space forward.
4. **`*.local`** — served from the mDNS view only; never forwarded (unknown → NXDOMAIN).
5. **Stub / forward zones** — a delegated subtree takes precedence over a parent
   mirrored zone; forwarded to the configured resolver(s) over plain UDP/TCP.
6. **vhost redirect** — for a mirrored zone, an address query for the apex / `www` /
   a known vhost label returns the reverse-proxy address (the apex's non-address RRsets stay
   real); excluded zones skip this.
7. **Authoritative mirrored zone** — wildcard synthesis, empty-non-terminal (ENT)
   suppression, tunnel/proxy flattening, RFC 2308 negative answers.
8. **Everything else** forwards to the upstreams. `ANY` on the forward path is answered
   minimally (RFC 8482) rather than relayed.

This order is load-bearing — e.g. a stub zone intentionally shadows a parent mirrored
zone, and the vhost redirect runs before the authoritative assembler.

## The snapshot model

Two immutable values are published independently via `atomic.Pointer`:

- the **zone Snapshot** (authoritative zones, reverse zones, stub zones, the vhost set
  and exclusion set, static specials, and the rebind allow-suffixes), and
- the **mDNS View** (`*.local` forward + reverse records).

The hot path loads each with a single atomic read — no locks, no I/O. Control-plane
workers build a *new* value and store it; a published value is never mutated. This is
what makes the data plane immune to a slow or failed dependency.

## Freshness and fail-static

The mirror refreshes on **SOA serial** change (polled from the upstreams) and persists
each build to a warm cache. On a cold start it publishes the warm cache (or, with
nothing cached, a base snapshot) immediately, so it serves last-known data even with
every dependency down — with a valid, non-zero SOA serial. The served serial tracks the
real Cloudflare serial once a refresh lands.

## Tunnel / proxy flattening

A `CNAME` whose target matches a configured tunnel suffix is never served as a CNAME;
instead the owner is resolved to the addresses Cloudflare currently presents (the real
endpoint), and those A/AAAA are served. The default suffix is `cfargotunnel.com`
(Cloudflare Tunnel); add others (e.g. `tcpshield.com`) via `[cloudflare].tunnel_suffixes`. An IPv4-only owner yields a clean NODATA for
AAAA rather than NXDOMAIN. Wildcards flatten via a fixed sentinel label.

## DNS-rebinding filter

Answers obtained by **forwarding** are scanned, and private/non-routable addresses are
stripped — unless the answer name falls under one of your own authoritative/stub
suffixes (where an internal address is legitimate). Locally assembled authoritative
answers are not filtered (they are yours by definition).

## The dynamic-DNS guard model

Write-back is fenced off in its own component — the only one holding the `DNS:Edit`
token and the only one that mutates Cloudflare. A write must pass, in order:

1. **Built at all** — the writer is constructed only when an edit token is readable.
2. **`enabled` and not `dry_run`.**
3. **Authenticated trigger** — either the peer-credential-checked local socket
   (`splitdns-notify`) or an mDNS announcement from a `trusted_sources` network.
4. **Eligibility** — the host's FQDN is on the `eligible` allowlist (empty = deny-all).
5. **Rate limits** — per-host minimum interval and a global token bucket.

Every decision is recorded in a hash-chained audit log. Removing the edit token makes
writes structurally impossible regardless of the flags.

## Supervision and the watchdog

Every control-plane worker runs under a supervisor that provides panic recovery with
capped backoff and **progress-based stall detection** — a worker that deadlocks without
panicking is restarted. The systemd watchdog is pinged only while an **in-process
liveness probe** can answer a synthetic query from the current snapshot; a stale primary
snapshot escalates (force-restart the mirror, then withhold the ping for a controlled
systemd restart). The watchdog is therefore immune to the inbound limiter and to
upstream outages — it reflects whether the daemon can actually resolve.

## Transport and resilience on the forward path

Forwarding is DoT first, with an optional audited cleartext fallback. Each upstream has
a circuit breaker that trips on consecutive failures or a rolling-window failure ratio,
then fails over to a healthy upstream without paying the dead one's timeout; it fails
open (never worse than no breaker) and probes recovery after a cooldown. Every request
carries a deadline so a slow upstream cannot exhaust the inbound concurrency limiter.
