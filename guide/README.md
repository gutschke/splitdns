# splitdns guide

Detailed documentation beyond the top-level [README](../README.md),
[ARCHITECTURE](../ARCHITECTURE.md), and the manual pages
(`splitdnsd(8)`, `splitdns.conf(5)`, `splitdns-notify(8)`).

- **[configuration.md](configuration.md)** — every config section explained, with
  rationale and worked examples.
- **[deployment.md](deployment.md)** — the three deployment modes, the parallel-safe
  validation pattern, cutover, and arming dynamic-DNS write-back.
- **[encrypted-dns.md](encrypted-dns.md)** — the opt-in DoT/DoH front-end and DDR
  auto-upgrade discovery: the ADN certificate, the optional DNR-via-DHCP recipe, and
  how to verify a client actually upgraded.
- **[diagnostics.md](diagnostics.md)** — the diagnostics console in full: recent
  queries, busiest clients, backend/cache health, the mDNS forward/reverse view, the
  encrypted/DDR panel, the transport query tool, and the gated control actions (flush
  cache, force refresh, restart) with their security model.
- **[troubleshooting.md](troubleshooting.md)** — reading the logs, the watchdog, and
  common problems.
- **[self-rebuild.md](self-rebuild.md)** — the optional `splitdnsd-selfbuild` package
  that rebuilds the static binary when the apt Go toolchain gets a security backport.
- **[internals.md](internals.md)** — a deeper design dive (the three planes, snapshot
  model, query precedence, the guard model) for operators and contributors.

## Reading order

New here? Start with the top-level [README](../README.md) and its Quickstart, then:

1. **[deployment.md](deployment.md)** — install, validate in parallel, cut over.
2. **[configuration.md](configuration.md)** — tune each section as you need it.
3. **[troubleshooting.md](troubleshooting.md)** — when something looks wrong.
4. **[internals.md](internals.md)** / [ARCHITECTURE](../ARCHITECTURE.md) — how and why.

The manual pages (`splitdns.conf(5)`, `splitdnsd(8)`, `splitdns-notify(8)`) are the
formal key reference; this guide explains and links to them rather than restating
every default.

## Glossary

- **Mode 1 / 2 / 3** — the three opt-in deployment levels (forwarder; + Cloudflare
  mirror; + dynamic-DNS write-back). Not "tiers".
- **The mirror** — the read-only local copy of your Cloudflare-hosted zones, refreshed
  by SOA-serial polling. It never writes back to Cloudflare.
- **vhost redirect** — pointing the bare domain, `www`, and known virtual hosts at your
  **internal reverse proxy** instead of the public edge.
- **Bare domain** — the zone apex (e.g. `example.com` with no label). Also "naked".
- **Tunnel flattening** — replacing a CNAME to a tunnel/proxy suffix (default
  `cfargotunnel.com`) with the real A/AAAA addresses currently presented.
- **Fail-static** — on a cold start with everything down, the resolver still serves
  last-known data from its warm cache rather than failing.
- **The LAN plane** — the passive mDNS view that serves `.lan` / `.local`, on-demand
  resolution, and unicast DNS-SD. Read-only and never written back to Cloudflare.
- **DNS-SD** — service discovery (SRV/TXT/PTR): browsing services like printers or casts.
  `splitdnsd` serves it over unicast from captured mDNS, reaching across VLANs.
- **ADN** — Authentication Domain Name: the hostname a client validates the encrypted
  front-end's TLS certificate against (see [encrypted-dns.md](encrypted-dns.md)).

All examples use documentation-range placeholders (RFC 5737 IPv4, RFC 3849 IPv6,
RFC 2606 / RFC 6761 names). Substitute your own zones and addresses.
