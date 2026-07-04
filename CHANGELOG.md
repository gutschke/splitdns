# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-03

### Encrypted client front-end (DoT/DoH) + DDR — opt-in, off by default
- Optional DNS-over-TLS (RFC 7858) and DNS-over-HTTPS (RFC 8484) listeners for LAN clients,
  reusing the `:53` query pipeline (so `[access]`, the answer cache, and the rebind filter
  apply unchanged) with no new dependencies. Configured under `[encrypted]`.
- Discovery of Designated Resolvers (RFC 9462): synthesizes the SVCB designation at
  `_dns.resolver.arpa` (and answers the ADN's A/AAAA via split-horizon) so ChromeOS/Chrome
  auto-upgrade and Android uses opportunistic DoT — instead of defecting to a public
  resolver that bypasses split-horizon. Advertised only while a valid certificate is loaded.
- Operator-provided certificate for the Authentication Domain Name, hot-reloaded on SIGHUP
  or file change (validate-before-swap; never serves an expired cert). Fail-closed: a bad
  cert degrades to Do53-only without taking DNS down; `-check-config` hard-fails on it.
- DNR (RFC 9463) documented as an operator DHCP/RA recipe (no daemon code). See
  `guide/encrypted-dns.md`.
- Diagnostics console gains an **Encrypted & DDR** panel (certificate ADN/expiry/SANs/
  validity, DoT/DoH listeners, the SVCB actually served, and an upgrade-readiness
  checklist that pinpoints *why* clients don't upgrade), a **transport query tool**
  (issue a Do53/DoT/DoH query at the resolver and see the answer plus the TLS handshake),
  and **per-query transport** — a `proto` column on recent queries, a transport rollup,
  and per-client lifetime protocol counts (did this client ever upgrade?).

### Local plane (mDNS / DNS-SD)
- Configurable unicast local domain (`[mdns] local_domain`, default `lan`) served from the
  passive mDNS view alongside `*.local`, with serve-stale (`stale_grace`) and a
  goodbye cushion (`goodbye_grace`) so hosts don't blink out behind a reflector/avahi bounce.
- On-demand resolution (`[mdns] resolve_on_demand`, default on): an unknown local host
  triggers a bounded, rate-limited targeted mDNS query and a short wait
  (`resolve_on_demand_wait`), so a quiet device is found on first ask. Never queries a
  managed name; a solicited reply can never move a Cloudflare record.
- Unicast DNS-SD serving (`[mdns] serve_dnssd`, default on): local names answer SRV/TXT/PTR
  synthesized from captured mDNS services, so clients resolve/browse services across VLANs.
- Active DNS-SD discovery (`[mdns] service_discovery`, default on) runs only while the
  diagnostics console is open — zero active multicast when idle.
- Diagnostics console mDNS forward/reverse panels show per-host hardware vendor (MAC OUI via
  the optional `ieee-data` package), captured Bonjour services with SRV ports, and a
  model/friendly name from TXT — on a whole-row hover — plus a redacted config panel.

### Resolver
- `resolver.arpa` (RFC 9462 special-use domain) is answered locally: authoritative NODATA
  when DDR is off, the synthesized SVCB designation when on — never forwarded upstream.

### Security
- Diagnostics control actions require a same-origin custom request header in addition to the
  Fetch-Metadata check, so a cross-site page cannot trigger a control action even on a
  no-password loopback bind.
- TSIG-authenticated dynamic-DNS triggers are single-use within the signature validity
  window, so a captured signed announcement cannot be replayed.

## [0.1.0] — 2026-06-25

First public release: a split-horizon DNS resolver that mirrors Cloudflare-hosted
zones read-only, flattens tunnel/proxy indirection to direct LAN addresses, serves
`*.local` (mDNS) and reverse zones, redirects vhost names at an internal reverse
proxy, and forwards everything else over DoT — all from a zero-I/O hot path. It ships
as three Debian packages: the `splitdnsd` server, the standalone `splitdns-notify`
mDNS helper, and the optional `splitdnsd-selfbuild` unattended security-rebuild package.

### Resolver
- Authoritative Cloudflare mirror with SOA-serial polling and a persistent warm cache
  (fail-static cold start).
- Tunnel/proxy flattening, vhost redirect with per-zone exclusions, wildcard/ENT
  synthesis, reverse (PTR) zones with optional prefix auto-detection.
- DoT forwarding with audited cleartext fallback and a per-upstream circuit breaker.
- DNS-rebinding protection, EDNS0/TC truncation, RFC 8482 minimal-ANY, RFC 2308 negative
  caching, and an answer cache with serve-stale.
- Worker supervisor with panic recovery, stall detection, and an sd_notify watchdog
  gated on an in-process liveness probe.
- Tiered diagnostics console (read-only views always on; dangerous controls password/
  socket-gated and off by default). Hardened systemd unit and man pages.

### Dynamic-DNS write-back
- Opt-in, double-guarded (disabled + dry-run by default), update-only on existing A/AAAA
  records, with an eligibility allowlist, per-host rate limits, and a hash-chained audit
  log.
- Authenticated triggers: a peer-credential-checked local socket; **group-authorized**
  socket access (`[ddns].notify_groups` — POSIX-ACL, multiple groups, no shared key, no
  `CAP_CHOWN`); **TSIG-signed announcements** (RFC 8945, honored regardless of source IP,
  defeating UDP spoofing while staying fire-and-forget — `splitdns-notify --genkey` mints
  a key); and/or trusted source networks. `require_signature` rejects unsigned triggers.

### Packaging
- Split into `splitdnsd` (server) and a standalone `splitdns-notify` (mDNS-announce
  helper — one static binary, no service/user/config), so hosts that only announce
  themselves never pull in the server; `splitdnsd` Recommends it. The helper reads a
  `[notify]` config file (servers, signing key, resolver socket path).
- **`splitdnsd-selfbuild`** (optional): rebuilds the static binaries against the current
  apt Go toolchain when it changes (apt-hook-triggered + weekly backstop), installing only
  after `-check-config` + a DNS health check with automatic rollback and email-on-failure
  (`default-mta | mail-transport-agent`; no MTA hard-coded). This is how a static binary
  picks up Go-stdlib/dependency CVE fixes on `apt dist-upgrade`. Version-forwarding
  (`scripts/pkg-version.sh`) keys the package version on the apt `golang-1.NN` package
  version, so an Ubuntu stdlib backport is a strictly-greater version apt offers as an
  upgrade. It does not hard-depend on the other two packages (it Recommends them), so any
  combination of the three is a valid install, and it rebuilds + reinstalls either one if
  it is removed. Produced by both the canonical `debian/` (dpkg-buildpackage) path and the
  `build-deb.sh` fallback.

### Testing & CI
- Race-enabled unit/integration tests, parser fuzzing, a network-namespace e2e harness,
  an adversarial chaos suite, and a golden-parity harness. CI gates on vet, govulncheck,
  golangci-lint, race tests, short fuzz, and a pristine/no-attribution scan.

[Unreleased]: https://github.com/gutschke/splitdns/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gutschke/splitdns/releases/tag/v0.1.0
