# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  upgrade.

### Testing & CI
- Race-enabled unit/integration tests, parser fuzzing, a network-namespace e2e harness,
  an adversarial chaos suite, and a golden-parity harness. CI gates on vet, govulncheck,
  golangci-lint, race tests, short fuzz, and a pristine/no-attribution scan.

[Unreleased]: https://github.com/gutschke/splitdns/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gutschke/splitdns/releases/tag/v0.1.0
