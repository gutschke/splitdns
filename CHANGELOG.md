# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Group-based access to the local notify socket** (`[ddns].notify_groups`): members of
  the named groups may trigger DDNS via `/run/splitdns/notify.sock` with no shared key.
  The unprivileged daemon stamps a POSIX ACL (multiple groups, no `CAP_CHOWN`, no group
  membership of its own) and authorizes a peer by membership — so e.g. naming `www-data`
  lets nginx trigger immediately, no `usermod`. `[ddns].notify_socket_mode` makes the
  socket permission configurable (default `0660`). A filesystem without ACL support is
  logged and skipped (DNS unaffected).
- Optional **TSIG (RFC 8945) authentication** for DDNS triggers. A `splitdns-notify`
  announcement can be HMAC-signed with a shared key (`[notify].tsig_*`), and the
  resolver (`[ddns].tsig_keys`) honors a valid signature regardless of source IP —
  cryptographic auth that defeats UDP source-IP spoofing while keeping delivery
  fire-and-forget. `[ddns].require_signature` (default off) rejects unsigned triggers.
  `splitdns-notify --genkey` mints a key and prints both ends' config; `--verbose`
  reports what was sent, signed or not, and whether it worked. Signing is opt-in:
  with no key configured the helper still works (socket → multicast).
- `splitdns-notify` now reads a `[notify]` config file (`/etc/splitdns/notify.toml`,
  falling back to `splitdnsd.toml`) for its servers, signing key, and resolver socket
  path (`[notify].socket`, overridden by `-socket`; defaults to — and matches — the
  resolver's `[ddns].notify_socket`), so options need not be retyped each call. The
  standalone package ships `notify.example.toml`.

### Changed
- Packaging is now split into two Debian packages: `splitdnsd` (server) and a
  standalone `splitdns-notify` (the mDNS-announce helper — one static binary, no
  service, user, or config). Hosts that only announce themselves can install
  `splitdns-notify` without ever pulling in the server. `splitdnsd` Recommends
  `splitdns-notify`, so a normal server install is unchanged.

## [0.1.0] — initial release

First public release: a split-horizon DNS resolver that mirrors Cloudflare-hosted
zones read-only, flattens tunnel/proxy indirection to direct LAN addresses, serves
`*.local` (mDNS) and reverse zones, redirects vhost names at an internal reverse
proxy, and forwards everything else over DoT — all from a zero-I/O hot path.

### Added
- Authoritative Cloudflare mirror with SOA-serial polling and a persistent warm
  cache (fail-static cold start).
- Tunnel/proxy flattening, vhost redirect with per-zone exclusions, wildcard/ENT
  synthesis, reverse (PTR) zones with optional prefix auto-detection.
- DoT forwarding with audited cleartext fallback and a per-upstream circuit breaker.
- DNS-rebinding protection, EDNS0/TC truncation, RFC 8482 minimal-ANY, RFC 2308
  negative caching.
- Opt-in dynamic-DNS write-back, double-guarded (disabled + dry-run by default) with
  authenticated triggers (peer-credential-checked local socket and/or trusted source
  networks), an eligibility allowlist, rate limits, and a hash-chained audit log.
- Worker supervisor with panic recovery, stall detection, and an sd_notify watchdog
  gated on an in-process liveness probe.
- Hardened systemd unit, `splitdns-notify(8)` helper, and man pages.
- Test suite: race-enabled unit/integration tests, parser fuzzing, a
  network-namespace e2e harness, an adversarial chaos suite, and a golden-parity
  harness.

[Unreleased]: https://github.com/gutschke/splitdns/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gutschke/splitdns/releases/tag/v0.1.0
