# splitdns

A lightweight **split-horizon DNS resolver** for a trusted LAN. `splitdnsd` serves
your locally managed zones — mirrored read-only from Cloudflare — while preferring
direct LAN addresses over public proxy/tunnel indirection, resolves local hosts
(`.lan` and `.local`) from mDNS, answers reverse (PTR) queries for your own address
space, and forwards everything else to upstream public resolvers over DoT. It is a
single static Go binary with no runtime dependencies.

Its defining property is a **zero-I/O hot path**: every query is answered from an
immutable, atomically published snapshot, so a slow or unreachable Cloudflare,
upstream, or mDNS peer can never wedge name resolution. On a cold start with every
dependency down it still serves last-known data (**fail-static**).

## Who it's for

You run a trusted LAN — home, lab, small office — and want some or all of:

- a **secure local forwarder** — DoT to upstreams, access-controlled to LAN clients,
  with DNS-rebinding protection;
- **local names that just work** — `host.lan` / `host.local` from a passive mDNS view,
  reverse-PTR for your own IPv4/IPv6 space, and unicast DNS-SD so clients can browse
  services (printers, casts) even across VLANs where multicast doesn't reach;
- **internal-direct answers for your own public domains** — if you host zones on a
  provider that proxies/tunnels traffic (this build integrates **Cloudflare**), LAN
  clients get the real internal address and your reverse proxy is reachable directly;
- optionally **encrypted client DNS** (DoT/DoH with auto-upgrade discovery) so
  privacy-seeking clients stay on *your* split-horizon resolver instead of defecting
  to a public one;
- optionally **keeping a dynamic (residential) IP up to date** in your DNS provider.

Each layer is independent and opt-in — the Cloudflare, encrypted-DNS, and dynamic-DNS
parts are entirely optional. Without any of them, `splitdnsd` is a capable
split-horizon forwarder that needs no account and no token.

## Why "split-horizon"?

The same name can need a **different answer inside your network than outside it**. A
service published on the public Internet (via a CDN/proxy, a tunnel, or a cloud load
balancer) should resolve, *from inside the LAN*, to the machine's **direct local
address** — skipping the round-trip out to the public edge and back, with its extra
latency, NAT-hairpin headaches, and loss of the real client IP. That is split-horizon
DNS: one resolver that serves a private view to trusted clients and otherwise behaves
like a normal forwarding resolver.

## Features

- **Local names, zero-config** — `.lan` and `.local` served from a passive mDNS view
  with serve-stale so hosts don't blink out between announcements. Unknown local hosts
  are found on first ask via a bounded, rate-limited targeted mDNS query.
- **Unicast DNS-SD** — local names answer SRV/TXT/PTR synthesized from captured mDNS
  services, so clients resolve and browse services over unicast, including across VLANs.
- **Reverse (PTR) zones** for your managed IPv4/IPv6 spaces, with optional auto-detection
  of a changing ISP-assigned prefix.
- **Authoritative Cloudflare mirror** (read-only), refreshed by SOA-serial polling with a
  persistent warm cache for instant, fail-static cold starts. It never writes to your
  account.
- **Tunnel/proxy flattening** — Cloudflare Tunnel (`*.cfargotunnel.com`) and other
  configurable suffixes resolve to the real presented addresses.
- **vhost redirect** — bare domain, `www`, and known virtual hosts point at an internal
  reverse proxy; per-zone exclusions; non-address records (MX/TXT/SVCB) stay real.
- **DoT forwarding** for everything else (cleartext fallback audited and off by default),
  with a per-upstream **circuit breaker** for fast failover; an **answer cache** with
  serve-stale; DNS-rebinding protection; RFC-correct EDNS0/TC, minimal-ANY, and negative
  caching.
- **Encrypted client DNS** (opt-in) — DoT + DoH listeners with a hot-reloading cert and
  DDR (RFC 9462) advertising, so capable clients auto-upgrade to *this* resolver.
- **Dynamic-DNS write-back** to Cloudflare (opt-in, off + dry-run by default), guarded by
  an eligibility allowlist, authenticated triggers, rate limits, and an audit log.
- **Diagnostics console** — a live page showing queries, cache, upstreams, and the mDNS
  forward/reverse view (with per-host vendor, Bonjour services, and model), plus a
  transport query tool and certificate detail.
- **Reliable by construction** — supervised workers with panic recovery and stall
  detection, a systemd watchdog gated on an in-process liveness probe, and a hardened,
  capability-bounded systemd unit.

## Quick start

A secure LAN forwarder with local (`.lan` / `.local`) and reverse-PTR names — no
account, no token:

```sh
./scripts/build-deb.sh && sudo apt install ./dist/splitdnsd_*.deb
sudo cp examples/splitdnsd.minimal.toml /etc/splitdns/splitdnsd.toml
sudoedit /etc/splitdns/splitdnsd.toml      # set your reverse zone
splitdnsd -config /etc/splitdns/splitdnsd.toml -check-config   # validate first
sudo systemctl enable --now splitdnsd
```

`splitdnsd` binds `:53`, so stop any resolver already on that port
(`systemd-resolved`, `dnsmasq`, `unbound`) first. Verify:

```sh
dig @127.0.0.1 example.org A +short        # forwarding works
dig @127.0.0.1 somehost.local A +short     # mDNS works
```

To mirror your Cloudflare-hosted zones or arm dynamic-DNS, add a scoped token and the
relevant config sections — see the [deployment guide](guide/deployment.md). Every
option is optional and falls back to a safe default; the full annotated config is
[`examples/splitdnsd.example.toml`](examples/splitdnsd.example.toml).

## Where to go next

| If you want to… | Read |
|------|------|
| Install, validate in parallel, cut over, arm DDNS | [guide/deployment.md](guide/deployment.md) |
| Configure every section, with worked examples | [guide/configuration.md](guide/configuration.md) |
| Turn on encrypted client DNS (DoT/DoH + DDR) | [guide/encrypted-dns.md](guide/encrypted-dns.md) |
| Use the diagnostics console | [guide/diagnostics.md](guide/diagnostics.md) |
| Diagnose a problem | [guide/troubleshooting.md](guide/troubleshooting.md) |
| Understand how it works inside | [ARCHITECTURE.md](ARCHITECTURE.md) · [guide/internals.md](guide/internals.md) |
| The exact key reference | `splitdns.conf(5)`, `splitdnsd(8)`, `splitdns-notify(8)` |
| Build, test, and contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |

## Security posture

The Cloudflare mirror and the mDNS view are **read-only**. The only component that
writes to an external account is the dynamic-DNS writer, which is disabled and in
dry-run by default and gated by an eligibility allowlist, authenticated triggers, and
rate limits. On-demand mDNS resolution and DNS-SD answers come from **unauthenticated**
mDNS on your LAN, so they are bounded and never override a managed name (see
[SECURITY.md](SECURITY.md)). The service runs as an unprivileged,
capability-bounded, sandboxed systemd unit, and no site-private data ships in the repo
or the `.deb`.

**API tokens are never stored in this repository or the package.** You provide them as
files on the deployed host; the source and the `.deb` contain only documentation
placeholders. Treat a leaked token as compromised and roll it.

## Uninstalling

```sh
sudo systemctl disable --now splitdnsd
sudo apt remove splitdnsd        # add --purge to also remove config/state
```

## License

[MIT](LICENSE) © 2026 gutschke. Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
</content>
</invoke>
