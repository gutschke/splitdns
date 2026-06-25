# splitdns

A lightweight **split-horizon DNS resolver** for a trusted LAN. `splitdnsd` serves
your locally managed zones — mirrored read-only from Cloudflare — while preferring
direct LAN addresses over public proxy/tunnel indirection, resolves `*.local` hosts
from mDNS, answers reverse (PTR) queries for your own address space, and forwards
everything else to upstream public resolvers over DoT.

Its defining property is a **zero-I/O hot path**: every query is answered from an
immutable, atomically published snapshot, so a slow or unreachable Cloudflare,
upstream, or mDNS peer can never wedge name resolution. It is a single static Go
binary with no runtime dependencies.

## Why "split-horizon"?

The same name can need a **different answer inside your network than outside it**.
A service published on the public Internet (often via a CDN/proxy, a tunnel, or a
cloud load balancer) should resolve, *from inside the LAN*, to the machine's **direct
local address** — skipping the round-trip out to the public edge and back, with its
extra latency, NAT-hairpin headaches, and loss of the real client IP. That is
split-horizon DNS: one resolver that serves a private view to trusted clients and
otherwise behaves like a normal forwarding resolver. Because of the zero-I/O hot path,
it is also **fail-static**: on a cold start with everything down it still serves
last-known data.

## Who it's for / use cases

You run a trusted LAN (home, lab, small office) and want some or all of:

- a **secure local forwarder** — DoT to upstreams, access-controlled to LAN clients,
  with DNS-rebinding protection and local `*.local` (mDNS) and reverse-PTR names;
- **internal-direct answers for your own public domains** — if you host zones on a
  provider that proxies/tunnels traffic (this build integrates **Cloudflare**), LAN
  clients get the real internal address and your reverse proxy is reachable directly;
- optionally, **keeping a dynamic (residential) IP up to date** in your DNS provider.

Each of these is an independent layer — see **Deployment modes** below. The
provider-specific parts (the Cloudflare mirror and dynamic-DNS write-back) are
**entirely optional**; without them `splitdnsd` is a capable split-horizon forwarder.

## Quickstart (mode 1)

A secure LAN forwarder with `*.local` and reverse-PTR names — no account, no token:

```sh
./scripts/build-deb.sh && sudo apt install ./dist/splitdnsd_*.deb
sudo cp examples/splitdnsd.minimal.toml /etc/splitdns/splitdnsd.toml
sudoedit /etc/splitdns/splitdnsd.toml      # set your reverse zone
sudo systemctl enable --now splitdnsd
```

`splitdnsd` binds `:53`, so disable any resolver already on that port first. To add
your Cloudflare-hosted zones (mode 2) or dynamic-DNS (mode 3), see the
[deployment guide](guide/deployment.md). Validate any config before starting:

```sh
splitdnsd -config /etc/splitdns/splitdnsd.toml -check-config
```

## Deployment modes

`splitdnsd` is useful at three increasing levels of involvement. Higher tiers are
strictly opt-in — you configure only what you need.

### 1. Local forwarder + LAN names — *no external account required*

Forward everything to your chosen upstreams over DoT; answer `*.local` from mDNS,
reverse (PTR) zones for your own address space, and stub/delegated subdomains; gate
queries to LAN clients and strip rebinding answers. This needs **no API tokens and no
cloud account** — just `[listen]`, `[access]`, `[upstream]`, and optionally
`[zones].reverse` / `[zones.stub]`. Many people will only ever want this.

### 2. + Cloudflare zone mirror — *read-only token*

If your public domains are **hosted on Cloudflare**, point `[zones].local` at them
and give `splitdnsd` a **read-only, scoped** API token. It mirrors those zones and
serves them authoritatively on the LAN, flattening proxied/tunnel records
(`*.cfargotunnel.com` by default; add other suffixes such as `*.tcpshield.com` via
`[cloudflare].tunnel_suffixes`) to the **real presented addresses** and
redirecting bare/`www`/vhost names at your internal reverse proxy. The mirror is
read-only — it never changes anything in your account — and if the token is absent or
Cloudflare is unreachable, those zones simply fall back to normal forwarding.

> Only Cloudflare is implemented today. If your zones live elsewhere, run in mode 1
> (or contribute another provider behind the existing mirror interface).

### 3. + Dynamic-DNS write-back — *opt-in, off by default*

If your WAN address changes (a typical residential ISP), `splitdnsd` can push the new
address into specific Cloudflare records — replacing a `ddclient`-style updater with
an integrated, guarded one. This is the **only** part that writes to your account, and
it is **disabled and in dry-run by default**, requires a separate `DNS:Edit` token, an
explicit per-host eligibility allowlist (empty = deny-all), authenticated triggers,
rate limits, and an audit log. Leave it off unless you specifically need it.

> **API tokens are never stored in this repository or the package.** You provide them
> as files on the deployed host (see *Cloudflare access* below); the source and the
> `.deb` contain only documentation placeholders.

`splitdnsd` is a single, testable, fail-static service that consolidates a multi-part
DNS setup into one self-contained Go binary.

## Features

- **Authoritative mirror** of Cloudflare-hosted zones (read-only), refreshed by SOA
  serial polling with a persistent warm cache for instant, fail-static cold starts.
- **Tunnel/proxy flattening** — Cloudflare Tunnel (`*.cfargotunnel.com`) and other
  configurable suffixes resolve to the real presented addresses.
- **vhost redirect** — bare domain, `www`, and known virtual hosts point at an
  internal reverse proxy; configurable per-zone exclusions.
- **`*.local` via mDNS**, plus authoritative **reverse (PTR)** zones for your managed
  IPv4/IPv6 spaces (with optional auto-detection of a changing ISP prefix).
- **Forwarding** of everything else over **DNS-over-TLS** (cleartext fallback is
  audited and off by default), with a per-upstream **circuit breaker** for fast
  failover.
- **DNS-rebinding protection**, RFC-correct EDNS0/TC truncation, RFC 8482 minimal
  ANY, RFC 2308 negative caching, RFC 4592 wildcards/ENT.
- **Opt-in dynamic DNS** write-back to Cloudflare, double-guarded (disabled +
  dry-run by default) and driven only by authenticated triggers.
- **Reliability harness** — supervised workers with panic recovery, stall detection,
  and a systemd watchdog gated on an in-process liveness probe.
- **Hardened systemd unit** — unprivileged service account, `CAP_NET_BIND_SERVICE`
  only, strict sandboxing, memory ceiling.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design in depth.

## Documentation

| If you want to… | Read |
|------|------|
| Get running fast (mode 1) | the **Quickstart** above |
| Install, validate in parallel, cut over, arm DDNS | [guide/deployment.md](guide/deployment.md) |
| Configure every section, with worked examples | [guide/configuration.md](guide/configuration.md) |
| Diagnose a problem | [guide/troubleshooting.md](guide/troubleshooting.md) |
| Use the diagnostics console (queries, clients, backends, cache, controls) | [guide/diagnostics.md](guide/diagnostics.md) |
| Understand how it works inside | [guide/internals.md](guide/internals.md) · [ARCHITECTURE.md](ARCHITECTURE.md) |
| The exact key reference | `splitdns.conf(5)`, `splitdnsd(8)`, `splitdns-notify(8)` |
| The annotated config | [examples/splitdnsd.example.toml](examples/splitdnsd.example.toml) (full) · [examples/splitdnsd.minimal.toml](examples/splitdnsd.minimal.toml) (mode 1) |
| Build, test, and contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |

## Cloudflare access (optional — modes 2 and 3)

Skip this for a mode-1 forwarder. Modes 2 and 3 use **scoped** API tokens, kept in
their own on-host files (never in the repo, the package, or a shared config):

- **read token** — `Zone:Read` + `DNS:Read` for the zones you mirror (mode 2);
- **edit token** — `DNS:Edit`, scoped to only the zone(s) dynamic-DNS may touch
  (mode 3). Leave `edit_token_file = ""` to disable write-back.

> **Never commit API tokens.** Treat a leaked token as compromised and roll it
> immediately. The step-by-step token setup is in
> [guide/deployment.md](guide/deployment.md).

## Security

The mirror and mDNS are read-only; the only component that writes to Cloudflare is the
dynamic-DNS writer, which is disabled and in dry-run by default. The service runs as an
unprivileged, capability-bounded, sandboxed systemd unit, and no site-private data
ships in the repo or the `.deb`. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Uninstalling

```sh
sudo systemctl disable --now splitdnsd
sudo apt remove splitdnsd        # add --purge to also remove config/state
```

## License

[MIT](LICENSE) © 2026 gutschke.

Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
