# Configuration

`splitdnsd` reads one TOML file (default `/etc/splitdns/splitdnsd.toml`). Every key is
optional and falls back to a safe default; the annotated
[`examples/splitdnsd.example.toml`](../examples/splitdnsd.example.toml) is the quickest
reference, and `splitdns.conf(5)` is the formal one. Always validate before
(re)starting:

```sh
splitdnsd -config /etc/splitdns/splitdnsd.toml -check-config
```

`-check-config` prints the resolved listen set and reverse zones, so it doubles as a
sanity check that you are binding where you think you are.

---

## `[listen]`

Where the daemon answers.

```toml
[listen]
mode = "private-auto"        # or "explicit"
# addresses = ["192.0.2.1:53", "[2001:db8::1]:53"]   # required for mode="explicit"
port = 53
udp  = true
tcp  = true
```

- **`private-auto`** (default) binds every *local-scope* address on the host — RFC 1918
  / ULA / loopback / link-local — and never a global one. Convenient, but it binds
  **all** such addresses, including secondaries.
- **`explicit`** binds exactly the `addresses` you list. Use this when you want the
  daemon on **one specific address** — e.g. to run it in parallel with an existing
  resolver during validation (see [deployment.md](deployment.md)).

> Binding `:53` needs `CAP_NET_BIND_SERVICE`; the packaged systemd unit grants it.

## `[access]`

Client allow/deny (a refuse match beats an allow match).

```toml
[access]
allow  = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
          "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10"]
# refuse = ["198.51.100.0/24"]
```

The default allows every private/local range — all three RFC 1918 blocks (including
`192.168.0.0/16`, the most common home LAN), loopback, link-local, and IPv6 ULA.
Narrow it to specific subnets if you prefer. Queries from a non-allowed client get
REFUSED.

## `[upstream]`

Forwarding of everything that is not answered locally.

```toml
[upstream]
servers            = ["1.1.1.1", "8.8.8.8"]   # DoT; tried in order
cleartext_fallback = false                     # audited UDP/TCP fallback; off by default
breaker            = true                       # per-upstream circuit breaker
```

- Transport is **DoT** (DNS-over-TLS, port 853). A `host` becomes a DoT endpoint plus a
  cleartext fallback target; pass `host@servername` if a server's TLS name differs.
- **`cleartext_fallback`** permits one audited plaintext retry when DoT fails. Off by
  default; turn it on only if you accept the downgrade.
- **`breaker`** skips an upstream that is down or flapping so queries fail over to a
  healthy one fast, without paying its timeout. It fails open (never worse than no
  breaker) and probes recovery after a short cooldown.

## `[zones]`

What the resolver is authoritative for or delegates.

```toml
[zones]
local          = ["example.com", "example.net"]   # mirrored from Cloudflare (read-only)
reverse        = ["2.0.192.in-addr.arpa.", "8.b.d.0.1.0.0.2.ip6.arpa."]
reverse_detect = "off"                             # off | private | global | all

[zones.stub]
# "internal.example.com." = ["192.0.2.53:53"]      # delegate a subtree to a LAN resolver
```

- **`local`** lists the zones to mirror authoritatively (requires a Cloudflare read
  token — see `[cloudflare]`). Without the token these names simply forward.
- **`reverse`** are PTR zones you are authoritative for, written octet/nibble-reversed
  (`192.0.2.0/24` → `2.0.192.in-addr.arpa.`). All other PTRs forward.
- **`reverse_detect`** can additionally auto-detect (and re-detect on network change)
  reverse zones from local interfaces — useful to track a changing ISP-assigned IPv6
  prefix (`global`).
- **`[zones.stub]`** forwards a delegated subtree to a specific resolver over plain
  UDP/TCP (these are trusted LAN resolvers, not DoT, and are not rebind-filtered).

## `[mdns]`

The LAN plane: local names served from a passive mDNS view, how long records survive,
and whether the daemon actively resolves and browses services.

```toml
[mdns]
local_domain   = "lan"     # unicast local domain served alongside *.local; "" = *.local only
stale_grace    = "30m"     # keep serving past the announced TTL; "0" disables
goodbye_grace  = "5m"      # cushion after an mDNS goodbye (reflector/avahi bounce)
resolve_on_demand = true   # query a targeted mDNS name on first ask for an unknown host
resolve_on_demand_wait = "300ms"   # how long to wait for a reply (clamped 50ms..2s)
serve_dnssd       = true   # answer SRV/TXT/PTR for local services over unicast
service_discovery = true   # actively browse services (only while the console is open)
```

- **`local_domain`** (default `lan`) serves `host.lan` from the same mDNS view as
  `host.local`, so a client that accepts only a single search domain can still reach LAN
  hosts by a real name. A reverse (PTR) query for a LAN address returns one canonical name
  under this domain. Set `""` to serve `*.local` only.
- **`stale_grace`** / **`goodbye_grace`** — the mDNS cache is a *passive* listener that
  expires a record at its announced TTL. If an announcer (or a mDNS reflector) re-broadcasts
  more slowly than that TTL, `stale_grace` keeps serving the last value so hosts don't blink
  out; `goodbye_grace` cushions a transient goodbye (a sleeping device, an avahi restart) so
  a bounce-then-reannounce is seamless. If you run `splitdns-notify`, keep its `-ttl` above
  its re-announce interval.
- **`resolve_on_demand`** (default on) — when a client asks for an *unknown* local host,
  the daemon multicasts a targeted mDNS query and waits `resolve_on_demand_wait`, so a quiet
  device (a printer or NAS not currently announcing) is found on the first ask instead of
  returning NXDOMAIN. It is heavily bounded — global and per-client rate limits, an in-flight
  cap, and recently-queried suppression — and **never queries a managed name** (a vhost, a
  mirrored, or a DDNS-eligible name), so a solicited reply can never move a Cloudflare
  record. Set `false` to keep the pure "unknown → NXDOMAIN" behavior with no active queries.
  See the [trust model](../SECURITY.md#on-demand-mdns-resolution-and-dns-sd) before relying
  on it on a shared segment.
- **`serve_dnssd`** (default on) — local names also answer SRV/TXT/PTR synthesized from the
  passively captured mDNS services, so a LAN client can resolve or browse services (e.g.
  printers) by **unicast**, including across VLANs where multicast doesn't reach. It is a
  read-only projection of the cache and never sends a query. Set `false` to serve only
  A/AAAA on the local domain.
- **`service_discovery`** (default on) — actively browse the LAN with the standard Bonjour
  service-discovery query so quiet devices and their services surface. Querying is
  **on-demand**: it runs only while the diagnostics console is open, so there is zero active
  multicast when nobody is watching. Set `false` to stay a pure passive listener.

## `[vhost]`

Redirect bare-domain / `www` / known virtual-host names at an internal reverse proxy.

```toml
[vhost]
feed          = "192.0.2.10:818"          # newline-separated names served by the reverse proxy
proxy_v4      = "192.0.2.10"
proxy_v6      = "2001:db8::10"
exclude_zones = ["excluded.example"]       # apexes NOT redirected (serve real records)
```

For a mirrored zone, an address query for the apex, `www`, or a name in the `feed`
returns the reverse-proxy address; the apex's non-address RRsets (MX/TXT/…) stay real. Zones in
`exclude_zones` are served authoritatively instead (e.g. an apex that is itself a
tunnel). Omit the whole section if you do not run an internal reverse proxy.

## `[cloudflare]` — optional

Only needed to mirror Cloudflare-hosted zones. See `[deployment.md](deployment.md)` and
the **token handling** rules below.

```toml
[cloudflare]
read_token_file = "/etc/splitdns/secrets/cf-read.token"   # Zone:Read + DNS:Read
edit_token_file = ""                                       # DNS:Edit; empty = no DDNS
```

Without a readable read token the mirror is disabled and `local` zones forward.

## `[ddns]` — optional, off by default

Guarded dynamic-DNS write-back. See [deployment.md](deployment.md) for the safe arming
procedure.

```toml
[ddns]
enabled         = false
dry_run         = true
rate            = "10m"
eligible        = []                              # REQUIRED allowlist; empty = deny-all
trusted_sources = []                              # CIDRs whose mDNS may trigger writes
notify_socket   = "/run/splitdns/notify.sock"     # authenticated local trigger
# notify_uids   = [0]
```

Writes require: `enabled=true`, `dry_run=false`, a non-empty `eligible` allowlist, and
an authenticated trigger (the peer-credential-checked socket, or a `trusted_sources`
network). An empty `eligible` forces dry-run.

### Internal LAN names vs the public Cloudflare zone (the scoping story)

There are **two separate databases**, and a host name lands in one, the other, or both —
never by accident:

- **Internal LAN** (the in-memory mDNS view, and later DHCP): `*.local` forward names and
  reverse PTRs for LAN addresses. These are served **authoritatively on the LAN only** and
  are **never written to Cloudflare**. They also feed the opportunistic host-name
  annotations on the diagnostics page. This database updates itself live as hosts appear.
- **Public Cloudflare zone** (the mirror for reads; DDNS for writes). Write-back to
  Cloudflare is **triple-gated** so internal data can't leak out:
  1. **Public addresses only** — a private/RFC-1918/ULA/link-local address is dropped
     (`no-public-addrs`); a host announcing only its LAN IP never touches Cloudflare.
  2. **`eligible` allowlist** — only host FQDNs you explicitly list are written
     (`not-eligible` otherwise). This is the master scoping knob.
  3. **Authenticated trigger** — the announcement must arrive via the peer-cred socket or
     a `trusted_sources` network.

So the rule of thumb is simple: **to keep a host LAN-only, just don't put it in
`eligible`** — mDNS serves it internally and it stays off Cloudflare. **To publish a
host's public IP, add it to `eligible`.** Its LAN address still never propagates; only the
public one does.

**Verify before you arm it.** Use the diagnostics **[DDNS simulate](diagnostics.md#ddns-simulate)**
tool — it shows exactly what (if anything) write-back *would* send to Cloudflare for a
given host, without writing, even while DDNS is disabled. A LAN-only host should read
`not-eligible` or `no-public-addrs`; a published host should read `would-apply` with the
expected `update`/`create` calls. (When DHCP-sourced hostnames land later, they plug into
the same internal view and the same gates — no new leak path.)

## `[cache]`

Two things live here: the on-disk **warm-start** cache (Cloudflare zone data, for a
fail-static cold start) and the in-memory **answer cache** for forwarded queries.

```toml
[cache]
dir         = "/var/lib/splitdns"  # warm-start cache directory
answers     = true                 # forward-path answer cache (default on)
serve_stale = true                 # serve stale on upstream failure, RFC 8767 (default on)
max_entries = 10000                # answer-cache LRU capacity
```

The answer cache caches forwarded responses by their TTL (floored at 5s, capped at 24h),
negatively caches NXDOMAIN/NODATA from the SOA minimum (RFC 2308), briefly caches
SERVFAIL to spare a flapping upstream (RFC 9520), and — with `serve_stale` — keeps
answering from an expired entry when the upstream is failing (RFC 8767, 30s stamped TTL,
24h retention) instead of returning SERVFAIL. Authoritative/local answers are never
cached. Live stats (hit ratio, stale serves, evictions, …) appear on the
[diagnostics console](diagnostics.md#answer-cache). Set `answers = false` to forward
every query (no caching).

<a id="cache"></a>

## `[diag]`

The diagnostics HTTP endpoint. The read-only views are always on; the mutating control
actions are off by default. Full reference: **[diagnostics.md](diagnostics.md)**.

```toml
[diag]
addr = "127.0.0.1:8080"    # host:port, OR a Unix socket: "/run/splitdns/diag.sock"
# allow = ["10.0.0.0/8"]   # optional source-IP allow-list (read + control); empty = all

# DANGEROUS control actions (flush cache / force mirror refresh / restart / backend) — off by default:
# allow_control         = false
# control_password_file = "/etc/splitdns/secrets/diag.pass"   # 0400; or control_password = "..."
```

A **Unix socket** (`addr` starting with `/` or `@`, or `unix:/path`) is local-only and
filesystem-permission-controlled (mode 0660) — the best way to keep the endpoint private
while fronting it with nginx/socat, and it counts as loopback for the control gate.

When `allow_control` is set, the actions are POST-only and authorized by a matching
`control_password`/`control_password_file` **or** — with no password — only on a loopback
bind. Enabling it on a non-loopback bind with no password is refused. The endpoint is
plain HTTP, so a password guards against casual/CSRF misuse, not an eavesdropper — see the
[security notes](diagnostics.md#enabling-and-authorizing).

## `[encrypted]` — optional, off by default

Opt-in **DNS-over-TLS** (RFC 7858) and **DNS-over-HTTPS** (RFC 8484) listeners for LAN
clients, plus **DDR** (RFC 9462) advertising so capable clients auto-upgrade to *this*
resolver instead of defecting to a public one. Full walkthrough (certificate, DNR recipe,
verification): **[encrypted-dns.md](encrypted-dns.md)**.

```toml
[encrypted]
enabled   = true
cert_file = "/etc/splitdns/tls/adn.crt"    # PEM chain for the ADN
key_file  = "/etc/splitdns/tls/adn.key"    # 0400 splitdns:splitdns
adn       = "dns.example.net"              # Authentication Domain Name (a cert SAN)
# advertise_ddr = true                     # synthesize _dns.resolver.arpa SVCB
[encrypted.dot]
enabled = true
port    = 853
[encrypted.doh]
enabled = true
port    = 443
path    = "/dns-query"
```

The encrypted listeners reuse the exact `:53` pipeline, so `[access]`, the answer cache,
and the rebinding filter apply unchanged. `mode`/`addresses` mirror `[listen]` (empty
inherits it). A missing, unparsable, or expired certificate degrades to **Do53-only**
rather than taking DNS down, and withdraws the DDR advert. The cert is hot-reloaded on
`SIGHUP` or file change, and `-check-config` hard-fails on a bad one. The **ADN must
resolve to this resolver's LAN addresses** — `splitdnsd` answers it authoritatively via
split-horizon.

---

## Token handling (read this before configuring Cloudflare)

- Use **scoped** tokens with the least privilege that works: a read token
  (`Zone:Read` + `DNS:Read`) for the mirror, and a separate `DNS:Edit` token scoped to
  only the zone(s) you allow write-back to.
- Store each token in **its own file**, mode `0400`, owned by the `splitdns` account.
- **Never** put a token value in the config, the repository, or anywhere shared — the
  config holds only the file *paths*. Treat any leaked token as compromised and roll it.
