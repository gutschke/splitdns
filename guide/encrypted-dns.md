# Encrypted client DNS (DoT / DoH) and DDR

`splitdnsd` can terminate **DNS-over-TLS** (RFC 7858, port 853) and **DNS-over-HTTPS**
(RFC 8484, port 443) for LAN clients, and advertise itself as a **Designated Resolver**
(RFC 9462) so capable clients auto-upgrade from plaintext Do53 to the encrypted endpoint
of *the same resolver*. This keeps privacy-seeking clients on your split-horizon resolver
instead of silently defecting to a public DoH provider (which would not see your internal
zones).

It is **opt-in and off by default**, reuses the exact `:53` query pipeline (so `[access]`,
the answer cache, and the DNS-rebinding filter all apply unchanged), and adds no new
dependencies. A missing/expired certificate degrades to **Do53-only** rather than taking
DNS down.

## Who upgrades, and how

| Client | Mechanism | What you need |
|---|---|---|
| ChromeOS / Chrome | **DDR (RFC 9462)** — probes `_dns.resolver.arpa` | DoH (or DoT) + `advertise_ddr` |
| Android | **opportunistic DoT on :853** ("Private DNS: Automatic") | DoT on :853 |
| Android (strict) | "Private DNS provider hostname" | DoT + a valid cert for the ADN |
| systemd-resolved, `kdig`, … | manual DoT/DoH config | DoT/DoH endpoint + ADN cert |

Not implementing this changes nothing: clients that find no designated resolver simply
stay on Do53.

## Certificate (the ADN)

Discovery designates an **Authentication Domain Name** (ADN) — a hostname the client
validates the TLS certificate against. Use a **publicly-trusted** certificate for the ADN
from your existing ACME setup (this sidesteps the private-IP trust problem entirely):

1. Issue/renew a cert whose SAN is the ADN (e.g. `dns.example.net`).
2. Have your ACME **deploy-hook** copy the cert + key into a directory readable by the
   service user, e.g. `/etc/splitdns/tls/`, with the **key mode `0400 splitdns:splitdns`**.
   (Do *not* point `splitdnsd` at `/etc/letsencrypt/live/…` — the `splitdns` user can't
   traverse it.)
3. `splitdnsd` hot-reloads on `SIGHUP` or file change; it validates the new cert before
   swapping and never serves an expired one.

**Split-horizon requirement (critical):** the ADN **must resolve to this resolver's LAN
IPs** on the LAN, or the upgrade fails. `splitdnsd` answers the ADN's A/AAAA authoritatively
from the same address hints it advertises, so as long as clients use *this* resolver for
the ADN lookup it is automatic. Do not also publish the ADN publicly to a different address.

## Configure

```toml
[encrypted]
enabled   = true
cert_file = "/etc/splitdns/tls/adn.crt"
key_file  = "/etc/splitdns/tls/adn.key"
adn       = "dns.example.net"
# mode/addresses inherit [listen] by default (local-scope binds only).
# advertise_ddr = true
[encrypted.dot]
enabled = true
port    = 853
[encrypted.doh]
enabled = true
port    = 443
path    = "/dns-query"
```

Validate before deploying — this parses the cert and prints the resolved bind sets:

```sh
splitdnsd -check-config
```

## DNR via DHCP/RA (RFC 9463) — optional, operator-side

DDR (above) covers ChromeOS/Chrome and, with opportunistic DoT, Android — none of which
consume DNR. **DNR is optional** and involves **no `splitdnsd` code**: you inject DHCP/RA
options on your own infrastructure to push the encrypted-resolver designation directly.

- **DHCPv4 — option 162** (`v4-dnr`): carries Service Priority, the ADN (DNS wire form),
  the IPv4 hints, and SvcParams (ALPN, `dohpath`). Configurable in Kea (≈2.6+); use a
  built-in `option-def` where available, else a custom one.
- **DHCPv6 — option 144** (`OPTION_V6_DNR`): the v6 equivalent. Deliver via Kea DHCPv6
  with the RA **O-flag** set so clients fetch it. (systemd-networkd's RA does not yet emit
  DNR; that path is deferred.)

Keep the ADN, ports, and hints consistent with `[encrypted]`.

## Verify

```sh
# DDR SVCB (or NODATA when advertising is off / cert lapsed):
dig @<resolver> _dns.resolver.arpa SVCB +short
# DoT parity:
kdig -d @<resolver> +tls +tls-hostname=<adn> example.com
# DoH:
curl -sS -H 'accept: application/dns-message' \
  "https://<adn>/dns-query?dns=$(…base64url wire query…)" | xxd | head
```

- **Chrome/ChromeOS:** `chrome://net-internals/#dns` shows the auto-upgraded secure DNS
  resolver when "Automatic" is selected.
- **Android:** Settings → Network → Private DNS → "Automatic" uses opportunistic DoT on
  :853; "Private DNS provider hostname" = the ADN (validates the cert).
- **Cert-expiry drill:** let the cert approach expiry and confirm the WARN in the journal;
  an expired cert withdraws the DDR advert and fails encrypted handshakes, leaving Do53
  serving — no hard outage.

## Debugging from the diagnostics console

The console (see `guide/diagnostics.md`) surfaces everything needed to debug this feature
without shell access:

- **Encrypted & DDR panel** — the certificate (ADN, SANs, expiry, validity), the DoT/DoH
  listeners, the exact SVCB served at `_dns.resolver.arpa`, and an **upgrade-readiness
  checklist** (enabled / cert valid / ADN matches a SAN / listeners up / DDR advertising /
  ADN resolves to LAN hints) — so "why won't clients upgrade?" is answered at a glance.
- **Transport query tool** — issue a query at the resolver over Do53 / DoT / DoH and see
  the answer *plus the TLS handshake* (negotiated version, ALPN, peer cert). A cert or SNI
  problem shows up here immediately.
- **Per-query transport** — the recent-queries table has a `proto` column, plus a
  transport rollup and per-client lifetime protocol counts, so you can see which clients
  have actually moved to DoT/DoH and which are still on plaintext Do53.
