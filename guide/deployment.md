# Deployment

`splitdnsd` is useful at three increasing levels; pick the highest you need. Then,
before pointing real clients at it, validate it **in parallel** with your existing
resolver so nothing on your network is at risk.

## Modes

| Mode | Needs | Gives |
|------|-------|-------|
| 1. Forwarder + LAN names | nothing external | DoT forwarding, access control, local names (`.lan` / `.local` via mDNS) with on-demand resolution and unicast DNS-SD, reverse zones, stub zones, rebind protection |
| 2. + Cloudflare mirror | a read-only scoped token | your CF-hosted zones served authoritatively on the LAN with direct/internal addresses; tunnel/proxy flattening; vhost redirect |
| 3. + Dynamic-DNS write-back | a `DNS:Edit` token | push a changing WAN address into specific CF records |

Modes 2 and 3 are opt-in. Without a Cloudflare token, mode-2 zones simply forward;
dynamic-DNS is disabled and in dry-run by default.

## Install

The build produces **two** packages:

| Package | Installs | Use on |
|---------|----------|--------|
| `splitdnsd` | the server binary, systemd unit, example config, man pages | the resolver host |
| `splitdns-notify` | only the `splitdns-notify` helper + its man page (one static binary, no service, no user, no config) | any host that announces itself to the resolver |

```sh
./scripts/build-deb.sh                       # -> dist/splitdnsd_<ver>_amd64.deb
                                             #    dist/splitdns-notify_<ver>_amd64.deb
sudo apt install ./dist/splitdnsd_*.deb      # the server (also pulls in splitdns-notify)
```

Use `apt install ./…deb`, **not** `dpkg -i` — `dpkg` ignores `Recommends`, so the optional
`ieee-data` package (OUI database that gives manufacturer names in the diagnostics host
panel) won't be pulled in. It's optional: without it, host enrichment still works but shows
raw MACs instead of vendors. If you did use `dpkg -i`, run `sudo apt install ieee-data`
(or `sudo apt-get -f install`).

The `splitdnsd` package creates the unprivileged `splitdns` account and `/etc/splitdns`,
`/etc/splitdns/secrets`, `/var/lib/splitdns`, and installs a hardened unit. It does not
ship a live config and does not start the service.

### `splitdns-notify` on other hosts

Hosts that only need to *announce* their name/address to the resolver — to refresh its
LAN view or trigger guarded dynamic-DNS write-back — should install the standalone
`splitdns-notify` package **instead of** the server. It carries no server binary, no
systemd unit, and creates no `splitdns` user, so the server cannot be started there even
by accident:

```sh
sudo apt install ./dist/splitdns-notify_*.deb   # just the helper; no server
splitdns-notify host1 203.0.113.45              # announce this host to the resolver
```

`splitdnsd` *Recommends* `splitdns-notify`, so a normal server install pulls the helper
onto the resolver host too; the two packages are otherwise independent and co-installable.

With no configuration at all, `splitdns-notify` tries the resolver's local unix socket
first, then multicasts to the LAN — so on the resolver host it just works. For an off-box
notifier, point it at the resolver and skip the (absent) local socket:

```sh
splitdns-notify -no-socket -server resolver.lan host1 203.0.113.45
```

To avoid repeating flags, drop a `/etc/splitdns/notify.toml` (see the package's
`notify.example.toml`) with a `[notify] servers = ["resolver.lan"]`. Use `-v`/`--verbose`
to see which config was used, whether the announcement was signed, and the per-path result.

### Letting non-root local services trigger (no key) — `notify_groups`

A process on the **resolver host itself** (nginx, the DHCP client, a deploy script) can
trigger DDNS through the local socket without being root and without any key. Name the
service's group under `[ddns]`:

```toml
[ddns]
notify_groups = ["www-data", "dhcp"]   # members may trigger via the socket
```

The daemon stamps a POSIX ACL on `/run/splitdns/notify.sock` granting those groups, and
authorizes a connecting peer by membership — so the moment splitdnsd restarts, anything
running as `www-data` or `dhcp` can run `splitdns-notify host …` and it works. No
`usermod`, no `SupplementaryGroups=`, no key, no `CAP_CHOWN` (the daemon owns the socket,
so setting the ACL needs no privilege).

> **Guardrail:** name a service's *dedicated* group, never `splitdns` (its group also
> unlocks `/etc/splitdns` and the secrets there) and never a broad group like `users`.
> Membership is read from the local group database (not LDAP/SSS). On a filesystem without
> ACL support the option is logged and skipped — DNS is unaffected.

For a caller in a **different container or on another host**, the socket can't reach it;
use TSIG below.

### Authenticating DDNS triggers across hosts (TSIG)

An off-box announcement is delivered as fire-and-forget UDP — by design, so it can never
block on a slow or down resolver. But which announcements may *trigger* a DDNS write is a
trust decision. There are two cross-host options:

- **`trusted_sources` (source-IP trust)** — quick to set up, but a UDP source address can
  be spoofed, so anyone able to originate from a trusted address could attempt a trigger.
  Fine on a tightly controlled LAN; weak for anything exposed.
- **TSIG signing (cryptographic, recommended)** — a shared HMAC key (RFC 8945) signs each
  announcement, so the resolver authenticates it *regardless of source IP*. Spoofing the
  source no longer helps. It stays a single unsigned-vs-signed UDP datagram — no handshake,
  no blocking.

TSIG is opt-in and made deliberately painless. Mint a key (prints both ends' config):

```sh
splitdns-notify --genkey edge-router
```

Put the `[notify]` block on the notifier (ideally with `tsig_secret_file` pointing at a
mode-0400 file) and the `tsig_keys` entry under `[ddns]` on the resolver. To *require*
signing — so `trusted_sources` alone can no longer trigger a write — also set:

```toml
[ddns]
require_signature = true
```

This keeps `*.local` view updates relaxed (any announcement still refreshes the LAN view);
only the privileged DDNS-write trigger demands the key.

## Validate in parallel (recommended for every install)

The goal: run the new resolver **on one address only**, with **no write path**, while
your current resolver keeps serving everything else. Then compare answers and confirm
the rest of the network is untouched.

1. **One address.** Use explicit listen so the daemon answers on a single test address
   (not every local-scope address):

   ```toml
   [listen]
   mode = "explicit"
   addresses = ["192.0.2.50:53", "127.0.0.1:53"]
   ```

2. **No write path.** Install only the read token; leave `edit_token_file = ""` and
   remove any edit token from the host. With no edit token the dynamic-DNS writer
   cannot even be constructed, so writes are structurally impossible.

3. **Check, then start.**

   ```sh
   sudo -u splitdns splitdnsd -config /etc/splitdns/splitdnsd.toml -check-config
   # confirm the listen set is EXACTLY your test address(es)
   sudo systemctl start splitdnsd
   journalctl -u splitdnsd -f
   ```

4. **Compare answers** against your existing resolver and the public Internet:

   ```sh
   dig @192.0.2.50 www.example.com A +short      # expect the internal/direct answer
   dig @192.0.2.50 example.com A +short          # apex -> reverse proxy, if vhost configured
   dig @192.0.2.50 -x 192.0.2.10 +short          # reverse
   dig @192.0.2.50 somehost.local A +short       # mDNS
   dig @192.0.2.50 example.org A +short          # plain forwarding
   dig @<old-resolver> www.example.com A +short  # parity where it should match
   ```

5. **Confirm isolation.** From another host, the new server must answer **only** on the
   test address; queries to any other address it might have should time out, and your
   old resolver must still answer.

Point a couple of *test* clients (hand-set DNS) at it and live with it for a while,
watching the logs and the diagnostics endpoint.

## Cut over

Once parallel validation looks right:

1. Choose the production listen set (`private-auto` to serve all local addresses, or
   `explicit` for specific ones).
2. Move clients to the new resolver (DHCP option 6 / router DNS), or take over the old
   resolver's address.
3. `sudo systemctl enable --now splitdnsd`.
4. Disable the old resolver.
5. Re-run the smoke tests against the production address.

## Arm dynamic-DNS write-back (last, optional)

Do this only after the resolver itself is stable. It is the only path that writes to
Cloudflare.

1. Install the `DNS:Edit` token (scoped to only the zone you allow writes to):

   ```sh
   printf '%s' "$CF_EDIT_TOKEN" | sudo tee /etc/splitdns/secrets/cf-edit.token >/dev/null
   sudo chmod 0400 /etc/splitdns/secrets/cf-edit.token
   sudo chown splitdns:splitdns /etc/splitdns/secrets/cf-edit.token
   ```

2. Configure with **dry-run first** and a non-empty allowlist:

   ```toml
   [cloudflare]
   edit_token_file = "/etc/splitdns/secrets/cf-edit.token"

   [ddns]
   enabled  = true
   dry_run  = true
   eligible = ["host1.example.com", "host2.example.com"]   # empty = deny-all
   # Authorize the trigger: a key (recommended) and/or a source CIDR.
   # tsig_keys = [{ name = "edge-router", secret_file = "/etc/splitdns/secrets/edge-router.tsig" }]
   # require_signature = true        # reject unsigned triggers once the key is in place
   # trusted_sources = ["10.0.0.0/24"]
   ```

3. Trigger a test announcement and confirm the audit log shows the intended edit but
   makes none (from an off-box notifier, sign it; on the resolver host the socket path
   needs nothing extra):

   ```sh
   sudo splitdns-notify host1 203.0.113.45
   journalctl -u splitdnsd | grep ddns        # outcome=dry-run + the planned change
   ```

4. When the dry-run plan is correct, set `dry_run = false`, restart, and verify a real
   change propagates to Cloudflare.

## Rollback

```sh
sudo systemctl stop splitdnsd
sudo systemctl start <old-resolver>
```

Nothing in the parallel-validation phase is persistent or external (read-only mirror,
no writes), so rollback is just stopping the service.
