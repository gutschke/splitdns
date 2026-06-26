# Diagnostics console

`splitdnsd` exposes a built-in diagnostics endpoint over HTTP — a single, live-updating
page (and a JSON twin) that shows what the resolver is doing right now. It is meant for
building confidence before cut-over and for debugging when something looks wrong.

> **Scope: this is a LAN-grade convenience tool, not a hardened production surface.** It
> speaks plain HTTP with no built-in user authentication; its "auth" is *where you bind
> it* (loopback / Unix socket / IP allow-list) plus an optional shared control-password.
> For a real/public deployment, **do not enable `[diag]` openly** — leave it on loopback
> or a Unix socket and put it behind a proper authenticating front-end (a TLS-terminating
> reverse proxy with real auth/SSO), or simply turn it off. Treat everything below as
> "fine on a trusted LAN; not a substitute for an access-control system."

- **HTML:** `http://<diag-addr>/` (default `http://127.0.0.1:8080/`) — auto-refreshes
- **JSON:** `http://<diag-addr>/diag.json` — the same data, machine-readable
- **Liveness:** `http://<diag-addr>/healthz` — `ok` / `degraded`, for monitors

The page **updates itself live** (polls `/diag.json` every few seconds) without ever
reloading or scrolling — and it pauses an update for any table you're actively selecting
text in or typing into, so a copy/paste is never yanked out from under you. The live
regions include the cache stats, queries, backends, workers, and the **mDNS
forward/reverse** tables; opportunistic client **host-name** annotations refresh as mDNS
(and, later, DHCP) learns them. Rarely-changing sections (zone inventory, reverse zones,
stub, vhost) refresh on a manual page reload.

Configure the bind address with `[diag] addr` (see [configuration.md](configuration.md)
and `splitdns.conf(5)`). The read-only views are **always available**; the mutating
[control actions](#control-actions-dangerous) are off by default.

> The page exposes your internal zone inventory and **per-client query stream** (who
> looked up what). On a trusted single-tenant LAN that's harmless and useful for
> debugging. On a shared/untrusted segment it's a privacy and recon concern — restrict it.

### Binding and access control

`addr` may be:
- a `host:port` (default `127.0.0.1:8080`). `0.0.0.0` binds IPv4-only here (not
  dual-stack); `[::]` binds IPv6-only.
- a **Unix socket** — a path beginning with `/` or `@`, or `unix:/path`. It's local-only,
  filesystem-permission-controlled, and plugs straight into nginx/socat. This is the
  cleanest way to keep the endpoint private while still reachable behind a proxy. The
  socket mode defaults to **0660**; set **`[diag] socket_mode = "0666"`** when a reverse
  proxy in another container must reach it across a uid boundary.

> **The diag endpoint is best-effort.** If it can't bind — a missing or non-writable
> socket directory, a stale socket, a permission error on a shared reverse-proxy path —
> the daemon logs a warning and **keeps serving DNS**. Losing diagnostics is benign by
> design; DNS service is never put at risk for it. (A `:53` bind failure, by contrast, is
> fatal — DNS is the job.)
>
> *Reverse-proxy recipe:* bind `addr = "/run/splitdns-diag/diag.sock"` in a directory
> shared with your proxy container, set `socket_mode = "0666"` (or arrange matching
> uid/gid), and point nginx at it: `proxy_pass http://unix:/run/splitdns-diag/diag.sock:/;`
> with your auth in front. If the shared dir isn't ready at boot, DNS still comes up and
> the socket appears once the path is usable on the next restart.

Two extra guards:
- **`[diag] allow`** — a CIDR list; when set, only those source IPs may connect (read or
  control), everything else gets 403. Unix-socket clients are always allowed. It's a
  coarse guard (IPs can be spoofed), not authentication.
- For real authentication, front it with a **TLS-terminating authenticating reverse
  proxy** (proxying to the Unix socket), or reach a loopback bind over an **SSH tunnel**.

## Read-only views

### Cloudflare mirror health
`healthy` when the last mirror build succeeded; `degraded (serving stale)` when it is
serving the warm cache pending a refresh. Each zone shows its serial and `STALE` /
`SYNTHETIC-STALE` flags.

### Answer cache
The forward-path answer cache (see [configuration.md](configuration.md#cache)).
Surfaced counters:

| Field | Meaning |
|-------|---------|
| hit ratio | hits / (hits + misses) — cache effectiveness |
| entries | live entries / capacity (LRU) |
| hits / misses | lookups served from cache vs forwarded |
| stale serves | RFC 8767 activations — a rising count means upstream trouble |
| servfail hits | RFC 9520 failure-cache hits — a flapping upstream |
| inserts / evictions | churn; steady evictions mean the cache is undersized |

### Queries
A rolling ring of the most recent queries plus per-client aggregates:

- **totals + by-decision** — how many queries, and how they resolved
  (`local`, `cache`, `stale`, `forward`, `stub`, `refused`, `servfail`, `dropped`).
- **busiest clients** — who is asking the most, with the client's **name** when we can
  resolve it locally (from the mDNS reverse view or a cached PTR — never a fresh lookup),
  and when they were last seen.
- **recent queries** — time, client (IP + resolved name), name, type, decision, rcode,
  latency (ms). **Click any column header to sort.**

This is in-memory only (cleared on restart) and holds nothing beyond the question
name/type and the client address.

### Upstreams (circuit breaker)
Per-upstream health from the forwarder's circuit breaker.

**Selection is sequential failover:** a query goes to the **first healthy upstream in
order**; if it fails or its breaker is open, the next is tried, and so on. It is *not*
round-robin and *not* query-all-take-first. (If every upstream is tripped, the breaker
fails open and tries them anyway, so it's never worse than having no breaker.)

- **state** — `closed` (healthy), `open` (tripped — failing fast, queries skip it),
  `half-open` (probing recovery), or `disabled` (manually disabled — see below).
- **consecutive failures**, **fail ratio** (rolling window), **tripped for**, and
  **cooldown** remaining before the next recovery probe.

When controls are enabled, each row has a **disable/enable** button to take an upstream
out of (or back into) rotation on the fly — handy for forcing traffic onto a specific
backend while debugging. A disable lasts until you re-enable it or the daemon restarts;
**Reset backend overrides** clears them all.

### Workers (supervisor)
Per-worker **restarts**, **stalls**, **panics**, and time since last progress. Non-zero
restart/stall/panic counts are flagged — a quick way to spot a misbehaving subsystem.

## Self-tests

`GET /selftest` (linked from the top of the page) runs a set of **active but
non-mutating** probes and reports pass/fail with timing — a quick "is everything wired
right?" before cut-over. It probes fixed targets only (no user-supplied destinations) and
is rate-limited.

| Check | What it confirms |
|-------|------------------|
| `upstream-resolve` | a live query to the configured upstreams succeeds (real DoT path, through the breaker) |
| `cloudflare-token` | the read token is valid and how many zones it can see (or "skipped" if none) |
| `local-resolve` | the in-process resolver answers from the snapshot (the synthetic health record) |
| `answer-cache` | the answer cache is enabled and its current size |

`GET /selftest` returns HTML (when your browser asks) or JSON for scripting:

```sh
curl -fsS http://127.0.0.1:8080/selftest | jq .
```

### DDNS simulate

`GET /ddns-simulate?host=<short-host>&addr=<ip>[&addr=<ip>…]` (there's a small form on the
page) shows the **exact Cloudflare API calls dynamic-DNS write-back *would* make** for a
host announcement — **without making them**, and **even when DDNS is disabled**. It runs
the real planning path (public-address filter → eligibility allowlist → minimal-edit
plan) and reports the outcome (`would-apply` / `unchanged` / `no-public-addrs` /
`not-eligible`) plus each `update`/`create`/`delete` (Cloudflare object IDs redacted), with
a one-line note guiding your next step. It never writes, and never bypasses the
public-address safety filter (a private/LAN address is always dropped).

> **What write-back actually does:** it *updates a host's existing non-proxied A/AAAA
> records* to track a changing public IP. It does **not** create new hostnames, and does
> **not** manage other record types — MX/TXT/CNAME are static records you configure in
> Cloudflare (splitdns mirrors them read-only). So simulate a host that **already has an
> A/AAAA record** (a record-less name like `testing` correctly reports `not-eligible`,
> with nothing to update). To check what records a name resolves to, use the zone
> inventory on this page or `dig` it.

Two modes, chosen by the two buttons on the form:

| Mode | What it shows | When to use |
|------|---------------|-------------|
| **As configured** | exactly what write-back does with your *current* policy | confidence check before/after arming DDNS |
| **Explore (ignore allowlist)** | the plan *as if this host were on `[ddns] eligible`* | planning — before you've built the allowlist |

Explore is a **what-if**: it ignores the eligibility allowlist so you can see the API calls
*before* you've configured one (its result is clearly marked, and still never writes). So a
typical setup flow is: run **Explore** to see what a host *would* do, confirm it's right,
then add it to `[ddns] eligible` and re-run **As configured** to confirm it now matches.

The calls are listed **in execution order — updates, then creates, then deletes** —
applied that way so the name keeps resolving throughout the change (no NXDOMAIN gap).
Write-back **converges** the host's records to *exactly* the announced public addresses, so
a `delete` appears for any current address you didn't announce (it cleans up stale IPs);
announce all the addresses you want to keep.

```sh
curl -fsS 'http://127.0.0.1:8080/ddns-simulate?host=edge&addr=203.0.113.7' | jq .          # as configured
curl -fsS 'http://127.0.0.1:8080/ddns-simulate?host=edge&addr=203.0.113.7&explore=1' | jq . # explore (ignore allowlist)
```

## Control actions (DANGEROUS)

These **mutate** running state and are therefore gated. They are **off by default**.

| Action | Effect |
|--------|--------|
| Flush answer cache | drop every cached answer AND zero the cache counters (fresh hit-ratio) |
| Force mirror refresh | restart the mirror worker → re-fetch zones from Cloudflare |
| Restart daemon | graceful shutdown; systemd (`Restart=always`) brings it back |
| Disable/enable backend | take an upstream out of / back into rotation (until reset/restart) |

**Lock/unlock UX:** when a `control_password` is configured, a **`controls: locked`
chip** sits in the sticky top strip (visible no matter where you've scrolled) and every
control button is greyed. Enter the password in the `<input type="password">` (your
**browser/password-manager can autofill and save it**) and click **Unlock**: the page
makes a single side-effect-free `POST /control/verify` to confirm the password, then
flips the chip to `controls: unlocked` and enables the buttons. The value is held for the
browser **session** (`sessionStorage`, cleared when you close the tab) and replayed as the
`X-Diag-Password` header on each action — no re-typing per click; a **Lock** button clears
it. Clicking any greyed control (e.g. an upstream **disable** button far down the page)
scrolls you to the password field and highlights it, so you never click into a dead end.

Every action gives **inline feedback** next to its own button — `working…` while in
flight (so "slow" is never mistaken for "failed"), then a specific result: `done`,
`incorrect password — re-enter` (which re-locks and refocuses the field),
`rate-limited — retry shortly`, the server's reason for a 4xx/5xx, or `request failed`
for a network error. No modal pop-ups.

### Enabling and authorizing

Set `[diag] allow_control = true`. Once enabled, every action is:

1. **POST-only** — a GET (or a stray `<img>` tag) can never trigger one.
2. **CSRF-guarded** — cross-site browser requests are rejected via Fetch Metadata
   (`Sec-Fetch-Site`), so a malicious page you happen to visit cannot drive the control
   plane even on a no-password loopback bind. The in-page form (same-origin) and
   non-browser clients like `curl` are unaffected.
3. **Authorized** by either:
   - a matching **`control_password`** / **`control_password_file`** (sent as the
     `X-Diag-Password` header or a `password` form field, compared in constant time), or
   - when **no password is set**, a **loopback bind only**. A bind to a **hostname** (or
     a wildcard like `0.0.0.0`/`[::]`) counts as **non-loopback** — only a literal
     loopback IP qualifies (fail-closed).
4. **Rate-limited** — `refresh-mirror` and `restart` are capped at once per 10s so even
   an authorized client can't restart-loop the daemon or hammer the Cloudflare API.
   `flush-cache` and the backend enable/disable toggles are **not** interval-limited (the
   toggle is a deliberate operator action you may want to do back-to-back — disable one
   upstream, immediately enable another).
5. **Throttled against guessing** — consecutive **wrong passwords** trip a shared
   exponential backoff (a short grace, then `1s, 2s, 4s … 30s`) that applies to
   `/control/verify` **and** every real action alike, so the side-effect-free verify probe
   can't be used as a friction-free brute-force oracle. A correct password resets it. The
   backoff is global and exponential (not a hard lockout) so a LAN attacker can slow — but
   not fully deny — the operator. (The `verify` endpoint exists only where controls do, is
   gated identically, and returns a 401 body indistinguishable from a failed real action.)

When `allow_control = true` on a **non-loopback** address with **no password**, the
control route (and `/control/verify`) is **not even registered** (and the condition is
logged loudly at startup) — dangerous actions are never exposed unauthenticated on the
LAN. In **loopback (no-password)** mode there is no lock chip, password field, or verify
step: the bind itself is the authorization.

> **Plain HTTP caveat:** the endpoint is not TLS. A password defends against casual and
> CSRF misuse, not a network eavesdropper. For real exposure, keep `addr` on loopback
> and reach it via an SSH tunnel, or front it with a TLS-terminating authenticating
> proxy. The strongest posture remains `allow_control = false`.

### From the command line

```sh
# loopback, no password:
curl -fsS -X POST http://127.0.0.1:8080/control/flush-cache

# with a password:
curl -fsS -X POST -H 'X-Diag-Password: <pw>' http://<addr>/control/refresh-mirror

# disable / re-enable / reset a backend:
curl -fsS -X POST 'http://127.0.0.1:8080/control/backend?op=disable&addr=1.1.1.1:853'
curl -fsS -X POST 'http://127.0.0.1:8080/control/backend?op=reset'

# over a Unix socket:
curl -fsS -X POST --unix-socket /run/splitdns/diag.sock http://x/control/flush-cache
```

## JSON for scripting

`GET /diag.json` returns every read-only section (`answer_cache`, `queries`,
`backends`, `workers`, zones, …). CF ZoneIDs/RecordIDs are redacted and no secrets are
ever included. The control actions are HTML/POST only and never appear in the JSON.

See also: [troubleshooting.md](troubleshooting.md) for reading these signals when
diagnosing a problem.
