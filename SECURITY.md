# Security policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub's
[private vulnerability reporting](https://github.com/gutschke/splitdns/security/advisories/new)
(the **Report a vulnerability** button under the repository's *Security* tab). Do not
open a public issue for a suspected vulnerability.

Include enough detail to reproduce (version, config shape with secrets redacted, and
the observed vs. expected behavior). You will get an acknowledgement, and a fix and
coordinated disclosure will follow.

## Scope and posture

`splitdnsd` is built to be safe by default:

- The query hot path performs no external I/O and reads immutable snapshots.
- Forwarding uses DoT; the cleartext fallback is off by default.
- Forwarded answers are DNS-rebinding filtered.
- Dynamic-DNS write-back is the only path that mutates an external account; it is
  disabled and in dry-run by default, requires a separately scoped `DNS:Edit` token, a
  non-empty eligibility allowlist (empty = deny-all), authenticated triggers, rate
  limits, and an audit log.
- The packaged systemd unit runs unprivileged, capability-bounded, and sandboxed.

Especially welcome: reports of a way to make the resolver answer a private/internal
address to an untrusted client, to trigger a Cloudflare write without authorization,
to bypass the rebinding filter, or to wedge resolution from off-path.

## Secrets

API tokens are never stored in this repository or the published package — they are
operator-supplied files on the deployed host. If you find a credential committed
anywhere in the project, please report it as above; treat any exposed token as
compromised and roll it immediately.

## Diagnostics control plane

The diagnostics console's mutating actions (cache flush, mirror refresh, restart, backend
toggle) are off by default and, when enabled, fail closed: the route is registered only
when `allow_control` is set **and** (a `control_password` is configured **or** the bind is
loopback-only). Deliberate design choices, recorded here so they are not "simplified" away:

- **The control password rides a custom request header (`X-Diag-Password`), held in
  `sessionStorage` and replayed per action — not a cookie/session token.** This is a CSRF
  decision, not an oversight: a cross-origin page cannot set a custom header on a simple
  request without a CORS preflight the server never grants, so the header *is* a primary
  CSRF defense (layered with the `Sec-Fetch-Site` check). A cookie would be sent
  automatically cross-site, collapsing that defense onto `Sec-Fetch-Site` alone and
  requiring `SameSite` + a CSRF token to regain parity — more moving parts for a
  self-contained page whose script surface (and thus XSS-exfil risk) is near zero. Keep
  the header model.
- **`POST /control/verify` is a side-effect-free auth probe** (so the UI can confirm
  "unlocked" without firing a real action). To stop it being a friction-free brute-force
  oracle, failed-password attempts trip a **shared global exponential backoff** across
  verify and every real action (constant-time compare first, then backoff applied to the
  failure path). It is exponential rather than a hard lockout so an unauthenticated LAN
  attacker can slow but not fully deny the operator.
- **`flush-cache` and backend enable/disable are intentionally not interval-rate-limited.**
  They are idempotent operator actions you may legitimately repeat back-to-back; the real
  abuse vector is password guessing, which the shared backoff (above) covers. Client-side
  button greying is cosmetic only — the server is the sole authority on every request.
