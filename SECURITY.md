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
