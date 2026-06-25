# Contributing

Thanks for your interest in `splitdns`. This document covers the basics for building,
testing, and submitting changes.

## Building and testing

The build is hermetic — vendored modules, no network toolchain download.

```sh
make                 # vet + race-enabled tests + build (-> bin/splitdnsd)
make build           # just the static binary
make test            # full suite under the race detector
make lint            # golangci-lint (enforces the per-request context-deadline gate)
make vuln            # govulncheck
make test-fuzz-short
make test-netns      # network-namespace e2e (skips where unprivileged userns is unavailable)
make test-chaos      # adversarial reliability suite
```

The build is a single static binary with no runtime dependencies (Go 1.24+). To build
a Debian package:

```sh
./scripts/build-deb.sh          # zero-build-dep fallback (only dpkg-deb + Go)
# or, where debhelper is available, the canonical path:
dpkg-buildpackage -us -uc -b
```

Every behavioral change should ship with the test that would have caught the bug it
fixes (or that pins the feature it adds). The repository has unit, integration, fuzz,
network-namespace e2e, chaos, and golden-parity tests — add to whichever fits.

## Keeping the source and package pristine

This repository must never contain site-private data (real domain names, IP
addresses, internal hostnames, secrets). Those live only in a private directory
**outside** the repository (e.g. `../splitdns-private/`), never under version control.

- `scripts/check-pristine.sh` scans public files against a private denylist and
  **must pass** before any commit. Install the provided git hook so this is automatic:

  ```sh
  make install-hooks
  ```

- Use documentation-range placeholders in code, tests, and docs:
  RFC 5737 IPv4 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 IPv6
  (`2001:db8::/32`), and RFC 2606 / RFC 6761 names (`example.com`, `*.test`,
  `*.invalid`). Site-specific values (e.g. excluded zones) are **configuration**, not
  source.

## Documentation ownership

To keep the docs from drifting out of sync, each fact has a single owner:

- **The manual pages** (`splitdns.conf(5)`, `splitdnsd(8)`, `splitdns-notify(8)`) are
  the formal key/default reference. Defaults and the full key list live there.
- **Markdown** (README, `guide/`) explains, gives worked examples, and **links** to the
  man pages for exhaustive defaults — it should not restate every default value.
- **Tokens:** the on-host file layout and `chmod`/`chown` recipe live in
  `guide/deployment.md`; other docs link to it rather than repeating the commands.
- **Deployment modes** are defined once in `guide/deployment.md` (and summarized in the
  README); don't re-enumerate them elsewhere.

When you change a default or add a key, update the man page first, then adjust any
markdown that references it.

## Style

- Standard `gofmt` / `go vet`; match the surrounding code's conventions.
- External calls carry a context with a deadline (enforced by the lint gate).
- Keep public files free of personal data; the project is credited to its author and
  contributors, no third-party tooling.

## Submitting

Open a pull request against `main` with a clear description and passing checks
(`make` plus `make lint` / `make vuln`). CI runs the same gates, including the
pristine scan.
