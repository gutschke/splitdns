# Releasing

Checklist for cutting a tagged release of `splitdns`.

## Pre-publish gate (first commit / every release)

1. `make install-hooks` is active, or run the pristine gate manually. It enforces BOTH
   no-site-private-strings and no-AI-tool-attribution over the tracked files:
   ```sh
   ./scripts/check-pristine.sh        # must exit 0
   ```
2. Confirm nothing private would be tracked:
   ```sh
   git status --ignored               # build artifacts + private trees (local/ docs/ dist/ bin/ cover.out) must be Ignored
   ```
3. Full gate suite:
   ```sh
   make ci                            # pristine + vet + vuln + race tests + fuzz-short
   make lint
   ```

### Leak defenses (layered)

- **`.gitignore`** excludes secret-bearing files (`*.token`, `*.secret`, `.env*`,
  `secrets/`) and the private trees (`local/`, `docs/`).
- **pre-commit hook** (`make install-hooks`) refuses staged secret files by name
  *and* runs the pristine string scan.
- **CI** runs the pristine scan (denylist supplied via the `SPLITDNS_PRIVATE_PATTERNS`
  secret).
- **On GitHub**, enable **Secret scanning** and **Push protection** (Settings →
  Code security). This catches token-*shaped* values (including Cloudflare tokens)
  that the name/string guards above would miss, and blocks the push.

## Version + changelog

- Update `## [Unreleased]` in `CHANGELOG.md` to the new `## [x.y.z] — date` and add a
  fresh `[Unreleased]` section.
- The package version embeds the building Go version automatically (e.g.
  `0.1.0~go1.24.4`); the base version is `BASE_VERSION` in `scripts/build-deb.sh`.

## Build artifacts

```sh
make build                            # static binary

# Debian packages — two equivalent paths:
./scripts/build-deb.sh                # zero-build-dep fallback (only dpkg-deb + Go)
dpkg-buildpackage -us -uc -b          # canonical (needs debhelper); lints clean
```

Each path produces **two** packages with the same install layout: `splitdnsd` (server)
and `splitdns-notify` (the standalone mDNS-announce helper, for hosts that should never
run the server). `splitdnsd` Recommends `splitdns-notify`. The canonical `debian/` path
is preferred where `debhelper` is available; `build-deb.sh` works in minimal environments
and embeds the building Go version in the package version (version-forwarding).

## Tag and push

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
```

Attach both `.deb`s (`splitdnsd` and `splitdns-notify`, and optionally the static
binaries) to the GitHub release.
