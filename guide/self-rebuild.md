# Unattended security self-rebuild

`splitdnsd` is a **statically linked** Go binary: the Go standard library and the
vendored libraries are compiled *into* it. Unlike a dynamically linked program — which
picks up a patched shared library automatically the next time it starts after
`apt dist-upgrade` — a static binary only absorbs a dependency fix when it is **rebuilt**.

The optional **`splitdnsd-selfbuild`** package closes that gap. It makes the resolver
rebuild itself against the current apt Go toolchain whenever that toolchain changes (for
example, an Ubuntu stdlib security backport), as an automatic side effect of the same
unattended `apt` upgrades that maintain the rest of the system — no human interaction.

## Install

On the resolver:

```sh
# 1. A mail-transport-agent, so failure notifications can be delivered. msmtp is the
#    lightweight choice (relay to a smarthost); any MTA works — nothing is hard-coded.
sudo apt install msmtp msmtp-mta bsd-mailx      # then configure /etc/msmtprc
# 2. The self-build package (pulls in the apt Go toolchain + helpers).
sudo apt install ./dist/splitdnsd-selfbuild_*.deb
# 3. Set where failures are emailed.
sudo cp /usr/share/doc/splitdnsd-selfbuild/autobuild.conf.example /etc/splitdns/autobuild.conf
sudoedit /etc/splitdns/autobuild.conf           # set ADMIN_EMAIL
```

Installing `msmtp-mta` *before* `splitdnsd-selfbuild` satisfies its
`default-mta | mail-transport-agent` dependency, so apt will **not** pull in postfix.

## How it works

- **Trigger.** An apt hook (`/etc/apt/apt.conf.d/80splitdnsd-autobuild`) fires the
  `splitdnsd-autobuild.service` `--no-block` after every apt run — so a rebuild rides
  your existing `apt dist-upgrade`, off the apt transaction (a build failure can never
  break apt or DNS). A weekly `splitdnsd-autobuild.timer` is a backstop.
- **Change detection (cheap).** The service compares the installed `splitdnsd` package
  version against the version a fresh build *would* stamp (derived from the apt
  `golang-1.NN` package version — no compile). If nothing moved, it exits in
  milliseconds. The package version encodes the toolchain provenance
  (`0.1.0+go1.24+apt1.24.4.1ubuntu1.24.04.2`), and an Ubuntu backport bumps the
  `apt…` suffix, so the change is detectable even though the `go1.24.x` string is frozen.
- **Rebuild + safe install.** On a real change it unpacks the shipped source
  (`/usr/src/splitdnsd/source.tar.gz`), rebuilds the binaries (vendored, hermetic, capped
  parallelism — no test suite; the source is already CI-tested), validates the new binary
  with `splitdnsd -check-config` against your live config, snapshots the current packages
  for rollback (`dpkg-repack`), installs, and runs a DNS **health check**. If the new
  build fails to serve, it **automatically rolls back** to the previous binary.
- **Failure email.** Because the work is asynchronous, a failure is no longer visible in
  the `apt` output — so on any failure the systemd `OnFailure=` notifier emails
  `ADMIN_EMAIL` the recent journal via the system MTA.

## Configuration

`/etc/splitdns/autobuild.conf` (POSIX shell; all keys optional):

| Key | Default | Meaning |
|-----|---------|---------|
| `ENABLE` | `yes` | master switch |
| `ADMIN_EMAIL` | `root` | where failures are emailed |
| `HEALTH_ADDR` / `HEALTH_NAME` | `127.0.0.1` / `health.splitdnsd.local` | post-install DNS health probe (any response counts as healthy) |
| `GOMAXPROCS` | `2` | build parallelism (keep low on a small resolver) |
| `BUILD_DIR` | `/var/cache/splitdnsd-selfbuild` | build + rollback workspace |

> **Sizing:** a rebuild peaks around **~340 MB RAM** (GOMAXPROCS=2, ~1–2 min CPU) and
> runs *outside* the daemon's `MemoryMax` cgroup, so the container needs that headroom
> above the running resolver — give a self-building container **≥ 512 MB**, or set
> `GOMAXPROCS=1` on a tighter box. (The 256 MB minimum applies to a resolver that does
> **not** self-build.)

## Testing it by hand

```sh
sudo systemctl start splitdnsd-autobuild.service     # run the check now
journalctl -u splitdnsd-autobuild -n 50              # what it decided/did
systemctl list-timers splitdnsd-autobuild.timer      # next backstop run
```

With no toolchain change it logs `up to date … nothing to do`. To exercise the full
rebuild path, run it after an `apt upgrade` that bumped `golang-1.NN`.

## Staying aware of pending fixes (`debsecan`)

`govulncheck` keys on the upstream Go version string and can't see Ubuntu's backports;
to know whether a CVE in your toolchain is *fixed-and-available* (a rebuild will pick it
up) or *not yet backported* (you may choose to move toolchains), use the distro's
backport-aware tracker. `debsecan` (Recommended by this package) checks installed package
versions against Ubuntu's security data and can email you — through the same MTA — so
"can't fix until Ubuntu backports" is a monitored, escalatable state rather than a blind
spot.
