#!/bin/sh
# build-deb.sh — assemble pristine .deb packages via the zero-build-dep dpkg-deb
# fallback (design §11.2). The canonical dpkg-buildpackage path lives in debian/;
# this script needs only dpkg-deb and a Go toolchain, so it works in minimal envs.
#
# Two packages are produced (design §11.4):
#   splitdnsd      — the server: binary, systemd unit, example config, man pages,
#                    plus the user/dir/enable maintainer scripts.
#   splitdns-notify — the standalone mDNS-announce helper: a single static binary
#                    and its man page, with NO server binary, unit, user, or config.
#                    Installable on hosts that should announce themselves to — but
#                    never run — splitdnsd.
# splitdnsd Recommends splitdns-notify, so a normal server install still pulls the
# helper, but the two are otherwise independent and co-installable.
#
# Version-forwarding (§11.3): the package version embeds the building Go version, so
# a rebuild on a newer apt Go is a distinct, higher version.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GO=$("$root/scripts/select-go.sh" | head -1)
export GOTOOLCHAIN=local CGO_ENABLED=0
gover=$(GOTOOLCHAIN=local "$GO" version | sed -n 's/.*go\([0-9.]*\).*/\1/p')   # 1.24.4 (for -X main.version)

BASE_VERSION=${BASE_VERSION:-0.1.0}
ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
# Version-forwarding (design §11.3) is computed in scripts/pkg-version.sh so the builder
# and the self-build autobuild agree byte-for-byte (the autobuild compares this against
# the installed package version to decide, without compiling, whether the toolchain moved).
PKGVER=$(BASE_VERSION="$BASE_VERSION" GO="$GO" "$root/scripts/pkg-version.sh" version)
BUILT_USING=$(BASE_VERSION="$BASE_VERSION" GO="$GO" "$root/scripts/pkg-version.sh" built-using)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "build-deb: go=$gover version=$PKGVER arch=$ARCH"

# 1. Build static, stripped, reproducible binaries.
LDFLAGS="-s -w -X main.version=${PKGVER}"
"$GO" build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$STAGE/splitdnsd" ./cmd/splitdnsd
"$GO" build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$STAGE/splitdns-notify" ./cmd/splitdns-notify

OUT=${OUT:-"$root/dist"}
mkdir -p "$OUT"

# ----------------------------------------------------------------------------
# Package 1: splitdns-notify — the standalone helper.
# A single static binary + its man page. No maintainer scripts: it creates no
# user, ships no service, and owns no config — nothing to set up or tear down.
# ----------------------------------------------------------------------------
N="$STAGE/notify"
install -D -m 0755 "$STAGE/splitdns-notify" "$N/usr/bin/splitdns-notify"
install -D -m 0644 man/splitdns-notify.8    "$N/usr/share/man/man8/splitdns-notify.8"
install -D -m 0644 examples/notify.example.toml "$N/usr/share/doc/splitdns-notify/notify.example.toml"
gzip -9 -f "$N/usr/share/man/man8/splitdns-notify.8"

mkdir -p "$N/DEBIAN"
cat > "$N/DEBIAN/control" <<EOF
Package: splitdns-notify
Version: ${PKGVER}
Architecture: ${ARCH}
Maintainer: gutschke <gutschke@users.noreply.github.com>
Section: net
Priority: optional
Built-Using: ${BUILT_USING}
Homepage: https://github.com/gutschke/splitdns
Description: mDNS hostname announcer for splitdnsd
 splitdns-notify sends authoritative multicast-DNS responses to announce a
 host's name and addresses, prompting a splitdnsd resolver to refresh its view
 of the LAN (and, where enabled, its guarded dynamic-DNS write-back).
 .
 It is a small static helper with no runtime dependencies and ships neither the
 server binary nor any service, so it is safe to install on hosts that should
 announce themselves to — but never run — splitdnsd. See splitdns-notify(8).
EOF

DEB_N="$OUT/splitdns-notify_${PKGVER}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$N" "$DEB_N"
echo "build-deb: wrote $DEB_N"

# ----------------------------------------------------------------------------
# Package 2: splitdnsd — the server.
# NOTE: the live config is NOT shipped (no conffile owning /etc/splitdns) — the
# operator copies the example and edits it, so apt upgrades never clobber local
# modifications (design §12.2).
# ----------------------------------------------------------------------------
S="$STAGE/server"
install -D -m 0755 "$STAGE/splitdnsd"  "$S/usr/sbin/splitdnsd"
install -D -m 0644 man/splitdnsd.8     "$S/usr/share/man/man8/splitdnsd.8"
install -D -m 0644 man/splitdns.conf.5 "$S/usr/share/man/man5/splitdns.conf.5"
install -D -m 0644 examples/splitdnsd.example.toml "$S/usr/share/doc/splitdnsd/splitdnsd.example.toml"
install -D -m 0644 packaging/splitdnsd.service     "$S/lib/systemd/system/splitdnsd.service"
gzip -9 -f "$S/usr/share/man/man8/splitdnsd.8"
gzip -9 -f "$S/usr/share/man/man5/splitdns.conf.5"

mkdir -p "$S/DEBIAN"
cat > "$S/DEBIAN/control" <<EOF
Package: splitdnsd
Version: ${PKGVER}
Architecture: ${ARCH}
Maintainer: gutschke <gutschke@users.noreply.github.com>
Section: net
Priority: optional
Depends: adduser, init-system-helpers (>= 1.54~)
Recommends: splitdns-notify (= ${PKGVER})
Built-Using: ${BUILT_USING}
Homepage: https://github.com/gutschke/splitdns
Description: split-horizon DNS resolver with Cloudflare mirror
 splitdnsd is a lightweight authoritative + forwarding DNS resolver. It mirrors
 Cloudflare-hosted zones for LAN clients (read-only), serves *.local names from
 mDNS, answers reverse zones, redirects vhosts to a local reverse proxy, and can
 optionally perform guarded, opt-in dynamic-DNS write-back.
 .
 Configuration is NOT shipped: copy /usr/share/doc/splitdnsd/splitdnsd.example.toml
 to /etc/splitdns/splitdnsd.toml and edit it. See splitdns.conf(5).
EOF

cat > "$S/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if ! getent group splitdns >/dev/null; then addgroup --system splitdns; fi
  if ! getent passwd splitdns >/dev/null; then
    adduser --system --no-create-home --ingroup splitdns \
      --home /var/lib/splitdns --shell /usr/sbin/nologin splitdns
  fi
  install -d -m 0750 -o splitdns -g splitdns /etc/splitdns
  install -d -m 0750 -o splitdns -g splitdns /etc/splitdns/secrets
  install -d -m 0700 -o splitdns -g splitdns /var/lib/splitdns
  if [ ! -e /etc/splitdns/splitdnsd.toml ]; then
    echo "splitdnsd: enabled to start at boot, but it will NOT run until configured." >&2
    echo "           Copy /usr/share/doc/splitdnsd/splitdnsd.example.toml to" >&2
    echo "           /etc/splitdns/splitdnsd.toml, edit it, then: systemctl start splitdnsd" >&2
  fi
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
  fi
  # Enable by default so DNS survives a reboot without the admin remembering to do it.
  # deb-systemd-helper (not raw `systemctl enable`) remembers the admin's choice: it
  # enables on first install, but on upgrade only re-enables when the unit was enabled
  # before — a deliberate `systemctl disable` is never overridden. Being enabled is
  # harmless before configuration because the unit's ConditionPathExists gate keeps it
  # skipped (no crash-loop) until splitdnsd.toml exists.
  if command -v deb-systemd-helper >/dev/null 2>&1; then
    if deb-systemd-helper --quiet was-enabled splitdnsd.service; then
      deb-systemd-helper enable splitdnsd.service >/dev/null || true
    else
      deb-systemd-helper update-state splitdnsd.service >/dev/null || true
    fi
  fi
  if [ -d /run/systemd/system ]; then
    # Bring the service to RUNNING after install: start on first install, restart on
    # upgrade so the new binary takes effect. Deliberately NOT try-restart — try-restart
    # is a no-op when the unit is momentarily not active (e.g. back-to-back installs, or
    # a prior cycle that left it stopped), which silently leaves DNS down. start/restart
    # always end with the unit running. deb-systemd-invoke acts ONLY on an enabled unit,
    # so a deliberate `systemctl disable` is still honored; and the unit's
    # ConditionPathExists gate keeps this a clean no-op until splitdnsd.toml exists, so an
    # unconfigured fresh install still does not actually run.
    if [ -n "$2" ]; then
      _action=restart   # $2 = previously-configured version => this is an upgrade
    else
      _action=start     # first install
    fi
    if command -v deb-systemd-invoke >/dev/null 2>&1; then
      deb-systemd-invoke "$_action" splitdnsd.service || true
    else
      systemctl "$_action" splitdnsd.service || true
    fi
  fi
fi
exit 0
EOF
chmod 0755 "$S/DEBIAN/postinst"

cat > "$S/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
  systemctl stop splitdnsd.service || true
fi
exit 0
EOF
chmod 0755 "$S/DEBIAN/prerm"

cat > "$S/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# Mirror the postinst enablement with deb-systemd-helper so the enable-state
# bookkeeping is cleaned up. On remove, mask the unit so it can't be started while
# the binary is gone but the config lingers; on purge, drop the remembered state and
# unmask. Guarded so a system without the helper (or without systemd) degrades cleanly.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if command -v deb-systemd-helper >/dev/null 2>&1; then
  if [ "$1" = "remove" ]; then
    deb-systemd-helper mask splitdnsd.service >/dev/null || true
  fi
  if [ "$1" = "purge" ]; then
    deb-systemd-helper purge splitdnsd.service >/dev/null || true
    deb-systemd-helper unmask splitdnsd.service >/dev/null || true
  fi
fi
exit 0
EOF
chmod 0755 "$S/DEBIAN/postrm"

DEB_S="$OUT/splitdnsd_${PKGVER}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$S" "$DEB_S"
echo "build-deb: wrote $DEB_S"

# ----------------------------------------------------------------------------
# Package 3: splitdnsd-selfbuild — unattended security self-rebuild (design §11).
# Ships the source + autobuild machinery so the resolver rebuilds splitdnsd against the
# CURRENT apt Go toolchain when it changes (the static-binary equivalent of the dynamic
# linker picking up a patched .so on apt dist-upgrade). Architecture: all, version =
# BASE_VERSION (it carries source, not a toolchain-stamped binary), so a toolchain bump
# rebuilds the binary packages but never this one.
# ----------------------------------------------------------------------------
B="$STAGE/selfbuild"
# Source payload: exactly what scripts/build-deb.sh needs to rebuild — and nothing
# private (the repo is pristine by policy, §12). Explicit list, so dist/.git/etc. and the
# tarball itself are never swept in.
install -d "$B/usr/src/splitdnsd"
"$root/scripts/make-source-tarball.sh" "$B/usr/src/splitdnsd/source.tar.gz"
# Autobuild machinery + the version-prediction helpers (cheap, compile-free change-detection).
install -D -m 0755 packaging/autobuild/splitdnsd-autobuild "$B/usr/lib/splitdnsd-selfbuild/splitdnsd-autobuild"
install -D -m 0755 packaging/autobuild/autobuild-notify     "$B/usr/lib/splitdnsd-selfbuild/autobuild-notify"
install -D -m 0755 scripts/pkg-version.sh                   "$B/usr/lib/splitdnsd-selfbuild/pkg-version.sh"
install -D -m 0755 scripts/select-go.sh                     "$B/usr/lib/splitdnsd-selfbuild/select-go.sh"
install -D -m 0644 /dev/stdin "$B/usr/lib/splitdnsd-selfbuild/VERSION" <<EOF
${BASE_VERSION}
EOF
# systemd units + apt hook + example config (config is NOT a conffile — operator copies it).
install -D -m 0644 packaging/autobuild/splitdnsd-autobuild.service         "$B/lib/systemd/system/splitdnsd-autobuild.service"
install -D -m 0644 packaging/autobuild/splitdnsd-autobuild.timer           "$B/lib/systemd/system/splitdnsd-autobuild.timer"
install -D -m 0644 packaging/autobuild/splitdnsd-autobuild-notify@.service "$B/lib/systemd/system/splitdnsd-autobuild-notify@.service"
install -D -m 0644 packaging/autobuild/80splitdnsd-autobuild               "$B/etc/apt/apt.conf.d/80splitdnsd-autobuild"
install -D -m 0644 packaging/autobuild/autobuild.conf                      "$B/usr/share/doc/splitdnsd-selfbuild/autobuild.conf.example"

mkdir -p "$B/DEBIAN"
cat > "$B/DEBIAN/control" <<EOF
Package: splitdnsd-selfbuild
Version: ${BASE_VERSION}
Architecture: all
Maintainer: gutschke <gutschke@users.noreply.github.com>
Section: net
Priority: optional
Depends: init-system-helpers (>= 1.54~), golang-1.24 | golang-go (>= 2:1.24~), default-mta | mail-transport-agent, dpkg-repack
Recommends: splitdnsd, splitdns-notify, bind9-dnsutils | dnsutils, debsecan
Homepage: https://github.com/gutschke/splitdns
Description: unattended security self-rebuild for splitdnsd
 splitdnsd ships as a STATIC Go binary, so its dependencies (the Go standard library and
 vendored libraries) are baked in at build time and only update on a rebuild — unlike a
 dynamically linked program, which picks up a patched shared library automatically on apt
 dist-upgrade. This package closes that gap: it ships the source and rebuilds
 splitdnsd/splitdns-notify against the current apt Go toolchain whenever it changes (e.g.
 an Ubuntu stdlib security backport), triggered right after apt runs and weekly as a
 backstop. The new build installs only after config-validation and a DNS health check,
 with automatic rollback to the previous binary on any failure, and emails the
 administrator if an unattended rebuild fails (via the system mail-transport-agent —
 install e.g. msmtp-mta to relay through a smarthost; no MTA is hard-coded).
EOF

cat > "$B/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if [ ! -e /etc/splitdns/autobuild.conf ]; then
    echo "splitdnsd-selfbuild: enabled — rebuilds splitdnsd when the apt Go toolchain moves." >&2
    echo "  To receive failure emails, install a mail-transport-agent (e.g." >&2
    echo "  'apt install msmtp msmtp-mta bsd-mailx' + a smarthost) and copy" >&2
    echo "  /usr/share/doc/splitdnsd-selfbuild/autobuild.conf.example to" >&2
    echo "  /etc/splitdns/autobuild.conf to set ADMIN_EMAIL." >&2
  fi
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
  fi
  if command -v deb-systemd-helper >/dev/null 2>&1; then
    if deb-systemd-helper --quiet was-enabled splitdnsd-autobuild.timer; then
      deb-systemd-helper enable splitdnsd-autobuild.timer >/dev/null || true
    else
      deb-systemd-helper update-state splitdnsd-autobuild.timer >/dev/null || true
    fi
  fi
  if [ -d /run/systemd/system ] && command -v deb-systemd-invoke >/dev/null 2>&1; then
    deb-systemd-invoke start splitdnsd-autobuild.timer >/dev/null 2>&1 || true
  fi
fi
exit 0
EOF
chmod 0755 "$B/DEBIAN/postinst"

cat > "$B/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
  systemctl stop splitdnsd-autobuild.timer splitdnsd-autobuild.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$B/DEBIAN/prerm"

cat > "$B/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
  if command -v deb-systemd-helper >/dev/null 2>&1; then
    deb-systemd-helper purge splitdnsd-autobuild.timer >/dev/null || true
  fi
  rm -rf /var/cache/splitdnsd-selfbuild
fi
exit 0
EOF
chmod 0755 "$B/DEBIAN/postrm"

DEB_B="$OUT/splitdnsd-selfbuild_${BASE_VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$B" "$DEB_B"
echo "build-deb: wrote $DEB_B"

# 4. Report.
for DEB in "$DEB_N" "$DEB_S" "$DEB_B"; do
  echo "=== $(basename "$DEB") ==="
  dpkg-deb --info "$DEB" | sed -n '1,16p'
  echo "--- contents ---"
  dpkg-deb --contents "$DEB"
done
