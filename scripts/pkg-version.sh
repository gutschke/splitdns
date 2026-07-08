#!/bin/sh
# pkg-version.sh — print the version-forwarded package version (design §11.3) for a
# toolchain, WITHOUT building. Shared by scripts/build-deb.sh (to stamp the build) and
# the self-build autobuild (to cheaply decide "has the toolchain moved?" by comparing
# this against the installed package version — no compile needed).
#
# The version encodes build PROVENANCE so a rebuild against a patched toolchain is a
# strictly-greater version apt offers as an upgrade. It keys on the apt PACKAGE version
# of golang-1.NN (which bumps when Ubuntu backports a stdlib fix) rather than the frozen
# "go1.24.x" string. '+' sorts ABOVE the base; epoch/'-'/'~' are sanitized so the whole
# string is a legal, monotonic Debian version.
#
# Env: BASE_VERSION (default 0.1.0), GO (default: scripts/select-go.sh).
# Arg:  "version" (default) prints the package version; "built-using" prints the
#       Built-Using value.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
: "${BASE_VERSION:=0.3.0}"
: "${GO:=$("$here/select-go.sh" | head -1)}"

gover=$(GOTOOLCHAIN=local "$GO" version | sed -n 's/.*go\([0-9.]*\).*/\1/p')   # 1.24.4
gominor=$(echo "$gover" | sed -n 's/^\([0-9]*\.[0-9]*\).*/\1/p')               # 1.24
aptver=$(dpkg-query -W -f='${Version}' "golang-${gominor}" 2>/dev/null || true)

if [ -n "$aptver" ]; then
  aptrev=$(echo "$aptver" | sed 's/^[0-9]*://; s/[-~+]/./g')                   # 1.24.4.1ubuntu1.24.04.2
  pkgver="${BASE_VERSION}+go${gominor}+apt${aptrev}"
  built_using="golang-${gominor} (= ${aptver})"
else
  # Non-apt Go (PATH fallback): no apt provenance to track.
  pkgver="${BASE_VERSION}+go${gover}"
  built_using="go (= ${gover})"
fi

case "${1:-version}" in
  built-using) printf '%s\n' "$built_using" ;;
  *)           printf '%s\n' "$pkgver" ;;
esac
