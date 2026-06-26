#!/bin/sh
# Print the path of the highest-versioned apt-installed Go toolchain (or the Go on
# PATH as a fallback). Used by the Makefile, scripts/build-deb.sh, and fuzz-short.sh;
# the build embeds the toolchain version into the package version (version-forwarding,
# design §11.3). Override with GO=/path.
#
# The project requires Go >= 1.24 (see go.mod). An older toolchain is still printed and
# will fail informatively at build time via the go.mod directive + GOTOOLCHAIN=local.
set -e
best=""; best_ver=0
for go in /usr/lib/go-1.*/bin/go; do
  [ -x "$go" ] || continue
  # Probe with GOTOOLCHAIN=local so a binary does NOT silently auto-upgrade to a
  # downloaded toolchain and misreport its real version.
  v=$(GOTOOLCHAIN=local "$go" version 2>/dev/null | sed -n 's/.*go1\.\([0-9]\+\).*/\1/p')
  [ -n "$v" ] || continue
  if [ "$v" -gt "$best_ver" ]; then best_ver=$v; best=$go; fi
done
[ -n "$best" ] || best=$(command -v go)
[ -n "$best" ] || { echo "no Go toolchain found" >&2; exit 1; }
echo "$best"
