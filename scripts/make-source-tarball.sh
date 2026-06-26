#!/bin/sh
# make-source-tarball.sh <output.tar.gz> — create the source payload the self-build needs
# to rebuild splitdnsd: exactly what scripts/build-deb.sh consumes, and nothing private
# (the repo is pristine by policy, §12) — the explicit list keeps dist/.git/etc. and the
# tarball itself out. Shared by scripts/build-deb.sh and debian/rules so both produce an
# identical payload. Run from anywhere; paths resolve against the repo root.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:?usage: make-source-tarball.sh <output.tar.gz>}
mkdir -p "$(dirname "$out")"
tar -czf "$out" -C "$root" \
  cmd internal vendor go.mod go.sum man examples packaging scripts Makefile README.md LICENSE THIRD_PARTY_NOTICES.md
