#!/bin/sh
# fuzz-short.sh — run every FuzzXxx target for a short, bounded time as a CI gate
# (design §5.3 / S31). Discovers targets by grepping the tree so new fuzz tests are
# picked up automatically. The race detector is NOT combined with fuzzing (the
# fuzzing engine already runs instrumented binaries and the combination is very
# memory-heavy); keep them separate gates.
#
# FUZZTIME (default 20s) bounds each target. The fuzzing engine uses GOMAXPROCS
# workers; CI runners are small so this stays well within memory. On a many-core
# host, cap with GOMAXPROCS if memory is tight.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GO=$("$root/scripts/select-go.sh" | head -1)
export GOTOOLCHAIN=local
FUZZTIME=${FUZZTIME:-20s}

# Discover "<package-dir> <FuzzFuncName>" pairs from the source tree.
grep -rl '^func Fuzz' --include='*_test.go' . | while read -r file; do
  dir=$(dirname "$file")
  grep -oE '^func (Fuzz[A-Za-z0-9_]+)' "$file" | awk '{print $2}' | while read -r fn; do
    echo "=== fuzz $dir $fn (${FUZZTIME}) ==="
    "$GO" test -p 1 -run='^$' -fuzz="^${fn}$" -fuzztime="$FUZZTIME" "$dir"
  done
done

echo "fuzz-short: all targets passed"
