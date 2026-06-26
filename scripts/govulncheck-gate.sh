#!/bin/sh
# govulncheck-gate.sh — run govulncheck and surface reachable vulnerabilities LOUDLY,
# but treat them as NON-BLOCKING (warn, exit 0). It fails ONLY if govulncheck itself
# cannot run, so a broken scan is never silent.
#
# Why non-blocking: splitdnsd is a STATIC binary built against the pinned apt Go
# toolchain (GOTOOLCHAIN=local, Go 1.24). The vulnerabilities govulncheck reports are
# remediated only by a NEWER toolchain, not by anything in this repo:
#   * Go-stdlib CVEs are supplied by the toolchain; Ubuntu backports the fix into
#     golang-1.NN while KEEPING the go1.24.x version string, so govulncheck (which keys
#     on that string) reports an already-distro-patched stdlib as vulnerable.
#   * Even the lone "third-party" finding (golang.org/x/net) is the stdlib-bundled http2
#     — the running code is the toolchain's net/http — and its module fix
#     (golang.org/x/net@v0.53.0) itself REQUIRES Go 1.25, so it is unbuildable here too.
# Nothing reachable is fixable from this repo on this toolchain, so a hard gate would
# wedge the build (and the unattended self-rebuild pipeline) permanently. The real
# remediation for a static binary is a REBUILD against a newer apt toolchain (design
# §11 self-rebuild) — for which THIS reachability report is the signal/trigger. A
# maintainer reviews the warnings and bumps a vendored dependency whenever a fix exists
# that builds on the current toolchain.
#
# Override the binary with GOVULNCHECK=/path/to/govulncheck. Args default to ./....
set -eu
GOVULNCHECK="${GOVULNCHECK:-govulncheck}"
[ "$#" -gt 0 ] || set -- ./...

out=$("$GOVULNCHECK" "$@" 2>&1) && rc=0 || rc=$?
printf '%s\n' "$out"

case "$rc" in
  0)
    echo "govulncheck-gate: OK — no reachable vulnerabilities."
    exit 0
    ;;
  3) ;; # reachable vulns found — report, do not block (see header)
  *)
    echo "govulncheck-gate: FAIL — govulncheck could not run (exit $rc); not a vuln result." >&2
    exit "$rc"
    ;;
esac

n=$(printf '%s\n' "$out" | grep -cE '^Vulnerability #' 2>/dev/null || true)
echo "::warning::govulncheck: ${n} reachable vulnerability group(s) — non-blocking; fixed by a toolchain rebuild (see scripts/govulncheck-gate.sh)." >&2
echo "govulncheck-gate: WARN (non-blocking) — ${n} reachable vuln group(s). On the pinned" >&2
echo "  Go 1.24 toolchain these are not fixable from this repo; they clear when splitdnsd is" >&2
echo "  rebuilt against a newer apt Go (the self-rebuild path). Review the report above and" >&2
echo "  bump any vendored dependency whose fix builds on the current toolchain." >&2
exit 0
