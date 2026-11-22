#!/bin/sh
# govulncheck-gate.sh — run govulncheck and surface reachable vulnerabilities LOUDLY,
# but treat them as NON-BLOCKING (warn, exit 0). It fails ONLY if govulncheck itself
# cannot run, so a broken scan is never silent.
#
# Why non-blocking: splitdnsd is a STATIC binary built against an apt Go toolchain
# (GOTOOLCHAIN=local; go.mod sets the 1.24 minimum). Reachable stdlib findings are
# remediated only by a NEWER toolchain, not by anything in this repo:
#   * Go-stdlib CVEs are supplied by the toolchain. Ubuntu sometimes backports a fix into
#     golang-1.NN while KEEPING the go1.NN.x version string, so govulncheck (which keys on
#     that string) can report an already-patched stdlib as vulnerable. Backports are not
#     guaranteed, though: noble's golang-1.24 1.24.13-2~24.04.1 carries none of the 33
#     reachable fixes released after 1.24.13. Prefer the newest golang-1.NN apt offers;
#     select-go.sh picks it, and the self-build rebuilds when it changes.
#   * Findings in stdlib-bundled code (e.g. the http2 copy of golang.org/x/net) are fixed
#     the same way; a module bump would not change the code that runs.
# A hard gate would therefore wedge the build (and the unattended self-rebuild pipeline)
# whenever the distribution lags. The real remediation for a static binary is a REBUILD
# against a newer apt toolchain (design §11 self-rebuild) — for which THIS reachability
# report is the signal/trigger. CI runs the scan on a current Go release, where a finding
# means something this repo can fix (a vendored dependency).
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
echo "govulncheck-gate: WARN (non-blocking) — ${n} reachable vuln group(s). Stdlib findings" >&2
echo "  clear when splitdnsd is rebuilt against a newer Go (install the newest golang-1.NN;" >&2
echo "  the self-rebuild path follows it). Review the report above and bump any vendored" >&2
echo "  dependency whose fix builds on the current toolchain." >&2
exit 0
