#!/bin/sh
# govulncheck-gate.sh — run govulncheck and apply the project's ship policy:
#
#   * a REACHABLE vulnerability in a THIRD-PARTY (vendored) module  -> FAIL.
#     These are fixable here: bump the vendored dependency and re-vendor.
#   * a REACHABLE vulnerability in the GO STANDARD LIBRARY          -> WARN, pass.
#     These cannot be fixed from this repo: the stdlib is supplied by the apt Go
#     toolchain (GOTOOLCHAIN=local), and Ubuntu backports the fix into golang-1.NN
#     while KEEPING the "go1.24.x" version string — which govulncheck keys on, so it
#     reports an already-distro-patched stdlib as vulnerable. Blocking on these would
#     wedge every build behind a toolchain move we deliberately don't make. The
#     self-rebuild path (keyed on the apt PACKAGE version of golang-1.NN) is what
#     actually delivers stdlib fixes; see design §11.
#
# govulncheck lists ONLY reachable ("called") vulns as numbered "Vulnerability #N"
# blocks, each tagged either "Standard library" or "Module: <path>"; merely-imported
# vulns are summarized, never given a "Module:" line. So a "Module:" line in the output
# is exactly a reachable third-party finding.
#
# Override the binary with GOVULNCHECK=/path/to/govulncheck. Extra args (default ./...)
# are passed through.
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
  3) ;; # vulnerabilities found — evaluate the policy below
  *)
    echo "govulncheck-gate: govulncheck failed to run (exit $rc), not a vuln result." >&2
    exit "$rc"
    ;;
esac

# rc=3: at least one reachable vuln. Block only if any is in a third-party module.
if printf '%s\n' "$out" | grep -qE '^[[:space:]]+Module:[[:space:]]'; then
  echo "govulncheck-gate: FAIL — a reachable vulnerability is in a third-party (vendored)" >&2
  echo "                  module. Bump the dependency to its fixed version and re-vendor:" >&2
  echo "                    go get <module>@<fixed> && go mod tidy && go mod vendor" >&2
  exit 1
fi

echo "govulncheck-gate: WARN — only Go standard-library vulnerabilities are reachable." >&2
echo "                  These are not fixable from this repo; they clear when the apt Go" >&2
echo "                  toolchain is updated (distro-backported) and splitdnsd is rebuilt" >&2
echo "                  (the self-rebuild path keys on the golang-1.NN apt package version)." >&2
echo "                  Treating as non-blocking per design §11." >&2
exit 0
