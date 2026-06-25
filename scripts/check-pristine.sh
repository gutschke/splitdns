#!/bin/sh
# check-pristine.sh — fail if any PUBLIC (committable/packageable) file (a) advertises
# an AI authoring tool, or (b) contains a site-private string. This keeps the repo and
# the .deb pristine (design §12).
#
# (a) The AI-attribution terms are public brand names, so they are listed inline. This
#     script (the enforcement mechanism) and .gitignore (an ignore-list referencing the
#     agent state dir) necessarily name them, so both are excluded from the scan; so is
#     vendored third-party code.
# (b) The private-string denylist is itself private, so it is NOT hardcoded here (that
#     would leak what we guard). It is discovered, in order:
#       1. $SPLITDNS_PRIVATE_PATTERNS                       (explicit override)
#       2. ../splitdns-private/private-patterns.txt          (private dir OUTSIDE the repo)
#       3. local/private-patterns.txt                        (in-tree, gitignored fallback)
#     (one extended-regex per line; '#' comments ok). If none is available THAT scan is
#     skipped with a warning (e.g. a fresh clone) rather than giving false comfort.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

# --- (a) No-AI-attribution gate (independent of the private denylist) ---------
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  ai_terms='claude|anthropic|copilot|co-authored-by|generated with|🤖'
  ai_hits=$(cd "$root" && git ls-files \
    | grep -vE '^(vendor/|scripts/check-pristine\.sh$|\.gitignore$)' \
    | xargs -r grep -IilE "$ai_terms" 2>/dev/null || true)
  if [ -n "$ai_hits" ]; then
    echo "check-pristine: FAIL — AI-tool attribution found in public files:" >&2
    echo "$ai_hits" >&2
    exit 1
  fi
fi

# --- (b) Site-private string gate --------------------------------------------
patterns="${SPLITDNS_PRIVATE_PATTERNS:-}"
if [ -z "$patterns" ]; then
  for cand in "$root/../splitdns-private/private-patterns.txt" "$root/local/private-patterns.txt"; do
    if [ -r "$cand" ]; then patterns="$cand"; break; fi
  done
fi

if [ -z "$patterns" ] || [ ! -r "$patterns" ]; then
  echo "check-pristine: OK (no-AI gate passed); private-string denylist not found — that scan skipped" >&2
  exit 0
fi

# Strip comments and blank lines from the denylist before use: grep -f treats every
# line as a pattern, and a blank line is an empty regex that matches EVERYTHING.
clean=$(grep -vE '^[[:space:]]*(#|$)' "$patterns")
if [ -z "$clean" ]; then
  echo "check-pristine: OK (no-AI gate passed); denylist has no usable patterns — private scan skipped" >&2
  exit 0
fi

# Public scope = everything except the private dirs and vendored third-party code.
# Scan tracked source/doc/config/build files only.
matches=$(printf '%s\n' "$clean" | grep -RniE -f - "$root" \
  --include='*.go' --include='*.toml' --include='*.5' --include='*.8' \
  --include='*.sh' --include='*.yml' --include='*.yaml' --include='Makefile' \
  --include='*.md' --include='*.json' --include='*.txt' \
  --include='control' --include='rules' --include='changelog' \
  2>/dev/null \
  | grep -vE "/(local|vendor|docs|\.git|\.claude)/" || true)

if [ -n "$matches" ]; then
  echo "check-pristine: FAIL — site-private strings found in public files:" >&2
  # Show file:line and the matched private token redacted to its first 3 chars,
  # so the failure log itself does not re-leak the secret.
  echo "$matches" | sed -E 's/(:[0-9]+:).*/\1<redacted private match>/' >&2
  exit 1
fi
echo "check-pristine: OK — no AI attribution or site-private strings in public files"
