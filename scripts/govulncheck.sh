#!/usr/bin/env bash
# Runs govulncheck on the daemon and fails on any vulnerability our code calls
# (a symbol-level finding), except the OSV IDs listed in the allowlist. Allowed
# findings are printed as GitHub warnings so they stay visible.
#
# Usage: scripts/govulncheck.sh [allowlist]   (default .github/govulncheck-allow.txt)
# Requires: govulncheck, jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOW_FILE="${1:-$ROOT/.github/govulncheck-allow.txt}"
GOVULNCHECK="${GOVULNCHECK:-govulncheck}"

# Allowlist: one OSV ID per line; '#' starts a comment.
allowed="$(sed 's/#.*//' "$ALLOW_FILE" | tr -d ' \t' | grep -v '^$' || true)"

json="$(cd "$ROOT/daemon" && "$GOVULNCHECK" -format json ./...)"
called="$(jq -r 'select(.finding and .finding.trace[0].function != null) | .finding.osv' <<<"$json" | sort -u)"

status=0
for id in $called; do
  if grep -qxF "$id" <<<"$allowed"; then
    echo "::warning title=govulncheck allowlist::$id is called by our code and allowed by $(basename "$ALLOW_FILE")"
  else
    echo "::error title=govulncheck::$id is called by our code (https://pkg.go.dev/vuln/$id)"
    status=1
  fi
done
[ -z "$called" ] && echo "govulncheck: no vulnerabilities called by our code"
[ "$status" = 0 ] || (cd "$ROOT/daemon" && "$GOVULNCHECK" ./... || true)  # human-readable detail
exit "$status"
