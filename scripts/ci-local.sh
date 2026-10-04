#!/usr/bin/env bash
# Local CI: runs the same checks as every job in .github/workflows/ci.yml
# (go, contracts, python, reproducible, e2e) on this machine, against the
# committed HEAD. Every job runs even if an earlier one fails; a summary table
# follows, and the exit status is non-zero if any job failed.
#
# Usage: make ci   (or scripts/ci-local.sh)
#
# Environment:
#   ALLOW_DIRTY=1          run on a dirty tree (the result then does not gate HEAD)
#   CI_JOBS="go python"    run only these jobs (default: all, in CI order)
#   PROTOC=/path/protoc    protoc for `make proto` (default: protoc on PATH);
#                          must be the version pinned in ci.yml
#   PYTHON=python3.12      interpreter for the venvs (default: python<ci.yml version>)
#   CI_E2E_ANVIL_PORT      anvil port for e2e (default 28545)
#   CI_E2E_GRPC_PORT       daemon gRPC port for e2e (default 25051)
#
# Pinned versions (Foundry, protoc, govulncheck, pip-audit, Python) are read
# from ci.yml so the two cannot drift. Logs go to ci-logs/<job>.log.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WORKFLOW=".github/workflows/ci.yml"
LOGS="$ROOT/ci-logs"
GOBIN_DIR="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN_DIR:$HOME/.foundry/bin"

# ci_env NAME: the value of NAME in the workflow's top-level env block.
ci_env() {
  sed -nE "s/^  $1: *\"?([^\"#]*[^\" #])\"?.*$/\1/p" "$WORKFLOW" | head -n 1
}
FOUNDRY_VERSION="$(ci_env FOUNDRY_VERSION)"
PYTHON_VERSION="$(ci_env PYTHON_VERSION)"
PROTOC_VERSION="$(ci_env PROTOC_VERSION)"
GOVULNCHECK_VERSION="$(ci_env GOVULNCHECK_VERSION)"
PIP_AUDIT_VERSION="$(ci_env PIP_AUDIT_VERSION)"
for v in FOUNDRY_VERSION PYTHON_VERSION PROTOC_VERSION GOVULNCHECK_VERSION PIP_AUDIT_VERSION; do
  [ -n "${!v}" ] || { echo "ci-local: cannot read $v from $WORKFLOW" >&2; exit 2; }
done

PROTOC="${PROTOC:-protoc}"
PYTHON="${PYTHON:-python$PYTHON_VERSION}"
ANVIL_PORT="${CI_E2E_ANVIL_PORT:-28545}"
GRPC_PORT="${CI_E2E_GRPC_PORT:-25051}"
# Ports of the long-running services on the operator's machine (testnet
# daemon gRPC and metrics, Prometheus). e2e must never bind or probe them.
RESERVED_PORTS="50551 9464 9090"

# --- HEAD and tree state ---------------------------------------------------
HEAD_SHA="$(git rev-parse HEAD)"
DIRTY="$(git status --porcelain)"
echo "ci-local: HEAD $HEAD_SHA ($(git rev-parse --abbrev-ref HEAD))"
if [ -n "$DIRTY" ]; then
  echo "ci-local: working tree is DIRTY:"
  echo "$DIRTY" | sed 's/^/  /'
  if [ "${ALLOW_DIRTY:-0}" != 1 ]; then
    echo "ci-local: refusing to run; the gate must test exactly the committed HEAD." >&2
    echo "ci-local: commit or stash first, or set ALLOW_DIRTY=1 for an informal run." >&2
    exit 2
  fi
  echo "ci-local: ALLOW_DIRTY=1: running anyway; this result does NOT gate HEAD"
else
  echo "ci-local: working tree is clean"
fi
echo "ci-local: $(go version | cut -d' ' -f3-), daemon/go.mod wants $(sed -nE 's/^go //p' daemon/go.mod)"

mkdir -p "$LOGS"

# --- helpers ---------------------------------------------------------------
die() { echo "ci-local: $*" >&2; exit 1; }

# with_timeout SECS CMD...: run CMD in its own process group; after SECS
# send TERM to the whole group (daemons and anvil included), KILL 10s later.
# Returns 124 on timeout. macOS has no timeout(1).
with_timeout() {
  local secs="$1"; shift
  local marker; marker="$(mktemp "${TMPDIR:-/tmp}/ci-local-timeout.XXXXXX")"
  rm -f "$marker"
  set -m
  "$@" &
  local pid=$!
  set +m
  (
    for ((i = 0; i < secs; i++)); do kill -0 "$pid" 2>/dev/null || exit 0; sleep 1; done
    touch "$marker"
    echo "ci-local: TIMEOUT after ${secs}s, killing process group $pid" >&2
    kill -TERM -- "-$pid" 2>/dev/null
    for ((i = 0; i < 10; i++)); do kill -0 "$pid" 2>/dev/null || exit 0; sleep 1; done
    kill -KILL -- "-$pid" 2>/dev/null
  ) &
  local watchdog=$!
  wait "$pid"
  local rc=$?
  wait "$watchdog" 2>/dev/null
  if [ -e "$marker" ]; then rm -f "$marker"; return 124; fi
  return "$rc"
}

# tree_state: fingerprint of tracked changes and untracked files, so the
# reproducible job can tell whether regeneration changed anything.
tree_state() { { git status --porcelain=v1 -uall; git diff HEAD; } | shasum -a 256; }

# --- jobs (each runs in a subshell with -e; output goes to its log) --------
job_go() {
  cd daemon
  echo "+ gofmt -l ."
  out="$(gofmt -l .)"
  if [ -n "$out" ]; then echo "gofmt needed:"; echo "$out"; exit 1; fi
  echo "+ go build ./..."; go build ./...
  echo "+ go vet ./..."; go vet ./...
  echo "+ go test -race -count=1 ./..."; go test -race -count=1 ./...
  echo "+ govulncheck@$GOVULNCHECK_VERSION"
  go install golang.org/x/vuln/cmd/govulncheck@"$GOVULNCHECK_VERSION"
  GOVULNCHECK="$GOBIN_DIR/govulncheck" ../scripts/govulncheck.sh
}

check_foundry() {
  local have; have="$(forge --version | sed -nE 's/^forge Version: ([^ -]+).*/\1/p')"
  [ "v${have#v}" = "$FOUNDRY_VERSION" ] || die "forge is ${have:-missing}, ci.yml pins $FOUNDRY_VERSION (foundryup -i $FOUNDRY_VERSION)"
}

check_python() {
  command -v "$PYTHON" >/dev/null || die "$PYTHON not found; ci.yml uses Python $PYTHON_VERSION (set PYTHON=...)"
  local have; have="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  [ "$have" = "$PYTHON_VERSION" ] || die "$PYTHON is Python $have, ci.yml uses $PYTHON_VERSION"
}

job_contracts() {
  check_foundry
  cd contracts
  echo "+ forge build"; forge build
  echo "+ forge test"; forge test
}

job_python() {
  check_python
  echo "+ fresh venv from the hashed lock"
  rm -rf sdk/python/.venv
  make venv PYTHON="$PYTHON"
  echo "+ pytest"; sdk/python/.venv/bin/pytest -q sdk/python
  echo "+ pip-audit==$PIP_AUDIT_VERSION"
  local audit="${XDG_CACHE_HOME:-$HOME/.cache}/verilog-ci/pip-audit-$PIP_AUDIT_VERSION"
  [ -x "$audit/bin/pip-audit" ] || { "$PYTHON" -m venv "$audit" && "$audit/bin/pip" install -q "pip-audit==$PIP_AUDIT_VERSION"; }
  "$audit/bin/pip-audit" --require-hashes --disable-pip -r sdk/python/requirements-dev.txt
}

job_reproducible() {
  check_foundry
  check_python
  command -v "$PROTOC" >/dev/null || die "protoc not found ($PROTOC); ci.yml pins $PROTOC_VERSION (set PROTOC=...)"
  local have; have="$("$PROTOC" --version | awk '{print $2}')"
  [ "$have" = "$PROTOC_VERSION" ] || die "$PROTOC is libprotoc $have, ci.yml pins $PROTOC_VERSION (set PROTOC=...)"
  echo "+ protoc $(command -v "$PROTOC") $have"
  local before; before="$(tree_state)"
  echo "+ make tools venv"; make tools venv PYTHON="$PYTHON"
  echo "+ make proto bindings vectors"; make proto bindings vectors PROTOC="$PROTOC"
  echo "+ committed generated code matches its sources"
  git status --short
  if [ "$(tree_state)" != "$before" ]; then
    git diff --stat
    git diff | head -n 200
    die "regeneration changed the tree (diff or untracked files above)"
  fi
}

port_free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

job_e2e() {
  check_foundry
  check_python
  for p in "$ANVIL_PORT" "$GRPC_PORT"; do
    for r in $RESERVED_PORTS; do [ "$p" != "$r" ] || die "port $p is reserved for a live service; pick another"; done
    port_free "$p" || die "port $p is already in use (set CI_E2E_ANVIL_PORT / CI_E2E_GRPC_PORT)"
  done
  echo "+ make venv"; make venv PYTHON="$PYTHON"
  local tmp="$LOGS/e2e-work"
  rm -rf "$tmp" && mkdir -p "$tmp"
  echo "+ scripts/e2e.sh (anvil :$ANVIL_PORT, gRPC :$GRPC_PORT, 900s limit; work dir kept on failure in $tmp)"
  local rc=0
  KEEP_WORK=1 TMPDIR="$tmp" ANVIL_PORT="$ANVIL_PORT" GRPC_PORT="$GRPC_PORT" \
    with_timeout 900 ./scripts/e2e.sh || rc=$?
  [ "$rc" = 0 ] && rm -rf "$tmp"
  return "$rc"
}

# Job timeouts mirror timeout-minutes in ci.yml.
job_timeout() {
  case "$1" in go) echo 1200 ;; contracts) echo 900 ;; python) echo 900 ;; reproducible) echo 1200 ;; e2e) echo 1500 ;; esac
}

ALL_JOBS="go contracts python reproducible e2e"
JOBS="${CI_JOBS:-$ALL_JOBS}"
for j in $JOBS; do
  case " $ALL_JOBS " in *" $j "*) ;; *) echo "ci-local: unknown job '$j' (jobs: $ALL_JOBS)" >&2; exit 2 ;; esac
done

declare -a RESULTS=()
failed=0
for j in $JOBS; do
  log="$LOGS/$j.log"
  printf 'ci-local: %-13s running (log: ci-logs/%s.log)\n' "$j" "$j"
  start=$(date +%s)
  with_timeout "$(job_timeout "$j")" bash -c "set -eo pipefail; $(declare -f); $(declare -p ROOT LOGS GOBIN_DIR FOUNDRY_VERSION PYTHON_VERSION PROTOC_VERSION GOVULNCHECK_VERSION PIP_AUDIT_VERSION PROTOC PYTHON ANVIL_PORT GRPC_PORT RESERVED_PORTS); cd \"\$ROOT\"; job_$j" >"$log" 2>&1
  rc=$?
  dur=$(($(date +%s) - start))
  if [ "$rc" = 0 ]; then status=PASS; else status=FAIL; failed=1; [ "$rc" = 124 ] && status="FAIL (timeout)"; fi
  printf 'ci-local: %-13s %s in %ds\n' "$j" "$status" "$dur"
  [ "$rc" = 0 ] || tail -n 15 "$log" | sed 's/^/    | /'
  RESULTS+=("$(printf '%-14s %-16s %6ss' "$j" "$status" "$dur")")
done

echo
echo "ci-local summary for $HEAD_SHA$([ -n "$DIRTY" ] && echo ' (DIRTY tree)')"
printf '%-14s %-16s %7s\n' JOB RESULT TIME
printf '%-14s %-16s %7s\n' -------------- ---------------- -------
printf '%s\n' "${RESULTS[@]}"
if [ "$failed" = 0 ]; then echo "ci-local: ALL PASSED"; else echo "ci-local: FAILED (logs in ci-logs/)"; fi
exit "$failed"
