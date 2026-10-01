#!/usr/bin/env bash
# End-to-end test: anvil -> deploy registry -> verilogd -> Python SDK events
# -> anchored epoch -> verilog-verify SUCCESS / FAILURE / operational errors,
# including a daemon restart.
#
# Requires: go, forge, anvil, cast, and the SDK venv (make venv).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -d "$HOME/.foundry/bin" ] && export PATH="$PATH:$HOME/.foundry/bin"

ANVIL_PORT="${ANVIL_PORT:-18545}"
GRPC_PORT="${GRPC_PORT:-15051}"
RPC="http://127.0.0.1:${ANVIL_PORT}"
TARGET="127.0.0.1:${GRPC_PORT}"
AGENT_ID="e2e-agent"
PYTHON="${PYTHON:-$ROOT/sdk/python/.venv/bin/python}"

# DEV ONLY: anvil's publicly known default account #0. Never use on a real network.
DEV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verilog-e2e.XXXXXX")"
DATA="$WORK/data"
ANVIL_PID=""
DAEMON_PID=""

log() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nE2E FAILED: %s\n' "$*" >&2; [ -f "$WORK/daemon.log" ] && tail -n 40 "$WORK/daemon.log" >&2; exit 1; }

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ "${KEEP_WORK:-0}" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

for tool in go forge anvil cast; do command -v "$tool" >/dev/null || fail "$tool not found on PATH"; done
[ -x "$PYTHON" ] || fail "Python venv not found at $PYTHON (run: make venv)"

log "building Go binaries"
(cd "$ROOT/daemon" && go build -o "$WORK/bin/" ./cmd/verilogd ./cmd/verilog-verify)
VERIFY="$WORK/bin/verilog-verify"

log "starting anvil on :$ANVIL_PORT"
anvil --port "$ANVIL_PORT" --silent >"$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
cast chain-id --rpc-url "$RPC" >/dev/null || fail "anvil did not start"

log "deploying VeriLogRegistry"
(cd "$ROOT/contracts" && forge script script/Deploy.s.sol --rpc-url "$RPC" --private-key "$DEV_KEY" --broadcast >"$WORK/deploy.log" 2>&1) \
  || { cat "$WORK/deploy.log"; fail "deploy failed"; }
CONTRACT="$(grep -Eo 'VeriLogRegistry deployed at 0x[0-9a-fA-F]{40}' "$WORK/deploy.log" | awk '{print $4}')"
[ -n "$CONTRACT" ] || fail "could not find deployed address"
echo "registry: $CONTRACT"

start_daemon() {
  VERILOG_PRIVATE_KEY="$DEV_KEY" "$WORK/bin/verilogd" \
    --listen "$TARGET" --rpc "$RPC" --contract "$CONTRACT" --data-dir "$DATA" \
    --epoch-interval 2s --epoch-max-logs 1000 --confirm-timeout 30s --retry-initial 200ms \
    >>"$WORK/daemon.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 100); do
    grep -q "verilogd listening" "$WORK/daemon.log" && return 0
    kill -0 "$DAEMON_PID" 2>/dev/null || fail "verilogd exited during startup"
    sleep 0.1
  done
  fail "verilogd did not start"
}

stop_daemon() {
  kill -TERM "$DAEMON_PID"
  wait "$DAEMON_PID" || fail "verilogd exited non-zero on SIGTERM"
  DAEMON_PID=""
}

AGENT_KEY="$(cast keccak "$AGENT_ID")"
wait_bundle() { # epoch
  local f="$DATA/evidence/$AGENT_KEY/epoch-$1.json"
  for _ in $(seq 1 300); do [ -f "$f" ] && { echo "$f"; return 0; }; sleep 0.2; done
  fail "epoch $1 was not anchored in time"
}

# verify <expected-exit> <expected-stdout> args...
expect_verify() {
  local want_code="$1" want_out="$2"; shift 2
  set +e
  local out; out="$("$VERIFY" "$@" 2>"$WORK/verify.err")"
  local code=$?
  set -e
  echo "exit=$code stdout='$out'"
  sed 's/^/    /' "$WORK/verify.err"
  [ "$code" = "$want_code" ] || fail "expected exit $want_code, got $code"
  [ "$out" = "$want_out" ] || fail "expected stdout '$want_out', got '$out'"
}

log "starting verilogd"
start_daemon

log "a second daemon on the same data dir is refused"
if VERILOG_PRIVATE_KEY="$DEV_KEY" "$WORK/bin/verilogd" --listen 127.0.0.1:0 --rpc "$RPC" --contract "$CONTRACT" \
    --data-dir "$DATA" >"$WORK/second.log" 2>&1; then
  fail "second daemon started on a locked data dir"
fi
grep -q "in use by another verilogd" "$WORK/second.log" || { cat "$WORK/second.log"; fail "unexpected second-daemon error"; }
echo "refused: $(tail -n 1 "$WORK/second.log")"

log "running the LangChain agent through the Python SDK"
ACKED="$("$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" --agent-id "$AGENT_ID" --runs 3)" || fail "agent run failed"
echo "events acknowledged: $ACKED"
[ "$ACKED" -gt 0 ] || fail "no events acknowledged"

log "waiting for epoch 1 to be anchored"
BUNDLE1="$(wait_bundle 1)"
COUNT1="$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["log_count"])' "$BUNDLE1")"
echo "bundle: $BUNDLE1 ($COUNT1 events)"
[ "$COUNT1" = "$ACKED" ] || fail "epoch 1 holds $COUNT1 events, expected $ACKED"
ONCHAIN_COUNT="$(cast call "$CONTRACT" 'agentAnchors(bytes32,uint256)(bytes32,uint64,uint32)' "$AGENT_KEY" 1 --rpc-url "$RPC" | sed -n 3p)"
[ "$ONCHAIN_COUNT" = "$COUNT1" ] || fail "on-chain logCount $ONCHAIN_COUNT != $COUNT1"

COMMON=(--epoch 1 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")

log "export from bundle + verify untouched event (expect SUCCESS)"
"$VERIFY" export --bundle "$BUNDLE1" --index 3 --out "$WORK/ev" 2>/dev/null
expect_verify 0 "[SUCCESS] Log Integrity Verified" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"

log "export via daemon GetProof + verify (expect SUCCESS)"
"$VERIFY" export --daemon "$TARGET" --agent-id "$AGENT_ID" --epoch 1 --index 0 --out "$WORK/ev0" 2>/dev/null
expect_verify 0 "[SUCCESS] Log Integrity Verified" --event "$WORK/ev0/event.json" --proof "$WORK/ev0/proof.json" "${COMMON[@]}"

log "one-byte tamper inside the payload (expect FAILURE)"
"$PYTHON" - "$WORK/ev/event.json" "$WORK/tampered.json" <<'PY'
import sys
src = open(sys.argv[1], "rb").read()
i = src.index(b'"run_id":"') + len(b'"run_id":"')
flipped = b"b" if src[i:i+1] != b"b" else b"c"
out = src[:i] + flipped + src[i+1:]
assert sum(a != b for a, b in zip(src, out)) == 1 and len(src) == len(out)
open(sys.argv[2], "wb").write(out)
PY
cmp -l "$WORK/ev/event.json" "$WORK/tampered.json" || true
expect_verify 1 "[FAILURE] Tampered Log Detected" --event "$WORK/tampered.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"

log "one-byte structural corruption (expect FAILURE)"
"$PYTHON" -c 'import sys; b=open(sys.argv[1],"rb").read(); open(sys.argv[2],"wb").write(b[:-2]+b"]"+b[-1:])' "$WORK/ev/event.json" "$WORK/corrupt.json"
expect_verify 1 "[FAILURE] Tampered Log Detected" --event "$WORK/corrupt.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"

log "un-anchored epoch (expect exit 2, no verdict)"
expect_verify 2 "" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 999 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

log "RPC unreachable (expect exit 2, no verdict)"
expect_verify 2 "" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 1 --agent-id "$AGENT_ID" --rpc "http://127.0.0.1:1" --contract "$CONTRACT"

log "restart verilogd (SIGTERM, then start again)"
stop_daemon
start_daemon
grep -q "engine: recovered from WAL" "$WORK/daemon.log" || fail "no recovery log line"

log "second agent session after restart -> epoch 2"
ACKED2="$("$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" --agent-id "$AGENT_ID" --runs 2)" || fail "second agent run failed"
BUNDLE2="$(wait_bundle 2)"
"$VERIFY" export --bundle "$BUNDLE2" --digest "$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"][-1]["content_digest"])' "$BUNDLE2")" --out "$WORK/ev2" 2>/dev/null
expect_verify 0 "[SUCCESS] Log Integrity Verified" --event "$WORK/ev2/event.json" --proof "$WORK/ev2/proof.json" --epoch 2 --agent-id "$AGENT_KEY" --rpc "$RPC" --contract "$CONTRACT"
log "an epoch-1 proof does not verify against epoch 2 (expect FAILURE)"
expect_verify 1 "[FAILURE] Tampered Log Detected" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 2 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

[ "$(cast call "$CONTRACT" 'latestEpoch(bytes32)(uint256)' "$AGENT_KEY" --rpc-url "$RPC")" = "2" ] || fail "latestEpoch != 2"
stop_daemon

printf '\nE2E PASSED: %s + %s events anchored in 2 epochs; SUCCESS, FAILURE and operational exits verified.\n' "$ACKED" "$ACKED2"
