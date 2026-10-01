#!/usr/bin/env bash
# End-to-end test: anvil -> deploy registry -> register the agent key ->
# verilogd -> signed Python SDK events -> anchored epoch -> verilog-verify
# SUCCESS / FAILURE / operational errors in single-event and run mode,
# including a daemon restart and attacks by a compromised daemon host that
# holds the anchorer key.
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

# DEV ONLY: anvil's publicly known default accounts. Never use on a real network.
# #0 deploys and is the admin (DEFAULT_ADMIN_ROLE + KEY_ADMIN_ROLE); in
# production that role goes to a multisig. #1 is the daemon's anchorer key,
# which must never be able to register agent keys.
ADMIN_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANCHOR_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verilog-e2e.XXXXXX")"
DATA="$WORK/data"
ANVIL_PID=""
DAEMON_PID=""
unset VERILOG_SIGNING_KEY VERILOG_SIGNING_KEY_FILE VERILOG_RPC_URL VERILOG_CONTRACT

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

ANCHORER="$(cast wallet address --private-key "$ANCHOR_KEY")"
log "deploying VeriLogRegistry (admin: dev key admin, anchorer: $ANCHORER)"
(cd "$ROOT/contracts" && VERILOG_ANCHORER="$ANCHORER" forge script script/Deploy.s.sol --rpc-url "$RPC" \
    --private-key "$ADMIN_KEY" --broadcast >"$WORK/deploy.log" 2>&1) \
  || { cat "$WORK/deploy.log"; fail "deploy failed"; }
CONTRACT="$(grep -Eo 'VeriLogRegistry deployed at 0x[0-9a-fA-F]{40}' "$WORK/deploy.log" | awk '{print $4}')"
[ -n "$CONTRACT" ] || fail "could not find deployed address"
echo "registry: $CONTRACT"
[ "$(cast call "$CONTRACT" 'hasRole(bytes32,address)(bool)' "$(cast keccak KEY_ADMIN_ROLE)" "$ANCHORER" --rpc-url "$RPC")" = "false" ] \
  || fail "the anchorer holds KEY_ADMIN_ROLE"

AGENT_KEY="$(cast keccak "$AGENT_ID")"

# keygen <file>: a new agent signing key (seed file, mode 0600); prints the public key.
keygen() {
  "$PYTHON" -m verilog_sdk keygen --out "$1" --agent-id "$AGENT_ID" >"$1.out" || fail "keygen failed"
  awk '/^pubkey:/ {print $2}' "$1.out"
}
seed_of() { tr -d '\n' <"$1"; }
register_key() { # <pubkey>, as the key admin
  cast send "$CONTRACT" 'registerAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$1" --private-key "$ADMIN_KEY" --rpc-url "$RPC" >/dev/null \
    || fail "registering agent key failed"
}
revoke_key() { # <pubkey>, as the key admin
  cast send "$CONTRACT" 'revokeAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$(cast keccak "$1")" --private-key "$ADMIN_KEY" --rpc-url "$RPC" >/dev/null \
    || fail "revoking agent key failed"
}

log "generating the agent signing key"
PUBKEY="$(keygen "$WORK/agent.key")"
echo "agent pubkey: $PUBKEY  key_id: $(cast keccak "$PUBKEY")"

log "the anchorer cannot register agent keys (expect revert)"
if cast send "$CONTRACT" 'registerAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$PUBKEY" --private-key "$ANCHOR_KEY" \
    --rpc-url "$RPC" >"$WORK/anchorer-register.log" 2>&1; then
  fail "the anchorer registered an agent key"
fi
grep -qi "revert" "$WORK/anchorer-register.log" || { cat "$WORK/anchorer-register.log"; fail "unexpected error"; }
echo "refused: $(grep -i -m1 -o 'revert.*' "$WORK/anchorer-register.log" | cut -c1-120)"

log "registering the agent key as the key admin"
register_key "$PUBKEY"

start_daemon() {
  VERILOG_PRIVATE_KEY="$ANCHOR_KEY" "$WORK/bin/verilogd" \
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

wait_bundle() { # epoch
  local f="$DATA/evidence/$AGENT_KEY/epoch-$1.json"
  for _ in $(seq 1 300); do [ -f "$f" ] && { echo "$f"; return 0; }; sleep 0.2; done
  fail "epoch $1 was not anchored in time"
}

# expect_verify <expected-exit> <expected-stdout> args...
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
# expect_stderr <regex>: the last verify run explained itself.
expect_stderr() { grep -q "$1" "$WORK/verify.err" || fail "expected stderr to match '$1'"; }

SUCCESS="[SUCCESS] Log Integrity Verified"
FAILURE="[FAILURE] Tampered Log Detected"

log "starting verilogd"
start_daemon

log "a second daemon on the same data dir is refused"
if VERILOG_PRIVATE_KEY="$ANCHOR_KEY" "$WORK/bin/verilogd" --listen 127.0.0.1:0 --rpc "$RPC" --contract "$CONTRACT" \
    --data-dir "$DATA" >"$WORK/second.log" 2>&1; then
  fail "second daemon started on a locked data dir"
fi
grep -q "in use by another verilogd" "$WORK/second.log" || { cat "$WORK/second.log"; fail "unexpected second-daemon error"; }
echo "refused: $(tail -n 1 "$WORK/second.log")"

log "an agent signing with an unregistered key is rejected by the daemon"
keygen "$WORK/rogue.key" >/dev/null
if VERILOG_SIGNING_KEY_FILE="$WORK/rogue.key" "$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" \
    --agent-id "$AGENT_ID" --runs 1 >/dev/null 2>"$WORK/rogue.log"; then
  fail "events signed with an unregistered key were accepted"
fi
grep -q "acked=0 rejected=" "$WORK/rogue.log" || { cat "$WORK/rogue.log"; fail "unexpected rogue agent outcome"; }
grep -q "is not registered for agent" "$WORK/rogue.log" || { cat "$WORK/rogue.log"; fail "no 'not registered' rejection"; }
echo "rejected: $(grep -o 'acked=0 rejected=[0-9]*' "$WORK/rogue.log")"

export VERILOG_SIGNING_KEY_FILE="$WORK/agent.key"
log "running the LangChain agent through the Python SDK (signing with the registered key)"
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

# ---------------------------------------------------------- single-event mode
COMMON=(--epoch 1 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")

log "export from bundle + verify untouched event (expect SUCCESS)"
"$VERIFY" export --bundle "$BUNDLE1" --index 3 --out "$WORK/ev" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"
expect_stderr "signing key:    valid at anchor time"

log "export via daemon GetProof + verify (expect SUCCESS)"
"$VERIFY" export --daemon "$TARGET" --agent-id "$AGENT_ID" --epoch 1 --index 0 --out "$WORK/ev0" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/ev0/event.json" --proof "$WORK/ev0/proof.json" "${COMMON[@]}"

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
expect_verify 1 "$FAILURE" --event "$WORK/tampered.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"

log "one-byte structural corruption (expect FAILURE)"
"$PYTHON" -c 'import sys; b=open(sys.argv[1],"rb").read(); open(sys.argv[2],"wb").write(b[:-2]+b"]"+b[-1:])' "$WORK/ev/event.json" "$WORK/corrupt.json"
expect_verify 1 "$FAILURE" --event "$WORK/corrupt.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"

log "un-anchored epoch (expect exit 2, no verdict)"
expect_verify 2 "" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 999 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

log "RPC unreachable (expect exit 2, no verdict)"
expect_verify 2 "" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 1 --agent-id "$AGENT_ID" --rpc "http://127.0.0.1:1" --contract "$CONTRACT"

# ------------------------------------------------------------------- run mode
EVIDENCE="$DATA/evidence/$AGENT_KEY"
RUN_ID="$("$PYTHON" -c 'import json,sys; print(json.loads(json.load(open(sys.argv[1]))["events"][0]["canonical_event"])["run_id"])' "$BUNDLE1")"
RUN=(--run-id "$RUN_ID" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")
echo "run under test: $RUN_ID"

log "run mode on the untouched evidence (expect SUCCESS)"
expect_verify 0 "$SUCCESS" "${RUN[@]}" --bundles "$EVIDENCE"
expect_stderr 'run_end:        status "ok"'

# drop_event <src bundle> <dst bundle> <python condition on ev>: copy the
# bundle without the one event of $RUN_ID matching the condition.
drop_event() {
  mkdir -p "$(dirname "$2")"
  "$PYTHON" - "$1" "$2" "$RUN_ID" "$3" <<'PY'
import json, sys
src, dst, run, cond = sys.argv[1:5]
b = json.load(open(src))
def match(e):
    ev = json.loads(e["canonical_event"])
    return ev["run_id"] == run and eval(cond, {"ev": ev})
keep = [e for e in b["events"] if not match(e)]
assert len(keep) == len(b["events"]) - 1, "expected to drop exactly one event"
b["events"] = keep
json.dump(b, open(dst, "w"), indent=2)
PY
}

log "run mode, a middle event withheld from the evidence (expect FAILURE)"
drop_event "$BUNDLE1" "$WORK/drop/epoch-1.json" 'ev["step_number"] == 3'
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/drop"
expect_stderr "events missing from the run: step 2 is followed by step 4"

log "run mode, run_end withheld (expect FAILURE)"
drop_event "$BUNDLE1" "$WORK/trunc/epoch-1.json" 'ev["event_type"] == "run_end"'
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/trunc"
expect_stderr "run ended without terminal event after step"

log "run mode, run_end withheld, --allow-incomplete (expect SUCCESS with a warning)"
expect_verify 0 "$SUCCESS" "${RUN[@]}" --bundles "$WORK/trunc" --allow-incomplete
expect_stderr "warning: .*run ended without terminal event"

log "run mode, RPC unreachable (expect exit 2, no verdict)"
expect_verify 2 "" --run-id "$RUN_ID" --bundles "$EVIDENCE" --agent-id "$AGENT_ID" --rpc "http://127.0.0.1:1" --contract "$CONTRACT"

# ------------------------------------------------------------------- restart
log "restart verilogd (SIGTERM, then start again)"
stop_daemon
start_daemon
grep -q "engine: recovered from WAL" "$WORK/daemon.log" || fail "no recovery log line"

log "second agent session after restart -> epoch 2"
ACKED2="$("$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" --agent-id "$AGENT_ID" --runs 2)" || fail "second agent run failed"
BUNDLE2="$(wait_bundle 2)"
"$VERIFY" export --bundle "$BUNDLE2" --digest "$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"][-1]["content_digest"])' "$BUNDLE2")" --out "$WORK/ev2" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/ev2/event.json" --proof "$WORK/ev2/proof.json" --epoch 2 --agent-id "$AGENT_KEY" --rpc "$RPC" --contract "$CONTRACT"
log "an epoch-1 proof does not verify against epoch 2 (expect FAILURE)"
expect_verify 1 "$FAILURE" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 2 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

[ "$(cast call "$CONTRACT" 'latestEpoch(bytes32)(uint256)' "$AGENT_KEY" --rpc-url "$RPC")" = "2" ] || fail "latestEpoch != 2"
stop_daemon

# ---------------------------------------------------------------------------
# A compromised daemon host: it holds the anchorer key and can anchor any
# root it likes, but it cannot sign as the agent or register keys.
FORGE="$ROOT/scripts/e2e_forge.py"
next_epoch() { echo $(( $(cast call "$CONTRACT" 'latestEpoch(bytes32)(uint256)' "$AGENT_KEY" --rpc-url "$RPC") + 1 )); }
attacker_anchor() { # <root> <count>: anchor as the anchorer; prints the new epoch
  local want; want="$(next_epoch)"
  cast send "$CONTRACT" 'anchorEpoch(bytes32,bytes32,uint32)' "$AGENT_KEY" "$1" "$2" --private-key "$ANCHOR_KEY" --rpc-url "$RPC" >/dev/null \
    || fail "attacker anchoring failed"
  [ "$(next_epoch)" = "$((want + 1))" ] || fail "unexpected epoch numbering"
  echo "$want"
}

log "forged event re-signed with an unregistered key, anchored by the anchorer (expect FAILURE)"
keygen "$WORK/attacker.key" >/dev/null
mkdir -p "$WORK/forged"
LEAF="$("$PYTHON" "$FORGE" resign "$WORK/ev/event.json" "$WORK/forged/event.json" --seed "$(seed_of "$WORK/attacker.key")" \
  --payload '{"text":"approve the wire transfer"}')"
EPOCH="$(attacker_anchor "$LEAF" 1)"
expect_verify 1 "$FAILURE" --event "$WORK/forged/event.json" --proof "$WORK/forged/proof.json" \
  --epoch "$EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "is not registered on chain"

advance_time() { cast rpc evm_increaseTime 10 --rpc-url "$RPC" >/dev/null && cast rpc evm_mine --rpc-url "$RPC" >/dev/null; }

log "key rotation: an event signed with an old key verifies in an epoch anchored before the revocation (expect SUCCESS)"
OLD_PUB="$(keygen "$WORK/old.key")"
register_key "$OLD_PUB"
mkdir -p "$WORK/late"
LEAF="$("$PYTHON" "$FORGE" resign "$WORK/ev/event.json" "$WORK/late/event.json" --seed "$(seed_of "$WORK/old.key")")"
advance_time
EPOCH="$(attacker_anchor "$LEAF" 1)"
advance_time
revoke_key "$OLD_PUB"
expect_verify 0 "$SUCCESS" --event "$WORK/late/event.json" --proof "$WORK/late/proof.json" \
  --epoch "$EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

log "the same event anchored after the key's revocation (expect FAILURE)"
advance_time
EPOCH="$(attacker_anchor "$LEAF" 1)"
expect_verify 1 "$FAILURE" --event "$WORK/late/event.json" --proof "$WORK/late/proof.json" \
  --epoch "$EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "was not valid when epoch"

log "genuine run with step 2 withheld and anchored after step 3 (expect FAILURE)"
"$PYTHON" "$ROOT/scripts/e2e_agent.py" --capture "$WORK/captured.jsonl" --agent-id "$AGENT_ID" --runs 1 >/dev/null 2>"$WORK/capture.log" \
  || { cat "$WORK/capture.log"; fail "capture run failed"; }
CAPTURED_RUN="$("$PYTHON" -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline())["run_id"])' "$WORK/captured.jsonl")"
N="$(wc -l <"$WORK/captured.jsonl" | tr -d ' ')"
REST="$("$PYTHON" -c 'import sys; print(",".join(str(i) for i in range(int(sys.argv[1])) if i != 1))' "$N")"
E1="$(next_epoch)"
read -r ROOT_A COUNT_A < <("$PYTHON" "$FORGE" bundle --events "$WORK/captured.jsonl" --indices "$REST" --agent-id "$AGENT_ID" --epoch "$E1" --out "$WORK/swap/epoch-$E1.json")
[ "$(attacker_anchor "$ROOT_A" "$COUNT_A")" = "$E1" ] || fail "epoch mismatch"
E2="$(next_epoch)"
read -r ROOT_B COUNT_B < <("$PYTHON" "$FORGE" bundle --events "$WORK/captured.jsonl" --indices 1 --agent-id "$AGENT_ID" --epoch "$E2" --out "$WORK/swap/epoch-$E2.json")
[ "$(attacker_anchor "$ROOT_B" "$COUNT_B")" = "$E2" ] || fail "epoch mismatch"
# Each event on its own is genuine, signed and included...
"$VERIFY" export --bundle "$WORK/swap/epoch-$E2.json" --index 0 --out "$WORK/swap-ev" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/swap-ev/event.json" --proof "$WORK/swap-ev/proof.json" \
  --epoch "$E2" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
# ...but the run shows step 2 anchored after step 3.
expect_verify 1 "$FAILURE" --run-id "$CAPTURED_RUN" --bundles "$WORK/swap" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "step 2 was anchored in epoch $E2, after its successor step 3"

printf '\nE2E PASSED: %s + %s signed events anchored in 2 epochs; single-event and run mode SUCCESS, FAILURE (tamper, withheld, truncated, forged, revoked key, reordered), key rotation and operational exits verified.\n' "$ACKED" "$ACKED2"
