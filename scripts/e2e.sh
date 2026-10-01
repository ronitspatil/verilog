#!/usr/bin/env bash
# End-to-end test: anvil -> deploy registry -> register the agent key ->
# verilogd -> signed Python SDK events -> anchored epoch -> verilog-verify
# SUCCESS / FAILURE / operational errors in single-event and run mode,
# including a daemon restart and attacks by a compromised daemon host that
# holds the anchorer key. The daemon runs with mutual TLS (dev certificates
# from verilog-devcerts); scripts/e2e_mtls.py checks its authorization.
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
(cd "$ROOT/daemon" && go build -o "$WORK/bin/" ./cmd/verilogd ./cmd/verilog-verify ./cmd/verilog-devcerts)
VERIFY="$WORK/bin/verilog-verify"

# DEV ONLY certificates: a throwaway CA, the daemon's server certificate, the
# agent's client certificate (URI SAN verilog://agent/e2e-agent), a second
# agent's and an auditor's.
OTHER_AGENT="other-agent"
AUDITOR="e2e-auditor"
CERTS="$WORK/certs"
log "issuing DEV-ONLY mTLS certificates"
"$WORK/bin/verilog-devcerts" --out "$CERTS" --agent "$AGENT_ID" --agent "$OTHER_AGENT" --auditor "$AUDITOR" \
  || fail "verilog-devcerts failed"
DAEMON_TLS=(--tls-cert "$CERTS/server.pem" --tls-key "$CERTS/server-key.pem" --tls-client-ca "$CERTS/ca.pem")
AGENT_TLS=(--tls-ca "$CERTS/ca.pem" --tls-cert "$CERTS/agent-$AGENT_ID.pem" --tls-key "$CERTS/agent-$AGENT_ID-key.pem")
AUDITOR_TLS=(--daemon-ca "$CERTS/ca.pem" --daemon-cert "$CERTS/auditor-$AUDITOR.pem" --daemon-key "$CERTS/auditor-$AUDITOR-key.pem")

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

# keygen <file>: a new agent signing key (seed file, mode 0600); prints the
# public key. The proof of possession is in <file>.out.
keygen() {
  "$PYTHON" -m verilog_sdk keygen --out "$1" --agent-id "$AGENT_ID" >"$1.out" || fail "keygen failed"
  awk '/^pubkey:/ {print $2}' "$1.out"
}
pop_of() { awk '/^pop:/ {print $2}' "$1.out"; }
seed_of() { tr -d '\n' <"$1"; }
register_key() { # <key file>: the key admin checks the key and its proof of possession, then registers it
  local pub; pub="$(awk '/^pubkey:/ {print $2}' "$1.out")"
  "$VERIFY" keycheck --agent-id "$AGENT_ID" --pubkey "$pub" --pop "$(pop_of "$1")" >"$WORK/keycheck.out" 2>/dev/null \
    || { cat "$WORK/keycheck.out"; fail "keycheck refused a freshly generated key"; }
  cast send "$CONTRACT" 'registerAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$pub" --private-key "$ADMIN_KEY" --rpc-url "$RPC" >/dev/null \
    || fail "registering agent key failed"
}
chain_time() { cast block latest -f timestamp --rpc-url "$RPC"; }
revoke_key() { # <pubkey> <seconds from now>: schedule the revocation, as the key admin
  local at=$(( $(chain_time) + $2 ))
  cast send "$CONTRACT" 'revokeAgentKey(bytes32,bytes32,uint64)' "$AGENT_KEY" "$(cast keccak "$1")" "$at" \
    --private-key "$ADMIN_KEY" --rpc-url "$RPC" >/dev/null || fail "revoking agent key failed"
}
advance_time() { cast rpc evm_increaseTime "${1:-10}" --rpc-url "$RPC" >/dev/null && cast rpc evm_mine --rpc-url "$RPC" >/dev/null; }

log "generating the agent signing key (with a proof of possession)"
PUBKEY="$(keygen "$WORK/agent.key")"
echo "agent pubkey: $PUBKEY  key_id: $(cast keccak "$PUBKEY")"

log "a small-order key is refused by keycheck and by the registry (expect [KEY REJECTED] and a revert)"
IDENTITY="0x0100000000000000000000000000000000000000000000000000000000000000"
set +e
"$VERIFY" keycheck --agent-id "$AGENT_ID" --pubkey "$IDENTITY" --pop "0x01$(printf '0%.0s' $(seq 1 126))" >"$WORK/weak.out" 2>/dev/null
code=$?
set -e
[ "$code" = 1 ] && grep -q "^\[KEY REJECTED\].*small order" "$WORK/weak.out" || { cat "$WORK/weak.out"; fail "keycheck accepted the identity point"; }
cat "$WORK/weak.out"
if cast send "$CONTRACT" 'registerAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$IDENTITY" --private-key "$ADMIN_KEY" \
    --rpc-url "$RPC" >"$WORK/weak-register.log" 2>&1; then
  fail "the registry accepted the identity point as an agent key"
fi
grep -qi "revert" "$WORK/weak-register.log" || { cat "$WORK/weak-register.log"; fail "unexpected error"; }
echo "registry refused: $(grep -i -m1 -o 'revert.*' "$WORK/weak-register.log" | cut -c1-120)"

log "a proof of possession made for another agent id is refused (expect [KEY REJECTED])"
if "$VERIFY" keycheck --agent-id "another-agent" --pubkey "$PUBKEY" --pop "$(pop_of "$WORK/agent.key")" >"$WORK/pop.out" 2>/dev/null; then
  fail "keycheck accepted a proof of possession for another agent"
fi
cat "$WORK/pop.out"

log "the anchorer cannot register agent keys (expect revert)"
if cast send "$CONTRACT" 'registerAgentKey(bytes32,bytes32)' "$AGENT_KEY" "$PUBKEY" --private-key "$ANCHOR_KEY" \
    --rpc-url "$RPC" >"$WORK/anchorer-register.log" 2>&1; then
  fail "the anchorer registered an agent key"
fi
grep -qi "revert" "$WORK/anchorer-register.log" || { cat "$WORK/anchorer-register.log"; fail "unexpected error"; }
echo "refused: $(grep -i -m1 -o 'revert.*' "$WORK/anchorer-register.log" | cut -c1-120)"

log "registering the agent key as the key admin (after keycheck)"
register_key "$WORK/agent.key"

start_daemon() {
  VERILOG_PRIVATE_KEY="$ANCHOR_KEY" "$WORK/bin/verilogd" \
    --listen "$TARGET" --rpc "$RPC" --contract "$CONTRACT" --data-dir "$DATA" "${DAEMON_TLS[@]}" \
    --epoch-interval 2s --epoch-max-logs 1000 --confirm-timeout 30s --retry-initial 200ms \
    >>"$WORK/daemon.log" 2>&1 &
  DAEMON_PID=$!
  local n; n="$(grep -c "verilogd listening" "$WORK/daemon.log" || true)"
  for _ in $(seq 1 100); do
    [ "$(grep -c "verilogd listening" "$WORK/daemon.log" || true)" -gt "$n" ] && return 0
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

EVIDENCE="$DATA/evidence/$AGENT_KEY"
latest_epoch() { cast call "$CONTRACT" 'latestEpoch(bytes32)(uint256)' "$AGENT_KEY" --rpc-url "$RPC"; }
anchored_count() { # events in the daemon's bundles
  "$PYTHON" -c 'import glob,json,sys; print(sum(json.load(open(f))["log_count"] for f in glob.glob(sys.argv[1]+"/epoch-*.json")))' "$EVIDENCE" 2>/dev/null || echo 0
}
wait_anchored() { # <total events>: wait until the daemon's bundles hold them all
  for _ in $(seq 1 300); do [ "$(anchored_count)" -ge "$1" ] && return 0; sleep 0.2; done
  fail "only $(anchored_count) of $1 events anchored in time"
}

# The complete evidence of the agent: the daemon's bundles plus the bundles
# of every epoch the attacker anchors below ($ATTACK). Run mode needs all.
ATTACK="$WORK/attacker-evidence"
mkdir -p "$ATTACK"
all_evidence() { # <dir>: a fresh copy of the complete evidence
  rm -rf "$1" && mkdir -p "$1" && cp "$EVIDENCE"/epoch-*.json "$1"/ && { cp "$ATTACK"/epoch-*.json "$1"/ 2>/dev/null || true; }
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
INCOMPLETE="[SUCCESS-INCOMPLETE] Log Integrity Verified, Run Incomplete"

log "starting verilogd"
start_daemon

log "a daemon with neither TLS nor --insecure-plaintext is refused"
if VERILOG_PRIVATE_KEY="$ANCHOR_KEY" "$WORK/bin/verilogd" --listen 127.0.0.1:0 --rpc "$RPC" --contract "$CONTRACT" \
    --data-dir "$WORK/unused" >"$WORK/notls.log" 2>&1; then
  fail "daemon started without transport security"
fi
grep -q "no transport security" "$WORK/notls.log" || { cat "$WORK/notls.log"; fail "unexpected no-TLS error"; }
echo "refused: $(tail -n 1 "$WORK/notls.log" | cut -c1-120)"

log "a second daemon on the same data dir is refused"
if VERILOG_PRIVATE_KEY="$ANCHOR_KEY" "$WORK/bin/verilogd" --listen 127.0.0.1:0 --rpc "$RPC" --contract "$CONTRACT" \
    --data-dir "$DATA" "${DAEMON_TLS[@]}" >"$WORK/second.log" 2>&1; then
  fail "second daemon started on a locked data dir"
fi
grep -q "in use by another verilogd" "$WORK/second.log" || { cat "$WORK/second.log"; fail "unexpected second-daemon error"; }
echo "refused: $(tail -n 1 "$WORK/second.log")"

log "an agent signing with an unregistered key is rejected by the daemon (after a bounded retry)"
keygen "$WORK/rogue.key" >/dev/null
if VERILOG_SIGNING_KEY_FILE="$WORK/rogue.key" "$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" "${AGENT_TLS[@]}" \
    --agent-id "$AGENT_ID" --runs 1 --key-wait 2 >/dev/null 2>"$WORK/rogue.log"; then
  fail "events signed with an unregistered key were accepted"
fi
grep -q "acked=0 rejected=" "$WORK/rogue.log" || { cat "$WORK/rogue.log"; fail "unexpected rogue agent outcome"; }
grep -q "is not registered for agent" "$WORK/rogue.log" || { cat "$WORK/rogue.log"; fail "no 'not registered' rejection"; }
grep -q "retrying in" "$WORK/rogue.log" || { cat "$WORK/rogue.log"; fail "'not registered' rejections were not retried"; }
echo "rejected: $(grep -o 'acked=0 rejected=[0-9]*' "$WORK/rogue.log")"

export VERILOG_SIGNING_KEY_FILE="$WORK/agent.key"
CRASHED_RUN="crashed-run-1"
log "running the LangChain agent through the Python SDK (plus a run that never ends)"
ACKED="$("$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" "${AGENT_TLS[@]}" --agent-id "$AGENT_ID" --runs 3 --open-run "$CRASHED_RUN")" \
  || fail "agent run failed"
echo "events acknowledged: $ACKED"
[ "$ACKED" -gt 0 ] || fail "no events acknowledged"

log "waiting for the events to be anchored"
wait_anchored "$ACKED"
BUNDLE1="$EVIDENCE/epoch-1.json"
ONCHAIN_COUNT="$(cast call "$CONTRACT" 'agentAnchors(bytes32,uint256)(bytes32,uint64,uint32)' "$AGENT_KEY" 1 --rpc-url "$RPC" | sed -n 3p)"
COUNT1="$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["log_count"])' "$BUNDLE1")"
[ "$ONCHAIN_COUNT" = "$COUNT1" ] || fail "on-chain logCount $ONCHAIN_COUNT != $COUNT1"
echo "anchored in $(latest_epoch) epoch(s)"

# ---------------------------------------------------------- single-event mode
COMMON=(--epoch 1 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")

log "export from bundle + verify untouched event (expect SUCCESS)"
"$VERIFY" export --bundle "$BUNDLE1" --index 1 --out "$WORK/ev" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"
expect_stderr "signing key:    valid at anchor time"

log "export via daemon GetProof as the auditor (mTLS) + verify (expect SUCCESS)"
"$VERIFY" export --daemon "$TARGET" "${AUDITOR_TLS[@]}" --agent-id "$AGENT_ID" --epoch 1 --index 0 --out "$WORK/ev0" 2>/dev/null \
  || fail "export via the daemon failed"
expect_verify 0 "$SUCCESS" --event "$WORK/ev0/event.json" --proof "$WORK/ev0/proof.json" "${COMMON[@]}"

log "export via daemon GetProof without a client certificate is refused"
if "$VERIFY" export --daemon "$TARGET" --daemon-ca "$CERTS/ca.pem" --agent-id "$AGENT_ID" --epoch 1 --index 0 \
    --out "$WORK/ev-nocert" 2>"$WORK/nocert.err"; then
  fail "the daemon served GetProof to a client without a certificate"
fi
echo "refused: $(tail -n 1 "$WORK/nocert.err" | cut -c1-140)"

log "mTLS authorization: no cert, plaintext, impersonation, auditor ingest, cross-agent GetProof (expect refusals)"
"$PYTHON" "$ROOT/scripts/e2e_mtls.py" --target "$TARGET" --certs "$CERTS" --agent-id "$AGENT_ID" \
  --other-agent "$OTHER_AGENT" --auditor "$AUDITOR" --epoch 1 2>"$WORK/mtls.err" || { cat "$WORK/mtls.err"; fail "mTLS checks failed"; }

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

log "the same event re-spelled (reformatted, non-canonical file) (expect FAILURE)"
"$PYTHON" -c 'import json,sys; open(sys.argv[2],"w").write(json.dumps(json.load(open(sys.argv[1])), indent=2))' "$WORK/ev/event.json" "$WORK/respelled.json"
expect_verify 1 "$FAILURE" --event "$WORK/respelled.json" --proof "$WORK/ev/proof.json" "${COMMON[@]}"
expect_stderr "not in canonical form"
expect_stderr "signed bytes:"

log "an epoch that is not anchored (expect FAILURE: false evidence, not 'no verdict')"
expect_verify 1 "$FAILURE" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 999 --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "epoch 999 is not anchored"

log "RPC unreachable (expect exit 2, no verdict)"
expect_verify 2 "" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch 1 --agent-id "$AGENT_ID" --rpc "http://127.0.0.1:1" --contract "$CONTRACT"

# ------------------------------------------------------------------- run mode
RUN_ID="$("$PYTHON" -c 'import json,sys; print(json.loads(json.load(open(sys.argv[1]))["events"][0]["canonical_event"])["run_id"])' "$BUNDLE1")"
RUN=(--run-id "$RUN_ID" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")
echo "run under test: $RUN_ID"

log "run mode on the complete evidence (expect SUCCESS)"
expect_verify 0 "$SUCCESS" "${RUN[@]}" --bundles "$EVIDENCE"
expect_stderr 'run_end:        status "ok"'

# drop_event <evidence dir> <python condition on ev>: remove the one event of
# $RUN_ID matching the condition from whichever bundle holds it.
drop_event() {
  "$PYTHON" - "$1" "$RUN_ID" "$2" <<'PY'
import glob, json, sys
d, run, cond = sys.argv[1:4]
dropped = 0
for f in glob.glob(d + "/epoch-*.json"):
    b = json.load(open(f))
    def match(e):
        ev = json.loads(e["canonical_event"])
        return ev["run_id"] == run and eval(cond, {"ev": ev})
    keep = [e for e in b["events"] if not match(e)]
    if len(keep) != len(b["events"]):
        dropped += len(b["events"]) - len(keep)
        b["events"] = keep
        json.dump(b, open(f, "w"), indent=2)
assert dropped == 1, dropped
PY
}

log "run mode, a middle event withheld from the evidence (expect FAILURE)"
all_evidence "$WORK/drop"
drop_event "$WORK/drop" 'ev["step_number"] == 3'
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/drop"
expect_stderr "does not match the on-chain anchors"

log "run mode, a decoy bundle for an unanchored epoch next to the gap (expect FAILURE, not 'no verdict')"
"$PYTHON" -c 'import json,sys; b=json.load(open(sys.argv[1])); b["epoch_id"]=999; json.dump(b, open(sys.argv[2],"w"))' "$BUNDLE1" "$WORK/drop/epoch-999.json"
echo '{not json' >"$WORK/drop/garbage.json"
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/drop"
expect_stderr "epoch 999 is not anchored for this agent"

log "run mode, an anchored epoch missing from the evidence (expect FAILURE)"
mkdir -p "$WORK/none"
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/none"
expect_stderr "evidence is incomplete"

log "run mode, a run that never ended (expect FAILURE)"
CRASH=(--run-id "$CRASHED_RUN" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT" --bundles "$EVIDENCE")
expect_verify 1 "$FAILURE" "${CRASH[@]}"
expect_stderr "run ended without terminal event after step 2"

log "run mode, the same run with --allow-incomplete (expect the distinct [SUCCESS-INCOMPLETE], exit 3)"
expect_verify 3 "$INCOMPLETE" "${CRASH[@]}" --allow-incomplete
expect_stderr "warning: .*INCOMPLETE"

log "run mode, RPC unreachable (expect exit 2, no verdict)"
expect_verify 2 "" --run-id "$RUN_ID" --bundles "$EVIDENCE" --agent-id "$AGENT_ID" --rpc "http://127.0.0.1:1" --contract "$CONTRACT"

# ------------------------------------------------------------------- restart
log "restart verilogd (SIGTERM, then start again)"
stop_daemon
start_daemon
grep -q "engine: recovered from WAL" "$WORK/daemon.log" || fail "no recovery log line"

log "second agent session after restart, with a 1.5 MB tool output (over the 1 MiB payload limit)"
BEFORE="$(anchored_count)"
"$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" "${AGENT_TLS[@]}" --agent-id "$AGENT_ID" --runs 2 --big-output 1572864 \
  >"$WORK/agent2.out" 2>"$WORK/agent2.log" || { tail -n 20 "$WORK/agent2.log"; fail "second agent run failed"; }
ACKED2="$(cat "$WORK/agent2.out")"
grep -Eq "truncated=[1-9][0-9]* chain_gaps=0" "$WORK/agent2.log" || { tail -n 5 "$WORK/agent2.log"; fail "the oversized payload was not replaced"; }
wait_anchored $(( BEFORE + ACKED2 ))
BIG_RUN="$("$PYTHON" - "$EVIDENCE" <<'PY'
import glob, json, sys
for f in sorted(glob.glob(sys.argv[1] + "/epoch-*.json")):
    for e in json.load(open(f))["events"]:
        ev = json.loads(e["canonical_event"])
        if ev["payload"].get("truncated") is True:
            print(ev["run_id"]); sys.exit(0)
sys.exit(1)
PY
)" || fail "no signed stand-in for the oversized payload in the evidence"
log "run mode on the run with the oversized tool output (expect SUCCESS)"
expect_verify 0 "$SUCCESS" --run-id "$BIG_RUN" --bundles "$EVIDENCE" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

LATEST="$(latest_epoch)"
BUNDLE2="$EVIDENCE/epoch-$LATEST.json"
"$VERIFY" export --bundle "$BUNDLE2" --digest "$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"][-1]["content_digest"])' "$BUNDLE2")" --out "$WORK/ev2" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/ev2/event.json" --proof "$WORK/ev2/proof.json" --epoch "$LATEST" --agent-id "$AGENT_KEY" --rpc "$RPC" --contract "$CONTRACT"
log "an epoch-1 proof does not verify against epoch $LATEST (expect FAILURE)"
expect_verify 1 "$FAILURE" --event "$WORK/ev/event.json" --proof "$WORK/ev/proof.json" --epoch "$LATEST" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

# ---------------------------------------------- kill between send and receipt
log "kill -9 between send and receipt: the restarted daemon reuses the nonce and anchors the root once"
cast rpc evm_setAutomine false --rpc-url "$RPC" >/dev/null
EPOCHS_BEFORE="$(latest_epoch)"
NONCE_BEFORE="$(cast nonce "$ANCHORER" --rpc-url "$RPC")"
SENT="$(grep -c "anchor: transaction sent" "$WORK/daemon.log" || true)"
BEFORE="$(anchored_count)"
KILLED_ACKED="$("$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" "${AGENT_TLS[@]}" --agent-id "$AGENT_ID" --runs 1 2>"$WORK/agent3.log")" \
  || { tail -n 20 "$WORK/agent3.log"; fail "agent run before the kill failed"; }
for _ in $(seq 1 100); do [ "$(grep -c "anchor: transaction sent" "$WORK/daemon.log" || true)" -gt "$SENT" ] && break; sleep 0.1; done
[ "$(grep -c "anchor: transaction sent" "$WORK/daemon.log" || true)" -gt "$SENT" ] || fail "no anchor transaction was sent"
[ -f "$DATA/anchor-pending.json" ] || fail "the pending transaction was not persisted before broadcast"
kill -KILL "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""
echo "killed with transaction $(jq -r .tx_hash "$DATA/anchor-pending.json") (nonce $(jq -r .nonce "$DATA/anchor-pending.json")) unmined"
SENT="$(grep -c "anchor: transaction sent" "$WORK/daemon.log" || true)"
start_daemon
grep -q "anchor: resuming pending transaction" "$WORK/daemon.log" || fail "the restarted daemon did not resume the pending transaction"
for _ in $(seq 1 100); do [ "$(grep -c "anchor: transaction sent" "$WORK/daemon.log" || true)" -gt "$SENT" ] && break; sleep 0.1; done
tail -n +"$(( $(grep -n "anchor: resuming pending transaction" "$WORK/daemon.log" | tail -n 1 | cut -d: -f1) ))" "$WORK/daemon.log" \
  | grep -q "anchor: transaction sent.* nonce=$(jq -r .nonce "$DATA/anchor-pending.json") replaces=1" \
  || fail "the restarted daemon did not replace the pending transaction with the same nonce"
cast rpc evm_setAutomine true --rpc-url "$RPC" >/dev/null
cast rpc evm_mine --rpc-url "$RPC" >/dev/null
wait_anchored $(( BEFORE + KILLED_ACKED ))
sleep 1; cast rpc evm_mine --rpc-url "$RPC" >/dev/null
EPOCHS_AFTER="$(latest_epoch)"
NONCE_AFTER="$(cast nonce "$ANCHORER" --rpc-url "$RPC")"
for e in $(seq $(( EPOCHS_BEFORE + 1 )) "$EPOCHS_AFTER"); do
  [ -f "$EVIDENCE/epoch-$e.json" ] || fail "epoch $e is on chain without a daemon bundle: a root was anchored twice"
done
[ $(( NONCE_AFTER - NONCE_BEFORE )) = $(( EPOCHS_AFTER - EPOCHS_BEFORE )) ] \
  || fail "the anchorer sent $(( NONCE_AFTER - NONCE_BEFORE )) transactions for $(( EPOCHS_AFTER - EPOCHS_BEFORE )) epochs"
[ ! -f "$DATA/anchor-pending.json" ] || fail "pending record left behind after confirmation"
echo "epochs $(( EPOCHS_BEFORE + 1 ))..$EPOCHS_AFTER anchored once each, $(( NONCE_AFTER - NONCE_BEFORE )) anchorer transactions"
grep -q "VERILOG_PRIVATE_KEY environment variable" "$WORK/daemon.log" || fail "no warning for the anchoring key from the environment"
stop_daemon

# ---------------------------------------------------------------------------
# A compromised daemon host: it holds the anchorer key and can anchor any
# root it likes, but it cannot sign as the agent or register keys. Every
# epoch it anchors also gets a bundle in $ATTACK, so the evidence stays
# complete for run mode.
FORGE="$ROOT/scripts/e2e_forge.py"
next_epoch() { echo $(( $(latest_epoch) + 1 )); }
attacker_anchor() { # bundle args for e2e_forge (without --epoch/--out): anchor as the anchorer; prints the new epoch
  local want; want="$(next_epoch)"
  local root count
  read -r root count < <("$PYTHON" "$FORGE" bundle "$@" --agent-id "$AGENT_ID" --epoch "$want" --out "$ATTACK/epoch-$want.json")
  cast send "$CONTRACT" 'anchorEpoch(bytes32,bytes32,uint32)' "$AGENT_KEY" "$root" "$count" --private-key "$ANCHOR_KEY" --rpc-url "$RPC" >/dev/null \
    || fail "attacker anchoring failed"
  [ "$(next_epoch)" = "$((want + 1))" ] || fail "unexpected epoch numbering"
  echo "$want"
}

log "forged event re-signed with an unregistered key, anchored by the anchorer (expect FAILURE)"
keygen "$WORK/attacker.key" >/dev/null
mkdir -p "$WORK/forged"
"$PYTHON" "$FORGE" resign "$WORK/ev/event.json" "$WORK/forged/event.json" --seed "$(seed_of "$WORK/attacker.key")" \
  --payload '{"text":"approve the wire transfer"}' >/dev/null
EPOCH="$(attacker_anchor --event "$WORK/forged/event.json")"
expect_verify 1 "$FAILURE" --event "$WORK/forged/event.json" --proof "$WORK/forged/proof.json" \
  --epoch "$EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "is not registered on chain"
log "...and in run mode, the forgery inside the run fails it (expect FAILURE)"
all_evidence "$WORK/all"
expect_verify 1 "$FAILURE" "${RUN[@]}" --bundles "$WORK/all"
expect_stderr "is not registered on chain"

log "key rotation: an event signed with a second key, anchored before that key's revocation"
OLD_PUB="$(keygen "$WORK/old.key")"
register_key "$WORK/old.key"
advance_time
mkdir -p "$WORK/late"
"$PYTHON" "$FORGE" resign "$WORK/ev/event.json" "$WORK/late/event.json" --seed "$(seed_of "$WORK/old.key")" >/dev/null
LATE_EPOCH="$(attacker_anchor --event "$WORK/late/event.json")"

log "an agent session signed with the second key, anchored by the daemon"
start_daemon
BEFORE="$(anchored_count)"
OLD_ACKED="$(VERILOG_SIGNING_KEY_FILE="$WORK/old.key" "$PYTHON" "$ROOT/scripts/e2e_agent.py" --target "$TARGET" "${AGENT_TLS[@]}" --agent-id "$AGENT_ID" --runs 1)" \
  || fail "old-key agent run failed"
wait_anchored $(( BEFORE + OLD_ACKED ))
OLD_BUNDLE="$EVIDENCE/epoch-$(latest_epoch).json"
OLD_RUN="$("$PYTHON" -c 'import json,sys; print(json.loads(json.load(open(sys.argv[1]))["events"][0]["canonical_event"])["run_id"])' "$OLD_BUNDLE")"

log "revoking the second key (effective in 30 s, then 40 s pass)"
revoke_key "$OLD_PUB" 30
advance_time 40

log "replaying the revoked key's events to the daemon: nothing is anchored (seal-time revocation check)"
EPOCHS_BEFORE="$(latest_epoch)"
"$PYTHON" "$FORGE" replay --bundle "$OLD_BUNDLE" --target "$TARGET" "${AGENT_TLS[@]}" | tee "$WORK/replay.out"
sleep 5
[ "$(latest_epoch)" = "$EPOCHS_BEFORE" ] || fail "events signed with a revoked key were anchored again"
if ! grep -q "accepted=0" "$WORK/replay.out"; then
  grep -q "signed with a revoked key left out of the epoch" "$WORK/daemon.log" || fail "accepted replays were not left out at seal time"
fi
stop_daemon

log "the event anchored before the revocation still verifies (expect SUCCESS)"
expect_verify 0 "$SUCCESS" --event "$WORK/late/event.json" --proof "$WORK/late/proof.json" \
  --epoch "$LATE_EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

log "the same event anchored after the key's revocation (expect FAILURE)"
EPOCH="$(attacker_anchor --event "$WORK/late/event.json")"
expect_verify 1 "$FAILURE" --event "$WORK/late/event.json" --proof "$WORK/late/proof.json" \
  --epoch "$EPOCH" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "was not valid when epoch"

log "replay after revocation: a copy of an honest run's step 2 re-anchored by the anchorer (expect SUCCESS with a warning)"
STEP2="$("$PYTHON" -c '
import json,sys
evs = json.load(open(sys.argv[1]))["events"]
print(next(i for i, e in enumerate(evs) if json.loads(e["canonical_event"])["step_number"] == 2))' "$OLD_BUNDLE")"
attacker_anchor --from-bundle "$OLD_BUNDLE" --indices "$STEP2" >/dev/null
all_evidence "$WORK/all"
expect_verify 0 "$SUCCESS" --run-id "$OLD_RUN" --bundles "$WORK/all" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
expect_stderr "step 2: a copy anchored in epoch .* was ignored"

log "genuine run with step 2 withheld and anchored after step 3 (expect FAILURE)"
"$PYTHON" "$ROOT/scripts/e2e_agent.py" --capture "$WORK/captured.jsonl" --agent-id "$AGENT_ID" --runs 1 >/dev/null 2>"$WORK/capture.log" \
  || { cat "$WORK/capture.log"; fail "capture run failed"; }
CAPTURED_RUN="$("$PYTHON" -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline())["run_id"])' "$WORK/captured.jsonl")"
N="$(wc -l <"$WORK/captured.jsonl" | tr -d ' ')"
REST="$("$PYTHON" -c 'import sys; print(",".join(str(i) for i in range(int(sys.argv[1])) if i != 1))' "$N")"
LATER="$("$PYTHON" -c 'import sys; print(",".join(str(i) for i in range(1, int(sys.argv[1]))))' "$N")"
E1="$(attacker_anchor --events "$WORK/captured.jsonl" --indices "$REST")"
E2="$(attacker_anchor --events "$WORK/captured.jsonl" --indices 1)"
CAP=(--run-id "$CAPTURED_RUN" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT")
# Each event on its own is genuine, signed and included...
"$VERIFY" export --bundle "$ATTACK/epoch-$E2.json" --index 0 --out "$WORK/swap-ev" 2>/dev/null
expect_verify 0 "$SUCCESS" --event "$WORK/swap-ev/event.json" --proof "$WORK/swap-ev/proof.json" \
  --epoch "$E2" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"
# ...but the run shows step 2 anchored after step 3.
all_evidence "$WORK/all"
expect_verify 1 "$FAILURE" "${CAP[@]}" --bundles "$WORK/all"
expect_stderr "step 2 was anchored in epoch $E2, after its successor step 3"

log "curated re-anchor: steps 2..$N anchored again, only the later copies presented (expect FAILURE)"
E3="$(attacker_anchor --events "$WORK/captured.jsonl" --indices "$LATER")"
all_evidence "$WORK/all"
expect_verify 1 "$FAILURE" "${CAP[@]}" --bundles "$WORK/all"
expect_stderr "step 2 was anchored in epoch $E2, after its successor step 3"
all_evidence "$WORK/curated"
"$PYTHON" "$FORGE" bundle --events "$WORK/captured.jsonl" --indices 0 --agent-id "$AGENT_ID" --epoch "$E1" --out "$WORK/curated/epoch-$E1.json" >/dev/null
rm "$WORK/curated/epoch-$E2.json"
expect_verify 1 "$FAILURE" "${CAP[@]}" --bundles "$WORK/curated"
expect_stderr "evidence is incomplete"
cp "$ATTACK/epoch-$E2.json" "$WORK/curated/"
expect_verify 1 "$FAILURE" "${CAP[@]}" --bundles "$WORK/curated"
expect_stderr "does not match the on-chain anchors"

log "an untouched run still verifies against the complete evidence, attacks included (expect SUCCESS)"
expect_verify 0 "$SUCCESS" --run-id "$BIG_RUN" --bundles "$WORK/all" --agent-id "$AGENT_ID" --rpc "$RPC" --contract "$CONTRACT"

printf '\nE2E PASSED: %s + %s + %s signed events anchored by the daemon; weak key refused at registration; single-event and run mode SUCCESS, FAILURE (tamper, re-spelled file, withheld, decoy, missing epoch, forged, revoked key, reordered, curated re-anchor), SUCCESS-INCOMPLETE, oversized payload, replay after revocation, key rotation, kill -9 between send and receipt, mTLS authorization and operational exits verified.\n' "$ACKED" "$ACKED2" "$OLD_ACKED"
