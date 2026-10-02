# VeriLog

[![CI](https://github.com/ronitspatil/verilog/actions/workflows/ci.yml/badge.svg)](https://github.com/ronitspatil/verilog/actions/workflows/ci.yml)

Tamper-evident audit logging for autonomous AI agents.

VeriLog records an agent's execution trace (prompts, tool calls, state
updates, LLM responses). Each event is signed inside the agent process with
the agent's Ed25519 key and hash-chained to the previous event of its run. A
daemon commits events into per-agent Merkle trees and periodically anchors
each root on an EVM chain. With an event, its inclusion proof and an RPC
endpoint, anyone can later prove the agent produced exactly that event, that
it has not been edited, and (in run mode, given the evidence of every epoch
anchored for the agent) that no event of the run was dropped, inserted or
anchored out of order, even if the daemon host was compromised.

```
 LangChain / LangGraph agent
   │  VeriLogLangGraphCallback (enqueue only, never blocks)
   ▼
 SDK background thread: step + prev_hash per run, Ed25519 sign
   │
   └─ gRPC IngestStream ─▶ verilogd
                             │ check signature against on-chain agentKeys
                             │ canonicalize, hash, WAL fsync ─▶ ack
                             │ append to per-agent Merkle tree, seal epoch
                             ▼
                    anchorEpoch() ─▶ VeriLogRegistry (EVM) ◀─ key admin (multisig)
                             ▼
              evidence/<agentKey>/epoch-<n>.json  (+ GetProof RPC)
                             ▼
 verilog-verify ─▶ [SUCCESS] Log Integrity Verified | [FAILURE] Tampered Log Detected
```

## What it guarantees

- **Signed at the source.** Events are signed in the agent process with a
  registered, checked key; the daemon cannot forge or alter them.
- **Complete runs.** Given a bundle for every epoch anchored for the agent,
  run mode proves a run is complete from step 1 to `run_end`, with no event
  removed, no event of another run or another branch inserted, and no event
  first anchored in a later epoch than its successor. Order is checked per
  epoch, not within one.
- **Tamper-evident once anchored.** Changing any byte of an anchored event or
  its proof fails verification, locally and through the contract.
- **Durable acks.** An event is acknowledged only after its WAL record is
  fsynced.

It does **not** detect suppression or delay of a whole run, cannot tell a
truncated run from a crashed agent, keeps only the hash of an oversized
payload, and cannot protect against a stolen agent key or agents that share
a host with the daemon. See [docs/security.md](docs/security.md)
for the threat model and the full list of limits.

## Quickstart

Prerequisites: Go 1.27, Foundry (`forge`, `anvil`, `cast`), `protoc` 3.x,
Python 3.12 and `jq`.

```sh
git clone --recurse-submodules git@github.com:ronitspatil/verilog.git && cd verilog
make tools                    # protoc-gen-go, protoc-gen-go-grpc, abigen
make venv PYTHON=python3.12   # sdk/python/.venv with the SDK installed editable
make build                    # bin/verilogd, bin/verilog-verify
make test                     # Go, Foundry and pytest suites
make e2e                      # anvil → deploy → daemon → SDK → anchor → verify
```

Deploy and run (see [docs/operations.md](docs/operations.md) for key
management, the production multisig hand-off and all daemon flags):

```sh
# 1. Deploy the registry. VERILOG_ANCHORER is the daemon's address and must differ from the admin.
cd contracts && VERILOG_ANCHORER=0xDaemonAddress forge script script/Deploy.s.sol \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast && cd ..

# 2. On the agent host: create the agent's signing key. The key admin runs the printed
#    `verilog-verify keycheck` (proof of possession), then registers the pubkey.
python -m verilog_sdk keygen --out /etc/verilog/support-bot.key --agent-id support-bot

# 3. Start the daemon (its signer needs ANCHORER_ROLE). In production keep that key in AWS KMS:
#    --signer aws-kms --kms-key-id alias/verilog-anchorer (docs/operations.md#anchoring-key).
#    Mutual TLS is required (`make certs` writes dev-only certificates; --insecure-plaintext for local dev only).
bin/verilogd --rpc "$RPC" --contract 0xRegistry --data-dir /var/lib/verilog --private-key-file key.hex \
    --tls-cert server.pem --tls-key server-key.pem --tls-client-ca clients-ca.pem
```

```python
# 4. Instrument the agent (with VERILOG_SIGNING_KEY_FILE=/etc/verilog/support-bot.key).
from verilog_sdk import VeriLogLangGraphCallback

handler = VeriLogLangGraphCallback(agent_id="support-bot", target="daemon.internal:50051",
                                   tls_ca="server-ca.pem", tls_cert="support-bot.pem", tls_key="support-bot-key.pem")
graph.invoke(inputs, config={"callbacks": [handler]})
handler.close()
```

Every client authenticates with a certificate whose URI SAN names it
(`verilog://agent/<agent_id>` or `verilog://auditor/<name>`); see
[Transport security](docs/operations.md#transport-security-mtls).

```sh
# 5. Verify one event...
bin/verilog-verify export --bundle /var/lib/verilog/evidence/<agentKey>/epoch-3.json --index 17 --out ./case-42
bin/verilog-verify --event case-42/event.json --proof case-42/proof.json \
    --epoch 3 --agent-id support-bot --rpc "$RPC" --contract 0xRegistry --chain-id 1

# ...or a whole run from a copy of all the agent's evidence bundles.
bin/verilog-verify --run-id <run_id> --bundles ./evidence/<agentKey> \
    --agent-id support-bot --rpc "$RPC" --contract 0xRegistry --chain-id 1
```

`verilog-verify` prints one verdict line and exits `0` (verified), `1`
(tampered, including any defect in the evidence), `3` (run mode with
`--allow-incomplete`: verified but no `run_end`) or `2` (no verdict: bad
arguments, unreadable files, RPC failure, wrong chain id, or evidence not final yet). See
[docs/operations.md](docs/operations.md#verifying-logs).

## Deployment requirement

The compromised-host guarantee holds only if agents do not share a host or
credentials with the daemon, the daemon can never read an agent signing key,
and the key admin (a multisig in production) is not on the daemon host.
Shared development setups such as `scripts/e2e.sh` still get tamper evidence
from the moment of anchoring. Details: [docs/operations.md](docs/operations.md#deployment-requirements).

## Repository layout

| Path | What |
|---|---|
| `proto/` | gRPC API: `IngestStream` (bidi) and `GetProof` |
| `contracts/` | Foundry project: `VeriLogRegistry.sol`, tests, deploy script |
| `daemon/cmd/verilogd` | the daemon |
| `daemon/cmd/verilog-verify` | forensic verifier and proof exporter |
| `daemon/internal/` | canonical JSON, Merkle tree, WAL, engine, anchoring, ingest, keys, verification |
| `sdk/python/` | `verilog-sdk`: signing client, LangChain callbacks, `keygen` |
| `testdata/` | golden cross-implementation vectors (Go, Foundry, pytest) |
| `scripts/e2e.sh` | full local run against anvil, including compromised-daemon attacks |
| `deploy/prometheus/` | alerting rules for the daemon's metrics |

## Documentation

- [docs/design.md](docs/design.md): hash scheme, canonical events, signing and
  run chaining, Merkle rules, daemon internals, contract, performance, source map.
- [docs/operations.md](docs/operations.md): build and test, deployment
  requirements, daemon configuration, key management and rotation, the Safe
  hand-off, verifier modes and exit codes.
- [docs/security.md](docs/security.md): threat model, guarantees and limits.
- [docs/runbook.md](docs/runbook.md): retention, backups, alerts, routine tasks and evidence exports for auditors.
- [sdk/python/README.md](sdk/python/README.md): Python SDK usage.

`scripts/e2e.sh` and the test vectors use publicly known development keys.
They are for local testing only.
