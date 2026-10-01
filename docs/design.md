# Design

How events are hashed, signed, chained, committed and anchored. For deployment
and configuration see [operations.md](operations.md); for what this does and
does not prove see [security.md](security.md).

## Hash scheme

The SDK, the daemon, the contract and the verifier all use one scheme, so a
proof produced off-chain verifies on-chain with OpenZeppelin's `MerkleProof`.
Canonical event v2 has nine fields:

```
event         = {agent_id, event_type, key_id, payload, prev_hash, run_id, sig, step_number, timestamp_utc}
signed bytes  = "VeriLog/event/v1\n" || canonical(event without "sig")
sig           = Ed25519(agent key, signed bytes)                    # 64 bytes, deterministic
key_id        = keccak256(ed25519 public key)
canonical     = JCS-style JSON of the event including "sig"
contentDigest = sha256(canonical)
prev_hash     = contentDigest of the previous event of the run       # 32 zero bytes for step 1
leaf          = keccak256(contentDigest)                             # 32-byte preimage
node          = keccak256(min(a, b) || max(a, b))                    # 64-byte preimage, sorted pair
agentId       = keccak256(utf8(agent_id))                            # bytes32 key on chain
```

- **The whole signed event is hashed**, signature included. Changing the
  agent, run, step, previous hash, event type, timestamp, key id or signature
  breaks the proof. The anchor proves "this signed record existed by block
  time T", so old epochs stay valid after a later key revocation.
- **Signatures are made in the agent process.** The domain tag stops the key
  from signing anything that is also a valid message elsewhere; `agent_id`
  and `run_id` in the signed bytes stop cross-agent and cross-run replay.
  `key_id`, `prev_hash` and `sig` are `0x` lowercase hex.
- **Runs are hash chains.** `run_id` is the LangChain root run id. The SDK
  assigns `step_number` (from 1) and `prev_hash` on its background thread
  after dequeue, so an overflow drop never leaves a gap: the SDK records a
  signed `sdk_dropped` event `{"count": n}` instead. A run ends with a signed
  `run_end` event `{"status": "ok"|"error"|"closed", "steps": n}`.
- **Canonicalization** follows RFC 8785: members sorted by UTF-16 code units,
  no insignificant whitespace, UTF-8 output with only mandatory escapes (no
  HTML escaping), non-integers in ECMAScript number format. One deliberate
  deviation: integer literals are kept exactly (never rounded through a
  double), so ids and counters above 2^53 survive. Duplicate keys and invalid
  UTF-8 are rejected. `timestamp_utc` is RFC 3339 UTC with exactly nine
  fractional digits. The daemon rebuilds the signed bytes from the fields it
  receives, so any drift between the Python and Go canonicalization shows up
  as a rejected event, never a silent mismatch.
- **Leaves and internal nodes are domain separated** by preimage length (32
  vs 64 bytes), OpenZeppelin's recommended defence against second-preimage
  attacks.
- **Odd node rule:** when a level has an odd number of nodes, the last one is
  promoted unchanged and its proof has no sibling at that level. A one-event
  epoch has `root == leaf` and an empty proof.

### Cross-implementation vectors

`daemon/internal/vectors` writes `testdata/merkle_vectors.json`,
`testdata/canonical_vectors.json` and `testdata/signed_vectors.json` (a
complete signed run from the public RFC 8032 test seed).

- Foundry verifies every Go proof with the contract and checks the vectors'
  key id against `registerAgentKey`.
- The Python suite reproduces every signed byte, signature and digest byte for
  byte.
- The Go canonical tests regenerate the vectors from their inputs.
- The Go anchor, keys and verify tests deploy the real contract on
  go-ethereum's simulated backend.

## SDK: never blocking the agent

Callbacks snapshot their arguments and append to a bounded deque. Chaining,
canonical JSON, signing (Ed25519, about 16-34 µs per event), protobuf encoding
and all I/O run on the SDK's background thread.

- When the queue is full, the default `drop_oldest` policy drops (and counts)
  the oldest event; `block` waits briefly, then drops the new one. Either way
  the loss is recorded in the run as a signed `sdk_dropped` event.
- SDK errors are logged on the `verilog_sdk` logger and never raised.
- The stream reconnects with exponential backoff and re-sends unacknowledged
  events byte for byte (signing is deterministic and done once). The daemon
  de-duplicates identical events within an open epoch and acks them with
  `duplicate=true`.

## Daemon

**Signature enforcement at ingest.** The daemon looks up `(agentId, key_id)`
in the registry and rejects events that are unsigned, use an unregistered or
revoked key, or whose signature does not verify. Lookups are cached:
registered keys are re-read every minute so revocations show up, unknown keys
after 5 s. If the registry cannot be read the stream fails with `UNAVAILABLE`,
so the SDK re-sends instead of losing a valid event. This keeps garbage out of
the log, but an auditor does not rely on it (the daemon is the party under
suspicion): the verifier repeats every check against the chain.

**Concurrency.** Each stream has a receive loop (validate, canonicalize,
hash, submit) and an ordered ack loop, so one stream can have
`--stream-window` events waiting on durability. A single committer goroutine
assigns sequence numbers, writes a whole batch to the WAL with one fsync, then
appends leaves to per-agent shards (mutex-guarded `merkle.Tree`s). Sealing
swaps a shard's tree for a fresh one under the lock (a pointer exchange) and
computes the root afterwards, so ingestion never waits on hashing or the
chain. Sealed epochs go to a FIFO drained by one anchor goroutine: one signer,
one nonce source, per-agent epochs in order. Failed attempts retry with
jittered exponential backoff; a sealed epoch is never dropped.

**Anchoring.** The chain ID comes from the RPC. Transactions are EIP-1559 via
`bind.NewKeyedTransactorWithChainID` with a fee cap of `2×baseFee + tip`,
awaited with `bind.WaitMined` under `--confirm-timeout`. The receipt status
and `LogAnchored` event are checked, and the assigned `epochId` is read from
the event. If a confirmation times out, the next attempt first looks for the
earlier transaction's receipt and otherwise replaces it with the same nonce
and 25% higher fees, so this process never anchors the same epoch twice.
Before sending, it also checks whether the agent's latest on-chain epoch
already holds this root (a crash after confirmation but before the
checkpoint) and, if so, recovers that epoch instead of anchoring again.

## Contract

`VeriLogRegistry` uses `AccessControl` with `ANCHORER_ROLE` and
`KEY_ADMIN_ROLE` (the admin grants and revokes both; no account may hold the
anchorer role together with an admin role) and custom errors.

- `agentKeys[agentId][keyId]` stores `{pubkey, validFrom, revokedAt}` in two
  slots; `registerAgentKey` returns `keyId = keccak256(pubkey)`.
- Zero agent id, zero root and zero `logCount` are rejected.
- `Anchor` packs into two slots, and `anchorEpoch` returns the new epoch.
- `verifyProof` is `pure` (`MerkleProof.verifyCalldata`).
- `verifyAnchoredLeaf` reverts with `EpochNotAnchored` for unknown epochs, so
  callers can tell "not anchored" apart from "not included".

## Performance

Apple M5, `make bench`: building a 1M-leaf tree takes about 48 ms (about 21M
leaves/s), a proof lookup about 51 ns, and engine ingestion with WAL fsync
runs at about 190–240k events/s with pipelined submitters (group commit). Real
numbers depend on the disk's fsync latency.

## Source map

| Path | What |
|---|---|
| `proto/verilog/v1/verilog.proto` | gRPC API: `IngestStream` (bidi) and `GetProof` |
| `contracts/` | Foundry project: `VeriLogRegistry.sol`, tests, `script/Deploy.s.sol` |
| `daemon/cmd/verilogd` | the daemon |
| `daemon/cmd/verilog-verify` | forensic verifier and proof exporter |
| `daemon/internal/canonical` | canonical event JSON, content digest, agent key (shared by daemon and verifier) |
| `daemon/internal/merkle` | thread-safe Merkle tree, proofs, benchmarks |
| `daemon/internal/engine` | committer, per-agent shards, sealing, WAL replay, evidence finalization |
| `daemon/internal/wal` | JSONL write-ahead log with group-commit fsync and compaction |
| `daemon/internal/anchor` | sequential retrying anchor worker, EIP-1559 go-ethereum client |
| `daemon/internal/ingest` | gRPC service (rejects events with a bad or unregistered signature) |
| `daemon/internal/keys` | on-chain agent key lookup, cache and validity rule |
| `daemon/internal/store` | checkpoint and evidence bundles |
| `daemon/internal/verify` | single-event and run verification used by `verilog-verify` |
| `daemon/internal/registry`, `daemon/gen` | generated contract bindings (abigen) and protobuf code (committed) |
| `sdk/python/` | `verilog-sdk`: signing client, LangChain callback handlers, `keygen` |
| `testdata/` | golden cross-implementation vectors (generated by Go, consumed by Foundry and pytest) |
| `scripts/e2e.sh` | full local run against anvil, including attacks by a compromised daemon host |
