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
- **Proof of possession.** Before registration, a new key signs
  `"VeriLog/pop/v1\n" || keccak256(utf8(agent_id)) || pubkey` (fixed length,
  its own domain tag). `keygen` prints it and `verilog-verify keycheck`
  checks it together with the key's safety (on the curve, canonical, prime
  order). `testdata/signed_vectors.json` carries a golden `pop`.
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
- **Oversized payloads.** If a payload's canonical JSON exceeds
  `max_payload_bytes` (default 1 MiB, the daemon's default limit), it is
  replaced before chaining by `{"bytes": n, "sha256": "0x…", "truncated": true}`:
  the size and SHA-256 of the original canonical JSON (UTF-8). The stand-in is
  signed and chained like any payload; `on_oversize` can keep the original.
- **Rejections.** A rejection with `Ack.retryable` set (the agent key is not
  yet visible on chain) is re-sent, byte for byte, with backoff for up to
  `key_wait_timeout`, holding later events back to keep the order. One that
  also carries `retry_after_ms` (daemon backpressure) is re-sent the same way
  with no time limit. Any other
  rejection of a chained event leaves a gap: it is logged at ERROR and counted
  in `stats().chain_gaps`.
- **Late and open runs.** An event submitted after its run's `run_end`
  becomes its own run `<run_id>#late-<n>`, closed by `run_end`
  `{"status": "late", "late_for_run": <run_id>}`. Ended runs beyond the last
  10,000 are remembered in a Bloom filter so a late event never restarts a
  run at step 1. At most `max_open_runs` runs stay open; the least recently
  used is closed with `run_end` status `"evicted"`. Timestamps outside
  1970..9999 are reported as a dropped event.
- The stream reconnects with exponential backoff and re-sends unacknowledged
  events byte for byte (signing is deterministic and done once). The daemon
  de-duplicates identical events within an open epoch and acks them with
  `duplicate=true`.

## Daemon

**Signature enforcement at ingest.** The daemon looks up `(agentId, key_id)`
in the registry and rejects events that are unsigned, use an unregistered,
unsafe or revoked key (a recorded revocation counts even before it takes
effect), or whose signature does not verify. "Not registered" rejections set
`Ack.retryable`. Payloads over `--max-payload-bytes` get a per-event
rejection; the gRPC receive limit (4× the cap plus 1 MiB) is far enough above
it that an oversized message never fails the whole stream. Lookups are cached:
registered keys are re-read every minute so revocations show up, unknown keys
after 5 s. If the registry cannot be read the stream fails with `UNAVAILABLE`,
so the SDK re-sends instead of losing a valid event. This keeps garbage out of
the log, but an auditor does not rely on it (the daemon is the party under
suspicion): the verifier repeats every check against the chain.

**Seal-time key check.** When an epoch is sealed the daemon re-reads each
distinct key of its events, uncached, and compares the revocation time with
the later of the latest block's timestamp and the local clock. Events whose
key's revocation is in effect are left out of the epoch, logged at ERROR and
counted in `revoked_excluded`. The `sealed` WAL record lists their sequence
numbers in `skip` (a seal that leaves out every event has `count` 0 and no
root), so recovery rebuilds exactly the same epoch. If the lookup fails the
events are anchored anyway; the verifier still judges the key.

**Concurrency.** Each stream has a receive loop (validate, canonicalize,
hash, submit) and an ordered ack loop, so one stream can have
`--stream-window` events waiting on durability. A single committer goroutine
assigns sequence numbers, writes a whole batch to the WAL with one fsync, then
appends leaves to per-agent shards (mutex-guarded `merkle.Tree`s). Sealing
swaps a shard's tree for a fresh one under the lock (a pointer exchange) and
computes the root afterwards, so ingestion never waits on hashing or the
chain. Sealed epochs go to a queue drained by one anchor goroutine: one
signer, one nonce source, agents taken in turn, per-agent epochs in order.
Failed attempts retry with jittered exponential backoff; a sealed epoch is
never dropped. Epochs hold event digests and WAL locations, not payloads.

**Resource limits.** Per-agent quotas, a rate limit, global byte and anchor
queue limits and a free-disk check are applied before an event is written;
an event over one gets a retryable rejection with `retry_after_ms` (see
[operations](operations.md#resource-limits-and-backpressure)).

**Anchoring.** The chain ID comes from the RPC. Transactions are EIP-1559,
signed through the `signer.Signer` interface (a local key, or AWS or Google Cloud KMS with
low-s normalization and `v` recovery), with a fee cap of `2×baseFee + tip`
bounded by `--max-fee-gwei` / `--max-priority-fee-gwei`, and awaited with
`bind.WaitMined` under `--confirm-timeout`. The receipt status
and `LogAnchored` event are checked, and the assigned `epochId` is read from
the event. If a confirmation times out, the next attempt first looks for the
earlier transaction's receipt and otherwise replaces it with the same nonce
and 25% higher fees (at the fee ceiling it rebroadcasts the old one instead).
The transaction is written to `anchor-pending.json` in the data dir before
it is broadcast, so the same holds across restarts and crashes.
Before sending, it also checks whether the agent's latest on-chain epoch
already holds this root (a crash after confirmation but before the
checkpoint) and, if so, recovers that epoch instead of anchoring again.
A mined anchor then waits for finality (`--finality`); only a final anchor,
re-read at the final block, gets its bundle, checkpoint and WAL compaction.
The next epoch is sent meanwhile, with a nonce above every anchor awaiting
finality, and a reorged-out anchor is sent again with its own nonce (see
[operations](operations.md#finality-and-reorgs)).

## Contract

`VeriLogRegistry` uses `AccessControl` with `ANCHORER_ROLE` and
`KEY_ADMIN_ROLE` (the admin grants and revokes both; no account may hold the
anchorer role together with an admin role) and custom errors.

- `agentKeys[agentId][keyId]` stores `{pubkey, validFrom, revokedAt}` in two
  slots; `registerAgentKey` returns `keyId = keccak256(pubkey)` and reverts
  with `WeakPubkey` for the encodings of small-order points and non-canonical
  encodings (`isWeakPubkey`).
- `revokeAgentKey(agentId, keyId, effectiveAt)` stores `effectiveAt` (at
  least the block timestamp) as `revokedAt` and emits it with the recording
  time in `AgentKeyRevoked`.
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
| `daemon/internal/canonical` | canonical event JSON, content digest, agent key, strict parsing, public key safety and proof of possession |
| `daemon/internal/merkle` | thread-safe Merkle tree, proofs, benchmarks |
| `daemon/internal/engine` | committer, per-agent shards, sealing, WAL replay, evidence finalization |
| `daemon/internal/wal` | JSONL write-ahead log with group-commit fsync and compaction |
| `daemon/internal/anchor` | retrying anchor worker (agents in turn), EIP-1559 go-ethereum client, fee ceiling, pending-transaction record |
| `daemon/internal/signer` | anchoring key signers: local key, AWS KMS and Google Cloud KMS (`kmsfake`, `gcpkmsfake`: in-memory fakes for tests) |
| `daemon/internal/diskspace`, `daemon/internal/metrics` | free-space check; Prometheus text format |
| `daemon/internal/redact` | strips RPC URL credentials from logs and errors |
| `daemon/internal/ingest` | gRPC service (rejects events with a bad or unregistered signature) |
| `daemon/internal/keys` | on-chain agent key lookup, cache and validity rule |
| `daemon/internal/store` | checkpoint and evidence bundles |
| `daemon/internal/verify` | single-event and run verification used by `verilog-verify` |
| `daemon/internal/registry`, `daemon/gen` | generated contract bindings (abigen) and protobuf code (committed) |
| `sdk/python/` | `verilog-sdk`: signing client, LangChain callback handlers, `keygen` |
| `testdata/` | golden cross-implementation vectors (generated by Go, consumed by Foundry and pytest) |
| `scripts/e2e.sh` | full local run against anvil, including attacks by a compromised daemon host |
