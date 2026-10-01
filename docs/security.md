# Security model

What a successful verification proves, and what it does not. These guarantees
hold only under the [deployment requirements](operations.md#deployment-requirements).

## Threat model

The attacker controls the daemon host, including the anchorer key, the WAL
and the evidence bundles. The agent hosts and the key admin are trusted.

| Attack | Outcome |
|---|---|
| Forge an event, or alter any field (including agent, step, timestamp) before anchoring | **Closed**: the signature fails |
| Drop, reorder or insert an event in the middle of a run; replay an event into another run | **Closed**: `prev_hash`/`step_number` break (run mode), and `run_id` is signed |
| Register its own key to sign forgeries | **Closed**: only `KEY_ADMIN_ROLE` registers keys, and the anchorer can never hold it |
| Truncate a run's tail | **Detected** as "no terminal event", but it cannot be told apart from an agent crash |
| Suppress a whole run, or never anchor it | **Not closed**: needs an external witness |
| Compromised agent host or stolen signing key; payload truthfulness; trusted time | **Not closed**: non-repudiation binds to the key holder, and anchor time is only an upper bound |

## Guarantees

- **Non-repudiation of anchored events.** A verified event was signed by a
  key registered for that agent and valid when the epoch was anchored, and
  has not changed since. Only the agent's key holder could have produced it.
- **Run integrity.** A run that verifies in run mode is complete from step 1
  to its `run_end`, in order, with no event inserted, removed, replayed from
  another run or anchored out of order. Events the SDK itself had to drop are
  reported as signed `sdk_dropped` counts, never as silent gaps.
- **An ack means durable.** An event is acknowledged only after its WAL record
  is written and fsynced. On restart the WAL is replayed: sealed but
  unanchored epochs are rebuilt, their roots re-checked against the sealed
  record, and re-queued; other unanchored events reopen the agent's current
  epoch. A torn final WAL record (crash mid-write) is truncated. Corruption
  anywhere else stops the daemon instead of guessing.
- **Anchored means tamper-evident.** Once an epoch is anchored, changing any
  byte of any of its events, or of the proof, makes verification fail both
  locally and through the contract.
- **Evidence is self-contained.** Each epoch's bundle stores the exact
  canonical bytes (with signatures), digest, leaf and proof of every event,
  plus the root, tx hash, block, chain ID and contract.

## Limits

State these explicitly in an audit.

- **Whole-run suppression.** A compromised daemon can refuse or never anchor
  an entire run, and nothing on chain shows that the run existed. Detecting
  that needs an external witness (for example the agent keeping the `run_end`
  digests the daemon acks). Not implemented.
- **Tail truncation vs. crash.** A run whose last events were withheld looks
  the same as a run whose agent crashed: both fail for a missing `run_end`.
- **Agent-side compromise.** Anyone holding an agent's signing key can sign
  as that agent; revoke it as soon as a compromise is suspected. Signatures
  prove who recorded an event, not that its payload is true.
- **Time.** `timestamp_utc` is the agent's claim. The anchor's block time is
  only an upper bound on when an event existed.
- **Shared hosts.** Agents that share a host or credentials with the daemon
  do not get the compromised-host guarantees (see
  [deployment requirements](operations.md#deployment-requirements)).
- **Tamper evidence starts at anchoring** for anything the agent did not
  sign: the evidence bundles' metadata and the WAL could be altered on the
  daemon host until then.
- **SDK overload drops events.** Dropped events never reach the daemon; they
  are counted in `client.stats()` and reported in the run as `sdk_dropped`.
  Size the queue for your burst rate and alert on drops.
- **Delivery is at-least-once** across reconnects. Identical events are
  de-duplicated within an open epoch; a retransmission that arrives after its
  epoch was sealed is committed again (same digest, new leaf). Run mode
  counts it once, at its earliest epoch.
- **No transport authentication.** Any client that can reach the port can
  submit events, but only events signed with a registered key are accepted.
  Bind to localhost or a private network and use `--tls-cert/--tls-key`.
  Mutual TLS is not implemented.
- **Finality.** An epoch counts as anchored after one successful receipt, with
  no extra confirmation depth, so a deep reorg could drop an anchor the daemon
  has already checkpointed. Use a chain with fast finality, or verify after
  finality.
- **fsync semantics.** Durability is whatever the OS's `fsync` provides. On
  macOS that does not flush the drive's write cache (`F_FULLFSYNC` is not
  used); on Linux it does.
- **Key handling.** The daemon's anchorer key and the agents' signing keys are
  read from an environment variable or a file and held in memory. They are
  never logged. A KMS or HSM signer is not implemented.
- **One daemon per data directory and signer.** The daemon locks its data
  directory, but two daemons using the same signer key with different data
  directories would race on nonces.
- **Size limits and retention.** Event fields are size-limited (agent id 256
  bytes, run id 256 bytes, event type 128 bytes, payload
  `--max-payload-bytes`). WAL segments are deleted once everything in them is
  anchored. Evidence bundles are kept forever; archive them as needed.
- **Development keys.** `scripts/e2e.sh` uses anvil's publicly known
  development keys (account #0 as the admin, #1 as the anchorer) and the
  vectors use the public RFC 8032 test seed. They are for local testing only.
