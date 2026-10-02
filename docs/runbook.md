# Runbook

Retention, backups, alerts and routine tasks for a production verilogd. For
configuration see [operations.md](operations.md); for what a verdict proves,
[security.md](security.md).

## Retention policy

The evidence is what an auditor verifies, so it outlives the daemon.

| Keep | Where it comes from |
|---|---|
| Evidence bundles | `<data-dir>/evidence/<agentKey>/epoch-N.json`, written once an anchor is final and never changed |
| Deployment record | registry address, chain id, deploy and role-handover transactions (for example [`deployments/base-sepolia.json`](../deployments/base-sepolia.json)) |
| Agent key records | each agent id, public key, key id, registration and revocation transactions |
| Verifier version | the VeriLog commit or release used to produce and check evidence (`report.json` records it) |
| Audit exports | each folder handed to an auditor, with the SHA-256 of its `MANIFEST.sha256` |

**How long** (a recommendation; confirm with counsel for your sector):

- Regulated sectors (finance, health): at least 7 years.
- SOC 2: at least the audit period plus 1 year.
- Never shorter than the longest retention of the systems the agents act on.

**Where.** Write-once storage, such as S3 Object Lock in *compliance* mode
(not governance mode, which an administrator can lift) with the retention
period above, in an account the daemon host cannot administer. Sync
`evidence/` there continuously (every few minutes): after an anchor is final
its events exist only in the bundle, because the WAL is compacted.

**What may be deleted.** Only the WAL, and verilogd already does it: a WAL
segment is removed once every event in it is anchored and final. Never delete
or edit bundles: run mode needs a bundle for every epoch ever anchored for an
agent, so one lost bundle makes every later run of that agent unverifiable.

## Backups and restore

**Back up** the whole data directory (`wal/`, `checkpoint.json`,
`anchor-pending.json` if present, `evidence/`) from a consistent snapshot: a
file-system or volume snapshot (EBS, ZFS, LVM), or a copy taken with the
daemon stopped. Bundles are also in the WORM archive above; the snapshot adds
the WAL (events acknowledged but not final yet) and the pending-transaction
record.

**Restore:**

1. Stop verilogd (`LOCK` refuses a second daemon on the same directory).
2. Restore the latest snapshot into the data directory.
3. Copy back from the WORM archive any bundle newer than the snapshot.
4. Start verilogd. Check the log for `engine: recovered from WAL` and no
   ERROR lines from `anchor:`; a pending transaction is re-checked against the
   chain before anything is sent.
5. Run `audit-export` for the last day (below) and confirm SUCCESS: it reads
   every epoch on chain, so a missing bundle shows up as an evidence problem.

Events acknowledged after the snapshot and not yet in a bundle are lost with
the old disk; the SDK does not resend acknowledged events. Keep snapshots
frequent, or the data directory on replicated storage.

## Alerts

Rules: [`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml),
for a scrape job named `verilog` on `--metrics-listen`. Check changes with
`promtool check rules` and `promtool test rules
deploy/prometheus/alerts_test.yml`. Every metric named here is also in the
`stats` log line, once a minute.

### VeriLogDown

`up == 0` for 2 minutes. Agents buffer in the SDK, then drop (counted as
`sdk_dropped`). **Diagnose:** service status and the last log lines; a
startup refusal names its flag (`--tls-cert`, `ANCHORER_ROLE`, the `finalized`
tag, the data-dir `LOCK`). **Act:** fix and restart; nothing acknowledged is
lost. **Escalate** after 15 minutes, or at once if the data directory is
damaged (`wal:` errors).

### VeriLogAnchorQueueGrowing

`verilog_anchor_queue_epochs` above 10 and rising for 30 minutes: epochs are
sealed faster than they become final. **Diagnose:**
`verilog_anchor_awaiting_finality_epochs` (mined, waiting) against the queue;
`anchor: attempt failed`, `anchor: fee ceiling reached` in the log; RPC
latency. **Act:** fix the RPC, raise `--max-fee-gwei` if fees are capped, or
fund the key. At `--max-anchor-queue` ingest is refused
(`anchor_queue_full`). **Escalate** if it reaches half of `--max-anchor-queue`.

### VeriLogAnchorQueueStuck

Epochs queued and none final for an hour. **Diagnose:** as above; also
`anchor: finality check failed` (RPC no longer serves the `finalized` tag) and
`anchor: epoch not final yet`. Check the anchor transaction on the explorer.
**Act:** restore the RPC or funds; the daemon resumes on its own, and
restarts are safe (the pending transaction is recorded). **Escalate** at
once: events are not tamper-evident until anchored.

### VeriLogFinalityLagHigh

The oldest mined anchor has not been final for 45 minutes (Base Sepolia
takes about 19). **Diagnose:** the chain's finality status (L1 batch posting
for an L2), the RPC's `finalized` block, `anchor: reorg` lines. **Act:**
usually wait; switch to a healthy RPC if only yours lags. Nothing is
compacted before finality, so nothing is lost. **Escalate** past 2 hours, or
on any reorg ERROR.

### VeriLogEpochsNotAnchored

Events accepted but no epoch final for an hour. Covers sealing failures the
queue alerts miss. **Diagnose:** `engine: sealing failed`,
`engine: epoch sealed empty` (all events signed with a revoked key),
`engine: seal-time key check failed`. **Act:** as for the cause; for revoked
keys, see key rotation below. **Escalate** at once.

### VeriLogBackpressure

Events refused (retryable) for 10 minutes, by `reason`. The SDK holds and
resends them, but its queue is finite. **Diagnose:**
`verilog_backpressure_rejections_total{reason}`,
`verilog_agent_unanchored_bytes{agent_id}` (which agent), the log line
`engine: backpressure: refusing events for now`. **Act:** per-agent reasons:
throttle or fix that agent, or raise its quota; global reasons: fix
anchoring first (the queue alerts), then raise the limit
([Resource limits](operations.md#resource-limits-and-backpressure)).
**Escalate** if agents report `sdk_dropped`.

### VeriLogDiskLow

`verilog_disk_low` is 1 (below `--min-free-disk-bytes`): ingest is refused.
`VeriLogDiskFreeLow` warns earlier, at 10% free. **Diagnose:**
`verilog_wal_bytes` (a large WAL means anchoring is behind) against the size
of `evidence/`. **Act:** grow the volume. Never delete WAL segments or
bundles by hand; the WAL shrinks once anchors are final. **Escalate** at
once: ingest has stopped.

### VeriLogSignerBalanceLow

`verilog_signer_balance_wei` below 0.01 ETH, about a week of anchoring every
30 seconds at the cost observed on Base Sepolia (about 4.7e11 wei per anchor:
77,000 gas at 0.006 gwei plus the L1 data fee). Re-derive the threshold from
your chain's cost and epoch rate. **Act:** fund the address in the alert's
`address` label (see Funding the anchorer). **Escalate** if it reaches a day
of anchoring.

### VeriLogTLSCertExpiring

The server certificate expires within 14 days. Once it does, agents cannot
connect. **Act:** renew it (see Certificate rotation) and restart verilogd;
the metric shows the new expiry. **Escalate** at 3 days.

## Routine tasks

- **Certificate rotation.** Renew the server and client certificates well
  before expiry; rotate CAs with overlap
  ([Transport security](operations.md#transport-security-mtls)). verilogd
  reads its certificate at startup, so restart it after renewal.
- **Agent key rotation.** Follow
  [drain before revoke](operations.md#rotation-drain-before-revoke); a
  revocation that takes effect too early fails the runs still in flight.
- **Anchoring key rotation.** Grant `ANCHORER_ROLE` to the new key, stop
  verilogd when `anchor-pending.json` does not exist, restart it with the new
  key, then revoke the old role (as in
  [moving to KMS](operations.md#aws-kms-setup)).
- **Monthly:** `make lock-upgrade` and the checks in
  [Upgrading the Python lock](operations.md#upgrading-the-python-lock-monthly).
- **Contract library releases:** when the weekly workflow warns, follow
  [Upgrading the contract libraries](operations.md#upgrading-the-contract-libraries);
  a new bytecode needs a new deployment before it takes effect.
- **Funding the anchorer.** Send ETH to the anchoring key's address (the
  `address` label of `verilog_signer_balance_wei`, or `chain ready ...
  address=` at startup). Keep a month of anchoring on it.
- **Quarterly:** produce an audit export for the quarter (below) and archive
  it; it proves the evidence is complete before an auditor asks.

## Producing evidence for an auditor

```sh
bin/verilog-verify audit-export --agent-id support-bot \
    --bundles /var/lib/verilog/evidence/<agentKey> \
    --from 2026-01-01 --to 2026-04-01 \
    --rpc "$RPC" --contract 0xRegistry --chain-id 8453 --out ./audit-2026-q1
```

- **Window.** Epochs are selected by their anchor (block) time, read from the
  registry: `--from` is inclusive, `--to` exclusive (RFC 3339, or a UTC date).
  Every run with an event in those epochs is verified in run mode.
- **The folder** holds `README.md` (for the auditor: what VeriLog proves and
  the exact commands to re-verify), `report.md` and `report.json` (chain id,
  verdict block, tool version and commit, every epoch's root, count, anchor
  transaction and time, and each run's steps, `run_end` status, verdict and
  reason), `evidence/` (bundles, byte for byte) and `MANIFEST.sha256`.
- **Context epochs.** Run mode needs every epoch anchored for the agent, so
  the export holds epochs `1..latestEpoch`; the report marks which are in the
  window and which are context.
- **Exit status:** 0 every run SUCCESS; 1 any FAILURE or evidence problem
  (the full report is still written); 3 none failed but a run is
  SUCCESS-INCOMPLETE (`--allow-incomplete`) or not final yet; 2 no verdict,
  and no folder is left behind. `--out` must not exist.
- **Hand-over.** Give the auditor the folder and, separately, the SHA-256 of
  its `MANIFEST.sha256` (printed on stderr). `verilog-verify audit-check
  <dir>` re-hashes every file (exit 0 unchanged, 1 changed). The folder holds
  only public data and the bundles the daemon wrote: no private or TLS keys.
