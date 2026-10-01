# Operations

Building, deploying, configuring and verifying. For the hash scheme and
internals see [design.md](design.md); for the threat model see
[security.md](security.md).

## Build and test

Toolchain (as used on macOS, Apple Silicon): Go 1.27, Foundry (`forge`,
`anvil`, `cast`), `protoc` 3.x, Python 3.12 and `jq`.

```sh
brew install go                                            # Go toolchain
curl -L https://foundry.paradigm.xyz | bash && foundryup   # Foundry, if not installed

git clone --recurse-submodules git@github.com:ronitspatil/verilog.git
cd verilog                    # existing clone: git submodule update --init --recursive

make tools                    # protoc-gen-go, protoc-gen-go-grpc, abigen
make venv PYTHON=python3.12   # sdk/python/.venv with the SDK installed editable
make build                    # bin/verilogd, bin/verilog-verify
make test                     # go vet + go test -race, forge test, pytest
make e2e                      # anvil → deploy → daemon (mTLS) → SDK → anchor → verify
make certs                    # DEV-ONLY mTLS certificates in dev-certs/ (gitignored)
make bench                    # Merkle and ingestion benchmarks
```

Individual suites:

- Go: `cd daemon && go vet ./... && go test -race ./...`
- Contracts: `cd contracts && forge test` (includes fuzzing and the Go vectors)
- Python: `sdk/python/.venv/bin/pytest -q sdk/python`

Regenerate generated code only after changing the proto, the contract or the
hash scheme: `make proto`, `make bindings`, `make vectors`. If you change
canonicalization or hashing, run `make vectors` and commit the updated
`testdata/`. The Go vectors test fails until you do; Foundry and pytest pick
up the new vectors.

## Deployment requirements

The guarantee against a compromised daemon host holds only if the agents'
signing keys are out of the daemon's reach:

- **Agents must not share a host or credentials with the daemon.** Run them
  as separate services, or at least in separate containers with separate
  credentials, so nothing on the daemon host (files, environment, secret
  stores, mounted volumes, service accounts) can read an agent signing key.
- **The daemon must never be able to read agent signing keys**, and must
  never hold `KEY_ADMIN_ROLE` or `DEFAULT_ADMIN_ROLE` (the contract enforces
  the latter).
- **The key admin is not on the daemon host**: a multisig in production (see
  [Hand the admin roles to a Safe](#production-hand-the-admin-roles-to-a-2-of-3-safe)).

Shared development setups (agent and daemon on one machine or under one
account, as in `scripts/e2e.sh`) do **not** get the compromised-host
guarantee: whoever controls that machine controls the agent key too. They
still get tamper evidence from the moment of anchoring.

## Running it

```sh
# 1. Deploy the registry. The deployer becomes the admin (DEFAULT_ADMIN_ROLE and
#    KEY_ADMIN_ROLE), or set VERILOG_ADMIN. VERILOG_ANCHORER is the daemon's
#    address and must differ from the admin. In production, hand the admin
#    roles to a Safe afterwards (see Key management below).
cd contracts
VERILOG_ANCHORER=0xDaemonAddress forge script script/Deploy.s.sol --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast

# 2. Generate each agent's signing key on the agent host and register it
#    as the key admin (see Key management below).

# 3. Start the daemon. Its signer needs ANCHORER_ROLE (checked at startup).
#    Production: the anchoring key lives in AWS KMS (see Anchoring key below).
#    Mutual TLS is required; see Transport security below for the certificates.
bin/verilogd --rpc "$RPC" --contract 0xRegistry --data-dir /var/lib/verilog \
             --signer aws-kms --kms-key-id alias/verilog-anchorer \
             --tls-cert server.pem --tls-key server-key.pem --tls-client-ca clients-ca.pem \
             --epoch-interval 30s --epoch-max-logs 1000
#    Development: a local key file (mode 0600) instead.
bin/verilogd --rpc "$RPC" --contract 0xRegistry --private-key-file anchorer.hex --tls-cert … (or --insecure-plaintext)
```

```python
# 4. Instrument the agent (on the agent host, with VERILOG_SIGNING_KEY_FILE set).
from verilog_sdk import VeriLogLangGraphCallback

handler = VeriLogLangGraphCallback(
    agent_id="support-bot", target="daemon.internal:50051",
    tls_ca="/etc/verilog/server-ca.pem",         # CA of the daemon's server certificate
    tls_cert="/etc/verilog/support-bot.pem",      # URI SAN verilog://agent/support-bot
    tls_key="/etc/verilog/support-bot-key.pem",
)
graph.invoke(inputs, config={"callbacks": [handler]})
handler.close()
```

### Daemon configuration

Flags win over environment variables.

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--listen` | `VERILOG_LISTEN` | `127.0.0.1:50051` | gRPC address |
| `--tls-cert`, `--tls-key` | `VERILOG_TLS_CERT`, `VERILOG_TLS_KEY` | | server certificate and key |
| `--tls-client-ca` | `VERILOG_TLS_CLIENT_CA` | | CA bundle for client certificates; turns on mutual TLS ([Transport security](#transport-security-mtls)) |
| `--insecure-plaintext` | `VERILOG_INSECURE_PLAINTEXT` | `false` | **dev only**: no TLS, no authentication or authorization |
| `--max-connections` | `VERILOG_MAX_CONNECTIONS` | `1024` | concurrent client connections (0: no limit) |
| `--max-concurrent-streams` | `VERILOG_MAX_CONCURRENT_STREAMS` | `64` | concurrent RPCs per connection |
| `--stream-idle-timeout` | `VERILOG_STREAM_IDLE_TIMEOUT` | `15m` | close an ingest stream that sends nothing for this long (0: never); the SDK reconnects |
| `--keepalive-min-time`, `--keepalive-time`, `--keepalive-timeout` | | `10s`, `30s`, `10s` | reject client pings more often than this; ping idle connections; drop unanswered ones |
| `--data-dir` | `VERILOG_DATA_DIR` | `./verilog-data` | WAL, checkpoint, evidence |
| `--rpc` | `VERILOG_RPC_URL` | required | EVM JSON-RPC |
| `--contract` | `VERILOG_CONTRACT` | required | registry address |
| `--signer` | `VERILOG_SIGNER` | `local` | `local` (key file or env) or `aws-kms` |
| `--kms-key-id` | `VERILOG_KMS_KEY_ID` | | KMS key ARN, id or `alias/<name>` (`aws-kms`) |
| `--private-key-file` | `VERILOG_PRIVATE_KEY_FILE` | | `local`: hex key file, mode 0600; otherwise `VERILOG_PRIVATE_KEY` (warns) |
| `--insecure-key-file-perms` | | off | development only: accept a group/world-readable key file |
| `--max-fee-gwei` | `VERILOG_MAX_FEE_GWEI` | `500` | ceiling on `maxFeePerGas` (decimals allowed) |
| `--max-priority-fee-gwei` | `VERILOG_MAX_PRIORITY_FEE_GWEI` | `50` | ceiling on `maxPriorityFeePerGas` |
| `--epoch-interval` | `VERILOG_EPOCH_INTERVAL` | `30s` | seal every open epoch this often |
| `--epoch-max-logs` | `VERILOG_EPOCH_MAX_LOGS` | `1000` | seal an agent's epoch at this size |
| `--confirm-timeout` | `VERILOG_CONFIRM_TIMEOUT` | `2m` | receipt wait before retrying |
| `--finality` | `VERILOG_FINALITY` | `finalized` | when an anchor is final: `finalized`, `safe` or `depth:N` ([Finality](#finality-and-reorgs)) |
| `--finality-poll` | `VERILOG_FINALITY_POLL` | `5s` | how often the oldest anchor awaiting finality is checked |
| `--finality-timeout` | `VERILOG_FINALITY_TIMEOUT` | `30m` | log ERROR (and again each period) when an anchor is not final this long after it was mined |
| `--retry-initial`, `--retry-max` | | `1s`, `60s` | anchoring backoff bounds |
| `--wal-segment-bytes` | `VERILOG_WAL_SEGMENT_BYTES` | 64 MiB | WAL rotation size |
| `--commit-batch` | | `4096` | max events per fsync |
| `--max-payload-bytes` | `VERILOG_MAX_PAYLOAD_BYTES` | 1 MiB | per-event payload limit; larger payloads get a per-event rejection (the gRPC receive limit is 4× this plus 1 MiB). Keep the SDK's `max_payload_bytes` at or below it |
| `--stream-window` | | `1024` | unacknowledged events per stream |
| `--log-level`, `--log-format` | `VERILOG_LOG_LEVEL`, `VERILOG_LOG_FORMAT` | `info`, `text` | logging |

Credentials and API keys in the RPC URL (userinfo, query parameters, provider
tokens in the path) are replaced with `REDACTED` in every log line and error.

## Anchoring key

The daemon signs `anchorEpoch` transactions with a secp256k1 key that holds
`ANCHORER_ROLE`. In production keep it in AWS KMS: the private key never
exists on the daemon host, every signature is logged in CloudTrail, and
access ends when the role's permission is removed. The daemon reads the
region and credentials from the AWS SDK's default chain (environment, shared
config, IRSA / web identity, container or instance role); AWS secrets are
never flags.

### AWS KMS setup

```sh
# 1. Create the key (spec and usage are checked at startup) and an alias.
aws kms create-key --key-spec ECC_SECG_P256K1 --key-usage SIGN_VERIFY --description "VeriLog anchorer"
aws kms create-alias --alias-name alias/verilog-anchorer --target-key-id <KeyId>

# 2. Its Ethereum address. verilogd also logs it at startup ("aws-kms signer ready address=0x…").
PUB=$(aws kms get-public-key --key-id alias/verilog-anchorer --query PublicKey --output text | base64 --decode | tail -c 64 | xxd -p -c 64)
cast to-check-sum-address 0x$(cast keccak 0x$PUB | tail -c 41)

# 3. Fund it for gas, and grant it ANCHORER_ROLE as the admin (the Safe in
#    production), or pass it as VERILOG_ANCHORER when deploying.
cast send $REGISTRY 'grantRole(bytes32,address)' $(cast keccak ANCHORER_ROLE) 0x<address> --rpc-url $RPC …

# 4. Run the daemon under an AWS identity with the policy below.
AWS_REGION=eu-west-1 bin/verilogd --signer aws-kms --kms-key-id alias/verilog-anchorer --rpc "$RPC" --contract 0xRegistry …
```

At startup the daemon calls `GetPublicKey`, checks the key spec
(`ECC_SECG_P256K1`), usage (`SIGN_VERIFY`) and algorithm (`ECDSA_SHA_256`),
derives and logs the address (nothing else about the key), makes one test
signature, and checks that the address holds `ANCHORER_ROLE`. It signs each
transaction hash with `Sign` (`MessageType=DIGEST`, `ECDSA_SHA_256`),
normalizes the signature to low-s and recovers `v` against the known public
key. Throttling and transient KMS errors are retried (5 attempts, backoff up
to 3 s); after that the anchor attempt fails and the anchor worker retries it
like any RPC error. Permanent errors (access denied, key disabled or pending
deletion, not found) name the cause.

Least-privilege IAM policy for the daemon's role (use the key ARN, not the
alias):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VeriLogAnchorerSign",
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "arn:aws:kms:eu-west-1:111122223333:key/<key-id>",
      "Condition": {
        "StringEquals": { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "DIGEST" }
      }
    },
    {
      "Sid": "VeriLogAnchorerPublicKey",
      "Effect": "Allow",
      "Action": "kms:GetPublicKey",
      "Resource": "arn:aws:kms:eu-west-1:111122223333:key/<key-id>"
    }
  ]
}
```

KMS never exports the private key of an asymmetric key. In the key policy,
also deny the daemon's role everything else, so a compromised daemon host
cannot delete, disable, re-policy, grant or re-import the key:

```json
{
  "Sid": "DenyVeriLogDaemonEverythingElse",
  "Effect": "Deny",
  "Principal": { "AWS": "arn:aws:iam::111122223333:role/verilogd" },
  "NotAction": ["kms:Sign", "kms:GetPublicKey"],
  "Resource": "*"
}
```

Keep key administration (including `ScheduleKeyDeletion`) with a separate
admin role, and alarm on `ScheduleKeyDeletion`, `DisableKey` and
`PutKeyPolicy` for this key in CloudTrail.

**Moving from a local key to KMS.** Grant `ANCHORER_ROLE` to the KMS address,
stop the daemon when `<data-dir>/anchor-pending.json` does not exist (no
transaction in flight), restart it with `--signer aws-kms`, then revoke the
old address's role with `revokeRole`.

### Local key (development)

`--private-key-file` (or `VERILOG_PRIVATE_KEY_FILE`) names a file holding the
hex key. A file readable by group or others is refused unless
`--insecure-key-file-perms` is given. `VERILOG_PRIVATE_KEY` (hex in the
environment) still works but logs a warning.

### Fee ceiling

Each retry of an unconfirmed transaction replaces it with the same nonce and
25% higher fees, up to `--max-fee-gwei` and `--max-priority-fee-gwei`. When
the ceiling leaves no room for a valid replacement (+10%), the daemon stops
bumping, rebroadcasts the pending transaction unchanged and logs
`anchor: fee ceiling reached` at ERROR on every retry. The epoch is never
dropped: it is anchored once fees fall below the ceiling or the ceiling is
raised (restart with a higher value; the pending transaction is then
replaced). Set the ceiling well above normal fees on your chain; on L2s the
defaults are effectively no ceiling, so lower them.

### Pending-transaction recovery

Before broadcasting, the daemon writes the transaction (hash of every
version, nonce, fees, signed bytes, agent and root) atomically to
`<data-dir>/anchor-pending.json`. Once mined, the transaction moves to the
record's `mined` list (with its block number and hash) until the anchor is
final and its bundle is written; the file is removed when both are empty.
After a crash or restart the daemon re-checks that record before sending
anything: a mined anchor is resumed and still waits for finality; if no
version was mined it replaces the transaction with the same nonce, so the
root is anchored at most once. A record made for another chain, contract or signer address is renamed
to `anchor-pending.json.stale` with a warning; an unreadable record stops the
daemon until you inspect it.

### Finality and reorgs

A mined anchor is not yet final: a reorg can remove it. The daemon therefore
keeps an epoch's events in the WAL until its anchor is **final**. Only then does
it re-read `agentAnchors(agent, epoch)` at the final block, check the root and
count, write the evidence bundle (with `block_number`, `block_hash`,
`finality` and `final_block_number`/`final_block_hash`), advance the
checkpoint and compact the WAL.

| `--finality` | Final when | Notes |
|---|---|---|
| `finalized` (default) | the block is at or below the RPC's `finalized` tag | strongest; the daemon refuses to start if the endpoint does not serve the tag |
| `safe` | at or below the `safe` tag | faster, weaker |
| `depth:N` | N blocks are built on it | for chains without the tags, and for anvil (`depth:2` in the e2e); `depth:0` is development only |

Recommended settings:

- **Ethereum L1**: `finalized` (about 13 minutes, two epochs).
- **OP Stack (Optimism, Base)**: `finalized` means the L2 block's batch is in
  a finalized L1 block (tens of minutes); `safe` means the batch is posted to
  L1 but that L1 block is not final yet (minutes), so it survives a sequencer
  reorg but not a deep L1 reorg. Use `finalized` for evidence; `safe` only if
  you accept that window.
- **Arbitrum**: `finalized` follows the L1 finality of the batch (tens of
  minutes); `safe` follows the batch's L1 inclusion, without L1 finality. The
  same trade-off applies.

Sending does not wait for finality: the next epoch's transaction goes out as
soon as the previous one is mined, so a slow finality rule delays the bundles
and WAL compaction, not anchoring, sealing or ingest. Nonce order stays safe:
a new transaction never takes a nonce at or below an anchor awaiting
finality, and every transaction is recorded before broadcast.

**Reorgs.** When the anchorer key's nonce on the canonical chain drops below
a mined anchor's nonce, the anchor was reorged out. The daemon logs
`anchor: reorg removed the anchor transaction; sending it again` at WARN with
the old block number and hash and the block now at that height, and sends the
same signed transaction again (after a few checks, a same-nonce replacement
with higher fees). A transaction re-mined in another block is logged as
`reorg moved the anchor transaction to another block`. If the anchor's nonce
was taken by another transaction in a final block (another user of the key),
or the anchor read at the final block does not match the receipt, it logs
ERROR and anchors the epoch again. None of this loses events, since nothing
is compacted before finality. An anchor not final after
`--finality-timeout` is logged at ERROR and keeps waiting.

## Transport security (mTLS)

verilogd authenticates and authorizes every connection with mutual TLS
(TLS 1.3 only). It refuses to start without `--tls-cert`, `--tls-key` and
`--tls-client-ca` unless given `--insecure-plaintext`, which is for local
development only and logs a warning: in that mode anyone who can reach the
port can read every agent's events and submit events for any agent.
Server-only TLS is not offered, because without a client certificate there is
no identity to authorize.

**Identity.** A client certificate must chain to `--tls-client-ca` and carry
exactly one URI SAN with the `verilog` scheme:

| URI SAN | Who | IngestStream | GetProof |
|---|---|---|---|
| `verilog://agent/<agent_id>` | an agent | only events whose `agent_id` is `<agent_id>`; any other event is rejected per event (non-retryable) | only `<agent_id>`'s epochs |
| `verilog://auditor/<name>` | a read-only auditor | refused (`PERMISSION_DENIED`) | every agent |

`<agent_id>` is path-escaped (`team/bot 1` becomes `team%2Fbot%201`). A
certificate without such a SAN, with two, or with another role is refused
(`UNAUTHENTICATED`). Authorization comes first: the daemon does no on-chain
key lookup and reads no evidence for a caller that is not allowed the
`agent_id`.

**Certificates.** Issue them from your own CA or PKI (for example a private
intermediate used only for VeriLog, step-ca, Vault PKI or a cloud private
CA). Use separate CAs, or at least separate intermediates, for the daemon's
server certificate and for client certificates, so a server key cannot mint
client identities. Keep client certificates short-lived (days to weeks) and
issue each agent's on its own host, next to its signing key; the client
certificate authorizes the connection, while the Ed25519 signing key is what
the verifier trusts. `make certs` writes development-only certificates into
`dev-certs/` (gitignored, a new throwaway CA each run).

**Rotation with overlap.** To rotate the client CA, put the old and new CA
certificates in the `--tls-client-ca` bundle and restart the daemon, reissue
client certificates from the new CA, then drop the old CA once no client uses
it. To rotate the server certificate, give clients a `tls_ca` bundle with
both server CAs first, then switch the daemon. Renew client certificates well
before they expire; a reconnecting SDK presents the files it was given, so
restart agents (or point them at renewed files) as part of renewal. There is
no revocation list: revoke by removing an identity's CA, or keep certificates
short-lived.

**Clients.**

- SDK: TLS by default. `VeriLogClient(target, tls_ca=..., tls_cert=...,
  tls_key=...)` (also accepted by the callback handlers), or
  `credentials=grpc.ssl_channel_credentials(...)`. Plaintext needs
  `insecure=True`, which logs a warning. The SDK checks every ack's
  `content_digest` against the event it sent; a mismatch is logged at ERROR,
  counted in `stats().ack_mismatches`, and the event is re-sent.
- `verilog-verify export --daemon`: `--daemon-ca`, `--daemon-cert`,
  `--daemon-key` (an auditor's certificate, or the agent's own);
  `--daemon-insecure` for a dev daemon.

**Limits.** `--max-connections` (a listener limit), `--max-concurrent-streams`,
the keepalive flags and `--stream-idle-timeout` bound what one client can hold
open ([Daemon configuration](#daemon-configuration)). The agent key cache is a
bounded LRU (65,536 keys); concurrent lookups of one key share a single RPC;
and lookups that find no key are limited per agent (a burst of 20, then one
per second), beyond which the event is rejected as retryable without an RPC.

## Key management

Each agent has its own Ed25519 key. The private key lives only in the agent
process; the public key is registered on chain, which is the verifier's only
trust anchor for keys.

```sh
# On the agent host: generate the key (32-byte seed, hex, mode 0600; never printed).
python -m verilog_sdk keygen --out /etc/verilog/support-bot.key --agent-id support-bot
#   pubkey: 0x…   key_id: 0x…   pop: 0x…   plus the keycheck and registerAgentKey commands

# The key admin first checks the key and its proof of possession:
verilog-verify keycheck --agent-id support-bot --pubkey 0x<pubkey> --pop 0x<pop>
#   [KEY OK] Safe Ed25519 key with a valid proof of possession   (exit 0)
#   [KEY REJECTED] <reason>                                       (exit 1: do not register)

# ...then (KEY_ADMIN_ROLE) registers it:
cast send $REGISTRY 'registerAgentKey(bytes32,bytes32)' $(cast keccak support-bot) 0x<pubkey> --rpc-url $RPC …

# The agent loads it from VERILOG_SIGNING_KEY_FILE (preferred) or VERILOG_SIGNING_KEY (hex).
export VERILOG_SIGNING_KEY_FILE=/etc/verilog/support-bot.key
```

- **Key checks.** `keycheck` accepts only a safe Ed25519 key (on the curve,
  canonically encoded, of prime order) with a valid proof of possession for
  the agent id. `registerAgentKey` itself reverts with `WeakPubkey` for
  small-order and non-canonical encodings; the daemon and the verifier refuse
  every unsafe key, including one registered in an older registry.
- **Revocation** is `revokeAgentKey(agentId, keyId, effectiveAt)`, where
  `effectiveAt` is a block timestamp no earlier than the revoking block, so
  it is never retroactive. For a suspected compromise use the current block
  time. Once a revocation is recorded the daemon refuses new events signed
  with the key (within its one-minute key cache), even before `effectiveAt`.
  A recorded revocation cannot be moved.
- **Validity** uses trusted anchor time, never the signed timestamp: a key is
  valid for an epoch when `validFrom <= anchor.timestamp` and
  (`revokedAt == 0` or `anchor.timestamp < revokedAt`), where `revokedAt` is
  the revocation's `effectiveAt`. A revocation therefore invalidates every
  epoch anchored from `effectiveAt` on, and none before. A revoked key cannot
  be registered again. Each event names its own `key_id`, so a run may mix
  keys.
- **Who holds `KEY_ADMIN_ROLE`.** The constructor gives `DEFAULT_ADMIN_ROLE`
  and `KEY_ADMIN_ROLE` to the admin. The contract refuses to let any account
  hold `ANCHORER_ROLE` together with either admin role, and `Deploy.s.sol`
  refuses an anchorer equal to the admin, so the daemon can never register
  its own key. Locally and on testnets the admin is a plain dev key, distinct
  from the anchorer key (`scripts/e2e.sh` uses anvil accounts #0 and #1).

### Rotation: drain before revoke

1. Generate a new key on the agent host, `keycheck` it and register it.
2. Restart the agent with the new key. Runs still open under the old key end
   when the agent stops (`run_end` status `"closed"`).
3. Wait until the old key's last events are anchored: the agent's final
   `run_end` events appear in the evidence bundles (or run mode passes for its
   last runs). Allow at least one `--epoch-interval` plus anchoring latency.
4. Revoke with a margin:
   `revokeAgentKey(agentId, oldKeyId, now + margin)`, with the margin at least
   `--epoch-interval` + `--confirm-timeout` + 60 s (the daemon's key cache), so
   anything accepted before the daemon saw the revocation is anchored before
   it takes effect.

When the daemon seals an epoch it re-reads the keys, uncached, and leaves out
events whose key's revocation is already in effect (they could never verify,
and a replay of old events after a revocation gets nothing anchored). It logs
them at ERROR and counts them in `revoked_excluded` on the periodic stats log
line. A non-zero count means events missed the drain window, and their runs
will not verify.

### Production: hand the admin roles to a 2-of-3 Safe

In production both admin roles belong to a 2-of-3 Safe multisig whose three
signers are hardware wallets held by different people. Switching is two role
grants and two renounces, with no code changes:

```sh
SAFE=0x…                                   # the Safe's address
KEY_ADMIN=$(cast keccak KEY_ADMIN_ROLE)
DEFAULT_ADMIN=0x0000000000000000000000000000000000000000000000000000000000000000

# 1. As the deployer (dev admin), grant both roles to the Safe.
cast send $REGISTRY 'grantRole(bytes32,address)' $KEY_ADMIN     $SAFE --private-key $DEPLOYER_KEY --rpc-url $RPC
cast send $REGISTRY 'grantRole(bytes32,address)' $DEFAULT_ADMIN $SAFE --private-key $DEPLOYER_KEY --rpc-url $RPC

# 2. Check them before giving anything up.
cast call $REGISTRY 'hasRole(bytes32,address)(bool)' $KEY_ADMIN     $SAFE --rpc-url $RPC   # true
cast call $REGISTRY 'hasRole(bytes32,address)(bool)' $DEFAULT_ADMIN $SAFE --rpc-url $RPC   # true

# 3. The deployer renounces both roles (KEY_ADMIN first; DEFAULT_ADMIN last).
DEPLOYER=$(cast wallet address --private-key $DEPLOYER_KEY)
cast send $REGISTRY 'renounceRole(bytes32,address)' $KEY_ADMIN     $DEPLOYER --private-key $DEPLOYER_KEY --rpc-url $RPC
cast send $REGISTRY 'renounceRole(bytes32,address)' $DEFAULT_ADMIN $DEPLOYER --private-key $DEPLOYER_KEY --rpc-url $RPC

# 4. Confirm the deployer and the anchorer hold neither role (all false).
for a in $DEPLOYER $ANCHORER; do for r in $KEY_ADMIN $DEFAULT_ADMIN; do
  cast call $REGISTRY 'hasRole(bytes32,address)(bool)' $r $a --rpc-url $RPC; done; done
```

From then on, `registerAgentKey`, `revokeAgentKey` and role changes are Safe
transactions that two of the three hardware signers approve. Never grant
either admin role to the daemon's anchorer address (the contract reverts with
`AnchorerCannotAdminister`), and never keep the Safe signers' keys on the
daemon host.

## Verifying logs

```sh
# Export one event and its proof from an evidence bundle...
bin/verilog-verify export --bundle /var/lib/verilog/evidence/<agentKey>/epoch-3.json --index 17 --out ./case-42
#    ...or straight from the daemon, with an auditor's (or the agent's) client certificate:
#    --daemon daemon.internal:50051 --daemon-ca server-ca.pem --daemon-cert auditor.pem --daemon-key auditor-key.pem \
#    --agent-id support-bot --epoch 3 --index 17

# Single-event mode.
bin/verilog-verify --event case-42/event.json --proof case-42/proof.json \
    --epoch 3 --agent-id support-bot --rpc "$RPC" --contract 0xRegistry --chain-id 1

# Run mode: a whole run (its run_id is in every event) from a copy of all the agent's evidence bundles.
bin/verilog-verify --run-id 01a0f526-62a8-7390-aefb-ba42851014ac --bundles ./evidence/<agentKey> \
    --agent-id support-bot --rpc "$RPC" --contract 0xRegistry --chain-id 1
```

Every verification is pinned to one chain and one block:

- `--chain-id N` (or `VERILOG_CHAIN_ID`) is **required**. If the endpoint's
  `eth_chainId` differs, the verifier exits 2 without a verdict. (A verdict
  read from the wrong chain, such as a testnet deployment at the same address,
  would look exactly like a real one, so there is no default.)
- `--finality finalized|safe|latest|depth:N` (default `finalized`) picks the
  block every read uses: `agentAnchors`, `latestEpoch`, `agentKeys` and
  `verifyAnchoredLeaf`. Its number and hash are printed on stderr
  (`chain: id …, verdict at block …`). If that block is reorganized during
  the run, the verifier exits 2.
- Single-event mode: an epoch anchored at the head but not at the final block
  is **not anchored yet** (exit 2, retry later). An epoch anchored nowhere is
  still a FAILURE.
- Run mode: the verdict covers the final epochs `1..latestEpoch` at the final
  block. Bundles of later, not yet final epochs are set aside with a warning,
  unless one matches its anchor at the head and holds events of the run: then
  the run is not anchored yet (exit 2), because those events could still change
  the verdict once final.

**Single-event mode** succeeds when:

- the event file is exactly the canonical event bytes (one trailing newline
  allowed). Any other spelling, even of the same values, is a FAILURE, and
  the signed bytes are printed on stderr;
- the epoch is anchored and the recomputed root equals the anchored root
  (and the contract's `verifyAnchoredLeaf` agrees);
- the signing key is a safe Ed25519 key registered on chain for the agent
  and valid at the epoch's anchor time;
- the Ed25519 signature verifies.

**Run mode** needs the complete evidence of the agent. `--bundles` is searched
recursively; bundles are untrusted input.

- There must be a bundle for every epoch `1..latestEpoch(agent)`, and each
  epoch's event list must rebuild its on-chain root with a count equal to its
  `logCount`. A missing or mismatched epoch is a FAILURE, so the verifier sees
  every anchored copy of every event. Run mode therefore reads the agent's
  whole history.
- Bundles of other agents, bundles of epochs that are not anchored, and files
  that are not bundles are ignored with a warning; events of other agents are
  skipped.
- Every event of the run is checked as in single-event mode. An event's epoch
  is its earliest anchored copy that verifies; other copies (a replay
  anchored after the key was revoked, say) only produce a warning.
- The chain starts at step 1 with a zero `prev_hash` and has no missing
  steps; each `prev_hash` is the previous event's digest; no two different
  events share a step (a fork means key misuse); no event is anchored in an
  earlier epoch than its predecessor (a later epoch means it was withheld).
- The last event is `run_end`. A missing `run_end` is a FAILURE ("run ended
  without terminal event after step N"). With `--allow-incomplete` it is the
  distinct verdict `[SUCCESS-INCOMPLETE]` (exit 3), for investigations of
  crashed agents only.

`verilog-verify` prints exactly one line on stdout and sets its exit code:

| stdout | exit | meaning |
|---|---|---|
| `[SUCCESS] Log Integrity Verified` | 0 | every check above passed |
| `[FAILURE] Tampered Log Detected` | 1 | any defect in the evidence: root mismatch, non-canonical or unparseable event file, an epoch that is not anchored, another agent's event, an unsafe, unregistered or not-yet/no-longer valid key, bad signature; in run mode also missing or mismatched epochs, no events of the run, a gap, fork, reorder, events after `run_end`, or a missing `run_end` |
| `[SUCCESS-INCOMPLETE] Log Integrity Verified, Run Incomplete` | 3 | run mode with `--allow-incomplete` only: every event present verifies and the chain is intact, but there is no `run_end`, so truncation cannot be ruled out. Not a pass |
| *(nothing)* | 2 | no verdict: bad arguments, files that cannot be read, RPC failure, no contract at the address |

Details (digests, roots, run id and step, key status, reason, warnings,
self-reported `sdk_dropped` counts) go to stderr. `--agent-id` accepts the
string id or the raw `0x…` bytes32 key. `--onchain-check=false` skips the
contract cross-check. Run `bin/verilog-verify --help` and
`bin/verilog-verify export --help` for the full flag list.
