"""E2E attacker tooling: plays a compromised daemon host that holds the
anchorer key but not the agent's signing key.

  resign IN OUT --seed HEX [--payload JSON]
      Rewrites an exported event (optionally with a new payload), signs it
      with another Ed25519 key, writes it to OUT and an empty proof next to it
      (a one-event epoch has root == leaf). Prints the leaf to anchor.

  bundle --events FILE --indices 0,2,3 --agent-id ID --epoch N --out PATH
      Builds an epoch from the chosen captured events (JSON lines with
      "canonical_event"), writes an evidence bundle and prints
      "<merkle root> <event count>" for the caller to anchor with cast.
"""

import argparse
import hashlib
import json
import pathlib
import sys

from verilog_sdk._keccak import keccak256
from verilog_sdk.canonical import SIGNING_DOMAIN, event_text, canonical_json
from verilog_sdk.signer import Signer


def leaf_of(canonical_event: str) -> bytes:
    return keccak256(hashlib.sha256(canonical_event.encode()).digest())


def _ns(ts: str) -> int:
    from datetime import datetime, timezone

    base, frac = ts.rstrip("Z").split(".")
    secs = int(datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return secs * 1_000_000_000 + int(frac)


def resign(args) -> int:
    ev = json.loads(pathlib.Path(args.src).read_text())
    signer = Signer.from_hex(args.seed)
    payload = json.loads(args.payload) if args.payload else ev["payload"]
    fields = dict(
        agent_id=ev["agent_id"], run_id=ev["run_id"], step_number=ev["step_number"],
        prev_hash=bytes.fromhex(ev["prev_hash"][2:]), event_type=ev["event_type"],
        payload_text=canonical_json(payload), timestamp_ns=_ns(ev["timestamp_utc"]), key_id=signer.key_id,
    )
    sig = signer.sign(SIGNING_DOMAIN + event_text(sig=None, **fields).encode())
    text = event_text(sig=sig, **fields)
    out = pathlib.Path(args.out)
    out.write_text(text + "\n")
    (out.parent / "proof.json").write_text("[]\n")
    print("0x" + leaf_of(text).hex())
    return 0


def _hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak256(min(a, b) + max(a, b))


def build_tree(leaves):
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [_hash_pair(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])  # odd node promoted
        levels.append(nxt)
    return levels


def proof_of(levels, index):
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append(level[sib])
        index //= 2
    return proof


def bundle(args) -> int:
    lines = [json.loads(line) for line in pathlib.Path(args.events).read_text().splitlines() if line.strip()]
    chosen = [lines[int(i)]["canonical_event"] for i in args.indices.split(",")]
    leaves = [leaf_of(c) for c in chosen]
    levels = build_tree(leaves)
    root = levels[-1][0]
    events = []
    for i, c in enumerate(chosen):
        events.append({
            "leaf_index": i, "seq": i + 1,
            "content_digest": "0x" + hashlib.sha256(c.encode()).hexdigest(),
            "leaf": "0x" + leaves[i].hex(),
            "proof": ["0x" + p.hex() for p in proof_of(levels, i)],
            "canonical_event": c,
        })
    doc = {
        "version": 2, "agent_id": args.agent_id,
        "agent_key": "0x" + keccak256(args.agent_id.encode()).hex(),
        "epoch_id": args.epoch, "merkle_root": "0x" + root.hex(), "log_count": len(chosen), "events": events,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"0x{root.hex()} {len(chosen)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resign")
    r.add_argument("src")
    r.add_argument("out")
    r.add_argument("--seed", required=True)
    r.add_argument("--payload")
    b = sub.add_parser("bundle")
    b.add_argument("--events", required=True)
    b.add_argument("--indices", required=True)
    b.add_argument("--agent-id", required=True)
    b.add_argument("--epoch", type=int, required=True)
    b.add_argument("--out", required=True)
    args = ap.parse_args()
    return resign(args) if args.cmd == "resign" else bundle(args)


if __name__ == "__main__":
    sys.exit(main())
