"""Command line helpers.

    python -m verilog_sdk keygen --out agent.key [--agent-id support-bot]

writes a new Ed25519 seed to ``agent.key`` (mode 0600, never printed) and
prints the public key and key id for the key admin to register on chain.
"""

from __future__ import annotations

import argparse
import sys

from .signer import Signer, keccak256, write_key_file


def _keygen(args: argparse.Namespace) -> int:
    signer = Signer.generate()
    try:
        write_key_file(signer, args.out, overwrite=args.force)
    except FileExistsError:
        print(f"error: {args.out} exists (use --force to overwrite)", file=sys.stderr)
        return 2
    pub = "0x" + signer.public_key.hex()
    print(f"key file: {args.out} (mode 0600; keep it on the agent host only)")
    print(f"pubkey:   {pub}")
    print(f"key_id:   0x{signer.key_id.hex()}")
    if args.agent_id:
        agent_key = "0x" + keccak256(args.agent_id.encode("utf-8")).hex()
        print(f"agent_id: {args.agent_id} (on-chain agentId {agent_key})")
        print("register (as KEY_ADMIN_ROLE):")
        print(f"  cast send <REGISTRY> 'registerAgentKey(bytes32,bytes32)' {agent_key} {pub} --rpc-url <RPC> <key-admin signer>")
    print(f"run the agent with: VERILOG_SIGNING_KEY_FILE={args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m verilog_sdk")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="generate an agent signing key")
    kg.add_argument("--out", required=True, help="file to write the hex seed to (created with mode 0600)")
    kg.add_argument("--agent-id", help="print the registration command for this agent id")
    kg.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = ap.parse_args(argv)
    if args.cmd == "keygen":
        return _keygen(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
