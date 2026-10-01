"""E2E mTLS checks against a running verilogd (scripts/e2e.sh).

Expects the dev certificates of verilog-devcerts in --certs: ca.pem, the
agent certificates of --agent-id and --other-agent, and the auditor
certificate of --auditor. --epoch must be anchored for --agent-id. Prints one
line per check and exits non-zero on the first failure.
"""

import argparse
import logging
import os
import sys

import grpc

from verilog_sdk import VeriLogClient
from verilog_sdk._proto import verilog_pb2, verilog_pb2_grpc


def read(path):
    with open(path, "rb") as f:
        return f.read()


def fail(msg):
    print(f"mTLS check FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--certs", required=True)
    ap.add_argument("--agent-id", required=True)
    ap.add_argument("--other-agent", required=True)
    ap.add_argument("--auditor", required=True)
    ap.add_argument("--epoch", type=int, default=1)
    args = ap.parse_args()
    ca = read(os.path.join(args.certs, "ca.pem"))

    def creds(name=None):
        if name is None:
            return grpc.ssl_channel_credentials(root_certificates=ca)
        return grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=read(os.path.join(args.certs, f"{name}-key.pem")),
            certificate_chain=read(os.path.join(args.certs, f"{name}.pem")),
        )

    def stub(c):
        ch = grpc.secure_channel(args.target, c) if c is not None else grpc.insecure_channel(args.target)
        return ch, verilog_pb2_grpc.VeriLogStub(ch)

    def ingest_error(c):
        """The status code of an IngestStream with one (unsigned) event, or None if it was served."""
        ch, s = stub(c)
        with ch:
            try:
                list(s.IngestStream(iter([verilog_pb2.LogEvent(agent_id=args.agent_id, sequence=1)]), timeout=10))
            except grpc.RpcError as err:
                return err.code(), err.details()
        return None, None

    def proof_error(c, agent):
        ch, s = stub(c)
        with ch:
            try:
                s.GetProof(verilog_pb2.GetProofRequest(agent_id=agent, epoch_id=args.epoch, leaf_index=0), timeout=10)
            except grpc.RpcError as err:
                return err.code(), err.details()
        return None, None

    # 1. No client certificate: the TLS handshake is refused.
    code, details = ingest_error(creds())
    if code != grpc.StatusCode.UNAVAILABLE:
        fail(f"a client without a certificate got {code} {details!r}, want UNAVAILABLE (handshake refused)")
    code2, _ = proof_error(creds(), args.agent_id)
    if code2 is None:
        fail("GetProof served a client without a certificate")
    print(f"refused: no client certificate ({code.name}: {details})")

    # 2. Plaintext client against the mTLS daemon.
    code, details = ingest_error(None)
    if code is None:
        fail("a plaintext client was served")
    print(f"refused: plaintext client ({code.name}: {details})")

    # 3. An agent certificate submitting another agent's events: rejected per event, not retried.
    log = logging.getLogger("verilog_sdk")
    seen = []

    class Grab(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    grab = Grab()
    log.addHandler(grab)
    client = VeriLogClient(
        args.target, tls_ca=os.path.join(args.certs, "ca.pem"),
        tls_cert=os.path.join(args.certs, f"agent-{args.agent_id}.pem"),
        tls_key=os.path.join(args.certs, f"agent-{args.agent_id}-key.pem"),
    )
    for i in range(3):
        client.submit(args.other_agent, "impersonation-run", "tool_start", {"i": i})
    client.flush(timeout=30)
    client.close(timeout=5)
    log.removeHandler(grab)
    st = client.stats()
    if st.acked != 0 or st.rejected != 3 or st.retried != 0:
        fail(f"impersonating events: {st}, want 3 rejected, none acked or retried")
    if not any("does not match the client certificate identity" in m for m in seen):
        fail("no identity-mismatch rejection logged: " + " | ".join(seen[-3:]))
    print(f"rejected per event: agent {args.agent_id!r} submitting {args.other_agent!r}'s events "
          f"(acked={st.acked} rejected={st.rejected} retried={st.retried})")

    # 4. An auditor cannot ingest, but can read proofs.
    code, details = ingest_error(creds(f"auditor-{args.auditor}"))
    if code != grpc.StatusCode.PERMISSION_DENIED:
        fail(f"auditor ingest got {code} {details!r}, want PERMISSION_DENIED")
    print(f"refused: auditor ingest ({code.name}: {details})")
    code, details = proof_error(creds(f"auditor-{args.auditor}"), args.agent_id)
    if code is not None:
        fail(f"auditor GetProof failed: {code} {details!r}")
    print(f"allowed: auditor GetProof of {args.agent_id!r} epoch {args.epoch}")

    # 5. An agent cannot read another agent's proofs; it can read its own.
    code, details = proof_error(creds(f"agent-{args.other_agent}"), args.agent_id)
    if code != grpc.StatusCode.PERMISSION_DENIED:
        fail(f"{args.other_agent!r} reading {args.agent_id!r}'s proof got {code} {details!r}, want PERMISSION_DENIED")
    print(f"refused: agent {args.other_agent!r} GetProof of {args.agent_id!r} ({code.name}: {details})")
    code, details = proof_error(creds(f"agent-{args.agent_id}"), args.agent_id)
    if code is not None:
        fail(f"agent GetProof of its own events failed: {code} {details!r}")
    print(f"allowed: agent {args.agent_id!r} GetProof of its own events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
