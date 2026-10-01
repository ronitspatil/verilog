import hashlib
import json
import pathlib
import threading
from concurrent import futures

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verilog_sdk._proto import verilog_pb2, verilog_pb2_grpc
from verilog_sdk.canonical import SIGNING_DOMAIN, ZERO_HASH, event_text

TESTDATA = pathlib.Path(__file__).resolve().parents[3] / "testdata"
# The public RFC 8032 test seed used by the Go vectors. Test material only.
TEST_SEED_HEX = json.loads((TESTDATA / "signed_vectors.json").read_text())["seed"]


@pytest.fixture(autouse=True)
def signing_key_env(monkeypatch):
    """Every client in the tests signs with the published test seed."""
    monkeypatch.delenv("VERILOG_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setenv("VERILOG_SIGNING_KEY", TEST_SEED_HEX)


def check_chains(events, public_key: bytes):
    """Verify signatures and per-run hash chains of LogEvents as the verifier
    would. Returns {run_id: [events in step order]}."""
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    runs = {}
    for ev in events:
        runs.setdefault(ev.run_id, []).append(ev)
    for run_id, evs in runs.items():
        evs.sort(key=lambda e: e.step_number)
        prev = ZERO_HASH
        for i, ev in enumerate(evs):
            assert ev.step_number == i + 1, (run_id, [e.step_number for e in evs])
            assert ev.prev_hash == prev, (run_id, ev.step_number)
            fields = dict(
                agent_id=ev.agent_id, run_id=ev.run_id, step_number=ev.step_number, prev_hash=ev.prev_hash,
                event_type=ev.event_type, payload_text=ev.payload_json,
                timestamp_ns=ev.timestamp_utc.ToNanoseconds(), key_id=ev.key_id,
            )
            pub.verify(ev.signature, SIGNING_DOMAIN + event_text(sig=None, **fields).encode())
            prev = hashlib.sha256(event_text(sig=ev.signature, **fields).encode()).digest()
    return runs


class FakeDaemon(verilog_pb2_grpc.VeriLogServicer):
    """In-process stand-in for verilogd's IngestStream.

    ``fail_after``: on the first stream, ack this many events, then abort the
    stream with UNAVAILABLE (to exercise reconnect + resend).
    ``reject_types``: event types answered with accepted=False.
    ``gate``: if set, each stream waits for this threading.Event before
    reading (to let the client's queue overflow).
    """

    def __init__(self, fail_after=None, reject_types=(), gate=None):
        self.events = []
        self.streams = 0
        self.fail_after = fail_after
        self.reject_types = set(reject_types)
        self.gate = gate
        self.lock = threading.Lock()

    def IngestStream(self, request_iterator, context):
        with self.lock:
            self.streams += 1
            stream_no = self.streams
        if self.gate is not None:
            self.gate.wait(30)
        acked = 0
        for ev in request_iterator:
            with self.lock:
                self.events.append(ev)
            if stream_no == 1 and self.fail_after is not None and acked >= self.fail_after:
                context.abort(grpc.StatusCode.UNAVAILABLE, "injected failure")
            acked += 1
            if ev.event_type in self.reject_types:
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=False, error="rejected by test")
            else:
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=True)


@pytest.fixture
def fake_daemon(request):
    params = getattr(request, "param", {}) or {}
    daemon = FakeDaemon(**params)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    verilog_pb2_grpc.add_VeriLogServicer_to_server(daemon, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    daemon.target = f"127.0.0.1:{port}"
    yield daemon
    server.stop(grace=None)


def unused_target():
    """An address with nothing listening."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"127.0.0.1:{port}"
