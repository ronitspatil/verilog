import hashlib
import json
import pathlib
import threading
import time
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


def content_digest_of(ev) -> bytes:
    """SHA-256 of the canonical event, as verilogd puts it in an Ack."""
    return hashlib.sha256(event_text(
        agent_id=ev.agent_id, run_id=ev.run_id, step_number=ev.step_number, prev_hash=ev.prev_hash,
        event_type=ev.event_type, payload_text=ev.payload_json,
        timestamp_ns=ev.timestamp_utc.ToNanoseconds(), key_id=ev.key_id, sig=ev.signature,
    ).encode("utf-8")).digest()


class FakeDaemon(verilog_pb2_grpc.VeriLogServicer):
    """In-process stand-in for verilogd's IngestStream.

    ``fail_after``: on the first stream, ack this many events, then abort the
    stream with UNAVAILABLE (to exercise reconnect + resend).
    ``reject_types``: event types answered with accepted=False.
    ``gate``: if set, each stream waits for this threading.Event before
    reading (to let the client's queue overflow).
    ``unregistered_for``: answer every event with a retryable "key not
    registered" rejection for this many seconds after the first event (a key
    registered moments ago, not yet visible to the daemon).
    ``max_payload``: reject larger payload_json like verilogd's --max-payload-bytes.
    ``bad_digests``: on each of the first this many streams, answer the first
    accepted event with a wrong ``content_digest`` (an impersonated or buggy
    daemon); it is not recorded as accepted.
    ``accepted`` holds the events acknowledged as accepted, in order.
    """

    def __init__(self, fail_after=None, reject_types=(), gate=None, unregistered_for=None, max_payload=None,
                 bad_digests=0):
        self.events = []
        self.accepted = []
        self.streams = 0
        self.fail_after = fail_after
        self.reject_types = set(reject_types)
        self.gate = gate
        self.unregistered_for = unregistered_for
        self.max_payload = max_payload
        self.first_seen = None
        self.bad_digests = bad_digests
        self.lock = threading.Lock()

    def IngestStream(self, request_iterator, context):
        with self.lock:
            self.streams += 1
            stream_no = self.streams
        if self.gate is not None:
            self.gate.wait(30)
        acked = 0
        forge_next = stream_no <= self.bad_digests
        for ev in request_iterator:
            with self.lock:
                self.events.append(ev)
            if stream_no == 1 and self.fail_after is not None and acked >= self.fail_after:
                context.abort(grpc.StatusCode.UNAVAILABLE, "injected failure")
            acked += 1
            with self.lock:
                if self.first_seen is None:
                    self.first_seen = time.monotonic()
                hidden = self.unregistered_for is not None and time.monotonic() - self.first_seen < self.unregistered_for
            if hidden:
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=False, retryable=True,
                                      error="key_id 0x.. is not registered for agent")
            elif self.max_payload is not None and len(ev.payload_json.encode()) > self.max_payload:
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=False, error="payload_json exceeds the size limit")
            elif ev.event_type in self.reject_types:
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=False, error="rejected by test")
            else:
                forged, forge_next = forge_next, False
                if not forged:
                    with self.lock:
                        self.accepted.append(ev)
                digest = content_digest_of(ev)
                if forged:
                    digest = bytes(32)
                yield verilog_pb2.Ack(sequence=ev.sequence, accepted=True, content_digest=digest)


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
