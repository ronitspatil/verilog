import threading
from concurrent import futures

import grpc
import pytest

from verilog_sdk._proto import verilog_pb2, verilog_pb2_grpc


class FakeDaemon(verilog_pb2_grpc.VeriLogServicer):
    """In-process stand-in for verilogd's IngestStream.

    ``fail_after``: on the first stream, ack this many events, then abort the
    stream with UNAVAILABLE (to exercise reconnect + resend).
    ``reject_types``: event types answered with accepted=False.
    """

    def __init__(self, fail_after=None, reject_types=()):
        self.events = []
        self.streams = 0
        self.fail_after = fail_after
        self.reject_types = set(reject_types)
        self.lock = threading.Lock()

    def IngestStream(self, request_iterator, context):
        with self.lock:
            self.streams += 1
            stream_no = self.streams
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
