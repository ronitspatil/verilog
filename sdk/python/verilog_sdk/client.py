"""Non-blocking streaming client for the VeriLog daemon.

``submit()`` only appends to a bounded in-memory queue and returns; it never
performs I/O and never raises. A background thread owns the gRPC
``IngestStream``: it sends queued events, matches the daemon's acks, and on any
stream failure reconnects with exponential backoff, re-sending events that were
sent but not acknowledged (the daemon de-duplicates identical events within an
open epoch, so delivery is effectively once in the common case and at least
once in the worst case).
"""

from __future__ import annotations

import collections
import enum
import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterator, Optional

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from ._proto import verilog_pb2, verilog_pb2_grpc
from .canonical import canonical_json

__all__ = ["OverflowPolicy", "VeriLogClient", "ClientStats"]

log = logging.getLogger("verilog_sdk")


class OverflowPolicy(str, enum.Enum):
    """What ``submit`` does when the queue is full."""

    #: Discard the oldest queued event to make room (never blocks).
    DROP_OLDEST = "drop_oldest"
    #: Wait up to ``block_timeout`` seconds for room, then drop the new event.
    BLOCK = "block"


@dataclass
class ClientStats:
    enqueued: int = 0
    sent: int = 0
    acked: int = 0
    rejected: int = 0
    duplicates: int = 0
    dropped: int = 0
    resent: int = 0
    reconnects: int = 0
    serialization_errors: int = 0


@dataclass
class _Item:
    seq: int
    agent_id: str
    step_number: int
    event_type: str
    payload: Any
    timestamp_ns: int
    payload_json: Optional[str] = None  # filled lazily on the sender thread


class VeriLogClient:
    """Thread-safe, non-blocking event shipper.

    Args:
        target: daemon address, e.g. ``"127.0.0.1:50051"``.
        queue_size: maximum queued (not yet sent) events.
        overflow_policy: behaviour when the queue is full.
        block_timeout: seconds ``submit`` may wait under ``OverflowPolicy.BLOCK``.
        max_in_flight: maximum sent-but-unacknowledged events.
        backoff_initial / backoff_max: reconnect delay bounds in seconds.
        credentials: optional ``grpc.ChannelCredentials`` (TLS); insecure if None.
        channel_options: extra gRPC channel options.
    """

    def __init__(
        self,
        target: str = "127.0.0.1:50051",
        *,
        queue_size: int = 10_000,
        overflow_policy: OverflowPolicy = OverflowPolicy.DROP_OLDEST,
        block_timeout: float = 0.05,
        max_in_flight: int = 1_000,
        backoff_initial: float = 0.2,
        backoff_max: float = 10.0,
        credentials: Optional[grpc.ChannelCredentials] = None,
        channel_options: Optional[list] = None,
    ) -> None:
        if queue_size <= 0 or max_in_flight <= 0:
            raise ValueError("queue_size and max_in_flight must be positive")
        self._target = target
        self._queue_size = queue_size
        self._policy = OverflowPolicy(overflow_policy)
        self._block_timeout = block_timeout
        self._max_in_flight = max_in_flight
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._credentials = credentials
        self._channel_options = list(channel_options or []) + [
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
        ]

        self._cond = threading.Condition()
        self._queue: Deque[_Item] = collections.deque()
        self._in_flight: "collections.OrderedDict[int, _Item]" = collections.OrderedDict()
        self._next_seq = 1
        self._closing = False
        self._stopped = False
        self._stats = ClientStats()
        self._call: Optional[grpc.Future] = None

        self._thread = threading.Thread(target=self._run, name="verilog-sdk-sender", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------ API

    def submit(
        self,
        agent_id: str,
        step_number: int,
        event_type: str,
        payload: Any,
        timestamp_ns: Optional[int] = None,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        try:
            ts = time.time_ns() if timestamp_ns is None else int(timestamp_ns)
            with self._cond:
                if self._closing:
                    self._stats.dropped += 1
                    return False
                if len(self._queue) >= self._queue_size:
                    if self._policy is OverflowPolicy.BLOCK:
                        deadline = time.monotonic() + self._block_timeout
                        while len(self._queue) >= self._queue_size and not self._closing:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            self._cond.wait(remaining)
                        if len(self._queue) >= self._queue_size or self._closing:
                            self._stats.dropped += 1
                            return False
                    else:
                        self._queue.popleft()
                        self._stats.dropped += 1
                item = _Item(self._next_seq, agent_id, int(step_number), event_type, payload, ts)
                self._next_seq += 1
                self._queue.append(item)
                self._stats.enqueued += 1
                self._cond.notify_all()
            return True
        except Exception:  # never propagate into the agent
            log.exception("verilog_sdk: submit failed")
            return False

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Wait until every event queued so far is acknowledged, rejected or dropped."""
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cond:
            target = self._next_seq
            while self._has_pending_below(target):
                if self._stopped:
                    return False
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self._cond.wait(0.1 if remaining is None else min(remaining, 0.1))
            return True

    def close(self, timeout: float = 5.0) -> bool:
        """Flush (up to ``timeout``), then stop the sender thread.

        Returns True if everything was acknowledged before shutdown.
        """
        flushed = self.flush(timeout)
        with self._cond:
            self._closing = True
            self._stopped = True
            self._cond.notify_all()
            call = self._call
        if call is not None:
            call.cancel()
        self._thread.join(timeout=max(1.0, timeout))
        if not flushed:
            with self._cond:
                lost = len(self._queue) + len(self._in_flight)
            if lost:
                log.warning("verilog_sdk: closed with %d unacknowledged events", lost)
        return flushed

    def stats(self) -> ClientStats:
        with self._cond:
            return ClientStats(**vars(self._stats))

    def __enter__(self) -> "VeriLogClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ internals

    def _has_pending_below(self, seq: int) -> bool:
        if self._in_flight and next(iter(self._in_flight)) < seq:
            return True
        return bool(self._queue) and self._queue[0].seq < seq

    def _channel(self) -> grpc.Channel:
        if self._credentials is not None:
            return grpc.secure_channel(self._target, self._credentials, options=self._channel_options)
        return grpc.insecure_channel(self._target, options=self._channel_options)

    def _run(self) -> None:
        attempt = 0
        while True:
            with self._cond:
                if self._stopped:
                    return
            got_ack = False
            channel = self._channel()
            broken = threading.Event()  # tells the request iterator to stop
            try:
                call = verilog_pb2_grpc.VeriLogStub(channel).IngestStream(self._requests(broken))
                with self._cond:
                    self._call = call
                for ack in call:
                    got_ack = True
                    self._on_ack(ack)
            except grpc.RpcError as err:
                code = err.code() if hasattr(err, "code") else None
                if code != grpc.StatusCode.CANCELLED or not self._stopped:
                    log.warning("verilog_sdk: stream to %s failed: %s", self._target, code)
            except Exception:
                log.exception("verilog_sdk: unexpected sender error")
            finally:
                broken.set()
                with self._cond:
                    self._call = None
                    # Re-send unacknowledged events first, in original order.
                    if self._in_flight:
                        self._stats.resent += len(self._in_flight)
                        self._queue.extendleft(reversed(list(self._in_flight.values())))
                        self._in_flight.clear()
                    self._cond.notify_all()
                channel.close()

            with self._cond:
                if self._stopped:
                    return
                self._stats.reconnects += 1
            attempt = 1 if got_ack else attempt + 1
            delay = min(self._backoff_max, self._backoff_initial * (2 ** (attempt - 1)))
            delay *= 0.8 + 0.4 * random.random()
            with self._cond:
                self._cond.wait_for(lambda: self._stopped, timeout=delay)

    def _requests(self, broken: threading.Event) -> Iterator[verilog_pb2.LogEvent]:
        """Request iterator consumed by gRPC; yields queued events."""
        while True:
            with self._cond:
                while True:
                    if broken.is_set() or self._stopped:
                        return
                    if self._queue and len(self._in_flight) < self._max_in_flight:
                        item = self._queue.popleft()
                        self._in_flight[item.seq] = item
                        self._cond.notify_all()  # room for BLOCK-policy submitters
                        break
                    self._cond.wait(0.1)
            msg = self._to_proto(item)
            if msg is None:
                continue
            with self._cond:
                self._stats.sent += 1
            yield msg

    def _to_proto(self, item: _Item) -> Optional[verilog_pb2.LogEvent]:
        if item.payload_json is None:
            try:
                item.payload_json = canonical_json(item.payload)
            except (TypeError, ValueError) as err:
                log.error("verilog_sdk: dropping event %d (%s): payload not serializable: %s",
                          item.seq, item.event_type, err)
                with self._cond:
                    self._in_flight.pop(item.seq, None)
                    self._stats.serialization_errors += 1
                    self._cond.notify_all()
                return None
        ts = Timestamp()
        ts.FromNanoseconds(item.timestamp_ns)
        return verilog_pb2.LogEvent(
            agent_id=item.agent_id,
            step_number=item.step_number,
            event_type=item.event_type,
            payload_json=item.payload_json,
            timestamp_utc=ts,
            sequence=item.seq,
        )

    def _on_ack(self, ack: verilog_pb2.Ack) -> None:
        with self._cond:
            item = self._in_flight.pop(ack.sequence, None)
            if ack.accepted:
                self._stats.acked += 1
                if ack.duplicate:
                    self._stats.duplicates += 1
            else:
                self._stats.rejected += 1
                log.warning("verilog_sdk: daemon rejected event %d (%s): %s", ack.sequence,
                            item.event_type if item else "?", ack.error)
            self._cond.notify_all()
