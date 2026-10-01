"""Non-blocking streaming client for the VeriLog daemon.

``submit()`` only appends to a bounded in-memory queue and returns; it never
performs I/O and never raises. A background thread owns the gRPC
``IngestStream``: it sends queued events, matches the daemon's acks, and on any
stream failure reconnects with exponential backoff, re-sending events that were
sent but not acknowledged (the daemon de-duplicates identical events within an
open epoch, so delivery is effectively once in the common case and at least
once in the worst case).

Signing and chaining happen on the background thread, after an event leaves
the queue, never in ``submit``. Each root run (``run_id``) is a hash chain:
the worker assigns ``step_number`` (1, 2, ...) and ``prev_hash`` (the content
digest of the run's previous event, zero for the first), then signs the event
with the agent's Ed25519 key. Because ordering is assigned after dequeue, an
overflow drop never leaves a gap in a chain: the worker instead records a
signed ``sdk_dropped`` event ``{"count": n}`` in the affected run, so
self-reported loss can be told apart from tampering. A ``run_end`` event
``{"status": ..., "steps": n}`` closes a run; it is the run's last event.
"""

from __future__ import annotations

import collections
import enum
import hashlib
import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterator, Optional, Tuple

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from ._proto import verilog_pb2, verilog_pb2_grpc
from .canonical import SIGNING_DOMAIN, ZERO_HASH, canonical_json, event_text
from .signer import Signer

__all__ = ["OverflowPolicy", "VeriLogClient", "ClientStats", "EVENT_RUN_END", "EVENT_SDK_DROPPED"]

log = logging.getLogger("verilog_sdk")

#: Terminal event of a run, emitted by the callback handler.
EVENT_RUN_END = "run_end"
#: Event recording how many events the SDK dropped from a run.
EVENT_SDK_DROPPED = "sdk_dropped"

# Remember this many ended runs, to refuse late events instead of forking a chain.
_ENDED_RUNS_MEMORY = 10_000

RunKey = Tuple[str, str]  # (agent_id, run_id)


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
    drop_reports: int = 0  # sdk_dropped events emitted


@dataclass
class _Item:
    seq: int
    agent_id: str
    run_id: str
    event_type: str
    payload: Any
    timestamp_ns: int
    # Assigned once, on the worker thread, when the event is chained and signed.
    step_number: Optional[int] = None
    prev_hash: bytes = ZERO_HASH
    payload_json: Optional[str] = None
    sig: bytes = b""
    digest: bytes = b""

    @property
    def chained(self) -> bool:
        return self.step_number is not None


@dataclass
class _Chain:
    next_step: int = 1
    prev_hash: bytes = ZERO_HASH


class VeriLogClient:
    """Thread-safe, non-blocking event shipper.

    Args:
        target: daemon address, e.g. ``"127.0.0.1:50051"``.
        signer: the agent's signing key; loaded with ``Signer.from_env()``
            (``VERILOG_SIGNING_KEY_FILE`` or ``VERILOG_SIGNING_KEY``) if omitted.
        queue_size: maximum queued (not yet sent) events.
        overflow_policy: behaviour when the queue is full.
        block_timeout: seconds ``submit`` may wait under ``OverflowPolicy.BLOCK``.
        max_in_flight: maximum sent-but-unacknowledged events.
        backoff_initial / backoff_max: reconnect delay bounds in seconds.
        credentials: optional ``grpc.ChannelCredentials`` (TLS); insecure if None.
        channel_options: extra gRPC channel options.

    Raises:
        ValueError: if no signing key is given or configured.
    """

    def __init__(
        self,
        target: str = "127.0.0.1:50051",
        *,
        signer: Optional[Signer] = None,
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
        self._signer = signer if signer is not None else Signer.from_env()
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
        # Drops not yet reported, per run (guarded by _cond).
        self._pending_drops: "collections.OrderedDict[RunKey, int]" = collections.OrderedDict()

        # Chain state, owned by whichever request iterator holds _chain_lock.
        self._chain_lock = threading.Lock()
        self._chains: Dict[RunKey, _Chain] = {}
        self._ended: "collections.OrderedDict[RunKey, None]" = collections.OrderedDict()

        self._thread = threading.Thread(target=self._run, name="verilog-sdk-sender", daemon=True)
        self._thread.start()

    @property
    def signer(self) -> Signer:
        return self._signer

    # ------------------------------------------------------------------ API

    def submit(
        self,
        agent_id: str,
        run_id: str,
        event_type: str,
        payload: Any,
        timestamp_ns: Optional[int] = None,
    ) -> bool:
        """Queue one event of run ``run_id``. Returns False if it was dropped. Never raises.

        ``step_number``, ``prev_hash`` and the signature are assigned later, on
        the background thread.
        """
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
                            if not self._closing:
                                self._note_drop((agent_id, run_id))
                            return False
                    elif not self._drop_oldest_unchained():
                        # Everything queued is an already-signed resend; dropping
                        # one would break its chain, so drop the new event.
                        self._stats.dropped += 1
                        self._note_drop((agent_id, run_id))
                        return False
                item = _Item(self._next_seq, agent_id, run_id, event_type, payload, ts)
                self._next_seq += 1
                self._queue.append(item)
                self._stats.enqueued += 1
                self._cond.notify_all()
            return True
        except Exception:  # never propagate into the agent
            log.exception("verilog_sdk: submit failed")
            return False

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Wait until every event queued so far is acknowledged, rejected or dropped,
        and every pending drop report has been sent."""
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
        if self._pending_drops:
            return True
        if any(s < seq for s in self._in_flight):
            return True
        return any(it.seq < seq for it in self._queue)

    def _note_drop(self, run: RunKey) -> None:
        """Record a dropped, never-chained event of ``run`` (caller holds _cond)."""
        if run in self._ended:
            return  # late event for a finished run; nothing to report into
        self._pending_drops[run] = self._pending_drops.get(run, 0) + 1

    def _drop_oldest_unchained(self) -> bool:
        """Drop the oldest queued event that has not been chained yet."""
        for i, it in enumerate(self._queue):
            if not it.chained:
                del self._queue[i]
                self._stats.dropped += 1
                self._note_drop((it.agent_id, it.run_id))
                return True
        return False

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
        """Request iterator consumed by gRPC; yields chained, signed events."""
        while True:
            with self._chain_lock:
                with self._cond:
                    while True:
                        if broken.is_set() or self._stopped:
                            return
                        if len(self._in_flight) < self._max_in_flight:
                            item = self._take()
                            if item is not None:
                                self._in_flight[item.seq] = item
                                self._cond.notify_all()  # room for BLOCK-policy submitters
                                break
                        self._cond.wait(0.1)
                if not item.chained and not self._chain(item):
                    continue
            msg = self._to_proto(item)
            with self._cond:
                self._stats.sent += 1
            yield msg

    def _take(self) -> Optional[_Item]:
        """Next event to send (caller holds _cond): drop reports first."""
        if self._pending_drops:
            run, count = self._pending_drops.popitem(last=False)
            item = _Item(self._next_seq, run[0], run[1], EVENT_SDK_DROPPED, {"count": count}, time.time_ns())
            self._next_seq += 1
            self._stats.drop_reports += 1
            return item
        if self._queue:
            return self._queue.popleft()
        return None

    def _discard(self, item: _Item, *, report: bool) -> None:
        with self._cond:
            self._in_flight.pop(item.seq, None)
            if report:
                self._note_drop((item.agent_id, item.run_id))
            self._cond.notify_all()

    def _chain(self, item: _Item) -> bool:
        """Assign step, prev_hash and signature (caller holds _chain_lock)."""
        run: RunKey = (item.agent_id, item.run_id)
        if run in self._ended:
            log.warning("verilog_sdk: dropping %s event for run %s after its run_end", item.event_type, item.run_id)
            with self._cond:
                self._stats.dropped += 1
            self._discard(item, report=False)
            return False
        chain = self._chains.get(run)
        if chain is None:
            chain = self._chains[run] = _Chain()
        payload = item.payload
        if item.event_type == EVENT_RUN_END and isinstance(payload, dict):
            payload = dict(payload, steps=chain.next_step - 1)
        try:
            payload_json = canonical_json(payload)
            fields = dict(
                agent_id=item.agent_id, run_id=item.run_id, step_number=chain.next_step,
                prev_hash=chain.prev_hash, event_type=item.event_type, payload_text=payload_json,
                timestamp_ns=item.timestamp_ns, key_id=self._signer.key_id,
            )
            sig = self._signer.sign(SIGNING_DOMAIN + event_text(sig=None, **fields).encode("utf-8"))
            digest = hashlib.sha256(event_text(sig=sig, **fields).encode("utf-8")).digest()
        except (TypeError, ValueError, UnicodeEncodeError) as err:
            log.error("verilog_sdk: dropping event %d (%s): payload not serializable: %s",
                      item.seq, item.event_type, err)
            with self._cond:
                self._stats.serialization_errors += 1
            # Not chained, so no gap: report it in the run instead.
            self._discard(item, report=True)
            if chain.next_step == 1:
                del self._chains[run]
            return False
        item.payload_json, item.sig, item.digest = payload_json, sig, digest
        item.prev_hash, item.step_number = chain.prev_hash, chain.next_step
        chain.prev_hash, chain.next_step = digest, chain.next_step + 1
        if item.event_type == EVENT_RUN_END:
            del self._chains[run]
            self._ended[run] = None
            while len(self._ended) > _ENDED_RUNS_MEMORY:
                self._ended.popitem(last=False)
        return True

    def _to_proto(self, item: _Item) -> verilog_pb2.LogEvent:
        ts = Timestamp()
        ts.FromNanoseconds(item.timestamp_ns)
        return verilog_pb2.LogEvent(
            agent_id=item.agent_id,
            run_id=item.run_id,
            step_number=item.step_number,
            prev_hash=item.prev_hash,
            event_type=item.event_type,
            payload_json=item.payload_json,
            timestamp_utc=ts,
            key_id=self._signer.key_id,
            signature=item.sig,
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
