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

Nothing that is chained may later go missing, since a gap fails the run:

* Oversized payloads. The daemon rejects a ``payload_json`` larger than its
  ``--max-payload-bytes`` (1 MiB by default). Before chaining, the worker
  replaces such a payload with a signed stand-in that commits to the content
  by hash and size: ``{"bytes": n, "sha256": "0x...", "truncated": true}``,
  where ``n`` and ``sha256`` are the length and SHA-256 of the UTF-8 canonical
  JSON of the original payload. Keep the original elsewhere (``on_oversize``)
  if it may be needed: anyone holding it can show it matches the stand-in.
* Key not yet visible. A rejection the daemon marks retryable (the agent key
  is not registered yet, typically just after registration) is retried with
  backoff for up to ``key_wait_timeout`` seconds before it is given up.
* Any other rejection of a chained event leaves a gap in its run: it is
  logged at ERROR and counted in ``stats().chain_gaps``.
* Events submitted after their run's ``run_end`` cannot join the run (the
  verifier rejects events after ``run_end``). Each is chained instead as its
  own run ``<run_id>#late-<n>`` followed by a ``run_end`` with status
  ``"late"`` and ``"late_for_run": <run_id>``, so it is still signed and
  anchored (``stats().late_events``).
* Acks the daemon did not compute. An accepting ack must carry the content
  digest of the event as the SDK computed it. One that does not (a buggy or
  impersonated daemon, a tampering proxy) is logged at ERROR, counted in
  ``stats().ack_mismatches``, and the event is treated as unacknowledged and
  sent again.
* Runs that never end. At most ``max_open_runs`` runs are kept open; beyond
  that the least recently used run is closed with ``run_end`` status
  ``"evicted"`` (``stats().evicted_runs``) and later events of it are late.

Transport security: the client connects with TLS by default and presents the
agent's client certificate (``tls_cert``/``tls_key``, with the URI SAN
``verilog://agent/<agent_id>``), since verilogd requires mutual TLS. Plaintext
needs an explicit ``insecure=True`` and is for local development only.
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
from typing import Any, Callable, Deque, Dict, Iterator, Optional, Tuple

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

# Remember this many ended runs exactly; older ones go into a Bloom filter, so a
# late event never restarts an ended run at step 1 (which would look like a fork).
_ENDED_RUNS_MEMORY = 10_000

# Largest timestamp the canonical form can carry: 9999-12-31T23:59:59.999999999Z.
_MAX_TIMESTAMP_NS = 253_402_300_799_999_999_999

# Longest run_id the daemon accepts, in UTF-8 bytes.
_MAX_RUN_ID_BYTES = 256


def _read(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as err:
        raise ValueError(f"cannot read {what} {path!r}: {err}") from err


def _channel_credentials(
    credentials: Optional[grpc.ChannelCredentials],
    tls_ca: Optional[str],
    tls_cert: Optional[str],
    tls_key: Optional[str],
    insecure: bool,
    target: str,
) -> Optional[grpc.ChannelCredentials]:
    """The channel credentials, or None for an (explicitly) insecure channel."""
    if insecure:
        if credentials is not None or tls_ca or tls_cert or tls_key:
            raise ValueError("insecure=True cannot be combined with credentials or tls_ca/tls_cert/tls_key")
        log.warning("verilog_sdk: insecure=True: connecting to %s over PLAINTEXT, without TLS; events can be read "
                    "and acknowledgements forged by anyone on the network path. Development only.", target)
        return None
    if credentials is not None:
        if tls_ca or tls_cert or tls_key:
            raise ValueError("pass either credentials or tls_ca/tls_cert/tls_key, not both")
        return credentials
    if bool(tls_cert) != bool(tls_key):
        raise ValueError("tls_cert and tls_key must be given together")
    return grpc.ssl_channel_credentials(
        root_certificates=_read(tls_ca, "tls_ca") if tls_ca else None,
        private_key=_read(tls_key, "tls_key") if tls_key else None,
        certificate_chain=_read(tls_cert, "tls_cert") if tls_cert else None,
    )


class _EndedFilter:
    """Bloom filter of ended runs that dropped out of the exact memory.

    4 MiB, 7 hashes: about 1 false positive in 10^5 after a million runs. A
    false positive routes a new run's events into late runs (still signed,
    anchored and verifiable), never into a fork. Reset after 2 million runs.
    """

    _BITS = 1 << 25
    _K = 7
    _CAPACITY = 2_000_000

    def __init__(self) -> None:
        self._bits = bytearray(self._BITS // 8)
        self._count = 0

    def _positions(self, run: "RunKey"):
        h = hashlib.blake2b(f"{run[0]}\0{run[1]}".encode("utf-8", "surrogatepass"), digest_size=4 * self._K).digest()
        for i in range(self._K):
            yield int.from_bytes(h[4 * i:4 * i + 4], "little") % self._BITS

    def add(self, run: "RunKey") -> None:
        if self._count >= self._CAPACITY:
            log.warning("verilog_sdk: forgetting %d old ended runs; an event more than that many runs late "
                        "would restart its run", self._count)
            self._bits = bytearray(self._BITS // 8)
            self._count = 0
        for pos in self._positions(run):
            self._bits[pos >> 3] |= 1 << (pos & 7)
        self._count += 1

    def __contains__(self, run: "RunKey") -> bool:
        return all(self._bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(run))

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
    chain_gaps: int = 0  # chained events finally rejected: each leaves a gap in its run
    retried: int = 0  # retryable rejections re-sent later (key not yet visible)
    truncated: int = 0  # oversized payloads replaced by a signed hash-and-size stand-in
    late_events: int = 0  # events after their run's run_end, chained as their own late run
    evicted_runs: int = 0  # open runs closed with run_end "evicted" (max_open_runs)
    ack_mismatches: int = 0  # accepting acks whose content_digest is not the event's; the event is re-sent


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
    # Monotonic time of the first retryable rejection, if any.
    first_rejected: Optional[float] = None
    # SDK-generated run_end closing an evicted run; moot if the run ended already.
    eviction: bool = False

    @property
    def chained(self) -> bool:
        return self.step_number is not None


@dataclass
class _Chain:
    next_step: int = 1
    prev_hash: bytes = ZERO_HASH
    closing: bool = False  # a run_end "evicted" is queued for it


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
        credentials: ``grpc.ChannelCredentials`` to use as is, e.g. from
            ``grpc.ssl_channel_credentials``; overrides the ``tls_*`` paths.
        tls_ca: PEM file of the CA that issued the daemon's certificate
            (the system roots if omitted).
        tls_cert / tls_key: PEM files of the agent's client certificate and
            key, for the daemon's mutual TLS.
        insecure: connect over plaintext, with no TLS at all. Development
            only; logs a warning. Cannot be combined with the TLS options.
        channel_options: extra gRPC channel options.
        max_payload_bytes: the daemon's ``--max-payload-bytes``; larger payloads
            are replaced by a signed hash-and-size stand-in before chaining.
        on_oversize: optional ``callable(agent_id, run_id, event_type, sha256_hex,
            payload_json)`` given each oversized payload before it is replaced,
            to keep it elsewhere. Called on the sender thread; must not block.
        key_wait_timeout: seconds to keep retrying events the daemon rejects as
            retryable (agent key not visible on chain yet).
        max_open_runs: runs kept open at once; the least recently used one is
            closed (``run_end`` status "evicted") beyond that.

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
        tls_ca: Optional[str] = None,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        insecure: bool = False,
        channel_options: Optional[list] = None,
        max_payload_bytes: int = 1 << 20,
        on_oversize: Optional[Callable[[str, str, str, str, str], None]] = None,
        key_wait_timeout: float = 60.0,
        max_open_runs: int = 10_000,
    ) -> None:
        if queue_size <= 0 or max_in_flight <= 0:
            raise ValueError("queue_size and max_in_flight must be positive")
        if max_payload_bytes < 1024:
            raise ValueError("max_payload_bytes must be at least 1024")
        if max_open_runs <= 0 or key_wait_timeout < 0:
            raise ValueError("max_open_runs must be positive and key_wait_timeout non-negative")
        self._max_payload_bytes = max_payload_bytes
        self._on_oversize = on_oversize
        self._key_wait_timeout = key_wait_timeout
        self._max_open_runs = max_open_runs
        self._signer = signer if signer is not None else Signer.from_env()
        self._target = target
        self._queue_size = queue_size
        self._policy = OverflowPolicy(overflow_policy)
        self._block_timeout = block_timeout
        self._max_in_flight = max_in_flight
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._credentials = _channel_credentials(credentials, tls_ca, tls_cert, tls_key, insecure, target)
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

        # Events rejected as retryable, waiting to be re-sent (guarded by _cond).
        self._retry: Dict[int, _Item] = {}
        self._retry_at = 0.0  # monotonic time before which nothing is sent while _retry is non-empty
        self._retry_attempt = 0
        # SDK-generated run_end events to send next (guarded by _cond).
        self._pending_ends: Deque[_Item] = collections.deque()

        # Chain state, owned by whichever request iterator holds _chain_lock.
        self._chain_lock = threading.Lock()
        self._chains: "collections.OrderedDict[RunKey, _Chain]" = collections.OrderedDict()  # LRU order
        self._ended: "collections.OrderedDict[RunKey, None]" = collections.OrderedDict()  # guarded by _cond
        self._ended_filter: Optional[_EndedFilter] = None  # guarded by _cond

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
                lost = len(self._queue) + len(self._in_flight) + len(self._retry)
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
        if self._pending_drops or self._pending_ends or self._retry:
            return True
        if any(s < seq for s in self._in_flight):
            return True
        return any(it.seq < seq for it in self._queue)

    def _is_ended(self, run: RunKey) -> bool:
        """Whether ``run`` has ended (caller holds _cond)."""
        return run in self._ended or (self._ended_filter is not None and run in self._ended_filter)

    def _mark_ended(self, run: RunKey) -> None:
        """Remember that ``run`` ended (caller holds _cond)."""
        self._ended[run] = None
        while len(self._ended) > _ENDED_RUNS_MEMORY:
            old, _ = self._ended.popitem(last=False)
            if self._ended_filter is None:
                self._ended_filter = _EndedFilter()
            self._ended_filter.add(old)

    def _note_drop(self, run: RunKey) -> None:
        """Record a dropped, never-chained event of ``run`` (caller holds _cond)."""
        if self._is_ended(run):
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
        if self._credentials is None:  # insecure=True
            return grpc.insecure_channel(self._target, options=self._channel_options)
        return grpc.secure_channel(self._target, self._credentials, options=self._channel_options)

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
                    if not self._on_ack(ack):
                        got_ack = False  # back off as after a failure
                        call.cancel()
                        break
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
        """Next event to send (caller holds _cond): retries first (after their
        backoff, holding everything else back so order is kept), then
        SDK-generated run_end events, then drop reports, then the queue."""
        if self._retry:
            if time.monotonic() < self._retry_at:
                return None
            return self._retry.pop(min(self._retry))
        if self._pending_ends:
            return self._pending_ends.popleft()
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

    def _new_item(self, agent_id: str, run_id: str, event_type: str, payload: Any) -> _Item:
        """An SDK-generated event (caller holds _cond)."""
        item = _Item(self._next_seq, agent_id, run_id, event_type, payload, time.time_ns())
        self._next_seq += 1
        return item

    def _late_run_id(self, item: _Item) -> str:
        late = f"{item.run_id}#late-{item.seq}"
        if len(late.encode("utf-8", "surrogatepass")) > _MAX_RUN_ID_BYTES:
            digest = hashlib.sha256(item.run_id.encode("utf-8", "surrogatepass")).hexdigest()[:32]
            late = f"#late-{digest}-{item.seq}"
        return late

    def _chain(self, item: _Item) -> bool:
        """Assign step, prev_hash and signature (caller holds _chain_lock)."""
        run: RunKey = (item.agent_id, item.run_id)
        with self._cond:
            ended = self._is_ended(run)
        if ended and item.eviction:
            self._discard(item, report=False)  # the run ended on its own meanwhile
            return False
        if ended:
            # The run is closed and signed as complete; the event becomes its
            # own run, linked to the original by its signed run_end.
            original = item.run_id
            item.run_id = self._late_run_id(item)
            run = (item.agent_id, item.run_id)
            log.warning("verilog_sdk: %s event for run %s arrived after its run_end; recorded as run %s",
                        item.event_type, original, item.run_id)
            with self._cond:
                self._stats.late_events += 1
                if item.event_type != EVENT_RUN_END:
                    self._pending_ends.append(self._new_item(
                        item.agent_id, item.run_id, EVENT_RUN_END, {"status": "late", "late_for_run": original}))
        chain = self._chains.get(run)
        if chain is None:
            chain = self._chains[run] = _Chain()
            if not ended:  # a late run is closed right away
                self._evict_runs()
        else:
            self._chains.move_to_end(run)
        payload = item.payload
        if item.event_type == EVENT_RUN_END and isinstance(payload, dict):
            payload = dict(payload, steps=chain.next_step - 1)
        try:
            if not 0 <= item.timestamp_ns <= _MAX_TIMESTAMP_NS:
                raise ValueError(f"timestamp_ns {item.timestamp_ns} is outside 1970..9999")
            payload_json = canonical_json(payload)
            raw = payload_json.encode("utf-8")
            if len(raw) > self._max_payload_bytes:
                payload_json = self._stand_in(item, payload_json, raw)
            fields = dict(
                agent_id=item.agent_id, run_id=item.run_id, step_number=chain.next_step,
                prev_hash=chain.prev_hash, event_type=item.event_type, payload_text=payload_json,
                timestamp_ns=item.timestamp_ns, key_id=self._signer.key_id,
            )
            sig = self._signer.sign(SIGNING_DOMAIN + event_text(sig=None, **fields).encode("utf-8"))
            digest = hashlib.sha256(event_text(sig=sig, **fields).encode("utf-8")).digest()
        except Exception as err:  # never let one bad event stall the sender
            log.error("verilog_sdk: dropping event %d (%s): cannot be serialized: %s",
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
            with self._cond:  # _ended is also read by submit()
                self._mark_ended(run)
        return True

    def _stand_in(self, item: _Item, payload_json: str, raw: bytes) -> str:
        """Replace an oversized payload by its signed hash-and-size commitment."""
        sha = "0x" + hashlib.sha256(raw).hexdigest()
        log.warning("verilog_sdk: payload of %s event %d is %d bytes (limit %d); recording its sha256 %s instead",
                    item.event_type, item.seq, len(raw), self._max_payload_bytes, sha)
        with self._cond:
            self._stats.truncated += 1
        if self._on_oversize is not None:
            try:
                self._on_oversize(item.agent_id, item.run_id, item.event_type, sha, payload_json)
            except Exception:
                log.exception("verilog_sdk: on_oversize callback failed")
        return canonical_json({"bytes": len(raw), "sha256": sha, "truncated": True})

    def _evict_runs(self) -> None:
        """Close the least recently used open runs beyond max_open_runs
        (caller holds _chain_lock)."""
        excess = len(self._chains) - self._max_open_runs
        if excess <= 0:
            return
        for run, chain in self._chains.items():
            if excess <= 0:
                break
            if chain.closing:
                continue
            chain.closing = True
            excess -= 1
            log.warning("verilog_sdk: more than %d open runs; closing run %s (run_end status \"evicted\")",
                        self._max_open_runs, run[1])
            with self._cond:
                self._stats.evicted_runs += 1
                end = self._new_item(run[0], run[1], EVENT_RUN_END, {"status": "evicted"})
                end.eviction = True
                self._pending_ends.append(end)
                self._cond.notify_all()

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

    def _on_ack(self, ack: verilog_pb2.Ack) -> bool:
        """Apply one ack. False if the stream must be dropped (ack mismatch)."""
        with self._cond:
            item = self._in_flight.pop(ack.sequence, None)
            if ack.accepted and item is not None and ack.content_digest != item.digest:
                # Not an ack for the event we sent: never take it as delivered.
                # The stream cannot be trusted either: put the event back at the
                # head of the unacknowledged events and reconnect (with backoff),
                # which re-sends them all in order.
                self._stats.ack_mismatches += 1
                self._in_flight[item.seq] = item
                self._in_flight.move_to_end(item.seq, last=False)
                log.error("verilog_sdk: daemon acknowledged event %d (%s, run %s, step %s) with content digest %s, "
                          "but the event's digest is %s; treating it as unacknowledged, reconnecting and sending "
                          "it again", ack.sequence, item.event_type, item.run_id, item.step_number,
                          ack.content_digest.hex() or "(none)", item.digest.hex())
                return False
            if ack.accepted:
                self._stats.acked += 1
                self._retry_attempt = 0
                if ack.duplicate:
                    self._stats.duplicates += 1
            elif item is not None and ack.retryable and self._retry_window_open(item):
                # Re-send the identical signed event later; hold back everything
                # else meanwhile so the run's order is kept.
                self._retry[item.seq] = item
                self._stats.retried += 1
                delay = min(5.0, 0.25 * (2 ** min(self._retry_attempt, 5)))
                self._retry_attempt += 1
                self._retry_at = max(self._retry_at, time.monotonic() + delay)
                log.warning("verilog_sdk: daemon rejected event %d (%s), retrying in %.2fs: %s",
                            ack.sequence, item.event_type, delay, ack.error)
            else:
                # The event is chained: its run now has a gap.
                self._stats.rejected += 1
                self._stats.chain_gaps += 1
                log.error("verilog_sdk: daemon rejected event %d (%s, run %s, step %s); the run's hash chain now "
                          "has a gap and will not verify: %s", ack.sequence, item.event_type if item else "?",
                          item.run_id if item else "?", item.step_number if item else "?", ack.error)
            self._cond.notify_all()
        return True

    def _retry_window_open(self, item: _Item) -> bool:
        now = time.monotonic()
        if item.first_rejected is None:
            item.first_rejected = now
        return now - item.first_rejected < self._key_wait_timeout
