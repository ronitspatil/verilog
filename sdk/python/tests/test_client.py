import json
import threading
import time

import pytest

from verilog_sdk import OverflowPolicy, Signer, VeriLogClient
from verilog_sdk.canonical import ZERO_HASH, canonical_json

from .conftest import TEST_SEED_HEX, check_chains, unused_target

PUB = Signer.from_hex(TEST_SEED_HEX).public_key


def test_streams_events_in_order(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    for i in range(200):
        assert client.submit("agent-a", "run-1", "tool_start", {"i": i, "b": [1, 2], "a": "x"})
    assert client.flush(timeout=10)
    client.close()

    assert [e.step_number for e in fake_daemon.events] == list(range(1, 201))
    assert [e.sequence for e in fake_daemon.events] == list(range(1, 201))
    first = fake_daemon.events[0]
    assert first.agent_id == "agent-a" and first.event_type == "tool_start" and first.run_id == "run-1"
    assert first.payload_json == canonical_json({"i": 0, "b": [1, 2], "a": "x"})
    assert first.prev_hash == ZERO_HASH and first.key_id == client.signer.key_id
    assert len(first.signature) == 64
    assert first.timestamp_utc.seconds > 0
    check_chains(fake_daemon.events, PUB)
    stats = client.stats()
    assert stats.acked == 200 and stats.dropped == 0 and stats.rejected == 0


def test_runs_are_independent_chains(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    for i in range(30):
        client.submit("agent-a", f"run-{i % 3}", "t", {"i": i})
    client.submit("agent-b", "run-0", "t", {})  # same run id, other agent: its own chain
    assert client.flush(timeout=10)
    client.close()
    runs = {}
    for e in fake_daemon.events:
        runs.setdefault((e.agent_id, e.run_id), []).append(e.step_number)
    assert runs[("agent-a", "run-0")] == list(range(1, 11))
    assert runs[("agent-b", "run-0")] == [1]
    check_chains([e for e in fake_daemon.events if e.agent_id == "agent-a"], PUB)


def test_requires_a_signing_key(monkeypatch):
    monkeypatch.delenv("VERILOG_SIGNING_KEY")
    with pytest.raises(ValueError, match="no signing key"):
        VeriLogClient(unused_target())


def test_submit_never_blocks_when_daemon_is_down():
    client = VeriLogClient(unused_target(), queue_size=100, backoff_initial=0.05)
    start = time.perf_counter()
    for i in range(10_000):
        client.submit("agent-a", "run-1", "llm_start", {"i": i})
    elapsed = time.perf_counter() - start
    stats = client.stats()
    client.close(timeout=0.2)
    # 10k enqueues against a dead daemon must stay well under a second.
    assert elapsed < 1.0, elapsed
    assert stats.enqueued == 10_000
    assert stats.dropped >= 10_000 - 100 - 1_000  # queue + in-flight capacity


def test_drop_oldest_keeps_newest():
    client = VeriLogClient(unused_target(), queue_size=3, max_in_flight=1)
    time.sleep(0.05)
    for i in range(10):
        client.submit("a", "r", "t", {"i": i})
    with client._cond:
        queued = [it.payload["i"] for it in client._queue]
    client.close(timeout=0.1)
    # Whatever is still queued is the newest events, in order.
    assert queued and queued == list(range(10 - len(queued), 10))
    assert client.stats().dropped >= 6


@pytest.mark.parametrize("fake_daemon", [{"gate": threading.Event()}], indirect=True)
def test_overflow_drops_are_reported_in_a_contiguous_chain(fake_daemon):
    """Drops never leave a gap: the chain stays contiguous and carries a signed
    sdk_dropped event with the number of lost events."""
    client = VeriLogClient(fake_daemon.target, queue_size=5, max_in_flight=1)
    for i in range(50):
        client.submit("agent-a", "run-1", "tool_start", {"i": i})
    client.submit("agent-a", "run-1", "run_end", {"status": "ok"})
    dropped = client.stats().dropped
    assert dropped > 0
    fake_daemon.gate.set()
    assert client.flush(timeout=10)
    client.close()

    runs = check_chains(fake_daemon.events, PUB)
    events = runs["run-1"]
    reports = [json.loads(e.payload_json) for e in events if e.event_type == "sdk_dropped"]
    assert reports and sum(r["count"] for r in reports) == dropped
    assert events[-1].event_type == "run_end"
    assert json.loads(events[-1].payload_json) == {"status": "ok", "steps": len(events) - 1}
    kept = [json.loads(e.payload_json)["i"] for e in events if e.event_type == "tool_start"]
    assert kept == sorted(kept) and len(kept) == 50 - dropped
    assert client.stats().drop_reports == len(reports)


def test_block_policy_times_out_and_drops_new_event():
    client = VeriLogClient(
        unused_target(), queue_size=1, max_in_flight=1,
        overflow_policy=OverflowPolicy.BLOCK, block_timeout=0.05,
    )
    results = [client.submit("a", "r", "t", {}) for i in range(5)]
    start = time.perf_counter()
    blocked = client.submit("a", "r", "t", {"i": 99})
    waited = time.perf_counter() - start
    client.close(timeout=0.1)
    assert results[0] is True
    assert blocked is False
    assert 0.03 <= waited < 0.5


@pytest.mark.parametrize("fake_daemon", [{"fail_after": 5}], indirect=True)
def test_reconnects_and_resends_unacked(fake_daemon):
    client = VeriLogClient(fake_daemon.target, backoff_initial=0.05)
    for i in range(50):
        client.submit("agent-a", "run-1", "chain_start", {"i": i})
    assert client.flush(timeout=15)
    client.close()
    assert fake_daemon.streams >= 2
    delivered = {e.sequence for e in fake_daemon.events}
    assert delivered == set(range(1, 51))
    # Resent events are byte-identical (same step, prev_hash and signature),
    # so the daemon de-duplicates them and the chain is unbroken.
    by_seq = {}
    for e in fake_daemon.events:
        if e.sequence in by_seq:
            assert by_seq[e.sequence] == e
        by_seq[e.sequence] = e
    check_chains(list(by_seq.values()), PUB)
    stats = client.stats()
    assert stats.reconnects >= 1 and stats.resent >= 1 and stats.acked == 50


@pytest.mark.parametrize("fake_daemon", [{"reject_types": {"bad"}}], indirect=True)
def test_rejections_are_counted_not_raised(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    client.submit("a", "r", "bad", {})
    client.submit("a", "r", "good", {})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.rejected == 1 and stats.acked == 1


def test_unserializable_payload_is_reported_without_raising(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    assert client.submit("a", "r", "t", {"obj": object()}) is True  # serialized later, off-thread
    client.submit("a", "r", "t", {"ok": True})
    assert client.flush(timeout=10)
    client.close()
    assert client.stats().serialization_errors == 1
    # The unserializable event never got a step; the run records the loss instead.
    assert [(e.event_type, json.loads(e.payload_json)) for e in fake_daemon.events] == [
        ("sdk_dropped", {"count": 1}), ("t", {"ok": True}),
    ]
    check_chains(fake_daemon.events, PUB)


def test_events_after_run_end_are_dropped(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    client.submit("a", "r", "t", {})
    client.submit("a", "r", "run_end", {"status": "ok"})
    client.submit("a", "r", "late", {})
    assert client.flush(timeout=10)
    client.close()
    assert [e.event_type for e in fake_daemon.events] == ["t", "run_end"]
    assert client.stats().dropped == 1


def test_submit_after_close_is_dropped(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    client.close()
    assert client.submit("a", "r", "t", {}) is False
