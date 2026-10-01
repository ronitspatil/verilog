import json
import time

import pytest

from verilog_sdk import OverflowPolicy, VeriLogClient
from verilog_sdk.canonical import canonical_json

from .conftest import unused_target


def test_streams_events_in_order(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    for i in range(200):
        assert client.submit("agent-a", i + 1, "tool_start", {"i": i, "b": [1, 2], "a": "x"})
    assert client.flush(timeout=10)
    client.close()

    assert [e.step_number for e in fake_daemon.events] == list(range(1, 201))
    assert [e.sequence for e in fake_daemon.events] == list(range(1, 201))
    first = fake_daemon.events[0]
    assert first.agent_id == "agent-a" and first.event_type == "tool_start"
    assert first.payload_json == canonical_json({"i": 0, "b": [1, 2], "a": "x"})
    assert first.timestamp_utc.seconds > 0
    stats = client.stats()
    assert stats.acked == 200 and stats.dropped == 0 and stats.rejected == 0


def test_submit_never_blocks_when_daemon_is_down():
    client = VeriLogClient(unused_target(), queue_size=100, backoff_initial=0.05)
    start = time.perf_counter()
    for i in range(10_000):
        client.submit("agent-a", i, "llm_start", {"i": i})
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
        client.submit("a", i, "t", {})
    with client._cond:
        queued = [it.step_number for it in client._queue]
    client.close(timeout=0.1)
    # Whatever is still queued is the newest events, in order.
    assert queued and queued == list(range(10 - len(queued), 10))
    assert client.stats().dropped >= 6


def test_block_policy_times_out_and_drops_new_event():
    client = VeriLogClient(
        unused_target(), queue_size=1, max_in_flight=1,
        overflow_policy=OverflowPolicy.BLOCK, block_timeout=0.05,
    )
    results = [client.submit("a", i, "t", {}) for i in range(5)]
    start = time.perf_counter()
    blocked = client.submit("a", 99, "t", {})
    waited = time.perf_counter() - start
    client.close(timeout=0.1)
    assert results[0] is True
    assert blocked is False
    assert 0.03 <= waited < 0.5


@pytest.mark.parametrize("fake_daemon", [{"fail_after": 5}], indirect=True)
def test_reconnects_and_resends_unacked(fake_daemon):
    client = VeriLogClient(fake_daemon.target, backoff_initial=0.05)
    for i in range(50):
        client.submit("agent-a", i + 1, "chain_start", {"i": i})
    assert client.flush(timeout=15)
    client.close()
    assert fake_daemon.streams >= 2
    delivered = {e.sequence for e in fake_daemon.events}
    assert delivered == set(range(1, 51))
    stats = client.stats()
    assert stats.reconnects >= 1 and stats.resent >= 1 and stats.acked == 50


@pytest.mark.parametrize("fake_daemon", [{"reject_types": {"bad"}}], indirect=True)
def test_rejections_are_counted_not_raised(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    client.submit("a", 1, "bad", {})
    client.submit("a", 2, "good", {})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.rejected == 1 and stats.acked == 1


def test_unserializable_payload_is_dropped_without_raising(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    assert client.submit("a", 1, "t", {"obj": object()}) is True  # serialized later, off-thread
    client.submit("a", 2, "t", {"ok": True})
    assert client.flush(timeout=10)
    client.close()
    assert client.stats().serialization_errors == 1
    assert [json.loads(e.payload_json) for e in fake_daemon.events] == [{"ok": True}]


def test_submit_after_close_is_dropped(fake_daemon):
    client = VeriLogClient(fake_daemon.target)
    client.close()
    assert client.submit("a", 1, "t", {}) is False
