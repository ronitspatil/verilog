import hashlib
import json
import threading
import time

import pytest

from verilog_sdk import OverflowPolicy, Signer, VeriLogClient
from verilog_sdk import client as client_mod
from verilog_sdk.canonical import ZERO_HASH, canonical_json

from .conftest import TEST_SEED_HEX, check_chains, unused_target

PUB = Signer.from_hex(TEST_SEED_HEX).public_key


def test_streams_events_in_order(fake_daemon):
    client = VeriLogClient(fake_daemon.target, insecure=True)
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
    client = VeriLogClient(fake_daemon.target, insecure=True)
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
        VeriLogClient(unused_target(), insecure=True)


def test_submit_never_blocks_when_daemon_is_down():
    client = VeriLogClient(unused_target(), insecure=True, queue_size=100, backoff_initial=0.05)
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
    client = VeriLogClient(unused_target(), insecure=True, queue_size=3, max_in_flight=1)
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
    client = VeriLogClient(fake_daemon.target, insecure=True, queue_size=5, max_in_flight=1)
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
        unused_target(), insecure=True, queue_size=1, max_in_flight=1,
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
    client = VeriLogClient(fake_daemon.target, insecure=True, backoff_initial=0.05)
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
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.submit("a", "r", "bad", {})
    client.submit("a", "r", "good", {})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.rejected == 1 and stats.acked == 1


def test_unserializable_payload_is_reported_without_raising(fake_daemon):
    client = VeriLogClient(fake_daemon.target, insecure=True)
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


def test_events_after_run_end_become_late_runs(fake_daemon):
    """L5: a late event is never dropped silently and never extends the ended
    run: it is signed as its own run, closed by a run_end naming the original."""
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.submit("a", "r", "t", {})
    client.submit("a", "r", "run_end", {"status": "ok"})
    client.submit("a", "r", "late", {"x": 1})
    assert client.flush(timeout=10)
    client.close()
    runs = check_chains(fake_daemon.events, PUB)
    assert [e.event_type for e in runs["r"]] == ["t", "run_end"]
    late_run = [r for r in runs if r.startswith("r#late-")]
    assert len(late_run) == 1
    late = runs[late_run[0]]
    assert [(e.event_type, json.loads(e.payload_json)) for e in late] == [
        ("late", {"x": 1}), ("run_end", {"status": "late", "late_for_run": "r", "steps": 1}),
    ]
    stats = client.stats()
    assert stats.late_events == 1 and stats.dropped == 0


def test_late_event_after_ended_run_memory_is_not_a_fork(fake_daemon, monkeypatch):
    """L5: after many runs have ended, a late event still does not restart its
    run at step 1 (which the verifier would report as a fork)."""
    monkeypatch.setattr(client_mod, "_ENDED_RUNS_MEMORY", 3)
    client = VeriLogClient(fake_daemon.target, insecure=True)
    for i in range(10):
        client.submit("a", f"r{i}", "t", {})
        client.submit("a", f"r{i}", "run_end", {"status": "ok"})
    assert client.flush(timeout=10)
    client.submit("a", "r0", "late", {})  # r0 left the exact memory long ago
    assert client.flush(timeout=10)
    client.close()
    runs = check_chains(fake_daemon.events, PUB)
    assert [e.event_type for e in runs["r0"]] == ["t", "run_end"]
    assert client.stats().late_events == 1


def test_open_runs_are_bounded(fake_daemon):
    """L5: runs that never end are closed with run_end "evicted" beyond max_open_runs."""
    client = VeriLogClient(fake_daemon.target, insecure=True, max_open_runs=2)
    for i in range(4):
        client.submit("a", f"open-{i}", "t", {})
    assert client.flush(timeout=10)
    client.submit("a", "open-0", "t2", {})  # evicted: becomes a late run
    assert client.flush(timeout=10)
    client.close()
    runs = check_chains(fake_daemon.events, PUB)
    ended = {r for r, evs in runs.items() if evs[-1].event_type == "run_end"}
    assert {"open-0", "open-1"} <= ended
    assert json.loads(runs["open-0"][-1].payload_json) == {"status": "evicted", "steps": 1}
    assert len(client._chains) <= 2
    assert client.stats().evicted_runs == 2 and client.stats().late_events == 1


@pytest.mark.parametrize("fake_daemon", [{"max_payload": 1 << 20}], indirect=True)
def test_oversized_payload_is_replaced_by_signed_stand_in(fake_daemon):
    """H2 / PoC 6: a payload over the daemon's limit never reaches the daemon;
    a stand-in committing to it by SHA-256 and size is chained instead, so
    the run stays verifiable."""
    kept = []
    client = VeriLogClient(fake_daemon.target, insecure=True, on_oversize=lambda *a: kept.append(a))
    big = {"output": "x" * ((1 << 20) + 10)}
    client.submit("agent", "run-1", "tool_start", {"i": 1})
    client.submit("agent", "run-1", "tool_end", big)
    client.submit("agent", "run-1", "tool_end", {"i": 3})
    client.submit("agent", "run-1", "run_end", {"status": "ok"})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.rejected == 0 and stats.chain_gaps == 0 and stats.truncated == 1 and stats.acked == 4
    events = check_chains(fake_daemon.accepted, PUB)["run-1"]
    assert len(events) == 4
    raw = canonical_json(big).encode()
    stand_in = json.loads(events[1].payload_json)
    assert stand_in == {"bytes": len(raw), "sha256": "0x" + hashlib.sha256(raw).hexdigest(), "truncated": True}
    assert kept and kept[0][3] == stand_in["sha256"] and kept[0][4].encode() == raw


@pytest.mark.parametrize("fake_daemon", [{"unregistered_for": 0.6}], indirect=True)
def test_key_not_yet_visible_is_retried_in_order(fake_daemon):
    """H2: "not registered" rejections are retried with backoff, so an agent
    that starts right after its key registration has no gap."""
    client = VeriLogClient(fake_daemon.target, insecure=True, key_wait_timeout=10)
    for i in range(5):
        client.submit("a", "r", "t", {"i": i})
    client.submit("a", "r", "run_end", {"status": "ok"})
    assert client.flush(timeout=15)
    client.close()
    stats = client.stats()
    assert stats.acked == 6 and stats.rejected == 0 and stats.chain_gaps == 0 and stats.retried >= 1
    # Accepted in chain order, every step present.
    assert [e.step_number for e in fake_daemon.accepted] == list(range(1, 7))
    check_chains(fake_daemon.accepted, PUB)


@pytest.mark.parametrize("fake_daemon", [{"unregistered_for": 60}], indirect=True)
def test_retry_window_is_bounded(fake_daemon, caplog):
    client = VeriLogClient(fake_daemon.target, insecure=True, key_wait_timeout=0.5)
    client.submit("a", "r", "t", {})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.rejected == 1 and stats.chain_gaps == 1 and stats.acked == 0
    assert any(r.levelname == "ERROR" and "gap" in r.message for r in caplog.records)


@pytest.mark.parametrize("fake_daemon", [{"reject_types": {"bad"}}], indirect=True)
def test_rejected_chained_event_is_an_error_and_counted(fake_daemon, caplog):
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.submit("a", "r", "bad", {})
    assert client.flush(timeout=10)
    client.close()
    assert client.stats().chain_gaps == 1
    assert any(r.levelname == "ERROR" and "gap" in r.message for r in caplog.records)


def test_far_future_timestamp_is_signed(fake_daemon):
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.submit("a", "r", "t", {}, timestamp_ns=10**20)  # year 5138: valid
    assert client.flush(timeout=10)
    client.close()
    assert client.stats().acked == 1 and client.stats().serialization_errors == 0
    check_chains(fake_daemon.events, PUB)


@pytest.mark.parametrize("ts", [10**21, 2**80, -1])
def test_bad_timestamp_does_not_poison_the_sender(fake_daemon, ts):
    """L4: a caller timestamp the canonical form cannot carry is reported as
    a dropped event; later events still flow."""
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.submit("a", "r", "t", {}, timestamp_ns=ts)
    client.submit("a", "r", "t", {"ok": True})
    assert client.flush(timeout=10)
    client.close()
    assert client.stats().serialization_errors == 1
    assert [(e.event_type, json.loads(e.payload_json)) for e in fake_daemon.events] == [
        ("sdk_dropped", {"count": 1}), ("t", {"ok": True}),
    ]


def test_submit_after_close_is_dropped(fake_daemon):
    client = VeriLogClient(fake_daemon.target, insecure=True)
    client.close()
    assert client.submit("a", "r", "t", {}) is False


@pytest.mark.parametrize("fake_daemon", [{"bad_digests": 2}], indirect=True)
def test_ack_with_wrong_digest_is_not_accepted(fake_daemon, caplog):
    client = VeriLogClient(fake_daemon.target, insecure=True, backoff_initial=0.05)
    for i in range(5):
        client.submit("agent-a", "run-1", "t", {"i": i})
    assert client.flush(timeout=10)
    client.close()
    stats = client.stats()
    assert stats.ack_mismatches == 2
    assert stats.acked == 5 and stats.rejected == 0 and stats.chain_gaps == 0
    assert stats.resent >= 2 and stats.reconnects >= 2
    assert any(r.levelname == "ERROR" and "content digest" in r.getMessage() for r in caplog.records)
    # Every event really reached the daemon, in chain order.
    steps = [e.step_number for e in fake_daemon.accepted]
    assert sorted(set(steps)) == [1, 2, 3, 4, 5]
    check_chains(list({e.step_number: e for e in fake_daemon.accepted}.values()), PUB)


def test_transport_security_defaults(tmp_path, caplog):
    import grpc

    # TLS by default; plaintext only on request, with a warning.
    tls = VeriLogClient(unused_target())
    tls.close(timeout=0.1)
    assert tls._credentials is not None
    with caplog.at_level("WARNING", logger="verilog_sdk"):
        c = VeriLogClient(unused_target(), insecure=True)
    c.close(timeout=0.1)
    assert c._credentials is None
    assert any("PLAINTEXT" in r.getMessage() for r in caplog.records)
    creds = grpc.ssl_channel_credentials()
    with pytest.raises(ValueError, match="cannot be combined"):
        VeriLogClient(unused_target(), insecure=True, credentials=creds)
    with pytest.raises(ValueError, match="cannot be combined"):
        VeriLogClient(unused_target(), insecure=True, tls_ca="ca.pem")
    with pytest.raises(ValueError, match="together"):
        VeriLogClient(unused_target(), tls_cert="c.pem")
    with pytest.raises(ValueError, match="cannot read tls_ca"):
        VeriLogClient(unused_target(), tls_ca=str(tmp_path / "missing.pem"))
    c = VeriLogClient(unused_target(), credentials=creds)
    c.close(timeout=0.1)
    assert c._credentials is creds
