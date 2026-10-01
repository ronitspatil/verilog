import asyncio
import json
import time
import uuid

from langchain_core.language_models.fake import FakeListLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool

from verilog_sdk import AsyncVeriLogLangGraphCallback, Signer, VeriLogClient, VeriLogLangGraphCallback

from .conftest import TEST_SEED_HEX, check_chains, unused_target

PUB = Signer.from_hex(TEST_SEED_HEX).public_key


@tool
def lookup_weather(city: str) -> str:
    """Look up the weather for a city."""
    return f"sunny in {city}"


def build_chain():
    llm = FakeListLLM(responses=["Paris"])
    prompt = PromptTemplate.from_template("Which city? {question}")
    return prompt | llm | RunnableLambda(lambda city: lookup_weather.invoke({"city": city.strip()}))


def _events(daemon):
    return [(e.event_type, e.step_number, json.loads(e.payload_json)) for e in daemon.events]


def test_records_real_langchain_run(fake_daemon):
    handler = VeriLogLangGraphCallback("agent-lc", target=fake_daemon.target, insecure=True)
    out = build_chain().invoke({"question": "where?"}, config={"callbacks": [handler]})
    assert out == "sunny in Paris"
    assert handler.flush(timeout=10)
    handler.close()

    events = _events(fake_daemon)
    types = [t for t, _, _ in events]
    for required in ("chain_start", "llm_start", "llm_end", "tool_start", "tool_end", "chain_end"):
        assert required in types, (required, types)

    # One root run: steps are 1..n in order, every event shares the root id,
    # and the run is a valid signed hash chain closed by run_end.
    steps = [s for _, s, _ in events]
    assert steps == list(range(1, len(events) + 1))
    runs = check_chains(fake_daemon.events, PUB)
    assert len(runs) == 1
    roots = {p["root_run_id"] for t, _, p in events if t != "run_end"}
    assert roots == set(runs)
    assert all(e.agent_id == "agent-lc" for e in fake_daemon.events)
    assert events[-1][0] == "run_end" and events[-1][2] == {"status": "ok", "steps": len(events) - 1}
    events = events[:-1]

    tool_start = next(p for t, _, p in events if t == "tool_start")
    assert tool_start["name"] == "lookup_weather"
    tool_end = next(p for t, _, p in events if t == "tool_end")
    assert "sunny in Paris" in json.dumps(tool_end["output"])
    llm_start = next(p for t, _, p in events if t == "llm_start")
    assert llm_start["prompts"] == ["Which city? where?"]
    assert events[-1][0] == "chain_end" and events[-1][2]["run_id"] == events[0][2]["run_id"]


def test_step_numbers_restart_per_root_run(fake_daemon):
    handler = VeriLogLangGraphCallback("agent-lc", target=fake_daemon.target, insecure=True)
    chain = build_chain()
    chain.invoke({"question": "a"}, config={"callbacks": [handler]})
    first_run = len(fake_daemon.events) if handler.flush(10) else None
    chain.invoke({"question": "b"}, config={"callbacks": [handler]})
    assert handler.flush(timeout=10)
    handler.close()
    events = _events(fake_daemon)
    assert first_run and events[first_run][1] == 1
    assert events[first_run][2]["root_run_id"] != events[0][2]["root_run_id"]
    assert fake_daemon.events[first_run].run_id != fake_daemon.events[0].run_id
    assert [e.event_type for e in fake_daemon.events].count("run_end") == 2
    check_chains(fake_daemon.events, PUB)


def test_errors_are_recorded(fake_daemon):
    handler = VeriLogLangGraphCallback("agent-lc", target=fake_daemon.target, insecure=True)

    def boom(_):
        raise RuntimeError("tool exploded")

    try:
        RunnableLambda(boom).invoke(1, config={"callbacks": [handler]})
    except RuntimeError:
        pass
    assert handler.flush(timeout=10)
    handler.close()
    err = next(p for t, _, p in _events(fake_daemon) if t == "chain_error")
    assert err["error"] == {"type": "RuntimeError", "message": "tool exploded"}
    assert _events(fake_daemon)[-1][0::2] == ("run_end", {"status": "error", "steps": 2})


def test_handler_is_cheap_with_daemon_down():
    handler = VeriLogLangGraphCallback("agent-x", target=unused_target(), insecure=True, queue_size=50)
    run_id = uuid.uuid4()
    start = time.perf_counter()
    for i in range(2_000):
        handler.on_tool_start({"name": "t"}, f"input {i}", run_id=uuid.uuid4(), parent_run_id=run_id)
        handler.on_tool_end("out", run_id=uuid.uuid4(), parent_run_id=run_id)
    elapsed = time.perf_counter() - start
    handler.close(timeout=0.1)
    assert elapsed < 1.0, elapsed  # ~4k callbacks, no network on the caller's thread


def test_shared_client_and_bad_inputs_never_raise(fake_daemon):
    client = VeriLogClient(fake_daemon.target, insecure=True)
    handler = VeriLogLangGraphCallback("agent-y", client=client)
    # Odd, non-JSON inputs are converted, not raised.
    handler.on_chain_start({"id": ["x", "MyChain"]}, {"obj": object(), "nan": float("nan"), "b": b"xx"},
                           run_id=uuid.uuid4())
    assert handler.close(timeout=10)  # does not close a client it does not own
    assert client.submit("agent-y", "other-run", "t", {}) is True
    client.close()
    payload = json.loads(fake_daemon.events[0].payload_json)
    assert payload["name"] == "MyChain" and payload["inputs"]["nan"] == "nan"
    assert payload["inputs"]["b"] == {"bytes_len": 2}


def test_async_handler_with_ainvoke(fake_daemon):
    handler = AsyncVeriLogLangGraphCallback("agent-async", target=fake_daemon.target, insecure=True)

    async def main():
        return await build_chain().ainvoke({"question": "q"}, config={"callbacks": [handler]})

    assert asyncio.run(main()) == "sunny in Paris"
    assert handler.flush(timeout=10)
    handler.close()
    types = [t for t, _, _ in _events(fake_daemon)]
    assert {"chain_start", "llm_start", "llm_end", "tool_start", "tool_end", "chain_end"} <= set(types)


def test_sync_handler_with_ainvoke(fake_daemon):
    handler = VeriLogLangGraphCallback("agent-mixed", target=fake_daemon.target, insecure=True)

    async def main():
        return await build_chain().ainvoke({"question": "q"}, config={"callbacks": [handler]})

    asyncio.run(main())
    assert handler.flush(timeout=10)
    handler.close()
    steps = [s for _, s, _ in _events(fake_daemon)]
    assert sorted(steps) == list(range(1, len(steps) + 1))
    check_chains(fake_daemon.events, PUB)


def test_close_ends_open_runs(fake_daemon):
    handler = VeriLogLangGraphCallback("agent-open", target=fake_daemon.target, insecure=True)
    root = uuid.uuid4()
    handler.on_chain_start({"name": "outer"}, {"x": 1}, run_id=root)
    handler.on_tool_start({"name": "t"}, "in", run_id=uuid.uuid4(), parent_run_id=root)
    assert handler.close(timeout=10)  # the agent never finished the run
    events = _events(fake_daemon)
    assert [t for t, _, _ in events] == ["chain_start", "tool_start", "run_end"]
    assert events[-1][2] == {"status": "closed", "steps": 2}
    check_chains(fake_daemon.events, PUB)
