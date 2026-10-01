"""E2E driver: runs a small LangChain pipeline with the VeriLog callback.

It uses langchain-core's FakeListLLM (no API key needed) and a real tool, so
the callbacks fired are exactly the ones a production chain fires. The agent
signs with the key in VERILOG_SIGNING_KEY_FILE.

With --capture FILE the events go to an in-process stand-in for a
compromised daemon instead, which writes the signed canonical events to FILE
(JSON lines) without anchoring them.
"""

import argparse
import json
import sys
import threading
from concurrent import futures

import grpc

from langchain_core.language_models.fake import FakeListLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool

from verilog_sdk import VeriLogLangGraphCallback
from verilog_sdk._proto import verilog_pb2, verilog_pb2_grpc
from verilog_sdk.canonical import event_text


class CaptureDaemon(verilog_pb2_grpc.VeriLogServicer):
    def __init__(self):
        self.lines = []
        self.lock = threading.Lock()

    def IngestStream(self, request_iterator, context):
        for ev in request_iterator:
            text = event_text(
                agent_id=ev.agent_id, run_id=ev.run_id, step_number=ev.step_number, prev_hash=ev.prev_hash,
                event_type=ev.event_type, payload_text=ev.payload_json,
                timestamp_ns=ev.timestamp_utc.ToNanoseconds(), key_id=ev.key_id, sig=ev.signature,
            )
            with self.lock:
                self.lines.append({"run_id": ev.run_id, "step_number": ev.step_number,
                                   "event_type": ev.event_type, "canonical_event": text})
            yield verilog_pb2.Ack(sequence=ev.sequence, accepted=True)


@tool
def lookup_weather(city: str) -> str:
    """Look up the weather for a city."""
    return f"sunny and 21C in {city}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target")
    ap.add_argument("--capture", help="write signed events to this file instead of sending them to a daemon")
    ap.add_argument("--agent-id", required=True)
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()

    cities = ["Paris", "Tokyo", "Lima", "Oslo", "Cairo"]
    llm = FakeListLLM(responses=cities)
    chain = (
        PromptTemplate.from_template("Which city should I check? {question}")
        | llm
        | RunnableLambda(lambda city: lookup_weather.invoke({"city": city.strip()}))
    )
    server = capture = None
    target = args.target
    if args.capture:
        capture = CaptureDaemon()
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        verilog_pb2_grpc.add_VeriLogServicer_to_server(capture, server)
        target = f"127.0.0.1:{server.add_insecure_port('127.0.0.1:0')}"
        server.start()
    elif not target:
        ap.error("--target or --capture is required")
    handler = VeriLogLangGraphCallback(args.agent_id, target=target)
    for i in range(args.runs):
        out = chain.invoke({"question": f"trip #{i}"}, config={"callbacks": [handler]})
        print(f"run {i}: {out}", file=sys.stderr)
    ok = handler.close(timeout=30)
    stats = handler.client.stats()
    print(f"acked={stats.acked} rejected={stats.rejected} dropped={stats.dropped}", file=sys.stderr)
    if capture is not None:
        server.stop(grace=None)
        with open(args.capture, "w") as f:
            for line in capture.lines:
                f.write(json.dumps(line) + "\n")
    if not ok or stats.rejected or stats.dropped:
        return 1
    print(stats.acked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
