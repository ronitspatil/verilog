"""E2E driver: runs a small LangChain pipeline with the VeriLog callback.

It uses langchain-core's FakeListLLM (no API key needed) and a real tool, so
the callbacks fired are exactly the ones a production chain fires.
"""

import argparse
import sys

from langchain_core.language_models.fake import FakeListLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool

from verilog_sdk import VeriLogLangGraphCallback


@tool
def lookup_weather(city: str) -> str:
    """Look up the weather for a city."""
    return f"sunny and 21C in {city}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
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
    handler = VeriLogLangGraphCallback(args.agent_id, target=args.target)
    for i in range(args.runs):
        out = chain.invoke({"question": f"trip #{i}"}, config={"callbacks": [handler]})
        print(f"run {i}: {out}", file=sys.stderr)
    ok = handler.close(timeout=30)
    stats = handler.client.stats()
    print(f"acked={stats.acked} rejected={stats.rejected} dropped={stats.dropped}", file=sys.stderr)
    if not ok or stats.rejected or stats.dropped:
        return 1
    print(stats.acked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
