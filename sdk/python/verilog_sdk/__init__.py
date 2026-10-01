"""VeriLog Python SDK: capture agent execution traces and stream them to verilogd."""

from .canonical import canonical_event, canonical_json, content_digest
from .client import ClientStats, OverflowPolicy, VeriLogClient

__all__ = [
    "VeriLogClient",
    "OverflowPolicy",
    "ClientStats",
    "canonical_json",
    "canonical_event",
    "content_digest",
    "VeriLogLangGraphCallback",
    "AsyncVeriLogLangGraphCallback",
]

__version__ = "0.1.0"


def __getattr__(name: str):
    # The callback handlers need langchain-core; import them lazily so the
    # client works without it.
    if name in ("VeriLogLangGraphCallback", "AsyncVeriLogLangGraphCallback"):
        from . import callback

        return getattr(callback, name)
    raise AttributeError(name)
