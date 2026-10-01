"""VeriLog Python SDK: capture agent execution traces and stream them to verilogd."""

from .canonical import canonical_event, canonical_json, content_digest, signing_bytes
from .client import EVENT_RUN_END, EVENT_SDK_DROPPED, ClientStats, OverflowPolicy, VeriLogClient
from .signer import Signer

__all__ = [
    "VeriLogClient",
    "OverflowPolicy",
    "ClientStats",
    "Signer",
    "EVENT_RUN_END",
    "EVENT_SDK_DROPPED",
    "canonical_json",
    "canonical_event",
    "signing_bytes",
    "content_digest",
    "VeriLogLangGraphCallback",
    "AsyncVeriLogLangGraphCallback",
]

__version__ = "0.2.0"


def __getattr__(name: str):
    # The callback handlers need langchain-core; import them lazily so the
    # client works without it.
    if name in ("VeriLogLangGraphCallback", "AsyncVeriLogLangGraphCallback"):
        from . import callback

        return getattr(callback, name)
    raise AttributeError(name)
