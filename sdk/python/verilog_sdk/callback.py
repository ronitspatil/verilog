"""LangChain / LangGraph callback handlers that ship execution traces to VeriLog.

Every hook snapshots its arguments into JSON-compatible data and hands them to
``VeriLogClient.submit`` (a bounded, in-memory enqueue). Serialization to
canonical JSON and all network I/O happen on the client's background thread,
so the agent is never blocked and SDK failures are logged, never raised.

``step_number`` is monotonic per root run: the first event of a top-level
invocation is step 1, and every nested chain, LLM and tool event of that
invocation continues the same counter. Each payload carries ``run_id``,
``parent_run_id`` and ``root_run_id`` so traces can be reassembled.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

from .client import VeriLogClient

__all__ = ["VeriLogLangGraphCallback", "AsyncVeriLogLangGraphCallback", "to_jsonable"]

log = logging.getLogger("verilog_sdk")

_MAX_DEPTH = 32


def to_jsonable(value: Any, max_str: Optional[int] = None, _depth: int = 0) -> Any:
    """Convert LangChain objects (messages, generations, documents, ...) to JSON data."""
    if _depth > _MAX_DEPTH:
        return "<max depth>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, str):
        return value if max_str is None or len(value) <= max_str else value[:max_str] + "...<truncated>"
    if isinstance(value, (UUID,)):
        return str(value)
    if isinstance(value, bytes):
        return {"bytes_len": len(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v, max_str, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v, max_str, _depth + 1) for v in value]
    if isinstance(value, BaseException):
        return {"type": type(value).__name__, "message": str(value)}
    model_dump = getattr(value, "model_dump", None)  # pydantic v2 (messages, LLMResult, ...)
    if callable(model_dump):
        try:
            return to_jsonable(model_dump(), max_str, _depth + 1)
        except Exception:
            pass
    as_dict = getattr(value, "dict", None)  # pydantic v1
    if callable(as_dict):
        try:
            return to_jsonable(as_dict(), max_str, _depth + 1)
        except Exception:
            pass
    return to_jsonable(repr(value), max_str, _depth + 1)


class _VeriLogCallbackCore:
    """Shared, thread-safe event construction for the sync and async handlers."""

    def _init_core(
        self,
        agent_id: str,
        client: Optional[VeriLogClient],
        target: str,
        max_str_len: Optional[int],
        client_kwargs: Dict[str, Any],
    ) -> None:
        if not agent_id:
            raise ValueError("agent_id is required")
        self.agent_id = agent_id
        self._owns_client = client is None
        self.client = client if client is not None else VeriLogClient(target, **client_kwargs)
        self._max_str = max_str_len
        self._lock = threading.Lock()
        self._root_of: Dict[UUID, UUID] = {}
        self._steps: Dict[UUID, int] = defaultdict(int)

    # -------------------------------------------------------------- helpers

    def _root(self, run_id: UUID, parent_run_id: Optional[UUID], starting: bool) -> UUID:
        if parent_run_id is None:
            root = self._root_of.get(run_id, run_id)
        else:
            root = self._root_of.get(parent_run_id, parent_run_id)
        if starting:
            self._root_of[run_id] = root
        return root

    def _emit(
        self,
        event_type: str,
        run_id: UUID,
        parent_run_id: Optional[UUID],
        fields: Dict[str, Any],
        *,
        starting: bool = False,
        ending: bool = False,
    ) -> None:
        try:
            with self._lock:
                root = self._root(run_id, parent_run_id, starting)
                self._steps[root] += 1
                step = self._steps[root]
                if ending:
                    self._root_of.pop(run_id, None)
                    if run_id == root:
                        self._steps.pop(root, None)
            payload = {
                "run_id": str(run_id),
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
                "root_run_id": str(root),
            }
            for key, value in fields.items():
                if value is not None:
                    payload[key] = to_jsonable(value, self._max_str)
            self.client.submit(self.agent_id, step, event_type, payload)
        except Exception:  # never break the agent
            log.exception("verilog_sdk: failed to record %s", event_type)

    @staticmethod
    def _name(serialized: Optional[Dict[str, Any]], kwargs: Dict[str, Any]) -> Optional[str]:
        if kwargs.get("name"):
            return kwargs["name"]
        if serialized:
            if serialized.get("name"):
                return serialized["name"]
            ident = serialized.get("id")
            if isinstance(ident, list) and ident:
                return str(ident[-1])
        return None

    # ------------------------------------------------------------ lifecycle

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Wait until queued events are acknowledged by the daemon."""
        return self.client.flush(timeout)

    def close(self, timeout: float = 5.0) -> bool:
        """Flush and, if this handler created its client, close it."""
        if self._owns_client:
            return self.client.close(timeout)
        return self.client.flush(timeout)

    # ----------------------------------------------------------- recorders

    def _llm_start(self, serialized, prompts, run_id, parent_run_id, tags, metadata, kwargs):
        self._emit("llm_start", run_id, parent_run_id, {
            "name": self._name(serialized, kwargs), "prompts": prompts,
            "tags": tags, "metadata": metadata,
            "invocation_params": kwargs.get("invocation_params"),
        }, starting=True)

    def _chat_start(self, serialized, messages, run_id, parent_run_id, tags, metadata, kwargs):
        self._emit("llm_start", run_id, parent_run_id, {
            "name": self._name(serialized, kwargs), "messages": messages,
            "tags": tags, "metadata": metadata,
            "invocation_params": kwargs.get("invocation_params"),
        }, starting=True)

    def _llm_end(self, response, run_id, parent_run_id):
        fields: Dict[str, Any] = {"generations": getattr(response, "generations", response)}
        llm_output = getattr(response, "llm_output", None)
        if llm_output:
            fields["llm_output"] = llm_output
        self._emit("llm_end", run_id, parent_run_id, fields, ending=True)

    def _llm_error(self, error, run_id, parent_run_id):
        self._emit("llm_error", run_id, parent_run_id, {"error": error}, ending=True)

    def _tool_start(self, serialized, input_str, run_id, parent_run_id, tags, metadata, inputs, kwargs):
        self._emit("tool_start", run_id, parent_run_id, {
            "name": self._name(serialized, kwargs), "input": input_str, "inputs": inputs,
            "tags": tags, "metadata": metadata,
        }, starting=True)

    def _tool_end(self, output, run_id, parent_run_id):
        self._emit("tool_end", run_id, parent_run_id, {"output": output}, ending=True)

    def _tool_error(self, error, run_id, parent_run_id):
        self._emit("tool_error", run_id, parent_run_id, {"error": error}, ending=True)

    def _chain_start(self, serialized, inputs, run_id, parent_run_id, tags, metadata, kwargs):
        self._emit("chain_start", run_id, parent_run_id, {
            "name": self._name(serialized, kwargs), "inputs": inputs,
            "tags": tags, "metadata": metadata,
        }, starting=True)

    def _chain_end(self, outputs, run_id, parent_run_id):
        self._emit("chain_end", run_id, parent_run_id, {"outputs": outputs}, ending=True)

    def _chain_error(self, error, run_id, parent_run_id):
        self._emit("chain_error", run_id, parent_run_id, {"error": error}, ending=True)


class VeriLogLangGraphCallback(_VeriLogCallbackCore, BaseCallbackHandler):
    """Synchronous LangChain/LangGraph callback handler.

    Usage::

        handler = VeriLogLangGraphCallback(agent_id="support-bot", target="127.0.0.1:50051")
        graph.invoke(inputs, config={"callbacks": [handler]})
        handler.close()

    The handler is also safe to pass to ``ainvoke``: it runs inline (it only
    enqueues), so LangChain does not dispatch it to a thread pool.
    """

    raise_error = False
    run_inline = True

    def __init__(
        self,
        agent_id: str,
        *,
        client: Optional[VeriLogClient] = None,
        target: str = "127.0.0.1:50051",
        max_str_len: Optional[int] = None,
        **client_kwargs: Any,
    ) -> None:
        super().__init__()
        self._init_core(agent_id, client, target, max_str_len, client_kwargs)

    def on_llm_start(self, serialized, prompts, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._llm_start(serialized, prompts, run_id, parent_run_id, tags, metadata, kwargs)

    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._chat_start(serialized, messages, run_id, parent_run_id, tags, metadata, kwargs)

    def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
        self._llm_end(response, run_id, parent_run_id)

    def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._llm_error(error, run_id, parent_run_id)

    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, tags=None, metadata=None, inputs=None, **kwargs):
        self._tool_start(serialized, input_str, run_id, parent_run_id, tags, metadata, inputs, kwargs)

    def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
        self._tool_end(output, run_id, parent_run_id)

    def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._tool_error(error, run_id, parent_run_id)

    def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._chain_start(serialized, inputs, run_id, parent_run_id, tags, metadata, kwargs)

    def on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs):
        self._chain_end(outputs, run_id, parent_run_id)

    def on_chain_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._chain_error(error, run_id, parent_run_id)


class AsyncVeriLogLangGraphCallback(_VeriLogCallbackCore, AsyncCallbackHandler):
    """Async variant for code that requires an ``AsyncCallbackHandler``.

    The coroutines do not await anything: recording is a non-blocking enqueue,
    so the event loop is never blocked on the network.
    """

    raise_error = False
    run_inline = True

    def __init__(
        self,
        agent_id: str,
        *,
        client: Optional[VeriLogClient] = None,
        target: str = "127.0.0.1:50051",
        max_str_len: Optional[int] = None,
        **client_kwargs: Any,
    ) -> None:
        super().__init__()
        self._init_core(agent_id, client, target, max_str_len, client_kwargs)

    async def on_llm_start(self, serialized, prompts, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._llm_start(serialized, prompts, run_id, parent_run_id, tags, metadata, kwargs)

    async def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._chat_start(serialized, messages, run_id, parent_run_id, tags, metadata, kwargs)

    async def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
        self._llm_end(response, run_id, parent_run_id)

    async def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._llm_error(error, run_id, parent_run_id)

    async def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, tags=None, metadata=None, inputs=None, **kwargs):
        self._tool_start(serialized, input_str, run_id, parent_run_id, tags, metadata, inputs, kwargs)

    async def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
        self._tool_end(output, run_id, parent_run_id)

    async def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._tool_error(error, run_id, parent_run_id)

    async def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._chain_start(serialized, inputs, run_id, parent_run_id, tags, metadata, kwargs)

    async def on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs):
        self._chain_end(outputs, run_id, parent_run_id)

    async def on_chain_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._chain_error(error, run_id, parent_run_id)
