"""Canonical JSON (RFC 8785 style), matching the daemon's Go implementation.

The daemon re-canonicalizes every payload and its canonicalization is the
authoritative one; the SDK emits canonical payloads so that what the client
sends is byte-identical to what gets hashed, which keeps payloads compact and
makes client-side digests reproducible.

Rules (see daemon/internal/canonical):
  * object members sorted by the UTF-16 code units of their names;
  * no insignificant whitespace;
  * strings as UTF-8 with only the mandatory escapes;
  * integers emitted exactly (never rounded through a double);
  * floats emitted with the ECMAScript Number.toString algorithm;
  * NaN and Infinity are rejected.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

__all__ = [
    "canonical_json",
    "canonical_event",
    "content_digest",
    "format_es6_float",
    "format_timestamp",
]

_MAX_DEPTH = 128


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def format_es6_float(value: float) -> str:
    """Serialize a float like ECMAScript Number.prototype.toString."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() gives the shortest round-tripping digits; Decimal exposes them.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in digit_tuple)
    k = len(digits)
    n = exponent + k  # decimal point position relative to the digits
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exp = ("+" if e >= 0 else "-") + str(abs(e))
        out = digits + "e" + exp if k == 1 else digits[0] + "." + digits[1:] + "e" + exp
    return sign + out


def _encode(value: Any, out: list[str], depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError(f"nesting deeper than {_MAX_DEPTH}")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(int(value)))
    elif isinstance(value, float):
        out.append(format_es6_float(value))
    elif isinstance(value, str):
        value.encode("utf-8")  # raises on lone surrogates, which are not valid UTF-8
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"object keys must be str, got {type(key).__name__}")
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if i:
                out.append(",")
            _encode(key, out, depth + 1)
            out.append(":")
            _encode(value[key], out, depth + 1)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, out, depth + 1)
        out.append("]")
    else:
        raise TypeError(f"value of type {type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text of a JSON-compatible value."""
    out: list[str] = []
    _encode(value, out, 0)
    return "".join(out)


def format_timestamp(ts_ns: int) -> str:
    """Format a Unix timestamp in nanoseconds the way the daemon hashes it."""
    secs, nanos = divmod(ts_ns, 1_000_000_000)
    base = datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanos:09d}Z"


def canonical_event(
    agent_id: str, step_number: int, event_type: str, payload: Any, timestamp_ns: int
) -> str:
    """Canonical event text, identical to what the daemon hashes."""
    return canonical_json(
        {
            "agent_id": agent_id,
            "event_type": event_type,
            "payload": payload,
            "step_number": step_number,
            "timestamp_utc": format_timestamp(timestamp_ns),
        }
    )


def content_digest(canonical_event_text: str) -> bytes:
    """SHA-256 of canonical event bytes (the daemon's content digest)."""
    return hashlib.sha256(canonical_event_text.encode("utf-8")).digest()
