"""Canonical JSON (RFC 8785 style) and canonical event v2, matching the
daemon's Go implementation byte for byte.

The agent signs ``SIGNING_DOMAIN + canonical(event without "sig")``; the
daemon rebuilds the same bytes from the fields it receives and rejects the
event if the signature does not verify, so any drift between the two
canonicalizations shows up as a rejected event, never as a silent mismatch.

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
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

__all__ = [
    "SIGNING_DOMAIN",
    "ZERO_HASH",
    "canonical_json",
    "canonical_event",
    "signing_bytes",
    "content_digest",
    "format_es6_float",
    "format_timestamp",
]

#: Prefix of every signed message (domain separation for the agent key).
SIGNING_DOMAIN = b"VeriLog/event/v1\n"

#: prev_hash of the first event of a run.
ZERO_HASH = bytes(32)

_MAX_DEPTH = 128

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


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
    # Not datetime.fromtimestamp: it fails on some platforms for far-future
    # values the daemon accepts (up to year 9999).
    base = (_EPOCH + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanos:09d}Z"


def _hex32(value: bytes, name: str) -> str:
    if len(value) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return "0x" + value.hex()


def event_text(
    *,
    agent_id: str,
    run_id: str,
    step_number: int,
    prev_hash: bytes,
    event_type: str,
    payload_text: str,
    timestamp_ns: int,
    key_id: bytes,
    sig: bytes | None,
) -> str:
    """Canonical event JSON from an already canonical payload text.

    With ``sig=None`` the "sig" member is left out (the signed body). Members
    are emitted in their sorted order: agent_id, event_type, key_id, payload,
    prev_hash, run_id, sig, step_number, timestamp_utc.
    """
    if not agent_id or not run_id or not event_type:
        raise ValueError("agent_id, run_id and event_type are required")
    if step_number < 0:
        raise ValueError("step_number must be non-negative")
    parts = [
        '{"agent_id":', canonical_json(agent_id),
        ',"event_type":', canonical_json(event_type),
        ',"key_id":"', _hex32(key_id, "key_id"), '"',
        ',"payload":', payload_text,
        ',"prev_hash":"', _hex32(prev_hash, "prev_hash"), '"',
        ',"run_id":', canonical_json(run_id),
    ]
    if sig is not None:
        if len(sig) != 64:
            raise ValueError("sig must be 64 bytes")
        parts += [',"sig":"0x', sig.hex(), '"']
    parts += [
        ',"step_number":', str(int(step_number)),
        ',"timestamp_utc":"', format_timestamp(timestamp_ns), '"}',
    ]
    return "".join(parts)


def signing_bytes(
    agent_id: str,
    run_id: str,
    step_number: int,
    prev_hash: bytes,
    event_type: str,
    payload: Any,
    timestamp_ns: int,
    key_id: bytes,
) -> bytes:
    """The bytes the agent signs: SIGNING_DOMAIN || canonical(event without sig)."""
    body = event_text(
        agent_id=agent_id, run_id=run_id, step_number=step_number, prev_hash=prev_hash,
        event_type=event_type, payload_text=canonical_json(payload), timestamp_ns=timestamp_ns,
        key_id=key_id, sig=None,
    )
    return SIGNING_DOMAIN + body.encode("utf-8")


def canonical_event(
    agent_id: str,
    run_id: str,
    step_number: int,
    prev_hash: bytes,
    event_type: str,
    payload: Any,
    timestamp_ns: int,
    key_id: bytes,
    sig: bytes,
) -> str:
    """Canonical signed event text, identical to what the daemon hashes."""
    return event_text(
        agent_id=agent_id, run_id=run_id, step_number=step_number, prev_hash=prev_hash,
        event_type=event_type, payload_text=canonical_json(payload), timestamp_ns=timestamp_ns,
        key_id=key_id, sig=sig,
    )


def content_digest(canonical_event_text: str) -> bytes:
    """SHA-256 of canonical event bytes (the daemon's content digest)."""
    return hashlib.sha256(canonical_event_text.encode("utf-8")).digest()
