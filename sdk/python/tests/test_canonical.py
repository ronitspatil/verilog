import json
import pathlib

import pytest

from verilog_sdk.canonical import (
    canonical_event,
    canonical_json,
    content_digest,
    format_es6_float,
    format_timestamp,
)

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "canonical_vectors.json"


def _cases():
    return json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


def _ns(ts: str) -> int:
    # "2026-09-30T12:00:00.123456789Z" -> unix nanoseconds
    from datetime import datetime, timezone

    base, frac = ts.rstrip("Z").split(".")
    secs = int(datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return secs * 1_000_000_000 + int(frac)


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_matches_go_vectors(case):
    payload = json.loads(case["payload_json"])
    assert canonical_json(payload) == case["canonical_payload"]
    text = canonical_event(case["agent_id"], case["step_number"], case["event_type"], payload, _ns(case["timestamp_utc"]))
    assert text == case["canonical_event"]
    assert "0x" + content_digest(text).hex() == case["content_digest"]


def test_key_order_and_whitespace():
    assert canonical_json({"b": 1, "a": [1, {"d": None, "c": True}]}) == '{"a":[1,{"c":true,"d":null}],"b":1}'


def test_strings_not_html_escaped():
    assert canonical_json("<a>& ") == '"<a>& "'
    assert canonical_json("\x01\n\"\\/") == '"\\u0001\\n\\"\\\\/"'


def test_big_integers_exact():
    assert canonical_json(123456789012345678901234567890) == "123456789012345678901234567890"


@pytest.mark.parametrize(
    "value,expected",
    [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (0.1, "0.1"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (-1.5e-7, "-1.5e-7"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (333333333.3333333, "333333333.3333333"),
        (9.999999999999997e22, "9.999999999999997e+22"),
    ],
)
def test_es6_floats(value, expected):
    assert format_es6_float(value) == expected


def test_rejects_non_json():
    for bad in (float("nan"), float("inf"), {1: "x"}, object(), "\ud800"):
        with pytest.raises((ValueError, TypeError, UnicodeEncodeError)):
            canonical_json(bad)


def test_timestamp_format():
    assert format_timestamp(1_800_000_000_000_000_001) == "2027-01-15T08:00:00.000000001Z"
