import hashlib
import json
import pathlib

import pytest

from verilog_sdk._keccak import keccak256
from verilog_sdk.canonical import (
    SIGNING_DOMAIN,
    canonical_event,
    canonical_json,
    content_digest,
    format_es6_float,
    format_timestamp,
    signing_bytes,
)
from verilog_sdk.signer import Signer

TESTDATA = pathlib.Path(__file__).resolve().parents[3] / "testdata"


def _load(name):
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def _ns(ts: str) -> int:
    # "2026-09-30T12:00:00.123456789Z" -> unix nanoseconds
    from datetime import datetime, timezone

    base, frac = ts.rstrip("Z").split(".")
    secs = int(datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return secs * 1_000_000_000 + int(frac)


def _vector_cases():
    out = []
    for name, key in (("canonical_vectors.json", "cases"), ("signed_vectors.json", "run")):
        data = _load(name)
        for case in data[key]:
            out.append(pytest.param(data["seed"], case, id=f"{name}:{case['name']}"))
    return out


@pytest.mark.parametrize("seed,case", _vector_cases())
def test_matches_go_signed_vectors(seed, case):
    """Byte-exact parity with the Go canonicalization and Ed25519 signatures."""
    signer = Signer.from_hex(seed)
    assert "0x" + signer.key_id.hex() == case["key_id"]
    payload = json.loads(case["payload_json"])
    assert canonical_json(payload) == case["canonical_payload"]
    prev = bytes.fromhex(case["prev_hash"][2:])
    args = (case["agent_id"], case["run_id"], case["step_number"], prev, case["event_type"], payload,
            _ns(case["timestamp_utc"]), signer.key_id)
    msg = signing_bytes(*args)
    assert msg == case["signing_bytes"].encode("utf-8")
    sig = signer.sign(msg)
    assert "0x" + sig.hex() == case["sig"]
    text = canonical_event(*args, sig)
    assert text == case["canonical_event"]
    assert "0x" + content_digest(text).hex() == case["content_digest"]
    assert "0x" + keccak256(content_digest(text)).hex() == case["leaf"]
    assert "0x" + keccak256(case["agent_id"].encode()).hex() == case["agent_key"]


def test_signed_vectors_form_a_chain():
    data = _load("signed_vectors.json")
    assert data["signing_domain"].encode() == SIGNING_DOMAIN
    signer = Signer.from_hex(data["seed"])
    assert "0x" + signer.public_key.hex() == data["public_key"]
    assert "0x" + signer.key_id.hex() == data["key_id"]
    prev = "0x" + "00" * 32
    for i, case in enumerate(data["run"]):
        assert case["step_number"] == i + 1
        assert case["prev_hash"] == prev
        prev = "0x" + hashlib.sha256(case["canonical_event"].encode()).hexdigest()
    assert data["run"][-1]["event_type"] == "run_end"


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
