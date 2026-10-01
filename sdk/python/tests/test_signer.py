import os
import stat

import pytest

from verilog_sdk.__main__ import main
from verilog_sdk._keccak import keccak256
from verilog_sdk.signer import Signer

from .conftest import TEST_SEED_HEX


def test_keccak256_known_values():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # `cast keccak agent-alpha`
    assert keccak256(b"agent-alpha").hex() == "765069f0d82dd70961ef67543724ecc2bc8bbdc4d1183662c723dc57f80e3720"
    # Multi-block input (longer than the 136-byte rate).
    assert keccak256(b"a" * 200).hex() == "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"


def test_signer_rfc8032_vector():
    s = Signer.from_hex(TEST_SEED_HEX)
    assert s.public_key.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert s.sign(b"").hex().startswith("e5564300c360ac72")  # RFC 8032 test 1
    assert s.key_id == keccak256(s.public_key)
    assert TEST_SEED_HEX[2:] not in repr(s)


def test_from_env_prefers_file(tmp_path):
    other = Signer.generate()
    path = tmp_path / "k"
    path.write_text(other.seed_hex())
    os.chmod(path, 0o600)
    env = {"VERILOG_SIGNING_KEY_FILE": str(path), "VERILOG_SIGNING_KEY": TEST_SEED_HEX}
    assert Signer.from_env(env.get).key_id == other.key_id
    assert Signer.from_env({"VERILOG_SIGNING_KEY": TEST_SEED_HEX}.get).key_id == Signer.from_hex(TEST_SEED_HEX).key_id
    with pytest.raises(ValueError, match="no signing key"):
        Signer.from_env({}.get)


def test_bad_key_error_does_not_echo_the_key():
    secret = "zz" + "ab" * 31
    with pytest.raises(ValueError) as exc:
        Signer.from_hex(secret)
    assert secret not in str(exc.value)


def test_keygen_writes_private_file(tmp_path, capsys):
    out = tmp_path / "agent.key"
    assert main(["keygen", "--out", str(out), "--agent-id", "support-bot"]) == 0
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    signer = Signer.from_file(str(out))
    printed = capsys.readouterr().out
    assert "0x" + signer.public_key.hex() in printed
    assert "0x" + signer.key_id.hex() in printed
    assert "0x" + keccak256(b"support-bot").hex() in printed
    assert signer.seed_hex() not in printed
    # Never overwrites by accident.
    assert main(["keygen", "--out", str(out), "--agent-id", "support-bot"]) == 2
    assert Signer.from_file(str(out)).key_id == signer.key_id


def test_proof_of_possession_matches_go_vectors():
    import json
    from .conftest import TESTDATA

    data = json.loads((TESTDATA / "signed_vectors.json").read_text())
    signer = Signer.from_hex(data["seed"])
    assert "0x" + signer.proof_of_possession(data["run"][0]["agent_id"]).hex() == data["pop"]


def test_keygen_prints_proof_of_possession(tmp_path, capsys):
    from verilog_sdk.__main__ import main

    assert main(["keygen", "--out", str(tmp_path / "k"), "--agent-id", "bot-1"]) == 0
    out = capsys.readouterr().out
    signer = Signer.from_file(str(tmp_path / "k"))
    assert f"pop:      0x{signer.proof_of_possession('bot-1').hex()}" in out
    assert "verilog-verify keycheck --agent-id bot-1" in out
