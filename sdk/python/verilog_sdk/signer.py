"""Per-agent Ed25519 signing keys.

Every event is signed inside the agent process, so a compromised daemon host
cannot forge, alter, drop or reorder events without detection. The private
key must therefore live with the agent and never on the daemon host.

The key is a 32-byte Ed25519 seed, stored hex-encoded. It is loaded from the
file named by ``VERILOG_SIGNING_KEY_FILE`` (preferred) or from the hex value
in ``VERILOG_SIGNING_KEY`` (which logs a warning). A key file readable by
group or others is refused unless ``insecure_key_file_perms=True`` or
``VERILOG_INSECURE_KEY_FILE_PERMS=1`` (development only). Its public key is registered on chain by the key
admin (``VeriLogRegistry.registerAgentKey``) under the agent's id; events
carry ``key_id = keccak256(public_key)``.
"""

from __future__ import annotations

import logging
import os
import stat
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from ._keccak import keccak256

__all__ = ["Signer", "ENV_KEY_FILE", "ENV_KEY", "ENV_INSECURE_PERMS", "POP_DOMAIN", "keccak256", "write_key_file"]

#: Prefix of the proof-of-possession message (see Signer.proof_of_possession).
POP_DOMAIN = b"VeriLog/pop/v1\n"

ENV_KEY_FILE = "VERILOG_SIGNING_KEY_FILE"
ENV_KEY = "VERILOG_SIGNING_KEY"
#: Development escape hatch: accept a key file readable by group or others.
ENV_INSECURE_PERMS = "VERILOG_INSECURE_KEY_FILE_PERMS"

log = logging.getLogger("verilog_sdk")


def _parse_seed(text: str) -> bytes:
    raw = text.strip()
    if raw[:2] in ("0x", "0X"):
        raw = raw[2:]
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        seed = b""
    if len(seed) != 32:
        # Never echo the input: it is key material.
        raise ValueError("signing key must be a 32-byte Ed25519 seed in hex (64 hex characters)")
    return seed


class Signer:
    """An agent's Ed25519 signing key."""

    __slots__ = ("_key", "public_key", "key_id")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        #: Raw 32-byte public key (what the key admin registers on chain).
        self.public_key: bytes = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        #: keccak256(public_key): the key id carried by every event.
        self.key_id: bytes = keccak256(self.public_key)

    def __repr__(self) -> str:  # never print key material
        return f"Signer(key_id=0x{self.key_id.hex()})"

    def sign(self, message: bytes) -> bytes:
        """Ed25519 signature (64 bytes, deterministic)."""
        return self._key.sign(message)

    def proof_of_possession(self, agent_id: str) -> bytes:
        """Signature over ``POP_DOMAIN || keccak256(agent_id) || public_key``.

        The key admin checks it (``verilog-verify keycheck``) before
        registering the key: it shows the requester holds the private key and
        meant it for this agent, and keycheck also refuses unsafe keys.
        """
        return self.sign(POP_DOMAIN + keccak256(agent_id.encode("utf-8")) + self.public_key)

    @classmethod
    def generate(cls) -> "Signer":
        return cls(os.urandom(32))

    @classmethod
    def from_hex(cls, text: str) -> "Signer":
        return cls(_parse_seed(text))

    @classmethod
    def from_file(cls, path: str, *, insecure_key_file_perms: bool = False) -> "Signer":
        """Load the key file. A file readable by group or others raises
        PermissionError unless ``insecure_key_file_perms`` (development only)."""
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO) and os.name != "nt":
            if not insecure_key_file_perms:
                raise PermissionError(
                    f"signing key file {path} has mode {mode:#o} and is readable by group or others; "
                    f"run chmod 600 on it (or set {ENV_INSECURE_PERMS}=1 for development only)"
                )
            log.warning("verilog_sdk: signing key file %s has mode %#o (readable by group or others); "
                        "accepted because insecure key file permissions were allowed", path, mode)
        with open(path, "r", encoding="ascii") as f:
            return cls(_parse_seed(f.read()))

    @classmethod
    def from_env(cls, getenv: Callable[[str], Optional[str]] = os.environ.get) -> "Signer":
        """Load from VERILOG_SIGNING_KEY_FILE, else VERILOG_SIGNING_KEY."""
        path = getenv(ENV_KEY_FILE)
        if path:
            insecure = (getenv(ENV_INSECURE_PERMS) or "").strip().lower() in ("1", "true", "yes")
            return cls.from_file(path, insecure_key_file_perms=insecure)
        value = getenv(ENV_KEY)
        if value:
            log.warning("verilog_sdk: signing key read from the %s environment variable; prefer %s (mode 0600)",
                        ENV_KEY, ENV_KEY_FILE)
            return cls.from_hex(value)
        raise ValueError(f"no signing key: set {ENV_KEY_FILE} (preferred) or {ENV_KEY}, or pass signer=")

    def seed_hex(self) -> str:
        """Hex-encoded seed, for writing a key file. Handle with care."""
        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def write_key_file(signer: Signer, path: str, *, overwrite: bool = False) -> None:
    """Write the seed (hex) to ``path`` with mode 0600."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (signer.seed_hex() + "\n").encode("ascii"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
