import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LogEvent(_message.Message):
    __slots__ = ("agent_id", "step_number", "event_type", "payload_json", "timestamp_utc", "run_id", "prev_hash", "key_id", "signature", "sequence")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_NUMBER_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_JSON_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_UTC_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PREV_HASH_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    step_number: int
    event_type: str
    payload_json: str
    timestamp_utc: _timestamp_pb2.Timestamp
    run_id: str
    prev_hash: bytes
    key_id: bytes
    signature: bytes
    sequence: int
    def __init__(self, agent_id: _Optional[str] = ..., step_number: _Optional[int] = ..., event_type: _Optional[str] = ..., payload_json: _Optional[str] = ..., timestamp_utc: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., run_id: _Optional[str] = ..., prev_hash: _Optional[bytes] = ..., key_id: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., sequence: _Optional[int] = ...) -> None: ...

class Ack(_message.Message):
    __slots__ = ("sequence", "accepted", "error", "content_digest", "leaf", "duplicate")
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    CONTENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    LEAF_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    sequence: int
    accepted: bool
    error: str
    content_digest: bytes
    leaf: bytes
    duplicate: bool
    def __init__(self, sequence: _Optional[int] = ..., accepted: _Optional[bool] = ..., error: _Optional[str] = ..., content_digest: _Optional[bytes] = ..., leaf: _Optional[bytes] = ..., duplicate: _Optional[bool] = ...) -> None: ...

class GetProofRequest(_message.Message):
    __slots__ = ("agent_id", "epoch_id", "leaf_index", "content_digest")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    EPOCH_ID_FIELD_NUMBER: _ClassVar[int]
    LEAF_INDEX_FIELD_NUMBER: _ClassVar[int]
    CONTENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    epoch_id: int
    leaf_index: int
    content_digest: bytes
    def __init__(self, agent_id: _Optional[str] = ..., epoch_id: _Optional[int] = ..., leaf_index: _Optional[int] = ..., content_digest: _Optional[bytes] = ...) -> None: ...

class GetProofResponse(_message.Message):
    __slots__ = ("agent_id", "agent_key", "epoch_id", "merkle_root", "leaf_index", "leaf", "content_digest", "proof", "canonical_event_json", "tx_hash", "block_number")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_KEY_FIELD_NUMBER: _ClassVar[int]
    EPOCH_ID_FIELD_NUMBER: _ClassVar[int]
    MERKLE_ROOT_FIELD_NUMBER: _ClassVar[int]
    LEAF_INDEX_FIELD_NUMBER: _ClassVar[int]
    LEAF_FIELD_NUMBER: _ClassVar[int]
    CONTENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    PROOF_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_EVENT_JSON_FIELD_NUMBER: _ClassVar[int]
    TX_HASH_FIELD_NUMBER: _ClassVar[int]
    BLOCK_NUMBER_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    agent_key: bytes
    epoch_id: int
    merkle_root: bytes
    leaf_index: int
    leaf: bytes
    content_digest: bytes
    proof: _containers.RepeatedScalarFieldContainer[bytes]
    canonical_event_json: str
    tx_hash: str
    block_number: int
    def __init__(self, agent_id: _Optional[str] = ..., agent_key: _Optional[bytes] = ..., epoch_id: _Optional[int] = ..., merkle_root: _Optional[bytes] = ..., leaf_index: _Optional[int] = ..., leaf: _Optional[bytes] = ..., content_digest: _Optional[bytes] = ..., proof: _Optional[_Iterable[bytes]] = ..., canonical_event_json: _Optional[str] = ..., tx_hash: _Optional[str] = ..., block_number: _Optional[int] = ...) -> None: ...
