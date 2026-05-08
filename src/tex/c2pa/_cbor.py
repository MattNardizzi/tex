"""
Minimal deterministic CBOR encoder/decoder for COSE_Sign1.

Implements the strict subset of RFC 8949 needed by RFC 8152 / RFC 9052
(COSE) and RFC 9360 (COSE x509) — no third-party CBOR dependency.

Supported types
---------------
- unsigned int (major 0)
- negative int (major 1)
- byte string (major 2)
- text string (major 3)
- array       (major 4)
- map         (major 5) — keys are str | int only
- tag         (major 6) — encoder side, used for COSE_Sign1_Tagged (61)
- nil/null    (major 7, simple value 22)

Determinism
-----------
- shortest length form (1/2/4/8 byte length per RFC 8949 §4.2.1)
- map keys serialized in **bytewise lexicographic order of their
  encoded forms** (RFC 8949 §4.2.1 "Core Deterministic Encoding")
- no indefinite-length items emitted
- floats rejected (not needed for COSE protected headers in scope)

Decoder
-------
A tiny walker sufficient for parsing COSE_Sign1_Tagged on the verifier
side. Tolerant: accepts non-deterministic encodings on read since
upstream signers may not implement deterministic CBOR.

Reference
---------
- RFC 8949 (CBOR)
- RFC 8152 / RFC 9052 (COSE)
- RFC 9360 (COSE x509)

TODO(P1): drop this in favor of cbor2 if/when added to requirements.txt.
TODO(P1): support indefinite-length on decode if a real-world signer
          emits them. Current ecosystem (DigiCert, c2patool) emits
          definite-length.
"""

from __future__ import annotations

import struct
from typing import Any


# Major types (RFC 8949 §3).
_MT_UINT = 0
_MT_NEGINT = 1
_MT_BYTES = 2
_MT_TEXT = 3
_MT_ARRAY = 4
_MT_MAP = 5
_MT_TAG = 6
_MT_SIMPLE = 7

# COSE_Sign1_Tagged tag per RFC 8152 §4.2 / RFC 9052.
COSE_SIGN1_TAG: int = 18


def _encode_head(major: int, value: int) -> bytes:
    """Emit the initial byte (and length suffix) for a CBOR item.

    Uses the shortest length form per RFC 8949 §4.2.1.
    """
    if value < 0:
        raise ValueError(f"length/value must be non-negative; got {value}")
    mt = major << 5
    if value < 24:
        return bytes([mt | value])
    if value < 0x100:
        return bytes([mt | 24, value])
    if value < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", value)
    if value < 0x10000000000000000:
        return bytes([mt | 27]) + struct.pack(">Q", value)
    raise ValueError("integer too large for CBOR head")


def _encode_int(value: int) -> bytes:
    if value >= 0:
        return _encode_head(_MT_UINT, value)
    return _encode_head(_MT_NEGINT, -value - 1)


def _encode_bytes(value: bytes) -> bytes:
    return _encode_head(_MT_BYTES, len(value)) + value


def _encode_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _encode_head(_MT_TEXT, len(raw)) + raw


def _encode_array(items: list[Any] | tuple[Any, ...]) -> bytes:
    out = _encode_head(_MT_ARRAY, len(items))
    for item in items:
        out += encode(item)
    return out


def _encode_map(items: dict[Any, Any]) -> bytes:
    """
    Encode a CBOR map with deterministic key ordering.

    Per RFC 8949 §4.2.1, map keys are sorted bytewise on their CBOR
    encodings. Only ``int`` and ``str`` keys are allowed in this
    subset — they are sufficient for COSE protected/unprotected
    header maps and the tex.verdict assertion payloads.
    """
    encoded_pairs: list[tuple[bytes, bytes]] = []
    for k, v in items.items():
        if not isinstance(k, (int, str)):
            raise TypeError(
                f"CBOR map keys must be int or str in this subset; got {type(k).__name__}"
            )
        encoded_pairs.append((encode(k), encode(v)))
    encoded_pairs.sort(key=lambda kv: kv[0])
    body = b"".join(k + v for k, v in encoded_pairs)
    return _encode_head(_MT_MAP, len(encoded_pairs)) + body


def encode_tag(tag: int, payload: Any) -> bytes:
    """Encode a CBOR tag (major type 6) wrapping ``payload``."""
    return _encode_head(_MT_TAG, tag) + encode(payload)


def encode(value: Any) -> bytes:
    """Encode ``value`` to deterministic CBOR bytes."""
    if value is None:
        return bytes([(_MT_SIMPLE << 5) | 22])  # null / nil
    if isinstance(value, bool):
        # bool first because bool is a subclass of int in Python.
        return bytes([(_MT_SIMPLE << 5) | (21 if value else 20)])
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, (bytes, bytearray)):
        return _encode_bytes(bytes(value))
    if isinstance(value, str):
        return _encode_text(value)
    if isinstance(value, (list, tuple)):
        return _encode_array(value)
    if isinstance(value, dict):
        return _encode_map(value)
    raise TypeError(f"unsupported CBOR value type: {type(value).__name__}")


# ---------------- decoder ----------------


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("CBOR truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]


def _read_length(reader: _Reader, info: int) -> int:
    if info < 24:
        return info
    if info == 24:
        return reader.byte()
    if info == 25:
        return struct.unpack(">H", reader.take(2))[0]
    if info == 26:
        return struct.unpack(">I", reader.take(4))[0]
    if info == 27:
        return struct.unpack(">Q", reader.take(8))[0]
    if info == 31:
        raise ValueError("indefinite-length CBOR not supported in this subset")
    raise ValueError(f"reserved CBOR additional info value: {info}")


def _decode(reader: _Reader) -> Any:
    initial = reader.byte()
    major = initial >> 5
    info = initial & 0x1F

    if major == _MT_UINT:
        return _read_length(reader, info)
    if major == _MT_NEGINT:
        return -1 - _read_length(reader, info)
    if major == _MT_BYTES:
        n = _read_length(reader, info)
        return reader.take(n)
    if major == _MT_TEXT:
        n = _read_length(reader, info)
        return reader.take(n).decode("utf-8")
    if major == _MT_ARRAY:
        n = _read_length(reader, info)
        return [_decode(reader) for _ in range(n)]
    if major == _MT_MAP:
        n = _read_length(reader, info)
        out: dict[Any, Any] = {}
        for _ in range(n):
            k = _decode(reader)
            v = _decode(reader)
            out[k] = v
        return out
    if major == _MT_TAG:
        tag = _read_length(reader, info)
        return ("__tag__", tag, _decode(reader))
    if major == _MT_SIMPLE:
        # We only emit / parse: false (20), true (21), null (22).
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info == 23:
            return None  # undefined → treat as None for our purposes
        # Float / other simple values not used in our COSE subset.
        raise ValueError(f"unsupported CBOR simple value: {info}")
    raise ValueError(f"unknown CBOR major type: {major}")


def decode(data: bytes) -> Any:
    """Decode the first CBOR item from ``data``.

    Tag items are returned as ``("__tag__", tag_number, value)`` triples
    so callers can match on COSE_Sign1_Tagged (tag 18) without fighting
    a dedicated tag class. Unused trailing bytes raise ``ValueError``.
    """
    reader = _Reader(data)
    item = _decode(reader)
    if reader.pos != len(data):
        raise ValueError(
            f"trailing bytes after CBOR item: {len(data) - reader.pos} byte(s)"
        )
    return item


def unwrap_tag(value: Any, expected_tag: int) -> Any:
    """If ``value`` is a tagged triple matching ``expected_tag``, return
    its inner value; otherwise return ``value`` unchanged.

    Per RFC 9052, COSE_Sign1 may appear bare (untagged) or wrapped in
    tag 18 (COSE_Sign1_Tagged). C2PA 2.1 §13.2 mandates the tagged
    form for storage in the Claim Signature box.
    """
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and value[0] == "__tag__"
        and value[1] == expected_tag
    ):
        return value[2]
    return value
