"""
RFC 8785 (JSON Canonicalization Scheme) helpers for ledger record hashing.

Pure-stdlib implementation. Restricts the value space to the subset that
``json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)``
canonicalizes deterministically: ``str | int | bool | None | dict | list``.

Floats are explicitly rejected. RFC 8785 mandates I-JSON number serialization
which stdlib ``json.dumps`` does not implement; current event payloads in
scope are dict/str/int/bool only. If a downstream package (drift, systemic)
needs float payloads, harden JCS here.

Reference
---------
- RFC 8785 (JSON Canonicalization Scheme)
- Mirrors the stable-JSON pattern in tex.evidence.chain._stable_json.

TODO(P1): full RFC 8785 number serialization (I-JSON) when float payloads land.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """
    Canonicalize a JSON-compatible value to a deterministic UTF-8 string.

    Rejects floats (see module docstring). All keys must be strings. All
    list/tuple elements must themselves be canonicalizable.

    Raises
    ------
    TypeError
        If the value contains a float, a non-string mapping key, or a
        non-JSON-compatible leaf (e.g. datetime, set, custom object).
    """
    _assert_canonicalizable(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(value: str) -> str:
    """SHA-256 hex digest of the UTF-8 encoding of ``value``."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_sha256(value: Any) -> str:
    """Convenience: SHA-256 hex of the canonical JSON of ``value``."""
    return sha256_hex(canonical_json(value))


# --- internals ---


def _assert_canonicalizable(value: Any) -> None:
    """Walk the value and reject anything outside the supported JCS subset."""
    if value is None or isinstance(value, (str, bool)):
        return
    # bool is a subclass of int; check bool first (above) so this allows ints
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise TypeError(
            "canonical_json does not support floats (RFC 8785 number "
            "serialization not yet implemented; see TODO P1 in _canonical.py)"
        )
    if isinstance(value, dict):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"canonical_json requires string keys; got {type(key).__name__}"
                )
            _assert_canonicalizable(sub)
        return
    if isinstance(value, (list, tuple)):
        for sub in value:
            _assert_canonicalizable(sub)
        return
    raise TypeError(
        f"canonical_json cannot serialize {type(value).__name__}"
    )
