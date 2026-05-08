"""Tests for tex.events._canonical (RFC 8785 subset)."""

from __future__ import annotations

import pytest

from tex.events._canonical import (
    canonical_json,
    canonical_sha256,
    sha256_hex,
)


def test_canonical_json_sorts_keys() -> None:
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b == '{"a":2,"b":1}'


def test_canonical_json_strips_whitespace() -> None:
    out = canonical_json({"k": [1, 2, 3]})
    assert " " not in out


def test_canonical_json_nested_determinism() -> None:
    obj1 = {"a": {"y": 1, "x": 2}, "b": [3, 1, 2]}
    obj2 = {"b": [3, 1, 2], "a": {"x": 2, "y": 1}}
    assert canonical_json(obj1) == canonical_json(obj2)


def test_canonical_json_preserves_list_order() -> None:
    """Lists are ordered data structures — order must be preserved."""
    assert canonical_json([3, 1, 2]) == "[3,1,2]"
    assert canonical_json([1, 2, 3]) != canonical_json([3, 2, 1])


def test_canonical_json_unicode_kept_raw() -> None:
    out = canonical_json({"k": "café"})
    assert "café" in out  # ensure_ascii=False


def test_canonical_json_rejects_floats() -> None:
    with pytest.raises(TypeError, match="floats"):
        canonical_json({"x": 1.5})


def test_canonical_json_rejects_floats_in_list() -> None:
    with pytest.raises(TypeError, match="floats"):
        canonical_json([1, 2.0, 3])


def test_canonical_json_rejects_non_string_keys() -> None:
    with pytest.raises(TypeError, match="string keys"):
        canonical_json({1: "value"})


def test_canonical_json_rejects_unsupported_type() -> None:
    class Foo:
        pass

    with pytest.raises(TypeError, match="cannot serialize"):
        canonical_json({"k": Foo()})


def test_canonical_json_accepts_bool_int_str_none() -> None:
    out = canonical_json({"a": True, "b": 1, "c": "x", "d": None, "e": False})
    assert out == '{"a":true,"b":1,"c":"x","d":null,"e":false}'


def test_canonical_sha256_matches_manual() -> None:
    out = canonical_sha256({"a": 1})
    expected = sha256_hex('{"a":1}')
    assert out == expected


def test_canonical_sha256_is_deterministic() -> None:
    assert canonical_sha256({"a": 1, "b": 2}) == canonical_sha256({"b": 2, "a": 1})


def test_sha256_hex_known_vector() -> None:
    # Known: sha256("abc") = ba7816bf...
    assert sha256_hex("abc").startswith("ba7816bf8f01cfea")
