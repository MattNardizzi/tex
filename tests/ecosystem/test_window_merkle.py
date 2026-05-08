"""
Tests for tex.ecosystem._window — RFC 9162 §2.1 Merkle helpers.

We pin the empty-tree root, exercise the leaf-hash domain separator, and
verify the recursive split-on-largest-power-of-two produces the same root
across every input ordering except input order itself (the function is
order-sensitive by design — callers sort first).
"""

from __future__ import annotations

import hashlib

import pytest

from tex.ecosystem._window import empty_root, leaf_hash, merkle_root


# Helpers --------------------------------------------------------------------


def _hex_sha256(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


def _record_hash(seed: int) -> str:
    """Deterministic record hash from an int seed."""
    return hashlib.sha256(f"event-{seed}".encode()).hexdigest()


# Empty tree -----------------------------------------------------------------


def test_empty_root_pinned() -> None:
    """The empty Merkle tree root is SHA-256("") per RFC 9162 §2.1."""
    assert empty_root() == hashlib.sha256(b"").hexdigest()
    # Concrete pinned hex so a test failure surfaces the algo change.
    assert empty_root() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_merkle_root_empty_returns_empty_root() -> None:
    assert merkle_root([]) == empty_root()


# Leaf hash ------------------------------------------------------------------


def test_leaf_hash_uses_0x00_prefix() -> None:
    """RFC 9162: leaf_hash(d) = SHA-256(0x00 || d)."""
    record_hex = "11" * 32  # 64 hex chars
    expected = hashlib.sha256(b"\x00" + bytes.fromhex(record_hex)).hexdigest()
    assert leaf_hash(record_hex) == expected


def test_leaf_hash_rejects_short_hex() -> None:
    with pytest.raises(ValueError, match="64 hex chars"):
        leaf_hash("ab")


def test_leaf_hash_rejects_non_hex() -> None:
    with pytest.raises(ValueError, match="not valid hex"):
        leaf_hash("z" * 64)


def test_leaf_hash_rejects_non_string() -> None:
    with pytest.raises(TypeError, match="must be str"):
        leaf_hash(b"a" * 64)  # type: ignore[arg-type]


# Single-leaf tree -----------------------------------------------------------


def test_merkle_root_single_leaf_equals_its_leaf_hash() -> None:
    rec = _record_hash(1)
    assert merkle_root([rec]) == leaf_hash(rec)


# Two-leaf tree --------------------------------------------------------------


def test_merkle_root_two_leaves_uses_0x01_inner_prefix() -> None:
    """For n=2: MTH = H(0x01 || leaf_hash(d_0) || leaf_hash(d_1))."""
    a, b = _record_hash(1), _record_hash(2)
    left = bytes.fromhex(leaf_hash(a))
    right = bytes.fromhex(leaf_hash(b))
    expected = _hex_sha256(b"\x01", left, right)
    assert merkle_root([a, b]) == expected


# Three-leaf tree (the asymmetric case RFC 9162 specifies) -------------------


def test_merkle_root_three_leaves_splits_at_largest_power_of_two() -> None:
    """
    For n=3, k = 2 (largest power of two strictly less than 3).
    MTH(d0,d1,d2) = H(0x01 || MTH(d0,d1) || MTH(d2))
                  = H(0x01 || H(0x01 || L(d0) || L(d1)) || L(d2))
    """
    a, b, c = _record_hash(1), _record_hash(2), _record_hash(3)
    left_subtree = _hex_sha256(
        b"\x01", bytes.fromhex(leaf_hash(a)), bytes.fromhex(leaf_hash(b))
    )
    right_leaf = leaf_hash(c)
    expected = _hex_sha256(
        b"\x01", bytes.fromhex(left_subtree), bytes.fromhex(right_leaf)
    )
    assert merkle_root([a, b, c]) == expected


# Order sensitivity ----------------------------------------------------------


def test_merkle_root_is_order_sensitive() -> None:
    """Callers must sort before passing in; root differs across permutations."""
    a, b = _record_hash(1), _record_hash(2)
    assert merkle_root([a, b]) != merkle_root([b, a])


# Determinism + scale --------------------------------------------------------


def test_merkle_root_is_deterministic_across_calls() -> None:
    records = [_record_hash(i) for i in range(17)]  # odd, non-power-of-two
    first = merkle_root(records)
    second = merkle_root(records)
    assert first == second


def test_merkle_root_changes_when_any_leaf_changes() -> None:
    base = [_record_hash(i) for i in range(8)]
    mutated = list(base)
    mutated[3] = _record_hash(999)
    assert merkle_root(base) != merkle_root(mutated)


def test_merkle_root_handles_large_input() -> None:
    """Sanity: 1024 leaves, no recursion limit issues."""
    records = [_record_hash(i) for i in range(1024)]
    root = merkle_root(records)
    assert len(root) == 64  # SHA-256 hex
