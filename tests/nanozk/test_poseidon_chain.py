"""Tests for tex.nanozk.poseidon_chain — Poseidon-BN254 set root."""

from __future__ import annotations

import pytest

from tex.nanozk.poseidon_chain import (
    BN254_FIELD_BYTES,
    BN254_PRIME,
    HashChainKind,
    layer_set_root,
    poseidon_available,
    poseidon_chain_root,
    poseidon_hash,
    poseidon_hash_hex,
)


class TestConstants:
    def test_bn254_prime_is_expected(self) -> None:
        # The standard BN254 scalar field prime.
        assert (
            BN254_PRIME
            == 21888242871839275222246405745257275088548364400416034343698204186575808495617
        )

    def test_field_bytes_is_32(self) -> None:
        assert BN254_FIELD_BYTES == 32


class TestPoseidonAvailability:
    def test_poseidon_available_returns_bool(self) -> None:
        # ``poseidon-hash`` is an optional extra (`pip install tex[zk]`)
        # because upstream 0.1.4 has a stale `pytest~=7.1.2` pin that
        # blocks a clean install otherwise. When the library is absent,
        # ``tex.nanozk.poseidon_chain`` falls back to SHA-256-reduced
        # hashing. Both branches must return a usable ``bool``.
        result = poseidon_available()
        assert isinstance(result, bool)


@pytest.mark.skipif(
    not poseidon_available(),
    reason="poseidon library not installed",
)
class TestPoseidonHash:
    def test_hash_deterministic(self) -> None:
        a = poseidon_hash([1, 2, 3])
        b = poseidon_hash([1, 2, 3])
        assert a == b

    def test_hash_changes_with_input(self) -> None:
        a = poseidon_hash([1, 2, 3])
        b = poseidon_hash([1, 2, 4])
        assert a != b

    def test_hash_reduces_modulo_prime(self) -> None:
        # Input > prime: result equals hash of (input mod prime).
        a = poseidon_hash([BN254_PRIME + 5])
        b = poseidon_hash([5])
        assert a == b

    def test_hash_hex_pads_to_64_chars(self) -> None:
        out = poseidon_hash_hex([1, 2, 3])
        assert len(out) == 64
        int(out, 16)

    def test_hash_hex_accepts_bytes(self) -> None:
        a = poseidon_hash_hex([b"\x01" * 32])
        b = poseidon_hash_hex([b"\x01" * 32])
        assert a == b

    def test_hash_hex_accepts_mixed_input(self) -> None:
        out = poseidon_hash_hex(["aa" * 32, 5, b"\x01" * 32])
        assert len(out) == 64


@pytest.mark.skipif(
    not poseidon_available(),
    reason="poseidon library not installed",
)
class TestPoseidonChainRoot:
    def test_root_is_deterministic(self) -> None:
        leaves = [b"\x01" * 32, b"\x02" * 32, b"\x03" * 32]
        r1 = poseidon_chain_root(leaves)
        r2 = poseidon_chain_root(leaves)
        assert r1 == r2

    def test_root_changes_with_leaf(self) -> None:
        a = poseidon_chain_root([b"\x01" * 32, b"\x02" * 32])
        b = poseidon_chain_root([b"\x01" * 32, b"\x03" * 32])
        assert a != b

    def test_root_changes_with_order(self) -> None:
        a = poseidon_chain_root([b"\x01" * 32, b"\x02" * 32])
        b = poseidon_chain_root([b"\x02" * 32, b"\x01" * 32])
        assert a != b

    def test_empty_leaves_raises(self) -> None:
        with pytest.raises(ValueError):
            poseidon_chain_root([])

    def test_single_leaf(self) -> None:
        # H(leaf) — should produce a 64-char hex string.
        r = poseidon_chain_root([b"\x01" * 32])
        assert len(r) == 64


class TestHashChainKindEnum:
    def test_values(self) -> None:
        assert HashChainKind.SHA256_LEGACY.value == "sha256-legacy"
        assert HashChainKind.POSEIDON_BN254.value == "poseidon-bn254"


class TestLayerSetRoot:
    def test_default_returns_sha256_legacy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEX_NANOZK_POSEIDON_ROOT", raising=False)
        monkeypatch.delenv("TEX_FRONTIER_NANOZK", raising=False)
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(leaves)
        assert kind == HashChainKind.SHA256_LEGACY
        assert len(root) == 64

    @pytest.mark.skipif(
        not poseidon_available(),
        reason="poseidon library not installed",
    )
    def test_force_poseidon(self) -> None:
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(
            leaves, force_kind=HashChainKind.POSEIDON_BN254
        )
        assert kind == HashChainKind.POSEIDON_BN254
        assert len(root) == 64

    def test_force_sha256(self) -> None:
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(
            leaves, force_kind=HashChainKind.SHA256_LEGACY
        )
        assert kind == HashChainKind.SHA256_LEGACY
        assert len(root) == 64

    @pytest.mark.skipif(
        not poseidon_available(),
        reason="poseidon library not installed",
    )
    def test_env_flag_activates_poseidon(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_NANOZK_POSEIDON_ROOT", "1")
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(leaves)
        assert kind == HashChainKind.POSEIDON_BN254

    def test_frontier_flag_implies_poseidon(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if not poseidon_available():
            pytest.skip("poseidon library not installed")
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        monkeypatch.delenv("TEX_NANOZK_POSEIDON_ROOT", raising=False)
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(leaves)
        assert kind == HashChainKind.POSEIDON_BN254

    def test_explicit_disable_overrides_frontier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        monkeypatch.setenv("TEX_NANOZK_POSEIDON_ROOT", "0_explicit")
        leaves = [b"\x01" * 32, b"\x02" * 32]
        root, kind = layer_set_root(leaves)
        assert kind == HashChainKind.SHA256_LEGACY

    def test_sha256_path_root_changes_with_input(self) -> None:
        a, _ = layer_set_root(
            [b"\x01" * 32], force_kind=HashChainKind.SHA256_LEGACY
        )
        b, _ = layer_set_root(
            [b"\x02" * 32], force_kind=HashChainKind.SHA256_LEGACY
        )
        assert a != b

    def test_accepts_hex_strings_and_bytes(self) -> None:
        a, _ = layer_set_root(
            [b"\x01" * 32], force_kind=HashChainKind.SHA256_LEGACY
        )
        b, _ = layer_set_root(
            ["01" * 32], force_kind=HashChainKind.SHA256_LEGACY
        )
        assert a == b
