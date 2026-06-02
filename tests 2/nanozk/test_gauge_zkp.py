"""Tests for tex.nanozk.gauge_zkp — Gauge canonicalisation."""

from __future__ import annotations

import pytest

from tex.nanozk.gauge_zkp import (
    CanonicalisationKind,
    DEFAULT_CANONICALISATION,
    GaugeCanonicalizer,
    PAPER_BASE_GATE_REDUCTION,
    PoVITag,
    build_poge_certificate,
    canonical_model_hash_for,
    compute_gate_reduction_factor,
    poge_certificate_hash,
    verify_poge,
)


class TestCanonicalisationKind:
    def test_default_is_base(self) -> None:
        assert DEFAULT_CANONICALISATION == CanonicalisationKind.GAUGEZKP_BASE

    def test_base_reduction_is_26_percent(self) -> None:
        assert PAPER_BASE_GATE_REDUCTION == 0.26

    def test_distinct_kinds(self) -> None:
        kinds = {
            CanonicalisationKind.NONE,
            CanonicalisationKind.GAUGEZKP_BASE,
            CanonicalisationKind.GAUGEZKP_ROPE,
            CanonicalisationKind.GAUGEZKP_GQA,
            CanonicalisationKind.GAUGEZKP_MOE,
        }
        assert len(kinds) == 5


class TestGaugeCanonicalizer:
    def test_default_construct(self) -> None:
        c = GaugeCanonicalizer()
        assert c.kind == DEFAULT_CANONICALISATION
        assert c.achieved_reduction == PAPER_BASE_GATE_REDUCTION

    def test_fingerprint_is_64_hex(self) -> None:
        c = GaugeCanonicalizer()
        fp = c.fingerprint()
        assert len(fp) == 64
        int(fp, 16)  # valid hex

    def test_fingerprint_changes_with_kind(self) -> None:
        a = GaugeCanonicalizer(kind=CanonicalisationKind.GAUGEZKP_BASE)
        b = GaugeCanonicalizer(kind=CanonicalisationKind.GAUGEZKP_ROPE)
        assert a.fingerprint() != b.fingerprint()

    def test_fingerprint_changes_with_heads(self) -> None:
        a = GaugeCanonicalizer(num_heads=12)
        b = GaugeCanonicalizer(num_heads=16)
        assert a.fingerprint() != b.fingerprint()

    def test_frozen(self) -> None:
        c = GaugeCanonicalizer()
        with pytest.raises(Exception):
            c.kind = CanonicalisationKind.NONE  # type: ignore[misc]


class TestComputeGateReductionFactor:
    def test_none_returns_zero(self) -> None:
        assert (
            compute_gate_reduction_factor(kind=CanonicalisationKind.NONE)
            == 0.0
        )

    def test_base_returns_paper_constant(self) -> None:
        v = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE
        )
        assert v == PAPER_BASE_GATE_REDUCTION

    def test_rope_increases_reduction(self) -> None:
        base = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE
        )
        rope = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE, rope_enabled=True
        )
        assert rope > base

    def test_gqa_increases_reduction(self) -> None:
        base = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE
        )
        gqa = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE, gqa_ratio=8
        )
        assert gqa > base

    def test_moe_increases_reduction(self) -> None:
        base = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE
        )
        moe = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE, moe_sparsity=0.9
        )
        assert moe > base

    def test_capped_at_55_percent(self) -> None:
        v = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE,
            rope_enabled=True,
            gqa_ratio=64,
            moe_sparsity=1.0,
        )
        assert v <= 0.55

    def test_composes_multiplicatively(self) -> None:
        rope_only = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE, rope_enabled=True
        )
        with_gqa = compute_gate_reduction_factor(
            kind=CanonicalisationKind.GAUGEZKP_BASE,
            rope_enabled=True,
            gqa_ratio=4,
        )
        assert with_gqa > rope_only


class TestPoGECertificate:
    def test_build_and_verify(self) -> None:
        cert = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
            kind=CanonicalisationKind.GAUGEZKP_BASE,
        )
        assert verify_poge(cert) is True

    def test_verify_fails_on_tampered_certificate(self) -> None:
        cert = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        bad = cert.model_copy(update={"certificate_bytes": b"\xff" * 32})
        assert verify_poge(bad) is False

    def test_verify_fails_on_tampered_hash(self) -> None:
        cert = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        bad = cert.model_copy(
            update={"canonical_model_hash": "c" * 64}
        )
        assert verify_poge(bad) is False

    def test_certificates_for_different_models_distinct(self) -> None:
        a = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        b = build_poge_certificate(
            original_model_hash="c" * 64,
            canonical_model_hash="d" * 64,
        )
        assert a.certificate_bytes != b.certificate_bytes

    def test_canonical_model_hash_deterministic(self) -> None:
        h1 = canonical_model_hash_for(original_model_hash="a" * 64)
        h2 = canonical_model_hash_for(original_model_hash="a" * 64)
        assert h1 == h2
        assert len(h1) == 64

    def test_canonical_model_hash_differs_by_kind(self) -> None:
        h_base = canonical_model_hash_for(
            original_model_hash="a" * 64,
            kind=CanonicalisationKind.GAUGEZKP_BASE,
        )
        h_rope = canonical_model_hash_for(
            original_model_hash="a" * 64,
            kind=CanonicalisationKind.GAUGEZKP_ROPE,
        )
        assert h_base != h_rope

    def test_poge_certificate_hash_is_64_hex(self) -> None:
        cert = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        h = poge_certificate_hash(cert)
        assert len(h) == 64
        int(h, 16)


class TestPoVITag:
    def test_construct(self) -> None:
        tag = PoVITag(
            canonicalizer_fingerprint="a" * 64,
            poge_certificate_hash="b" * 64,
        )
        assert tag.canonicalizer_fingerprint == "a" * 64

    def test_frozen(self) -> None:
        tag = PoVITag(
            canonicalizer_fingerprint="a" * 64,
            poge_certificate_hash="b" * 64,
        )
        with pytest.raises(Exception):
            tag.canonicalizer_fingerprint = "c" * 64  # type: ignore[misc]


class TestBindingKeyEnvOverride:
    def test_env_override_changes_certificate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEX_GAUGEZKP_BINDING_KEY", raising=False)
        c1 = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        monkeypatch.setenv("TEX_GAUGEZKP_BINDING_KEY", "alt-key")
        c2 = build_poge_certificate(
            original_model_hash="a" * 64,
            canonical_model_hash="b" * 64,
        )
        assert c1.certificate_bytes != c2.certificate_bytes
