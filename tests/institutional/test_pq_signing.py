"""Unit tests for ``tex.institutional._pq_signing``."""

from __future__ import annotations

import pytest

from tex.institutional._pq_signing import (
    _try_provider,
    select_institutional_signing_provider,
)
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


class TestTryProvider:
    """Direct probes against each algorithm."""

    def test_ecdsa_p256_always_works(self):
        """ECDSA-P256 is backed by `cryptography` (hard dep) — must succeed."""
        provider, reason = _try_provider(SignatureAlgorithm.ECDSA_P256)
        assert provider is not None
        assert reason == ""

    def test_ed25519_works(self):
        """Ed25519 is also a hard dep via cryptography."""
        provider, reason = _try_provider(SignatureAlgorithm.ED25519)
        # Ed25519 is one path that's outside the chain but we should
        # still be able to probe it.
        assert provider is not None
        assert reason == ""

    def test_ml_dsa_65_when_no_backend_available_fails_cleanly(self):
        """Without ANY ML-DSA backend (no pyca native, no liboqs), the
        probe must fail with a diagnostic — not crash. With either
        backend present the probe succeeds."""
        from tex.pqcrypto.ml_dsa import active_backend_id

        if active_backend_id() is not None:
            # At least one backend resolved (pyca/cryptography 48 native
            # or liboqs). Confirm the probe succeeds rather than skipping
            # entirely — this is the path real deployments take.
            provider, reason = _try_provider(SignatureAlgorithm.ML_DSA_65)
            assert provider is not None
            assert reason == ""
            return

        provider, reason = _try_provider(SignatureAlgorithm.ML_DSA_65)
        assert provider is None
        assert "probe_failed" in reason

    def test_slh_dsa_now_wired_and_usable(self):
        """
        Thread 10 (May 18, 2026): SLH-DSA-128S is now a wired provider via
        ``SlhDsaProvider`` + liboqs 0.15. The institutional probe must
        succeed when liboqs is installed.
        """
        try:
            import oqs  # noqa: F401
        except ImportError:
            pytest.skip("liboqs not installed; SLH-DSA probe path not exercised")
        provider, reason = _try_provider(SignatureAlgorithm.SLH_DSA_128S)
        assert provider is not None
        assert reason == ""


class TestSelectInstitutionalSigningProvider:
    """The resolution chain must always return a usable provider."""

    def test_returns_a_usable_provider(self):
        selected = select_institutional_signing_provider()
        assert selected.provider is not None
        assert selected.algorithm in {
            # Thread 8.1 (May 19, 2026) added BLAKE3-ML-DSA-65 as the top
            # of the selection chain. Thread 10 (May 20, 2026) further
            # extended the agility surface but does NOT change this
            # ordering — BLAKE3-ML-DSA-65 remains the preferred picker
            # for the institutional governance log.
            SignatureAlgorithm.BLAKE3_ML_DSA_65,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
            SignatureAlgorithm.ECDSA_P256,
        }

    def test_returned_provider_signs_and_verifies(self):
        """Smoke-test: the selected provider can actually sign and verify."""
        selected = select_institutional_signing_provider()
        keypair = selected.provider.generate_keypair("test-key")
        sig = selected.provider.sign(b"hello", keypair)
        assert selected.provider.verify(b"hello", sig, keypair.public_key)

    def test_falls_back_to_ecdsa_when_no_pq_backend(self):
        """When NO post-quantum backend is available (no pyca/cryptography
        native ML-DSA, no liboqs), ECDSA-P256 is the floor.

        With a backend present (the normal case after the May 2026
        frontier upgrade), the selection picks a PQ algorithm and this
        assertion path is exercised only to confirm the backend is
        actually doing what it claims.
        """
        from tex.pqcrypto.ml_dsa import active_backend_id

        if active_backend_id() is not None:
            # Backend present — the selector picks a PQ algorithm
            # (BLAKE3-ML-DSA-65, ML-DSA-65, or HYBRID); not ECDSA.
            selected = select_institutional_signing_provider()
            assert selected.algorithm in {
                SignatureAlgorithm.BLAKE3_ML_DSA_65,
                SignatureAlgorithm.ML_DSA_65,
                SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
            }
            return

        selected = select_institutional_signing_provider()
        # Truly no PQ backend: floor at ECDSA-P256.
        assert selected.algorithm is SignatureAlgorithm.ECDSA_P256
        assert selected.fallback_reason
        assert "ml-dsa-65" in selected.fallback_reason
        assert "hybrid-ml-dsa-65-ed25519" in selected.fallback_reason
