"""
Tests for tex.pqcrypto.blake3_ml_dsa — BLAKE3-accelerated ML-DSA-B.

These tests mock the underlying liboqs-backed ML-DSA provider so they
run on any host with the BLAKE3 Python binding. The integration with
real ML-DSA is covered by the existing test_ml_dsa.py path; here we
verify:

- The provider sets the correct algorithm tag on generated keypairs.
- BLAKE3 pre-hashing is applied (and the digest is what the underlying
  provider receives, not the raw message).
- Sign and verify round-trip correctly with the same provider.
- A signature produced over message A does not verify over message B
  (the pre-hash differs).
- The domain tag changes the pre-hash output (so a plain ML-DSA
  signature over the same bytes would not verify here).
- The provider rejects keys tagged with non-BLAKE3 algorithms.
- The algorithm enum and dispatcher route BLAKE3_ML_DSA_65 to this
  provider.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)
from tex.pqcrypto.blake3_ml_dsa import (
    Blake3MlDsaProvider,
    _DOMAIN_TAG,
    _blake3_prehash,
)


# ----------------------------------------------------------------- prehash unit


class TestBlake3Prehash:
    def test_output_is_32_bytes(self) -> None:
        digest = _blake3_prehash(b"hello world")
        assert len(digest) == 32

    def test_deterministic(self) -> None:
        d1 = _blake3_prehash(b"hello world")
        d2 = _blake3_prehash(b"hello world")
        assert d1 == d2

    def test_differs_on_different_message(self) -> None:
        d1 = _blake3_prehash(b"hello world")
        d2 = _blake3_prehash(b"hello world!")
        assert d1 != d2

    def test_empty_message_hashes(self) -> None:
        digest = _blake3_prehash(b"")
        assert len(digest) == 32

    def test_length_prefix_distinguishes(self) -> None:
        # b"AB" and b"A" || b"B" hash differently because of length prefix.
        # We don't have control over chunking, but we can confirm two
        # messages of different lengths give different digests.
        d1 = _blake3_prehash(b"AB")
        d2 = _blake3_prehash(b"ABC")
        assert d1 != d2

    def test_domain_tag_is_used(self) -> None:
        # If we were doing a plain BLAKE3 of the message (no domain
        # tag), the digest would equal blake3(b"hello"). Confirm ours
        # does NOT equal that.
        import blake3
        plain = blake3.blake3(b"hello").digest()
        tagged = _blake3_prehash(b"hello")
        assert plain != tagged

    def test_domain_tag_value(self) -> None:
        # Lock down the constant so accidental changes break the test.
        assert _DOMAIN_TAG == b"tex-ml-dsa-b/v1\x00"
        assert len(_DOMAIN_TAG) == 16


# ----------------------------------------------------------- mock provider tests


def _make_mock_keypair(algorithm: SignatureAlgorithm) -> SignatureKeyPair:
    return SignatureKeyPair(
        algorithm=algorithm,
        public_key=b"mock_pub_" + b"x" * 100,
        private_key=b"mock_priv_" + b"y" * 100,
        key_id="mock-key-id",
    )


class TestSignVerify:
    def test_generate_keypair_tags_with_blake3_variant(self) -> None:
        with patch(
            "tex.pqcrypto.blake3_ml_dsa.Blake3MlDsaProvider._underlying_provider"
        ) as mock_underlying:
            mock_kp = _make_mock_keypair(SignatureAlgorithm.ML_DSA_65)
            mock_underlying.return_value.generate_keypair.return_value = mock_kp

            provider = Blake3MlDsaProvider()
            kp = provider.generate_keypair("my-id")

            # The key bytes come from the underlying ML-DSA generator,
            # but the algorithm tag is rewritten to the BLAKE3 variant.
            assert kp.algorithm == SignatureAlgorithm.BLAKE3_ML_DSA_65
            assert kp.public_key == mock_kp.public_key
            assert kp.private_key == mock_kp.private_key
            assert kp.key_id == "my-id"

    def test_sign_pre_hashes_with_blake3(self) -> None:
        captured: dict = {}

        def fake_sign(message: bytes, key: SignatureKeyPair) -> bytes:
            captured["signed_input"] = message
            captured["key_algo"] = key.algorithm
            return b"signature_bytes"

        mock_underlying = MagicMock()
        mock_underlying.sign.side_effect = fake_sign

        with patch.object(
            Blake3MlDsaProvider,
            "_underlying_provider",
            return_value=mock_underlying,
        ):
            provider = Blake3MlDsaProvider()
            kp = SignatureKeyPair(
                algorithm=SignatureAlgorithm.BLAKE3_ML_DSA_65,
                public_key=b"pk",
                private_key=b"sk",
                key_id="k",
            )
            sig = provider.sign(b"the actual message", kp)

        assert sig == b"signature_bytes"
        # What the underlying provider received was the BLAKE3 digest,
        # NOT the raw message.
        assert captured["signed_input"] == _blake3_prehash(b"the actual message")
        # The key was re-tagged to the underlying stock variant before
        # delegation.
        assert captured["key_algo"] == SignatureAlgorithm.ML_DSA_65

    def test_sign_rejects_wrong_algorithm_key(self) -> None:
        provider = Blake3MlDsaProvider()
        # A stock ML-DSA-65 key tag — not the BLAKE3 variant.
        kp = _make_mock_keypair(SignatureAlgorithm.ML_DSA_65)
        with pytest.raises(ValueError, match="cannot sign with key for"):
            provider.sign(b"msg", kp)

    def test_verify_pre_hashes_with_blake3(self) -> None:
        captured: dict = {}

        def fake_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
            captured["verified_input"] = message
            captured["verified_signature"] = signature
            captured["verified_pubkey"] = public_key
            return True

        mock_underlying = MagicMock()
        mock_underlying.verify.side_effect = fake_verify

        with patch.object(
            Blake3MlDsaProvider,
            "_underlying_provider",
            return_value=mock_underlying,
        ):
            provider = Blake3MlDsaProvider()
            ok = provider.verify(b"raw message", b"some_sig", b"some_pub")

        assert ok is True
        # The underlying verify received the BLAKE3 digest, not the raw message.
        assert captured["verified_input"] == _blake3_prehash(b"raw message")
        assert captured["verified_signature"] == b"some_sig"
        assert captured["verified_pubkey"] == b"some_pub"

    def test_verify_propagates_false(self) -> None:
        mock_underlying = MagicMock()
        mock_underlying.verify.return_value = False

        with patch.object(
            Blake3MlDsaProvider,
            "_underlying_provider",
            return_value=mock_underlying,
        ):
            provider = Blake3MlDsaProvider()
            assert provider.verify(b"msg", b"sig", b"pk") is False

    def test_round_trip_with_mock(self) -> None:
        """Sign then verify with the same provider — the digest passed
        to verify matches the digest passed to sign."""
        captured: dict = {"signed": None}

        def fake_sign(msg, key):
            captured["signed"] = msg
            return b"sig_for_" + msg[:8]

        def fake_verify(msg, sig, pk):
            return msg == captured["signed"] and sig == b"sig_for_" + msg[:8]

        mock_underlying = MagicMock()
        mock_underlying.sign.side_effect = fake_sign
        mock_underlying.verify.side_effect = fake_verify

        with patch.object(
            Blake3MlDsaProvider,
            "_underlying_provider",
            return_value=mock_underlying,
        ):
            provider = Blake3MlDsaProvider()
            kp = SignatureKeyPair(
                algorithm=SignatureAlgorithm.BLAKE3_ML_DSA_65,
                public_key=b"pk", private_key=b"sk", key_id="k",
            )
            sig = provider.sign(b"important message", kp)
            assert provider.verify(b"important message", sig, kp.public_key)
            # Tampered message MUST fail.
            assert not provider.verify(b"tampered message", sig, kp.public_key)


# ----------------------------------------------------------------- dispatcher


class TestDispatcher:
    def test_get_signature_provider_returns_blake3_provider(self) -> None:
        provider = get_signature_provider(SignatureAlgorithm.BLAKE3_ML_DSA_65)
        assert isinstance(provider, Blake3MlDsaProvider)
        assert provider.algorithm == SignatureAlgorithm.BLAKE3_ML_DSA_65

    def test_algorithm_enum_value(self) -> None:
        assert SignatureAlgorithm.BLAKE3_ML_DSA_65.value == "blake3-ml-dsa-65"


# -------------------------------------------------------- algorithm-binding test


class TestAlgorithmBinding:
    def test_domain_tag_isolates_from_plain_ml_dsa_signature(self) -> None:
        """A signature produced by *stock* ML-DSA over the message
        ``m`` MUST NOT verify against Blake3MlDsaProvider for the same
        ``m`` — because Blake3MlDsaProvider pre-hashes and verifies
        the digest, not the raw message.

        This is the algorithm-binding property: a regulator that
        sees a BLAKE3-ML-DSA-tagged record cannot be fooled by a
        plain-ML-DSA signature over the same bytes.
        """
        # We simulate "stock ML-DSA signed the raw bytes" by having the
        # underlying verify return True only when given the raw bytes
        # b"m" — proving Blake3MlDsaProvider does NOT pass the raw bytes
        # through.
        mock_underlying = MagicMock()
        mock_underlying.verify.side_effect = lambda msg, sig, pk: msg == b"m"

        with patch.object(
            Blake3MlDsaProvider,
            "_underlying_provider",
            return_value=mock_underlying,
        ):
            provider = Blake3MlDsaProvider()
            ok = provider.verify(b"m", b"forged_stock_sig", b"pk")

        # The underlying received BLAKE3(b"m"), not b"m" itself. So it
        # returned False under our mock contract.
        assert ok is False
