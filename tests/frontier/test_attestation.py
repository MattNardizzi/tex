"""
Thread 6 tests — Hardware attestation EAT JWT (gap 2).

Covers:
  * EAT JWT parsing (header, payload, claims).
  * ``synthesize_test_eat_jwt`` + ``verify_attestation_assertion`` roundtrip.
  * user_data binding (claim_cbor_sha256 mismatch flagged).
  * Expiry detection.
  * Signature verification when trust anchors are provided.
  * Profile-specific behaviour for NRAS, Intel Trust Authority, Veraison.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tex.c2pa import (
    ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
    TEX_EVIDENCE_ATTESTATION_SCHEMA_V1,
    AttestationVerificationResult,
    AttestationVerifier,
    EatTokenKind,
    build_tex_evidence_attestation_assertion,
    parse_eat_jwt,
    synthesize_test_eat_jwt,
    verify_attestation_assertion,
)
from tex.c2pa.attestation import (
    EAT_PROFILE_INTEL_TRUST_AUTHORITY,
    EAT_PROFILE_NVIDIA_NRAS_V3,
    EAT_PROFILE_VERAISON_EAR,
    ISSUE_ATTESTATION_EXPIRED,
    ISSUE_ATTESTATION_MISSING,
    ISSUE_ATTESTATION_TOKEN_MALFORMED,
    ISSUE_ATTESTATION_USER_DATA_MISMATCH,
    ISSUE_ATTESTATION_VALIDATED,
    ISSUE_ATTESTATION_VERIFIER_UNKNOWN,
)


# ---------------------------------------------------------------------------
# Fixtures — synthesized issuer keys for each verifier
# ---------------------------------------------------------------------------


@pytest.fixture
def es256_keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"priv_pem": priv_pem, "pub_pem": pub_pem}


@pytest.fixture
def es384_keypair():
    key = ec.generate_private_key(ec.SECP384R1())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"priv_pem": priv_pem, "pub_pem": pub_pem}


@pytest.fixture
def claim_hash() -> str:
    return "c" * 64


# ---------------------------------------------------------------------------
# EAT JWT parsing
# ---------------------------------------------------------------------------


class TestParseEatJwt:
    def test_parse_well_formed_jwt(self, es256_keypair, claim_hash):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="nras-key-1",
        )
        parsed = parse_eat_jwt(token)
        assert parsed.header["alg"] == "ES256"
        assert parsed.header["kid"] == "nras-key-1"
        assert parsed.payload["iss"] == "nvidia-nras"
        assert parsed.user_data == claim_hash
        assert parsed.expires_at is not None
        assert parsed.expires_at > parsed.issued_at

    def test_parse_rejects_non_three_part(self):
        with pytest.raises(ValueError, match="three"):
            parse_eat_jwt("a.b")
        with pytest.raises(ValueError, match="three"):
            parse_eat_jwt("a.b.c.d")

    def test_parse_rejects_bad_base64(self):
        with pytest.raises(ValueError):
            parse_eat_jwt("@@@.@@@.@@@")


# ---------------------------------------------------------------------------
# Attestation assertion builder + verifier round-trip
# ---------------------------------------------------------------------------


class TestAttestationRoundtripNRAS:
    def test_full_roundtrip_with_signature_check(
        self, es384_keypair, claim_hash
    ):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es384_keypair["priv_pem"],
            kid="nras-jwk-1",
            algorithm="ES384",
            extra_claims={
                "cc_mode_enabled": True,
                "overall_result": "SUCCESS",
                "gpu_evidence_list": [{"device_id": "GPU-0"}],
            },
        )
        assertion = build_tex_evidence_attestation_assertion(
            eat_token=token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            claim_cbor_sha256=claim_hash,
            platform_measurement_sha256="d" * 64,
        )
        assert assertion["$schema"] == TEX_EVIDENCE_ATTESTATION_SCHEMA_V1
        assert assertion["attestation_verifier"] == "nvidia-nras"
        assert assertion["profile"] == EAT_PROFILE_NVIDIA_NRAS_V3
        assert assertion["algorithm"] == "ES384"

        result = verify_attestation_assertion(
            assertion,
            expected_claim_cbor_sha256=claim_hash,
            trusted_issuer_public_keys={"nras-jwk-1": es384_keypair["pub_pem"]},
        )
        assert isinstance(result, AttestationVerificationResult)
        assert result.is_valid, result.issues
        assert result.user_data_bound is True
        assert result.signature_checked is True
        assert ISSUE_ATTESTATION_VALIDATED in result.issues
        assert result.fully_bound


class TestAttestationRoundtripIntelTrustAuthority:
    def test_composite_tdx_gpu_token(self, es384_keypair, claim_hash):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.INTEL_TRUST_AUTHORITY,
            signing_key_pem=es384_keypair["priv_pem"],
            kid="ita-jwk-1",
            algorithm="ES384",
            extra_claims={
                "intel_tdx": {"mrtd": "abc", "mrsigner": "def"},
                "nvidia_gpu": [{"device_id": "GPU-0"}],
            },
        )
        assertion = build_tex_evidence_attestation_assertion(
            eat_token=token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.INTEL_TRUST_AUTHORITY,
            claim_cbor_sha256=claim_hash,
        )
        assert assertion["profile"] == EAT_PROFILE_INTEL_TRUST_AUTHORITY
        result = verify_attestation_assertion(
            assertion,
            expected_claim_cbor_sha256=claim_hash,
            trusted_issuer_public_keys={"ita-jwk-1": es384_keypair["pub_pem"]},
        )
        assert result.is_valid


class TestAttestationRoundtripVeraison:
    def test_veraison_ear_profile(self, es256_keypair, claim_hash):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.VERAISON,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="veraison-jwk-1",
        )
        assertion = build_tex_evidence_attestation_assertion(
            eat_token=token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.VERAISON,
            claim_cbor_sha256=claim_hash,
        )
        assert assertion["profile"] == EAT_PROFILE_VERAISON_EAR
        result = verify_attestation_assertion(
            assertion,
            expected_claim_cbor_sha256=claim_hash,
            trusted_issuer_public_keys={"veraison-jwk-1": es256_keypair["pub_pem"]},
        )
        assert result.is_valid


# ---------------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------------


class TestAttestationNegativePaths:
    def test_missing_assertion(self, claim_hash):
        result = verify_attestation_assertion(
            None, expected_claim_cbor_sha256=claim_hash
        )
        assert result.is_valid is False
        assert ISSUE_ATTESTATION_MISSING in result.issues

    def test_user_data_mismatch(self, es256_keypair, claim_hash):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256="aaaa" * 16,  # token bound to a DIFFERENT claim
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="nras-jwk-2",
        )
        assertion = build_tex_evidence_attestation_assertion(
            eat_token=token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            claim_cbor_sha256="aaaa" * 16,  # builder accepts any 64-hex
        )
        # But the verifier expects the *current* claim hash.
        result = verify_attestation_assertion(
            assertion, expected_claim_cbor_sha256=claim_hash
        )
        assert result.is_valid is False
        assert ISSUE_ATTESTATION_USER_DATA_MISMATCH in result.issues

    def test_expired_token(self, es256_keypair, claim_hash):
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="nras-jwk-3",
            issued_at=past,
            valid_for_seconds=60,  # expired in 2020
        )
        assertion = build_tex_evidence_attestation_assertion(
            eat_token=token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            claim_cbor_sha256=claim_hash,
        )
        result = verify_attestation_assertion(
            assertion, expected_claim_cbor_sha256=claim_hash
        )
        assert ISSUE_ATTESTATION_EXPIRED in result.issues

    def test_malformed_token_rejected(self, claim_hash):
        # Three dots but the parts aren't valid base64-encoded JSON.
        assertion = {
            "$schema": TEX_EVIDENCE_ATTESTATION_SCHEMA_V1,
            "profile": EAT_PROFILE_VERAISON_EAR,
            "eat_token": "not.a.valid_jwt",
            "eat_token_kind": "jwt",
            "attestation_verifier": "veraison",
            "claim_cbor_sha256": claim_hash,
        }
        result = verify_attestation_assertion(
            assertion, expected_claim_cbor_sha256=claim_hash
        )
        assert ISSUE_ATTESTATION_TOKEN_MALFORMED in result.issues

    def test_unknown_verifier_flagged(self, es256_keypair, claim_hash):
        # Construct a syntactically-valid assertion with an unknown verifier.
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256=claim_hash,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="k",
        )
        assertion = {
            "$schema": TEX_EVIDENCE_ATTESTATION_SCHEMA_V1,
            "profile": "made-up-profile",
            "eat_token": token,
            "eat_token_kind": "jwt",
            "attestation_verifier": "made-up-verifier",
            "claim_cbor_sha256": claim_hash,
        }
        result = verify_attestation_assertion(
            assertion, expected_claim_cbor_sha256=claim_hash
        )
        assert ISSUE_ATTESTATION_VERIFIER_UNKNOWN in result.issues


# ---------------------------------------------------------------------------
# Builder input validation
# ---------------------------------------------------------------------------


class TestAttestationBuilderValidation:
    def test_short_claim_hash_rejected(self, es256_keypair):
        token = synthesize_test_eat_jwt(
            claim_cbor_sha256="c" * 64,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=es256_keypair["priv_pem"],
            kid="k",
        )
        with pytest.raises(ValueError, match="64-character"):
            build_tex_evidence_attestation_assertion(
                eat_token=token,
                eat_token_kind=EatTokenKind.JWT,
                verifier=AttestationVerifier.NVIDIA_NRAS,
                claim_cbor_sha256="xyz",
            )

    def test_empty_token_rejected(self):
        with pytest.raises(ValueError, match="eat_token"):
            build_tex_evidence_attestation_assertion(
                eat_token="",
                eat_token_kind=EatTokenKind.JWT,
                verifier=AttestationVerifier.NVIDIA_NRAS,
                claim_cbor_sha256="c" * 64,
            )
