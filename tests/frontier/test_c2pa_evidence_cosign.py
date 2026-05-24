"""
Tests for Thread 5 — C2PA Content Credentials → Evidence Emission.

Covers:
- ``build_signed_manifest_with_cosign`` end-to-end roundtrip.
- ``verify_evidence_cosign`` against well-formed and tampered inputs.
- Each of the five attack-defense flags from arxiv 2604.24890.
- Backwards compatibility: vanilla ``verify_manifest`` still passes
  on a cosigned manifest (cosign is an extension assertion, the outer
  signature covers it).

Cryptographic round-trips here use Ed25519 (always available via
``cryptography``) so the suite runs without liboqs. A separate
``test_pqcrypto.py`` covers ML-DSA-65 when ``liboqs`` is present.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tex.c2pa import (
    ALL_ATTACKS,
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    ATTACK_CERT_EXPIRY_BEFORE_RETENTION,
    ATTACK_CROSS_VALIDATOR_CONTRADICTION,
    ATTACK_EXCLUSION_RANGE_TAMPER,
    ATTACK_REVOCATION_SKIPPED,
    ATTACK_TIMESTAMP_SWAP,
    COSIGN_CANONICALIZATION_VERSION,
    C2paAssertion,
    CosignError,
    CosignVerificationResult,
    TEX_EVIDENCE_COSIGN_SCHEMA_V1,
    attach_cosign_assertion,
    build_email_manifest,
    build_signed_manifest_with_cosign,
    build_tex_evidence_cosign_assertion,
    clear_signing_keys,
    cosign_manifest_hash,
    full_file_sha256,
    get_cosign_assertion,
    register_signing_key,
    serialize_manifest_for_storage,
    verify_evidence_cosign,
    verify_manifest,
)
from tex.c2pa.cosign_verifier import (
    ISSUE_COSIGN_CANONICALIZATION_DRIFT,
    ISSUE_COSIGN_FULL_FILE_HASH_MISMATCH,
    ISSUE_COSIGN_MISSING,
    ISSUE_COSIGN_RETENTION_ANCHOR_MISSING,
    ISSUE_COSIGN_SIGNATURE_MISMATCH,
    ISSUE_COSIGN_VALIDATED,
)
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


# ---------------------------------------------------------------------------
# Helpers — minted CA + leaf chain (Ed25519 outer, Ed25519 cosign).
# ---------------------------------------------------------------------------


def _mint_chain_ed25519() -> dict:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Test Root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.signer.thread5")]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_priv_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    leaf_pub_pem = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chain_pem = (
        leaf.public_bytes(serialization.Encoding.PEM).decode()
        + ca.public_bytes(serialization.Encoding.PEM).decode()
    )
    return {
        "leaf_priv_pem": leaf_priv_pem,
        "leaf_pub_pem": leaf_pub_pem,
        "chain_pem": chain_pem,
    }


@pytest.fixture(autouse=True)
def _isolated_keystore():
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


@pytest.fixture
def outer_chain():
    return _mint_chain_ed25519()


@pytest.fixture
def outer_keypair(outer_chain):
    from tex.pqcrypto.algorithm_agility import SignatureKeyPair

    key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=outer_chain["leaf_pub_pem"],
        private_key=outer_chain["leaf_priv_pem"],
        key_id="thread5-outer-key",
    )
    register_signing_key(key)
    return key


@pytest.fixture
def cosign_keypair():
    return Ed25519Provider().generate_keypair("thread5-cosign-key")


@pytest.fixture
def unsigned_email_manifest():
    body_hash = hashlib.sha256(b"hello recruiter").hexdigest()
    return build_email_manifest(
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Re: Tex Aegis pilot",
        body_sha256=body_hash,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        tex_verdict_id="v-thread5-test-001",
    )


@pytest.fixture
def standard_retention_anchor():
    return {
        "record_hash": "a" * 64,
        "jsonl_path": "/var/tex/evidence.jsonl",
        "evidence_id": "ev-thread5-001",
    }


@pytest.fixture
def standard_revocation_proof():
    return {
        "kind": "crl_snapshot_pin",
        "sha256": "b" * 64,
        "issued_at": "2026-05-18T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# build_tex_evidence_cosign_assertion — unit tests
# ---------------------------------------------------------------------------


class TestEvidenceCosignAssertionBuilder:
    def test_builder_produces_schema_versioned_assertion(self, standard_retention_anchor):
        a = build_tex_evidence_cosign_assertion(
            cosign_algorithm="ed25519",
            cosign_signature_b64="c2lnLWJ5dGVz",
            cosign_public_key_b64="cHViLWJ5dGVz",
            cosign_key_id="kid-1",
            bound_timestamp="2026-05-18T00:00:00+00:00",
            full_file_sha256="c" * 64,
            canonicalization_version=COSIGN_CANONICALIZATION_VERSION,
            retention_anchor=standard_retention_anchor,
        )
        assert a.label == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN
        assert a.data["$schema"] == TEX_EVIDENCE_COSIGN_SCHEMA_V1
        assert a.data["algorithm"] == "ed25519"
        assert a.data["bound_timestamp"] == "2026-05-18T00:00:00+00:00"
        # defends_against bibliography must be carried verbatim — auditors
        # rely on the paper reference being present.
        assert a.data["defends_against"]["paper"] == "arxiv:2604.24890"
        assert set(a.data["defends_against"]["attacks"]) == set(ALL_ATTACKS)

    def test_builder_rejects_short_sha(self, standard_retention_anchor):
        with pytest.raises(ValueError, match="64-character"):
            build_tex_evidence_cosign_assertion(
                cosign_algorithm="ed25519",
                cosign_signature_b64="x",
                cosign_public_key_b64="x",
                cosign_key_id="x",
                bound_timestamp="2026-05-18T00:00:00+00:00",
                full_file_sha256="abc",
                canonicalization_version=COSIGN_CANONICALIZATION_VERSION,
                retention_anchor=standard_retention_anchor,
            )

    def test_builder_requires_record_hash_in_retention_anchor(self):
        with pytest.raises(ValueError, match="record_hash"):
            build_tex_evidence_cosign_assertion(
                cosign_algorithm="ed25519",
                cosign_signature_b64="x",
                cosign_public_key_b64="x",
                cosign_key_id="x",
                bound_timestamp="2026-05-18T00:00:00+00:00",
                full_file_sha256="c" * 64,
                canonicalization_version=COSIGN_CANONICALIZATION_VERSION,
                retention_anchor={"jsonl_path": "/var/tex/evidence.jsonl"},
            )


# ---------------------------------------------------------------------------
# attach_cosign_assertion — extension assertion preserves outer claim shape
# ---------------------------------------------------------------------------


class TestAttachCosignAssertion:
    def test_appended_not_prepended(self, unsigned_email_manifest, standard_retention_anchor):
        cosign = build_tex_evidence_cosign_assertion(
            cosign_algorithm="ed25519",
            cosign_signature_b64="c2ln",
            cosign_public_key_b64="cHVi",
            cosign_key_id="k",
            bound_timestamp="2026-05-18T00:00:00+00:00",
            full_file_sha256="c" * 64,
            canonicalization_version=COSIGN_CANONICALIZATION_VERSION,
            retention_anchor=standard_retention_anchor,
        )
        out = attach_cosign_assertion(unsigned_email_manifest, cosign)
        labels = [a.label for a in out.claim.assertions]
        # cosign last → trailing extension assertion
        assert labels[-1] == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN
        # spec-conformant assertions still come first
        assert labels[0] == "c2pa.actions.v2"
        assert labels[1] == "cawg.creative_work"
        assert labels[2] == "tex.verdict"

    def test_rejects_wrong_label(self, unsigned_email_manifest):
        bogus = C2paAssertion(label="some.other.label", data={})
        with pytest.raises(ValueError, match="expected label"):
            attach_cosign_assertion(unsigned_email_manifest, bogus)


# ---------------------------------------------------------------------------
# build_signed_manifest_with_cosign — end-to-end roundtrip
# ---------------------------------------------------------------------------


class TestBuildSignedManifestWithCosign:
    def test_roundtrip_produces_outer_signature_and_cosign(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"Hello recruiter, this is an AI-generated email body."
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        assert signed.signature_b64 is not None
        assert signed.certificate_chain_pem == outer_chain["chain_pem"]
        assert get_cosign_assertion(signed) is not None
        # Cosign carries the full-file hash, not the body-only hash from the
        # cawg.creative_work assertion (those can differ).
        co = get_cosign_assertion(signed)
        assert co["full_file_sha256"] == full_file_sha256(body)

    def test_outer_verifier_passes_on_cosigned_manifest(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"another email body"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        result = verify_manifest(signed)
        assert result.is_valid, result.issues
        # The cosign assertion lives inside the claim, so the outer
        # signature MUST cover it — that's the whole point of the two-pass.

    def test_cosign_verify_roundtrip_all_defenses_satisfied(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"the full email artifact bytes"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        result = verify_evidence_cosign(
            signed,
            expected_full_file_sha256=full_file_sha256(body),
        )
        assert isinstance(result, CosignVerificationResult)
        assert result.is_valid, result.issues
        assert ISSUE_COSIGN_VALIDATED in result.issues
        # All five attack-defenses satisfied because we supplied a real
        # revocation_proof, retention_anchor, full file hash, ISO ts, and
        # the canonicalization version matches.
        assert result.all_attacks_defended is True
        for attack in ALL_ATTACKS:
            assert result.attack_defended(attack), f"defense {attack} not satisfied"


# ---------------------------------------------------------------------------
# Attack #1 — timestamp swap is detected
# ---------------------------------------------------------------------------


class TestAttackTimestampSwap:
    def test_tampering_bound_timestamp_breaks_cosign_signature(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"timestamp swap victim"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        # Attacker swaps bound_timestamp in the cosign assertion. Because
        # the cosign signature covers the timestamp, signature verification
        # fails → all defenses collapse to false.
        new_assertions = []
        for a in signed.claim.assertions:
            if a.label == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN:
                tampered_data = dict(a.data)
                tampered_data["bound_timestamp"] = "2099-01-01T00:00:00+00:00"
                new_assertions.append(C2paAssertion(label=a.label, data=tampered_data))
            else:
                new_assertions.append(a)
        tampered_claim = signed.claim.model_copy(
            update={"assertions": tuple(new_assertions)}
        )
        tampered_manifest = signed.model_copy(update={"claim": tampered_claim})

        result = verify_evidence_cosign(
            tampered_manifest,
            expected_full_file_sha256=full_file_sha256(body),
        )
        assert result.is_valid is False
        assert ISSUE_COSIGN_SIGNATURE_MISMATCH in result.issues
        # Timestamp-swap defense not satisfied because the signature fails.
        assert result.attack_defended(ATTACK_TIMESTAMP_SWAP) is False


# ---------------------------------------------------------------------------
# Attack #2 — revocation skipped
# ---------------------------------------------------------------------------


class TestAttackRevocationSkipped:
    def test_missing_revocation_proof_drops_revocation_defense(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
    ):
        body = b"no revocation proof"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            # revocation_proof=None  → expected to drop the defense flag
        )
        result = verify_evidence_cosign(
            signed,
            expected_full_file_sha256=full_file_sha256(body),
        )
        # Cosign signature still verifies — the assertion fields are still
        # consistent. But the revocation defense is NOT satisfied because
        # there's no proof.
        assert result.attack_defended(ATTACK_REVOCATION_SKIPPED) is False
        # Other defenses still hold.
        assert result.attack_defended(ATTACK_TIMESTAMP_SWAP) is True


# ---------------------------------------------------------------------------
# Attack #3 — cross-validator contradiction (canonicalization drift)
# ---------------------------------------------------------------------------


class TestAttackCanonicalizationDrift:
    def test_canonicalization_drift_detected(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"a body"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        # Verifier expects a different canonicalization version than the
        # one the cosign was signed under. Defense should not be satisfied.
        result = verify_evidence_cosign(
            signed,
            expected_full_file_sha256=full_file_sha256(body),
            expected_canonicalization_version="tex.evidence_cosign/v99",
        )
        assert ISSUE_COSIGN_CANONICALIZATION_DRIFT in result.issues
        assert (
            result.attack_defended(ATTACK_CROSS_VALIDATOR_CONTRADICTION) is False
        )


# ---------------------------------------------------------------------------
# Attack #4 — exclusion-range tamper (artifact bytes != hash claim)
# ---------------------------------------------------------------------------


class TestAttackExclusionRangeTamper:
    def test_mismatched_full_file_hash_detected(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"the original artifact"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        # Pretend the caller hands the verifier a different asset bytes
        # (e.g. one with GPS coordinates injected into a C2PA exclusion
        # range). The verifier must flag the mismatch.
        tampered_body = b"the tampered artifact with injected metadata"
        result = verify_evidence_cosign(
            signed,
            expected_full_file_sha256=full_file_sha256(tampered_body),
        )
        assert ISSUE_COSIGN_FULL_FILE_HASH_MISMATCH in result.issues
        assert result.attack_defended(ATTACK_EXCLUSION_RANGE_TAMPER) is False


# ---------------------------------------------------------------------------
# Attack #5 — cert expiry before retention obligation
# ---------------------------------------------------------------------------


class TestAttackCertExpiryBeforeRetention:
    def test_missing_retention_anchor_drops_defense(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_revocation_proof,
    ):
        # We can't omit retention_anchor at build time (builder rejects it),
        # so simulate the attack by stripping it post-hoc in the assertion.
        body = b"body"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor={"record_hash": "a" * 64},
            revocation_proof=standard_revocation_proof,
        )
        # Manually strip record_hash to simulate a manifest a downstream
        # actor has tampered with.
        new_assertions = []
        for a in signed.claim.assertions:
            if a.label == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN:
                bad = dict(a.data)
                bad["retention_anchor"] = {}
                new_assertions.append(C2paAssertion(label=a.label, data=bad))
            else:
                new_assertions.append(a)
        bad_claim = signed.claim.model_copy(
            update={"assertions": tuple(new_assertions)}
        )
        bad_manifest = signed.model_copy(update={"claim": bad_claim})
        result = verify_evidence_cosign(
            bad_manifest,
            expected_full_file_sha256=full_file_sha256(body),
        )
        # Tampering with the retention_anchor also breaks the cosign
        # signature (signature covers retention_anchor). Both the
        # "missing retention_anchor" issue and the signature mismatch
        # surface.
        assert (
            ISSUE_COSIGN_RETENTION_ANCHOR_MISSING in result.issues
            or ISSUE_COSIGN_SIGNATURE_MISMATCH in result.issues
        )
        assert (
            result.attack_defended(ATTACK_CERT_EXPIRY_BEFORE_RETENTION) is False
        )


# ---------------------------------------------------------------------------
# Negative — missing cosign assertion
# ---------------------------------------------------------------------------


class TestVerifyEvidenceCosignMissing:
    def test_manifest_without_cosign_returns_missing(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
    ):
        # Sign the manifest via the plain pathway — no cosign appended.
        from tex.c2pa import sign_manifest

        signed = sign_manifest(
            unsigned_email_manifest,
            signing_key_id=outer_keypair.key_id,
            certificate_chain_pem=outer_chain["chain_pem"],
        )
        result = verify_evidence_cosign(signed)
        assert result.is_valid is False
        assert ISSUE_COSIGN_MISSING in result.issues
        # None of the defenses are satisfied.
        assert all(not v for _k, v in result.defenses_satisfied)


# ---------------------------------------------------------------------------
# Serialization for Postgres mirror
# ---------------------------------------------------------------------------


class TestSerializeForStorage:
    def test_serialized_dict_carries_cosign_flag(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"x"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        row = serialize_manifest_for_storage(signed)
        assert row["schema"] == "tex.evidence_manifests/v1"
        assert row["has_cosign"] is True
        assert ASSERTION_LABEL_TEX_EVIDENCE_COSIGN in row["assertion_labels"]
        assert len(row["claim_sha256"]) == 64
        # Round-trip the CBOR blob.
        cbor_bytes = base64.b64decode(row["claim_cbor_b64"])
        assert len(cbor_bytes) > 100  # non-trivially sized

    def test_unsigned_manifest_serialization_rejected(
        self, unsigned_email_manifest
    ):
        with pytest.raises(ValueError, match="unsigned"):
            serialize_manifest_for_storage(unsigned_email_manifest)


# ---------------------------------------------------------------------------
# cosign_manifest_hash — used as the evidence-record reference
# ---------------------------------------------------------------------------


class TestCosignManifestHash:
    def test_hash_is_deterministic(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"body"
        s1 = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            bound_timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        s2 = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            bound_timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        # Note: ed25519 signatures are deterministic; ML-DSA-65 is not.
        # The hash here is over the canonical claim CBOR which DOES include
        # the cosign signature value, so deterministic algos give same hash
        # for identical inputs.
        assert cosign_manifest_hash(s1) == cosign_manifest_hash(s2)


# ---------------------------------------------------------------------------
# Defends-against bibliography assertion — auditor-facing invariant.
# ---------------------------------------------------------------------------


class TestDefendsAgainstBibliography:
    def test_paper_reference_is_carried_verbatim(
        self,
        unsigned_email_manifest,
        outer_chain,
        outer_keypair,
        cosign_keypair,
        standard_retention_anchor,
        standard_revocation_proof,
    ):
        body = b"x"
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned_email_manifest,
            outer_signing_key_id=outer_keypair.key_id,
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_keypair,
            outbound_artifact_bytes=body,
            retention_anchor=standard_retention_anchor,
            revocation_proof=standard_revocation_proof,
        )
        cosign = get_cosign_assertion(signed)
        assert cosign["defends_against"]["paper"] == "arxiv:2604.24890"
        assert set(cosign["defends_against"]["attacks"]) == set(ALL_ATTACKS)
