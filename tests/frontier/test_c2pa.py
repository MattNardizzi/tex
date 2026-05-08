"""
Tests for the Tex c2pa package (Thread 6).

Coverage targets:
    - manifest builders emit the three required assertions
    - signer produces a base64'd COSE_Sign1_Tagged envelope
    - verifier round-trips: build → sign → verify
    - tampering at any layer breaks verification
    - trust-list anchoring transitions Valid → Trusted
    - C2PA 2.2 §13.2 algorithm allowed-list is enforced
    - the included CBOR codec is deterministic and self-inverting
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tex.c2pa import (
    ASSERTION_LABEL_ACTIONS_V2,
    ASSERTION_LABEL_CAWG_CREATIVE_WORK,
    ASSERTION_LABEL_TEX_VERDICT,
    DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
    TEX_VERDICT_SCHEMA_V1,
    C2paAssertion,
    C2paClaim,
    C2paManifest,
    C2paVerificationResult,
    build_ai_generation_assertion,
    build_cawg_creative_work_assertion,
    build_email_manifest,
    build_tex_verdict_assertion,
    clear_signing_keys,
    register_signing_key,
    sign_manifest,
    verify_manifest,
)
from tex.c2pa import _cbor
from tex.c2pa._canonical_claim import canonical_claim_cbor
from tex.c2pa._cose_alg import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    cose_alg_for,
    cose_alg_label,
    is_supported,
)
from tex.c2pa.signer import set_keystore
from tex.c2pa.verifier import (
    ISSUE_ALGORITHM_UNSUPPORTED,
    ISSUE_CLAIM_SIG_MISMATCH,
    ISSUE_CLAIM_SIG_MISSING,
    ISSUE_CLAIM_SIG_VALIDATED,
    ISSUE_OUTSIDE_VALIDITY,
    ISSUE_SIGNING_CRED_INVALID,
    ISSUE_SIGNING_CRED_TRUSTED,
    ISSUE_SIGNING_CRED_UNTRUSTED,
)
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


# ---------------------------------------------------------------------------
# Fixtures: mint a CA + leaf chain so we can sign and verify offline.
# ---------------------------------------------------------------------------


def _mint_chain(
    *,
    leaf_curve: ec.EllipticCurve | None = None,
    leaf_use_ed25519: bool = False,
    leaf_validity: tuple[timedelta, timedelta] = (timedelta(days=1), timedelta(days=30)),
) -> dict:
    """Mint a CA and a leaf signing certificate.

    Returns a dict with PEM bytes for everything the signer/verifier
    needs. The leaf can be ECDSA-P256 (default) or Ed25519.
    """
    now = datetime.now(timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Test Root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_subj)
        .issuer_name(ca_subj)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    if leaf_use_ed25519:
        leaf_key = ed25519.Ed25519PrivateKey.generate()
    else:
        leaf_key = ec.generate_private_key(leaf_curve or ec.SECP256R1())

    leaf_subj = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.signer.test")]
    )
    not_before_delta, not_after_delta = leaf_validity
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subj)
        .issuer_name(ca_subj)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
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
    leaf_only_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    return {
        "leaf_priv_pem": leaf_priv_pem,
        "leaf_pub_pem": leaf_pub_pem,
        "chain_pem": chain_pem,
        "leaf_only_pem": leaf_only_pem,
        "ca_pem": ca_pem,
    }


@pytest.fixture(autouse=True)
def _isolated_keystore():
    """Each test starts with an empty in-process keystore."""
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


@pytest.fixture
def ecdsa_chain():
    return _mint_chain()


@pytest.fixture
def ed25519_chain():
    return _mint_chain(leaf_use_ed25519=True)


@pytest.fixture
def trust_list_path(tmp_path: Path, ecdsa_chain: dict) -> str:
    p = tmp_path / "ca.pem"
    p.write_text(ecdsa_chain["ca_pem"])
    return str(p)


@pytest.fixture
def signing_key_ecdsa(ecdsa_chain: dict) -> SignatureKeyPair:
    kp = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ECDSA_P256,
        public_key=ecdsa_chain["leaf_pub_pem"],
        private_key=ecdsa_chain["leaf_priv_pem"],
        key_id="tex-test-ecdsa-1",
    )
    register_signing_key(kp)
    return kp


@pytest.fixture
def signing_key_ed25519(ed25519_chain: dict) -> SignatureKeyPair:
    kp = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=ed25519_chain["leaf_pub_pem"],
        private_key=ed25519_chain["leaf_priv_pem"],
        key_id="tex-test-ed25519-1",
    )
    register_signing_key(kp)
    return kp


@pytest.fixture
def email_manifest() -> C2paManifest:
    return build_email_manifest(
        from_address="ai@vortexblack.io",
        to_addresses=("buyer@example.com", "ops@example.com"),
        subject="Q3 underwriting demo",
        body_sha256=hashlib.sha256(b"hello world").hexdigest(),
        model_name="claude-opus-4-7",
        model_version="2026-04-01",
        tex_verdict_id="vrd_01HZX8YQ",
        verdict="PERMIT",
        policy_version="tex-policy/v3.2.1",
    )


# ---------------------------------------------------------------------------
# CBOR codec tests
# ---------------------------------------------------------------------------


class TestCbor:
    def test_roundtrip_primitive_types(self):
        for value in (0, 1, -1, 23, 24, 255, 256, 65535, 65536, "hello", b"\x00\x01\x02", True, False, None):
            assert _cbor.decode(_cbor.encode(value)) == value

    def test_roundtrip_array_and_map(self):
        value = [1, "two", b"\x03", {"k": [1, 2, 3]}]
        assert _cbor.decode(_cbor.encode(value)) == value

    def test_map_keys_sorted_deterministically(self):
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        assert _cbor.encode(a) == _cbor.encode(b)

    def test_int_keys_sorted_before_str_keys_by_encoding(self):
        # Int 1 encodes as 0x01; str "a" encodes as 0x61 'a'.
        # Bytewise lex comparison puts the int first.
        encoded = _cbor.encode({1: "x", "a": "y"})
        # Decode preserves whatever order — we only need byte equality.
        # Verify by encoding the swapped insertion order.
        encoded2 = _cbor.encode({"a": "y", 1: "x"})
        assert encoded == encoded2

    def test_unsupported_value_raises(self):
        with pytest.raises(TypeError):
            _cbor.encode(3.14)
        with pytest.raises(TypeError):
            _cbor.encode({1.0: "x"})

    def test_negative_int_encoding(self):
        # Major type 1, value -1 → 0x20
        assert _cbor.encode(-1) == bytes([0x20])
        assert _cbor.decode(bytes([0x20])) == -1

    def test_tag_unwrap(self):
        wrapped = _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, [1, 2])
        decoded = _cbor.decode(wrapped)
        unwrapped = _cbor.unwrap_tag(decoded, _cbor.COSE_SIGN1_TAG)
        assert unwrapped == [1, 2]

    def test_unwrap_tag_passthrough_when_not_tagged(self):
        assert _cbor.unwrap_tag([1, 2, 3], _cbor.COSE_SIGN1_TAG) == [1, 2, 3]

    def test_trailing_bytes_rejected(self):
        with pytest.raises(ValueError):
            _cbor.decode(_cbor.encode(1) + b"\x00")

    def test_truncated_blob_rejected(self):
        with pytest.raises(ValueError):
            _cbor.decode(b"\x59\x00")  # text len=0 but indicator says 2-byte len

    def test_indefinite_length_rejected(self):
        # Major 2, additional info 31 = indefinite-length byte string.
        with pytest.raises(ValueError):
            _cbor.decode(bytes([0x5F]))

    def test_long_uint_encoding(self):
        # 4-byte length region
        v = 65537
        assert _cbor.decode(_cbor.encode(v)) == v
        # 8-byte length region
        v = 2**33
        assert _cbor.decode(_cbor.encode(v)) == v


# ---------------------------------------------------------------------------
# Manifest builder tests
# ---------------------------------------------------------------------------


class TestManifestBuilders:
    def test_email_manifest_has_three_required_assertions(self, email_manifest):
        labels = [a.label for a in email_manifest.claim.assertions]
        assert labels == [
            ASSERTION_LABEL_ACTIONS_V2,
            ASSERTION_LABEL_CAWG_CREATIVE_WORK,
            ASSERTION_LABEL_TEX_VERDICT,
        ]

    def test_email_manifest_marks_ai_generation(self, email_manifest):
        actions = email_manifest.claim.assertions[0]
        assert actions.label == ASSERTION_LABEL_ACTIONS_V2
        assert (
            actions.data["actions"][0]["digitalSourceType"]
            == DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC
        )
        assert actions.data["actions"][0]["action"] == "c2pa.created"

    def test_email_manifest_records_creator_mailbox_only(self, email_manifest):
        cawg = email_manifest.claim.assertions[1]
        assert cawg.data["creator"]["identifier"] == "mailto:ai@vortexblack.io"
        # Recipients live under provenance.delivery, not in the top-level creator.
        recipients = cawg.data["provenance"]["delivery"]["recipients"]
        assert {r["identifier"] for r in recipients} == {
            "mailto:buyer@example.com",
            "mailto:ops@example.com",
        }

    def test_email_manifest_omits_body_bytes(self, email_manifest):
        cawg = email_manifest.claim.assertions[1]
        delivery = cawg.data["provenance"]["delivery"]
        # Only the hash, never the body.
        assert "bodySha256" in delivery
        assert "body" not in delivery

    def test_email_manifest_carries_tex_verdict(self, email_manifest):
        v = email_manifest.claim.assertions[2]
        assert v.label == ASSERTION_LABEL_TEX_VERDICT
        assert v.data["$schema"] == TEX_VERDICT_SCHEMA_V1
        assert v.data["verdict_id"] == "vrd_01HZX8YQ"
        assert v.data["verdict"] == "PERMIT"
        assert v.data["policy_version"] == "tex-policy/v3.2.1"

    def test_email_manifest_starts_unsigned(self, email_manifest):
        assert email_manifest.signature_b64 is None
        assert email_manifest.certificate_chain_pem is None

    def test_email_manifest_rejects_empty_recipients(self):
        with pytest.raises(ValueError):
            build_email_manifest(
                from_address="a@x", to_addresses=(), subject="s",
                body_sha256="0" * 64, model_name="m", model_version="v",
                tex_verdict_id="vid",
            )

    def test_email_manifest_rejects_short_body_hash(self):
        with pytest.raises(ValueError):
            build_email_manifest(
                from_address="a@x", to_addresses=("b@y",), subject="s",
                body_sha256="abc", model_name="m", model_version="v",
                tex_verdict_id="vid",
            )

    def test_email_manifest_rejects_missing_verdict(self):
        with pytest.raises(ValueError):
            build_email_manifest(
                from_address="a@x", to_addresses=("b@y",), subject="s",
                body_sha256="0" * 64, model_name="m", model_version="v",
                tex_verdict_id="",
            )

    def test_email_manifest_rejects_missing_from(self):
        with pytest.raises(ValueError):
            build_email_manifest(
                from_address="", to_addresses=("b@y",), subject="s",
                body_sha256="0" * 64, model_name="m", model_version="v",
                tex_verdict_id="v",
            )

    def test_ai_generation_assertion_no_marker_when_not_ai(self):
        a = build_ai_generation_assertion(
            model_name="m", model_version="v",
            training_data_class="public", is_ai_generated=False,
        )
        assert "digitalSourceType" not in a.data["actions"][0]

    def test_tex_verdict_assertion_minimal(self):
        a = build_tex_verdict_assertion(verdict_id="v1")
        assert a.data["verdict"] == "PERMIT"
        assert "policy_version" not in a.data
        assert "issued_at" not in a.data

    def test_cawg_assertion_carries_iso_timestamp(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        a = build_cawg_creative_work_assertion(creator_mailbox="x@y", sent_at=ts)
        assert a.data["datePublished"] == ts.isoformat()


# ---------------------------------------------------------------------------
# Canonical CBOR
# ---------------------------------------------------------------------------


class TestCanonicalClaim:
    def test_canonicalization_is_deterministic(self, email_manifest):
        a = canonical_claim_cbor(email_manifest.claim)
        b = canonical_claim_cbor(email_manifest.claim)
        assert a == b

    def test_canonicalization_changes_with_field_change(self, email_manifest):
        original = canonical_claim_cbor(email_manifest.claim)
        mutated = email_manifest.claim.model_copy(update={"title": "different"})
        assert canonical_claim_cbor(mutated) != original


# ---------------------------------------------------------------------------
# COSE alg mapping
# ---------------------------------------------------------------------------


class TestCoseAlg:
    def test_es256_mapping(self):
        assert cose_alg_for(SignatureAlgorithm.ECDSA_P256) == COSE_ALG_ES256
        assert cose_alg_label(SignatureAlgorithm.ECDSA_P256) == "ES256"
        assert is_supported(SignatureAlgorithm.ECDSA_P256)

    def test_eddsa_mapping(self):
        assert cose_alg_for(SignatureAlgorithm.ED25519) == COSE_ALG_EDDSA
        assert cose_alg_label(SignatureAlgorithm.ED25519) == "EdDSA"

    @pytest.mark.parametrize(
        "alg",
        [
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
            SignatureAlgorithm.SLH_DSA_128S,
            SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
        ],
    )
    def test_post_quantum_algos_rejected_for_c2pa(self, alg):
        assert not is_supported(alg)
        with pytest.raises(NotImplementedError):
            cose_alg_for(alg)


# ---------------------------------------------------------------------------
# Round-trip: build → sign → verify
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_sign_populates_signature_and_chain(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )
        assert signed.signature_b64 is not None
        assert signed.certificate_chain_pem == ecdsa_chain["chain_pem"]
        # base64 decodes cleanly
        envelope = base64.b64decode(signed.signature_b64)
        # And it parses as the tagged COSE_Sign1 structure.
        decoded = _cbor.decode(envelope)
        unwrapped = _cbor.unwrap_tag(decoded, _cbor.COSE_SIGN1_TAG)
        assert isinstance(unwrapped, list)
        assert len(unwrapped) == 4

    def test_verify_with_trust_list_returns_trusted(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa, trust_list_path
    ):
        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )
        result = verify_manifest(signed, trust_list_pem_paths=(trust_list_path,))
        assert isinstance(result, C2paVerificationResult)
        assert result.is_valid
        assert result.is_trust_list_anchored
        assert ISSUE_CLAIM_SIG_VALIDATED in result.issues
        assert ISSUE_SIGNING_CRED_TRUSTED in result.issues
        assert result.signing_certificate_subject == "CN=tex.signer.test"

    def test_verify_without_trust_list_caps_at_valid(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )
        result = verify_manifest(signed)
        assert result.is_valid
        assert not result.is_trust_list_anchored
        assert ISSUE_CLAIM_SIG_VALIDATED in result.issues
        assert ISSUE_SIGNING_CRED_TRUSTED not in result.issues
        assert ISSUE_SIGNING_CRED_UNTRUSTED not in result.issues

    def test_verify_with_unrelated_anchor_marks_untrusted(
        self, tmp_path, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        # A second, unrelated CA acts as the trust list — it does not
        # cover our chain.
        other = _mint_chain()
        anchor_path = tmp_path / "other.pem"
        anchor_path.write_text(other["ca_pem"])

        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )
        result = verify_manifest(
            signed, trust_list_pem_paths=(str(anchor_path),)
        )
        assert result.is_valid
        assert not result.is_trust_list_anchored
        assert ISSUE_SIGNING_CRED_UNTRUSTED in result.issues

    def test_round_trip_with_ed25519(
        self, email_manifest, ed25519_chain, signing_key_ed25519
    ):
        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ed25519.key_id,
            certificate_chain_pem=ed25519_chain["chain_pem"],
        )
        result = verify_manifest(signed)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Negative cases: tampering, bad envelopes
# ---------------------------------------------------------------------------


class TestNegativeCases:
    def _signed(self, email_manifest, ecdsa_chain, signing_key_ecdsa):
        return sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )

    def test_tampered_claim_fails_verification(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        signed = self._signed(email_manifest, ecdsa_chain, signing_key_ecdsa)
        tampered_claim = signed.claim.model_copy(update={"title": "INJECTED"})
        tampered = signed.model_copy(update={"claim": tampered_claim})
        result = verify_manifest(tampered)
        assert not result.is_valid
        assert ISSUE_CLAIM_SIG_MISMATCH in result.issues

    def test_tampered_assertion_fails_verification(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        signed = self._signed(email_manifest, ecdsa_chain, signing_key_ecdsa)
        # Swap the verdict from PERMIT to FORBID — this is exactly the
        # downgrade attack the manifest is meant to prevent.
        verdict = signed.claim.assertions[2]
        new_data = {**verdict.data, "verdict": "FORBID"}
        new_assertion = C2paAssertion(label=verdict.label, data=new_data)
        new_assertions = (
            signed.claim.assertions[0],
            signed.claim.assertions[1],
            new_assertion,
        )
        tampered_claim = signed.claim.model_copy(update={"assertions": new_assertions})
        tampered = signed.model_copy(update={"claim": tampered_claim})
        result = verify_manifest(tampered)
        assert not result.is_valid
        assert ISSUE_CLAIM_SIG_MISMATCH in result.issues

    def test_missing_signature_field_reports_missing(self, email_manifest):
        result = verify_manifest(email_manifest)
        assert not result.is_valid
        assert result.issues == (ISSUE_CLAIM_SIG_MISSING,)

    def test_garbage_signature_b64_reports_mismatch(self, email_manifest):
        garbage = email_manifest.model_copy(
            update={"signature_b64": "!!!not-base64!!!"}
        )
        result = verify_manifest(garbage)
        assert not result.is_valid
        assert ISSUE_CLAIM_SIG_MISMATCH in result.issues

    def test_envelope_with_wrong_shape_rejected(self, email_manifest):
        # 3-element CBOR array tagged as COSE_Sign1 — wrong arity.
        bad = _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, [b"", {}, b""])
        bad_b64 = base64.b64encode(bad).decode()
        bad_manifest = email_manifest.model_copy(update={"signature_b64": bad_b64})
        result = verify_manifest(bad_manifest)
        assert not result.is_valid
        assert ISSUE_CLAIM_SIG_MISMATCH in result.issues

    def test_envelope_without_alg_header_rejected(self, email_manifest):
        # Build a syntactically valid COSE_Sign1 with empty protected hdr.
        cose_sign1 = [b"", {}, None, b"sig"]
        bad = _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, cose_sign1)
        bad_b64 = base64.b64encode(bad).decode()
        bad_manifest = email_manifest.model_copy(update={"signature_b64": bad_b64})
        result = verify_manifest(bad_manifest)
        assert not result.is_valid
        assert ISSUE_ALGORITHM_UNSUPPORTED in result.issues

    def test_envelope_with_unsupported_alg_rejected(self, email_manifest):
        # COSE alg = -48 (proposed ML-DSA-44, not on C2PA allowed list).
        protected = _cbor.encode({1: -48})
        cose_sign1 = [protected, {}, None, b"sig"]
        bad = _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, cose_sign1)
        bad_b64 = base64.b64encode(bad).decode()
        bad_manifest = email_manifest.model_copy(update={"signature_b64": bad_b64})
        result = verify_manifest(bad_manifest)
        assert not result.is_valid
        assert ISSUE_ALGORITHM_UNSUPPORTED in result.issues

    def test_envelope_without_x5chain_rejected(self, email_manifest):
        protected = _cbor.encode({1: COSE_ALG_ES256})
        cose_sign1 = [protected, {}, None, b"sig"]
        bad = _cbor.encode_tag(_cbor.COSE_SIGN1_TAG, cose_sign1)
        bad_b64 = base64.b64encode(bad).decode()
        bad_manifest = email_manifest.model_copy(update={"signature_b64": bad_b64})
        result = verify_manifest(bad_manifest)
        assert not result.is_valid
        assert ISSUE_SIGNING_CRED_INVALID in result.issues


# ---------------------------------------------------------------------------
# Validity-window check
# ---------------------------------------------------------------------------


class TestValidityWindow:
    def test_expired_certificate_marked_outside_validity(
        self, tmp_path, email_manifest
    ):
        # Mint a chain whose leaf already expired.
        chain = _mint_chain(
            leaf_validity=(timedelta(days=10), timedelta(days=-1))
        )
        kp = SignatureKeyPair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            public_key=chain["leaf_pub_pem"],
            private_key=chain["leaf_priv_pem"],
            key_id="expired-key",
        )
        register_signing_key(kp)
        signed = sign_manifest(
            email_manifest,
            signing_key_id="expired-key",
            certificate_chain_pem=chain["chain_pem"],
        )
        result = verify_manifest(signed)
        assert not result.is_valid
        assert ISSUE_OUTSIDE_VALIDITY in result.issues

    def test_explicit_now_within_window_validates(
        self, email_manifest, ecdsa_chain, signing_key_ecdsa
    ):
        signed = sign_manifest(
            email_manifest,
            signing_key_id=signing_key_ecdsa.key_id,
            certificate_chain_pem=ecdsa_chain["chain_pem"],
        )
        # Pin "now" to a moment we know is inside the chain's validity.
        result = verify_manifest(signed, now=datetime.now(timezone.utc))
        assert result.is_valid


# ---------------------------------------------------------------------------
# Keystore plumbing
# ---------------------------------------------------------------------------


class TestKeystore:
    def test_unknown_key_id_raises(self, email_manifest, ecdsa_chain):
        with pytest.raises(KeyError):
            sign_manifest(
                email_manifest,
                signing_key_id="does-not-exist",
                certificate_chain_pem=ecdsa_chain["chain_pem"],
            )

    def test_custom_keystore_lookup(self, email_manifest, ecdsa_chain):
        kp = SignatureKeyPair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            public_key=ecdsa_chain["leaf_pub_pem"],
            private_key=ecdsa_chain["leaf_priv_pem"],
            key_id="from-hsm",
        )
        called: list[str] = []

        def lookup(key_id: str) -> SignatureKeyPair:
            called.append(key_id)
            return kp

        set_keystore(lookup)
        try:
            signed = sign_manifest(
                email_manifest,
                signing_key_id="from-hsm",
                certificate_chain_pem=ecdsa_chain["chain_pem"],
            )
        finally:
            set_keystore(None)
        assert called == ["from-hsm"]
        assert verify_manifest(signed).is_valid

    def test_clear_drops_registered_keys(self, ecdsa_chain):
        kp = SignatureKeyPair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            public_key=ecdsa_chain["leaf_pub_pem"],
            private_key=ecdsa_chain["leaf_priv_pem"],
            key_id="will-be-cleared",
        )
        register_signing_key(kp)
        clear_signing_keys()
        with pytest.raises(KeyError):
            sign_manifest(
                C2paManifest(
                    claim=C2paClaim(
                        title="t",
                        format="text/plain",
                        instance_id="i",
                        claim_generator="x",
                        claim_generator_info={},
                        created_at=datetime.now(timezone.utc),
                        assertions=(),
                    )
                ),
                signing_key_id="will-be-cleared",
                certificate_chain_pem=ecdsa_chain["chain_pem"],
            )


# ---------------------------------------------------------------------------
# Sanity: durable_credentials remains a stub
# ---------------------------------------------------------------------------


class TestDurableCredentialsStillStub:
    def test_attach_durable_marks_raises(self):
        from tex.c2pa.durable_credentials import attach_durable_marks

        with pytest.raises(NotImplementedError):
            attach_durable_marks(b"content", "manifest-id")
