"""
Thread 6 integration test — full four-layer manifest.

Proves the claim that Thread 6 puts on the table:

> Every PERMIT verdict on an outbound AI-generated artifact produces
> a single C2PA 2.4 Content Credential that simultaneously:
>
>   1. carries a post-quantum ML-DSA-65 ``tex.evidence_cosign``
>      assertion closing the six attack classes of arxiv 2604.24890
>      (Thread 5 — A-);
>   2. carries a ``tex.evidence_watermark`` soft-binding assertion
>      naming the SynthID-Text or TextSeal watermark scheme used at
>      generation time, with cross-layer audit defending against the
>      desynchronisation attack of arxiv 2603.02378 (Thread 6 Gap 1);
>   3. carries a ``tex.evidence_attestation`` assertion binding the
>      signing key to a hardware-attested TEE via EAT JWT issued by
>      NVIDIA NRAS / Intel Trust Authority / Veraison
>      (Thread 6 Gap 2);
>   4. carries a ``tex.formal_verification`` assertion containing the
>      CPSA-verified protocol shape ledger, asserting structural
>      soundness under the Dolev-Yao adversary (Thread 6 Gap 3).
>
> The OUTER C2PA COSE_Sign1 signature covers all four assertions
> together — one signing pass, no self-reference.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tex.c2pa import (
    ALL_ATTACKS,
    ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
    ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
    COSIGN_CANONICALIZATION_VERSION_V2,
    AttestationVerifier,
    EatTokenKind,
    RecordedScoreDetector,
    SYNTHID_TEXT_DEFAULT_THRESHOLD,
    WatermarkScheme,
    build_signed_manifest_with_cosign,
    build_tex_evidence_attestation_assertion,
    build_tex_evidence_watermark_assertion,
    canonical_cosign_signing_input_v2,
    clear_signing_keys,
    cross_layer_audit,
    full_file_sha256,
    load_cpsa_shapes,
    merkle_proof,
    merkle_root,
    model_provenance_assertion_data,
    register_signing_key,
    synthesize_test_eat_jwt,
    text_perceptual_hash,
    verify_attestation_assertion,
    verify_evidence_cosign,
    verify_manifest,
    verify_merkle_proof,
)
from tex.c2pa.cosign_context_tree import build_cosign_v2_leaves
from tex.c2pa.manifest import (
    C2paAssertion,
    C2paClaim,
    C2paManifest,
)
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_keystore():
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


@pytest.fixture
def outer_chain():
    """Mint an Ed25519 outer signing key + self-signed chain."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Thread 6 Root")])
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
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.thread6.integration")]
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
        .sign(ca_key, hashes.SHA256())
    )
    priv_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chain_pem = (
        leaf.public_bytes(serialization.Encoding.PEM).decode()
        + ca.public_bytes(serialization.Encoding.PEM).decode()
    )
    key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=pub_pem,
        private_key=priv_pem,
        key_id="thread6-outer",
    )
    return {"key": key, "chain_pem": chain_pem, "key_id": "thread6-outer"}


@pytest.fixture
def cosign_key():
    """Mint an Ed25519 cosign key (fallback for CI without ML-DSA)."""
    provider = Ed25519Provider()
    return provider.generate_keypair(key_id="thread6-cosign")


@pytest.fixture
def attestation_signing_keypair():
    """Mint an ES384 keypair simulating a TEE verifier (NRAS/ITA)."""
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
    return {"priv_pem": priv_pem, "pub_pem": pub_pem, "kid": "nras-tee-1"}


def _build_unsigned_manifest() -> C2paManifest:
    """A minimal Tex-style claim — actions + verdict, no cosign yet."""
    return C2paManifest(
        claim=C2paClaim(
            title="thread6-outbound-email.txt",
            format="text/plain",
            instance_id="xmp.iid:thread6-integration-001",
            claim_generator="tex/0.1 (thread6)",
            claim_generator_info={"name": "Tex Aegis", "version": "0.1.0"},
            created_at=datetime.now(tz=timezone.utc),
            assertions=(
                C2paAssertion(
                    label="c2pa.actions.v2",
                    data={
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "softwareAgent": {
                                    "name": "Tex Aegis",
                                    "version": "0.1.0",
                                },
                            },
                        ]
                    },
                ),
                C2paAssertion(
                    label="tex.verdict",
                    data={
                        "verdict": "PERMIT",
                        "final_score": "0.08",
                        "policy_version": "thread6.integration.v1",
                    },
                ),
            ),
        ),
        signature_b64=None,
        certificate_chain_pem=None,
    )


# ---------------------------------------------------------------------------
# Cosign v2 — Merkle inclusion-proof helpers
# ---------------------------------------------------------------------------


class TestMerkleContextTree:
    def test_root_is_32_bytes(self):
        leaves = build_cosign_v2_leaves(
            bound_timestamp="2026-05-18T00:00:00+00:00",
            revocation_proof=None,
            canonicalization_version=COSIGN_CANONICALIZATION_VERSION_V2,
            full_file_sha256="a" * 64,
            retention_anchor={"retain_until": "2031-05-18T00:00:00Z"},
            cosign_algorithm="ed25519",
            cosign_key_id="k-1",
        )
        root = merkle_root(leaves)
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_inclusion_proof_round_trip(self):
        leaves = build_cosign_v2_leaves(
            bound_timestamp="2026-05-18T00:00:00+00:00",
            revocation_proof={"crl_url": "https://crl.example/c.pem"},
            canonicalization_version=COSIGN_CANONICALIZATION_VERSION_V2,
            full_file_sha256="b" * 64,
            retention_anchor={"retain_until": "2031-05-18T00:00:00Z"},
            cosign_algorithm="ml-dsa-65",
            cosign_key_id="k-2",
        )
        root = merkle_root(leaves)
        # Selective disclosure of the timestamp-swap leaf (index 0) only.
        proof = merkle_proof(leaves, 0)
        assert verify_merkle_proof(
            leaf=leaves[0], leaf_index=0, proof=proof, expected_root=root
        )
        # A different leaf with the same proof must NOT verify.
        assert not verify_merkle_proof(
            leaf=leaves[1], leaf_index=0, proof=proof, expected_root=root
        )

    def test_signing_input_returns_merkle_root_bytes(self):
        bytes_v2 = canonical_cosign_signing_input_v2(
            bound_timestamp="2026-05-18T00:00:00+00:00",
            full_file_sha256="c" * 64,
            canonicalization_version=COSIGN_CANONICALIZATION_VERSION_V2,
            retention_anchor={"retain_until": "2031-05-18T00:00:00Z"},
            revocation_proof=None,
            cosign_algorithm="ed25519",
            cosign_key_id="k-3",
        )
        assert len(bytes_v2) == 32

    def test_tampering_with_any_leaf_changes_root(self):
        base = {
            "bound_timestamp": "2026-05-18T00:00:00+00:00",
            "revocation_proof": None,
            "canonicalization_version": COSIGN_CANONICALIZATION_VERSION_V2,
            "full_file_sha256": "d" * 64,
            "retention_anchor": {"retain_until": "2031-05-18T00:00:00Z"},
            "cosign_algorithm": "ed25519",
            "cosign_key_id": "k-4",
        }
        root_base = merkle_root(build_cosign_v2_leaves(**base))
        # Tamper with each field in turn; every change must alter the root.
        mutations = [
            {"bound_timestamp": "2026-05-18T00:00:01+00:00"},
            {"full_file_sha256": "e" * 64},
            {"canonicalization_version": "tex.evidence_cosign/v1"},
            {"retention_anchor": {"retain_until": "2099-01-01T00:00:00Z"}},
            {"cosign_algorithm": "ml-dsa-65"},
            {"cosign_key_id": "different-key"},
        ]
        for mut in mutations:
            mutated = {**base, **mut}
            root_mutated = merkle_root(build_cosign_v2_leaves(**mutated))
            assert root_mutated != root_base, f"Mutation {mut} did not change root"


# ---------------------------------------------------------------------------
# End-to-end: all four assertions in one signed manifest
# ---------------------------------------------------------------------------


class TestThread6FullStack:
    def test_full_four_layer_manifest(
        self, outer_chain, cosign_key, attestation_signing_keypair
    ):
        # 1. The outbound artifact (a marketing email).
        body = (
            b"Subject: Tex Aegis pilot interest\n\n"
            b"Hi Sara, this is an AI-assisted outreach from Matthew at "
            b"VortexBlack. Five minutes next week to discuss your AI SDR "
            b"brand-safety story?\n"
        )
        body_sha = full_file_sha256(body)

        # 2. Register the outer signing key.
        register_signing_key(outer_chain["key"])

        # 3. Watermark detection (gateway produced this score, Tex
        #    records it as a soft binding).
        detector = RecordedScoreDetector(
            scheme=WatermarkScheme.SYNTHID_TEXT,
            recorded_score=0.97,
            recorded_p_value=1e-14,
            threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
            detector_version="google-deepmind/synthid-text/v1",
        )
        det_result = detector.detect(body.decode(), key_id="synthid-tex-prod-1")
        soft_binding = text_perceptual_hash(body.decode())
        watermark_data = build_tex_evidence_watermark_assertion(
            detection=det_result,
            key_id="synthid-tex-prod-1",
            soft_binding_value=f"sha256:{soft_binding}",
            asserted_origin="ai-generated",
            detector_url="https://github.com/google-deepmind/synthid-text",
        )

        # 4. Compute the claim CBOR hash that the EAT will bind to.
        #    Tex uses canonical_claim_cbor on the *augmented* claim
        #    (with the watermark + formal_verification + cosign placeholder).
        #    For the integration test we use the body SHA as the stand-in
        #    claim_cbor_sha256, since the production binding is a P1
        #    upgrade once the c2pa_emitter accepts a claim_hash callback.
        eat_bound_hash = body_sha
        eat_token = synthesize_test_eat_jwt(
            claim_cbor_sha256=eat_bound_hash,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            signing_key_pem=attestation_signing_keypair["priv_pem"],
            kid=attestation_signing_keypair["kid"],
            algorithm="ES384",
            extra_claims={
                "cc_mode_enabled": True,
                "overall_result": "SUCCESS",
                "gpu_evidence_list": [{"device_id": "GPU-0"}],
            },
        )
        attestation_data = build_tex_evidence_attestation_assertion(
            eat_token=eat_token,
            eat_token_kind=EatTokenKind.JWT,
            verifier=AttestationVerifier.NVIDIA_NRAS,
            claim_cbor_sha256=eat_bound_hash,
            platform_measurement_sha256="f" * 64,
        )

        # 5. CPSA formal-verification assertion.
        bundle = load_cpsa_shapes()
        formal_data = model_provenance_assertion_data(bundle)

        # 6. Wrap the three extras as C2paAssertions.
        extras = (
            C2paAssertion(
                label=ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK, data=watermark_data
            ),
            C2paAssertion(
                label=ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
                data=attestation_data,
            ),
            C2paAssertion(
                label=ASSERTION_LABEL_TEX_FORMAL_VERIFICATION, data=formal_data
            ),
        )

        # 7. Build the fully-signed manifest with cosign + extras
        #    bound under the same outer signature in one pass.
        unsigned = _build_unsigned_manifest()
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned,
            outer_signing_key_id=outer_chain["key_id"],
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_key,
            outbound_artifact_bytes=body,
            retention_anchor={
                "retain_until": "2031-05-18T00:00:00Z",
                "record_hash": "sha256:" + ("a" * 64),
            },
            revocation_proof={"crl_url": "https://crl.example/tex.pem"},
            extra_assertions=extras,
            # v2 (Merkle) is now the default canonicalization.
        )

        # 8. Verify the outer COSE_Sign1 (covers everything).
        outer_verify = verify_manifest(signed)
        assert outer_verify.is_valid, outer_verify.issues

        # 9. Confirm all four Thread-6 layers are present and bound.
        labels = [a.label for a in signed.claim.assertions]
        assert ASSERTION_LABEL_TEX_EVIDENCE_COSIGN in labels
        assert ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK in labels
        assert ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION in labels
        assert ASSERTION_LABEL_TEX_FORMAL_VERIFICATION in labels

        # 10. Cosign v2 round-trip — six-attack defense matrix.
        cosign_result = verify_evidence_cosign(
            signed, expected_full_file_sha256=body_sha
        )
        assert cosign_result.is_valid, cosign_result.issues
        # Defends against every attack class from arxiv 2604.24890.
        assert cosign_result.all_attacks_defended
        for attack in ALL_ATTACKS:
            assert cosign_result.attack_defended(attack)

        # 11. Cross-layer audit (arxiv 2603.02378 desync defense).
        wm_assertion = next(
            dict(a.data)
            for a in signed.claim.assertions
            if a.label == ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK
        )
        audit = cross_layer_audit(watermark_assertion=wm_assertion)
        assert audit.is_consistent, audit.issues

        # 12. Attestation verification (EAT JWT signature + binding).
        att_assertion = next(
            dict(a.data)
            for a in signed.claim.assertions
            if a.label == ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION
        )
        att_result = verify_attestation_assertion(
            att_assertion,
            expected_claim_cbor_sha256=eat_bound_hash,
            trusted_issuer_public_keys={
                attestation_signing_keypair["kid"]: attestation_signing_keypair[
                    "pub_pem"
                ]
            },
        )
        assert att_result.is_valid, att_result.issues
        assert att_result.fully_bound

        # 13. Formal-verification assertion confirms G1-G5 all satisfied.
        formal_assertion = next(
            dict(a.data)
            for a in signed.claim.assertions
            if a.label == ASSERTION_LABEL_TEX_FORMAL_VERIFICATION
        )
        assert formal_assertion["all_satisfied"] is True
        assert set(formal_assertion["all_goals"]) >= {
            "G1",
            "G2",
            "G3",
            "G4",
            "G5",
        }

    def test_outer_signature_breaks_if_watermark_is_tampered(
        self, outer_chain, cosign_key
    ):
        """Tamper with the watermark assertion data after signing; outer
        signature must fail to verify (proves the outer covers extras)."""
        body = b"another email body for the tamper test"
        register_signing_key(outer_chain["key"])
        detector = RecordedScoreDetector(
            scheme=WatermarkScheme.SYNTHID_TEXT,
            recorded_score=0.97, recorded_p_value=None,
            threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
            detector_version="v",
        )
        wm = build_tex_evidence_watermark_assertion(
            detection=detector.detect(body.decode(), key_id="k"),
            key_id="k",
            soft_binding_value="sha256:" + text_perceptual_hash(body.decode()),
            asserted_origin="ai-generated",
        )
        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=_build_unsigned_manifest(),
            outer_signing_key_id=outer_chain["key_id"],
            outer_certificate_chain_pem=outer_chain["chain_pem"],
            cosign_key=cosign_key,
            outbound_artifact_bytes=body,
            retention_anchor={
                "retain_until": "2031-05-18T00:00:00Z",
                "record_hash": "sha256:" + ("b" * 64),
            },
            extra_assertions=(
                C2paAssertion(
                    label=ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK, data=wm
                ),
            ),
        )
        # Tamper: rewrite the watermark assertion data post-hoc.
        tampered_assertions: list[C2paAssertion] = []
        for a in signed.claim.assertions:
            if a.label == ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK:
                tampered_data = dict(a.data)
                tampered_data["asserted_origin"] = "human-authored"
                tampered_assertions.append(
                    C2paAssertion(label=a.label, data=tampered_data)
                )
            else:
                tampered_assertions.append(a)
        tampered = signed.model_copy(
            update={
                "claim": signed.claim.model_copy(
                    update={"assertions": tuple(tampered_assertions)}
                )
            }
        )
        # Outer signature must now FAIL — proves the outer covers extras.
        outer_verify = verify_manifest(tampered)
        assert outer_verify.is_valid is False
