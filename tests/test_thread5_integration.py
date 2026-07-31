"""
Thread 5 integration test — EvidenceRecorder → C2PA → cosign roundtrip.

Proves the wiring claim in ``CLAIMS.md``:

> Every PERMIT verdict on an outbound AI-generated artifact produces
> an evidence record AND a C2PA 2.4 Content Credential with a
> ``tex.evidence_cosign`` post-quantum assertion that closes the
> six attack classes identified in arxiv 2604.24890.

The integration goes through the actual ``EvidenceRecorder``
public surface — no mocking of c2pa internals — so a regression in
any of the modules surfaces here.

Two channels exercised:
  1. PERMIT path  → manifest emission, mirror write, verify roundtrip
  2. FORBID path  → SCITT refusal event inlined in the evidence row
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from tex.c2pa import (
    ALL_ATTACKS,
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    clear_signing_keys,
    full_file_sha256,
    register_signing_key,
    verify_evidence_cosign,
    verify_manifest,
)
from tex.c2pa.signer import set_keystore
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.evidence.c2pa_emitter import (
    C2paEmissionContext,
    C2paEmitter,
    REFUSAL_EVENT_POST_GENERATION,
    RISK_REAL_PERSON_DEEPFAKE,
    ScittRefusalEvent,
)
from tex.evidence.recorder import EvidenceRecorder
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mint_outer_chain() -> dict:
    """Mint a CA + leaf Ed25519 chain for the outer C2PA signature."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex T5 Root")])
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
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.thread5.integration")]
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
    return {"priv_pem": priv_pem, "pub_pem": pub_pem, "chain_pem": chain_pem}


@pytest.fixture(autouse=True)
def _isolated_keystore():
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


def _make_decision(verdict: Verdict, content: bytes) -> Decision:
    body_sha = hashlib.sha256(content).hexdigest()
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.95,
        final_score=0.10 if verdict is Verdict.PERMIT else 0.85,
        action_type="email.outbound",
        channel="email",
        environment="prod",
        recipient="prospect@example.com",
        content_excerpt=content.decode("utf-8", errors="replace")[:200],
        content_sha256=body_sha,
        policy_version="thread5.integration.v1",
        scores={"deterministic": 0.0, "semantic": 0.05},
        reasons=["thread5-integration-test"],
        uncertainty_flags=[] if verdict is Verdict.PERMIT else ["forbid-reason"],
        decided_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# PERMIT path — full manifest + cosign roundtrip through EvidenceRecorder
# ---------------------------------------------------------------------------


def test_permit_emits_manifest_with_cosign_through_recorder(tmp_path: Path):
    """End-to-end: Decision → EvidenceRecorder.record_decision → C2PA manifest.

    Verifies that:

      1. The evidence row carries the outbound-artifact SHA-256 and the
         manifest hash in the payload.
      2. A real C2PA outer signature is produced (round-trips via
         ``verify_manifest``).
      3. A real PQ-track cosign assertion is produced and all five
         attack defenses verify (``verify_evidence_cosign``).
    """
    outer = _mint_outer_chain()
    outer_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=outer["pub_pem"],
        private_key=outer["priv_pem"],
        key_id="thread5-integration-outer",
    )
    register_signing_key(outer_key)

    cosign_key = Ed25519Provider().generate_keypair("thread5-integration-cosign")

    # Capture the manifest written to the mirror so we can re-verify.
    captured: dict[str, dict] = {}

    class _CapturingMirror:
        def record(self, **kwargs):
            captured[str(kwargs["record_id"])] = kwargs

        def fetch_by_record_id(self, record_id):
            return captured.get(str(record_id))

    recorder = EvidenceRecorder(
        path=tmp_path / "evidence.jsonl",
        c2pa_emitter=C2paEmitter(),
        manifest_mirror=_CapturingMirror(),
    )
    assert recorder.has_c2pa_emitter is True

    body = b"Hello recruiter, this is an AI-generated email body for Thread 5 integration."
    decision = _make_decision(Verdict.PERMIT, body)

    context = C2paEmissionContext(
        outer_signing_key_id="thread5-integration-outer",
        outer_certificate_chain_pem=outer["chain_pem"],
        cosign_key=cosign_key,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Re: Tex pilot",
        tenant_id="vortexblack",
        revocation_proof={
            "kind": "crl_snapshot_pin",
            "sha256": "b" * 64,
            "issued_at": "2026-05-18T00:00:00+00:00",
        },
    )

    record = recorder.record_decision(
        decision,
        outbound_artifact=body,
        c2pa_context=context,
    )

    # ----- Evidence payload assertions -----
    payload = json.loads(record.payload_json)
    assert payload["verdict"] == "PERMIT"
    assert payload["outbound_artifact"]["sha256"] == hashlib.sha256(body).hexdigest()
    assert payload["outbound_artifact"]["byte_length"] == len(body)
    assert "c2pa" in payload, "PERMIT with outbound_artifact must record c2pa block"
    c2pa_block = payload["c2pa"]
    assert c2pa_block["has_cosign"] is True
    assert c2pa_block["cosign_algorithm"] == "ed25519"
    assert c2pa_block["canonicalization_version"] in (
        "tex.evidence_cosign/v1",
        "tex.evidence_cosign/v2",
    ), c2pa_block["canonicalization_version"]
    assert c2pa_block["full_file_sha256"] == full_file_sha256(body)
    assert len(c2pa_block["manifest_hash"]) == 64

    # ----- Mirror row assertions -----
    assert str(record.evidence_id) in captured, "Manifest must be mirrored"
    mirror_row = captured[str(record.evidence_id)]
    assert mirror_row["tenant_id"] == "vortexblack"
    assert mirror_row["manifest_row"]["has_cosign"] is True
    assert ASSERTION_LABEL_TEX_EVIDENCE_COSIGN in mirror_row["manifest_row"][
        "assertion_labels"
    ]

    # ----- Manifest round-trip (verify outer + cosign offline) -----
    # Re-build the C2paManifest from the stored CBOR claim and outer signature.
    import base64

    from tex.c2pa._cbor import decode as cbor_decode
    from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paManifest

    claim_cbor = base64.b64decode(mirror_row["manifest_row"]["claim_cbor_b64"])
    decoded_claim_map = cbor_decode(claim_cbor)
    # The canonical claim CBOR is a map; rebuild the Pydantic shell.
    assertions = tuple(
        C2paAssertion(label=a["label"], data=a["data"])
        for a in decoded_claim_map["assertions"]
    )
    rebuilt = C2paManifest(
        claim=C2paClaim(
            title=decoded_claim_map["title"],
            format=decoded_claim_map["format"],
            instance_id=decoded_claim_map["instance_id"],
            claim_generator=decoded_claim_map["claim_generator"],
            claim_generator_info=decoded_claim_map["claim_generator_info"],
            created_at=datetime.fromisoformat(decoded_claim_map["created_at"]),
            assertions=assertions,
        ),
        signature_b64=mirror_row["manifest_row"]["outer_signature_b64"],
        certificate_chain_pem=mirror_row["manifest_row"]["certificate_chain_pem"],
    )

    outer_result = verify_manifest(rebuilt)
    assert outer_result.is_valid, (
        f"Outer C2PA signature must verify; issues={outer_result.issues}"
    )

    cosign_result = verify_evidence_cosign(
        rebuilt,
        expected_full_file_sha256=full_file_sha256(body),
    )
    assert cosign_result.is_valid, (
        f"Cosign must verify; issues={cosign_result.issues}"
    )
    # All five NSA-paper attack defenses must be satisfied.
    for attack in ALL_ATTACKS:
        assert cosign_result.attack_defended(attack), (
            f"defense for {attack!r} must be satisfied in round-trip"
        )


def test_permit_without_outbound_artifact_skips_c2pa(tmp_path: Path):
    """A bare PERMIT with no outbound_artifact must NOT emit a manifest.

    This protects 2,200+ existing tests from any unintended C2PA wire-up.
    """
    recorder = EvidenceRecorder(
        path=tmp_path / "evidence.jsonl",
        c2pa_emitter=C2paEmitter(),
    )
    decision = _make_decision(Verdict.PERMIT, b"x")
    record = recorder.record_decision(decision)
    payload = json.loads(record.payload_json)
    assert "c2pa" not in payload
    assert "outbound_artifact" not in payload


# ---------------------------------------------------------------------------
# FORBID path — SCITT refusal event inlined
# ---------------------------------------------------------------------------


def test_forbid_emits_scitt_refusal_event(tmp_path: Path):
    """FORBID with a refusal_event inlines the SCITT taxonomy in the payload."""
    recorder = EvidenceRecorder(
        path=tmp_path / "evidence.jsonl",
        c2pa_emitter=C2paEmitter(),
    )
    body = b"AI-generated content the policy forbade."
    decision = _make_decision(Verdict.FORBID, body)

    refusal = ScittRefusalEvent(
        event_type=REFUSAL_EVENT_POST_GENERATION,
        risk_category=RISK_REAL_PERSON_DEEPFAKE,
        rationale="output appeared to depict a real public figure",
        issued_at=datetime.now(tz=timezone.utc),
        issuer="vortexblack",
    )
    context = C2paEmissionContext(refusal_event=refusal)
    record = recorder.record_decision(
        decision,
        outbound_artifact=body,
        c2pa_context=context,
    )
    payload = json.loads(record.payload_json)
    assert payload["verdict"] == "FORBID"
    # FORBID does NOT emit a C2PA manifest (no PERMIT → no signed asset).
    assert "c2pa" not in payload
    # SCITT refusal event is inlined.
    assert "scitt" in payload
    scitt = payload["scitt"]
    assert scitt["spec"] == "draft-kamimura-scitt-refusal-events-02"
    assert scitt["refusal_event"]["event_type"] == REFUSAL_EVENT_POST_GENERATION
    assert scitt["refusal_event"]["risk_category"] == RISK_REAL_PERSON_DEEPFAKE
    assert scitt["refusal_event"]["issuer"] == "vortexblack"


def test_forbid_with_no_refusal_event_still_records(tmp_path: Path):
    """A bare FORBID is recorded normally; SCITT block only on opt-in."""
    recorder = EvidenceRecorder(
        path=tmp_path / "evidence.jsonl",
        c2pa_emitter=C2paEmitter(),
    )
    decision = _make_decision(Verdict.FORBID, b"x")
    record = recorder.record_decision(decision)
    payload = json.loads(record.payload_json)
    assert payload["verdict"] == "FORBID"
    assert "scitt" not in payload


# ---------------------------------------------------------------------------
# Negative: tampering the artifact bytes makes verify fail
# ---------------------------------------------------------------------------


def test_tampering_outbound_artifact_breaks_verification(tmp_path: Path):
    """If a verifier downstream is handed tampered bytes, the cosign must
    flag the mismatch.

    This is the auditor-facing invariant in the brief: an attacker who
    swaps the asset cannot keep the manifest's defenses claim valid.
    """
    outer = _mint_outer_chain()
    outer_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=outer["pub_pem"],
        private_key=outer["priv_pem"],
        key_id="thread5-tamper-outer",
    )
    register_signing_key(outer_key)
    cosign_key = Ed25519Provider().generate_keypair("thread5-tamper-cosign")

    captured: dict[str, dict] = {}

    class _Mirror:
        def record(self, **kwargs):
            captured[str(kwargs["record_id"])] = kwargs

        def fetch_by_record_id(self, record_id):
            return captured.get(str(record_id))

    recorder = EvidenceRecorder(
        path=tmp_path / "evidence.jsonl",
        c2pa_emitter=C2paEmitter(),
        manifest_mirror=_Mirror(),
    )
    body = b"the original artifact"
    decision = _make_decision(Verdict.PERMIT, body)

    context = C2paEmissionContext(
        outer_signing_key_id="thread5-tamper-outer",
        outer_certificate_chain_pem=outer["chain_pem"],
        cosign_key=cosign_key,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Re: Tex pilot",
        revocation_proof={
            "kind": "crl_snapshot_pin",
            "sha256": "b" * 64,
        },
    )
    record = recorder.record_decision(
        decision,
        outbound_artifact=body,
        c2pa_context=context,
    )
    mirror_row = captured[str(record.evidence_id)]

    # Rebuild manifest, then verify against TAMPERED bytes.
    import base64

    from tex.c2pa._cbor import decode as cbor_decode
    from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paManifest

    claim_cbor = base64.b64decode(mirror_row["manifest_row"]["claim_cbor_b64"])
    decoded_claim_map = cbor_decode(claim_cbor)
    assertions = tuple(
        C2paAssertion(label=a["label"], data=a["data"])
        for a in decoded_claim_map["assertions"]
    )
    rebuilt = C2paManifest(
        claim=C2paClaim(
            title=decoded_claim_map["title"],
            format=decoded_claim_map["format"],
            instance_id=decoded_claim_map["instance_id"],
            claim_generator=decoded_claim_map["claim_generator"],
            claim_generator_info=decoded_claim_map["claim_generator_info"],
            created_at=datetime.fromisoformat(decoded_claim_map["created_at"]),
            assertions=assertions,
        ),
        signature_b64=mirror_row["manifest_row"]["outer_signature_b64"],
        certificate_chain_pem=mirror_row["manifest_row"]["certificate_chain_pem"],
    )

    tampered_body = b"the tampered artifact with injected metadata"
    cosign_result = verify_evidence_cosign(
        rebuilt,
        expected_full_file_sha256=full_file_sha256(tampered_body),
    )
    # Outer signature still verifies — the manifest itself wasn't touched.
    # But the cosign's full_file_sha256 doesn't match the tampered body.
    from tex.c2pa.cosign_verifier import ISSUE_COSIGN_FULL_FILE_HASH_MISMATCH

    assert ISSUE_COSIGN_FULL_FILE_HASH_MISMATCH in cosign_result.issues
