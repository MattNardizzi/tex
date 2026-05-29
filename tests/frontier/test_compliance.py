"""
Tests for the Tex compliance package (Thread 8).

Coverage targets per Thread 8 acceptance criteria:
  - each emit_*_evidence produces a deterministic, signed compliance
    evidence record
  - each record references a real C2PA manifest ID from Thread 6
  - each record is appended to the Thread 2 event ledger as a
    POLICY_DECISION event
  - records validate against the relevant statute's machine-readable
    schema (pydantic-emitted JSON Schema)
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tex.c2pa import (
    build_email_manifest,
    clear_signing_keys,
    register_signing_key,
    set_keystore,
    sign_manifest,
)
from tex.c2pa.manifest import C2paManifest
from tex.compliance._common import (
    Article50CumulativeCriteria,
    Article50DisclosurePayload,
    Article50MarkingLayers,
    ComplianceEvidenceRecord,
    ComplianceFramework,
    DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
    EmittedEvidence,
    FTCDisclosureTier,
    FTCSubstantiationClaim,
    FTCSubstantiationPayload,
    SB942LatentDisclosurePayload,
    SB942MediaType,
)
from tex.compliance.eu_ai_act.article_50 import (
    article_50_payload_schema,
    emit_article_50_evidence,
)
from tex.compliance.ftc.policy_statement import (
    emit_ftc_substantiation_packet,
    ftc_payload_schema,
)
from tex.compliance.state.california_sb942 import (
    emit_sb942_disclosure,
    sb942_payload_schema,
)
from tex.events import CryptoProvenance, InMemoryLedger
from tex.events._canonical import canonical_json, sha256_hex
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.ontology.event_types import EventKind
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)


# --- minimal cert plumbing for a signed C2PA manifest ------------------------
# (ported from tests/frontier/test_c2pa.py — copied locally so this file is
# self-contained; we don't import the helper from a sibling test module.)

from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _mint_chain() -> dict:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subj = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.test.ca")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_subj)
        .issuer_name(ca_subj)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subj = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex.test.signer")]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subj)
        .issuer_name(ca_subj)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=180))
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


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_keystore():
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


@pytest.fixture
def chain():
    return _mint_chain()


@pytest.fixture
def c2pa_signing_key(chain) -> SignatureKeyPair:
    kp = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ECDSA_P256,
        public_key=chain["leaf_pub_pem"],
        private_key=chain["leaf_priv_pem"],
        key_id="tex-c2pa-test-1",
    )
    register_signing_key(kp)
    return kp


@pytest.fixture
def signed_manifest(chain, c2pa_signing_key) -> C2paManifest:
    body_sha = hashlib.sha256(b"hello compliance").hexdigest()
    manifest = build_email_manifest(
        from_address="ai@vortexblack.io",
        to_addresses=("buyer@example.com",),
        subject="Compliance test",
        body_sha256=body_sha,
        model_name="claude-opus-4-7",
        model_version="2026-04-01",
        tex_verdict_id="vrd_compliance_test_001",
        created_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=UTC),
    )
    return sign_manifest(
        manifest,
        signing_key_id=c2pa_signing_key.key_id,
        certificate_chain_pem=chain["chain_pem"],
    )


@pytest.fixture
def content_hash() -> str:
    return hashlib.sha256(b"hello compliance").hexdigest()


@pytest.fixture
def ledger_keypair() -> SignatureKeyPair:
    return EcdsaP256Provider().generate_keypair("compliance-ledger-1")


@pytest.fixture
def provenance(ledger_keypair) -> CryptoProvenance:
    return CryptoProvenance(
        signing_key=ledger_keypair,
        signing_provider=EcdsaP256Provider(),
    )


@pytest.fixture
def ledger(ledger_keypair) -> InMemoryLedger:
    return InMemoryLedger(
        verifying_public_key=ledger_keypair.public_key,
        signing_provider=EcdsaP256Provider(),
    )


@pytest.fixture
def issued_at() -> datetime:
    return datetime(2026, 5, 7, 15, 0, 0, tzinfo=UTC)


# --- Article 50 --------------------------------------------------------------


def _full_compliance_layers() -> Article50MarkingLayers:
    return Article50MarkingLayers(
        digitally_signed_metadata=True,
        imperceptible_watermark=True,
        fingerprint_or_logging_fallback=True,
    )


def _full_compliance_criteria() -> Article50CumulativeCriteria:
    return Article50CumulativeCriteria(
        effective=True, interoperable=True, robust=True, reliable=True,
    )


class TestArticle50:
    def test_emit_returns_signed_record_bound_to_manifest(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )

        assert isinstance(emitted, EmittedEvidence)
        assert isinstance(emitted.record, ComplianceEvidenceRecord)
        assert emitted.record.framework is ComplianceFramework.EU_AI_ACT_ARTICLE_50
        assert emitted.record.c2pa_manifest_id == signed_manifest.claim.instance_id
        assert emitted.record.c2pa_instance_id == signed_manifest.claim.instance_id
        assert emitted.record.content_hash == content_hash
        assert emitted.record.signing_algorithm == SignatureAlgorithm.ECDSA_P256.value
        assert emitted.record.signature_b64
        assert emitted.record.record_hash
        # ledger linkage
        assert emitted.record.ledger_event_id == emitted.ledger_event.event_id
        assert emitted.record.ledger_sequence_number == 1
        assert emitted.record.ledger_record_hash == emitted.ledger_event.record_hash

    def test_emit_appends_policy_decision_to_ledger(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        assert len(ledger) == 1
        evt = ledger.stream_after(0)[0]
        assert evt.kind == EventKind.POLICY_DECISION.value
        assert evt.actor_entity_id == "agent_sdr_1"
        assert "compliance_evidence" in evt.payload
        assert ledger.verify_chain(from_sequence=1, to_sequence=1) is True

    def test_record_hash_is_deterministic_across_emits(
        self, signed_manifest, content_hash, issued_at, ledger_keypair,
    ):
        # Two independent emissions with identical inputs must produce
        # the same evidence record_hash. Signatures may differ for
        # non-deterministic schemes (ECDSA-P256 is non-deterministic by
        # default in cryptography>=42), so determinism is asserted on
        # the record hash, not the signature bytes. Both evidence_id
        # AND ledger_event_id must be pinned for full hash determinism
        # — see ``_emit_evidence`` determinism contract.
        out_a = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=InMemoryLedger(
                verifying_public_key=ledger_keypair.public_key,
                signing_provider=EcdsaP256Provider(),
            ),
            provenance=CryptoProvenance(
                signing_key=ledger_keypair,
                signing_provider=EcdsaP256Provider(),
            ),
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
            evidence_id="evd_fixed_001",
            ledger_event_id="evt_fixed_001",
        )
        out_b = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=InMemoryLedger(
                verifying_public_key=ledger_keypair.public_key,
                signing_provider=EcdsaP256Provider(),
            ),
            provenance=CryptoProvenance(
                signing_key=ledger_keypair,
                signing_provider=EcdsaP256Provider(),
            ),
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
            evidence_id="evd_fixed_001",
            ledger_event_id="evt_fixed_001",
        )
        # Same identity surface → same record hash + same ledger record hash.
        assert out_a.record.record_hash == out_b.record.record_hash
        assert out_a.record.ledger_record_hash == out_b.record.ledger_record_hash

    def test_record_hash_recomputable_from_canonical_input(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        recomputed = sha256_hex(canonical_json(emitted.record.canonical_record_input()))
        assert recomputed == emitted.record.record_hash

    def test_payload_validates_against_machine_readable_schema(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        # Re-validating against the schema via the pydantic model is
        # semantically identical to JSON Schema validation (pydantic v2
        # emits draft-2020-12 JSON Schema via model_json_schema, and
        # model_validate enforces the same constraints).
        Article50DisclosurePayload.model_validate(emitted.record.disclosure_payload)
        # Schema is non-empty + structural.
        schema = article_50_payload_schema()
        assert schema["type"] == "object"
        assert "digital_source_type" in schema["properties"]
        assert "marking_layers" in schema["properties"]
        assert "cumulative_criteria" in schema["properties"]

    def test_digital_source_type_is_iptc_trained_algorithmic(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        assert emitted.record.disclosure_payload["digital_source_type"] == (
            DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC
        )

    def test_manifest_id_mismatch_raises(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        with pytest.raises(ValueError, match="does not match"):
            emit_article_50_evidence(
                c2pa_manifest_id="wrong-id",
                content_hash=content_hash,
                manifest=signed_manifest,
                ledger=ledger,
                provenance=provenance,
                actor_entity_id="agent_sdr_1",
                marking_layers=_full_compliance_layers(),
                cumulative_criteria=_full_compliance_criteria(),
                issued_at=issued_at,
            )

    def test_unsigned_manifest_raises(
        self, ledger, provenance, content_hash, issued_at,
    ):
        unsigned = build_email_manifest(
            from_address="ai@vortexblack.io",
            to_addresses=("buyer@example.com",),
            subject="x",
            body_sha256=hashlib.sha256(b"x").hexdigest(),
            model_name="claude-opus-4-7",
            model_version="2026-04-01",
            tex_verdict_id="vrd_unsigned",
        )
        with pytest.raises(ValueError, match="must be signed"):
            emit_article_50_evidence(
                c2pa_manifest_id=unsigned.claim.instance_id,
                content_hash=content_hash,
                manifest=unsigned,
                ledger=ledger,
                provenance=provenance,
                actor_entity_id="agent_sdr_1",
                marking_layers=_full_compliance_layers(),
                cumulative_criteria=_full_compliance_criteria(),
                issued_at=issued_at,
            )

    def test_invalid_content_hash_raises(
        self, signed_manifest, ledger, provenance, issued_at,
    ):
        with pytest.raises(ValueError, match="64-character"):
            emit_article_50_evidence(
                c2pa_manifest_id=signed_manifest.claim.instance_id,
                content_hash="not-a-hash",
                manifest=signed_manifest,
                ledger=ledger,
                provenance=provenance,
                actor_entity_id="agent_sdr_1",
                marking_layers=_full_compliance_layers(),
                cumulative_criteria=_full_compliance_criteria(),
                issued_at=issued_at,
            )

    def test_payload_schema_rejects_extra_fields(self):
        # extra="forbid" is the contract — make sure it actually is.
        with pytest.raises(ValidationError):
            Article50DisclosurePayload.model_validate(
                {
                    "digital_source_type": DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
                    "marking_layers": _full_compliance_layers().model_dump(),
                    "cumulative_criteria": _full_compliance_criteria().model_dump(),
                    "rogue_field": "not allowed",
                }
            )


# --- SB 942 ------------------------------------------------------------------


def _sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at):
    return {
        "c2pa_manifest_id": signed_manifest.claim.instance_id,
        "content_hash": content_hash,
        "manifest": signed_manifest,
        "ledger": ledger,
        "provenance": provenance,
        "actor_entity_id": "agent_sdr_1",
        "covered_provider_name": "VortexBlack, Inc.",
        "genai_system_name": "Tex",
        "genai_system_version": "2.0",
        "created_or_altered_at": issued_at,
        "unique_identifier": signed_manifest.claim.instance_id,
        "media_type": SB942MediaType.IMAGE,
        "issued_at": issued_at,
    }


class TestSB942:
    def test_emit_returns_signed_record_bound_to_manifest(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at),
        )
        assert emitted.record.framework is ComplianceFramework.CA_SB942
        assert emitted.record.c2pa_manifest_id == signed_manifest.claim.instance_id
        assert emitted.record.signature_b64
        assert emitted.record.record_hash

    def test_all_four_required_fields_present(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at),
        )
        # § 22757.1(b)(1)(A)–(D) plus the unique identifier
        payload = emitted.record.disclosure_payload
        assert payload["covered_provider_name"] == "VortexBlack, Inc."
        assert payload["genai_system_name"] == "Tex"
        assert payload["genai_system_version"] == "2.0"
        assert payload["created_or_altered_at"] == issued_at.isoformat().replace("+00:00", "Z")
        assert payload["unique_identifier"] == signed_manifest.claim.instance_id

    def test_emit_appends_policy_decision_to_ledger(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at),
        )
        assert len(ledger) == 1
        evt = ledger.stream_after(0)[0]
        assert evt.kind == EventKind.POLICY_DECISION.value
        assert ledger.verify_chain(from_sequence=1, to_sequence=1) is True

    def test_payload_validates_against_machine_readable_schema(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at),
        )
        SB942LatentDisclosurePayload.model_validate(emitted.record.disclosure_payload)
        schema = sb942_payload_schema()
        assert schema["type"] == "object"
        for required in ("covered_provider_name", "genai_system_name",
                         "genai_system_version", "created_or_altered_at",
                         "unique_identifier", "media_type"):
            assert required in schema["properties"]
            assert required in schema["required"]

    def test_record_hash_is_deterministic_across_emits(
        self, signed_manifest, content_hash, issued_at, ledger_keypair,
    ):
        def fresh_pair():
            ld = InMemoryLedger(
                verifying_public_key=ledger_keypair.public_key,
                signing_provider=EcdsaP256Provider(),
            )
            pv = CryptoProvenance(
                signing_key=ledger_keypair,
                signing_provider=EcdsaP256Provider(),
            )
            return ld, pv

        ld1, pv1 = fresh_pair()
        out_a = emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ld1, pv1, content_hash, issued_at),
            evidence_id="evd_sb942_fixed",
            ledger_event_id="evt_sb942_fixed",
        )
        ld2, pv2 = fresh_pair()
        out_b = emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ld2, pv2, content_hash, issued_at),
            evidence_id="evd_sb942_fixed",
            ledger_event_id="evt_sb942_fixed",
        )
        assert out_a.record.record_hash == out_b.record.record_hash

    def test_media_type_text_not_in_enum(self):
        # SB 942 § 22757.1(b) covers image/video/audio/combined; text-only
        # is intentionally outside this module's scope.
        assert "text" not in {m.value for m in SB942MediaType}


# --- FTC §5 substantiation ---------------------------------------------------


def _ftc_claims() -> tuple[FTCSubstantiationClaim, ...]:
    return (
        FTCSubstantiationClaim(
            capability_claim="Tex adjudicates 100% of outbound AI emails.",
            disclosure_tier=FTCDisclosureTier.GENERATED,
            verdict_id="vrd_ftc_001",
            bound_manifest_id="sha256:bound-1",
            supporting_evidence_digests=("dgst_red_team_001", "dgst_eval_pack_001"),
            lifecycle_stage="post_market_monitoring",
        ),
        FTCSubstantiationClaim(
            capability_claim="Every Permit verdict carries a signed audit record.",
            disclosure_tier=FTCDisclosureTier.GENERATED,
            verdict_id="vrd_ftc_002",
            bound_manifest_id="sha256:bound-2",
            supporting_evidence_digests=("dgst_audit_chain_001",),
            lifecycle_stage="deployment",
        ),
    )


class TestFTCSubstantiation:
    def test_emit_returns_signed_record_bound_to_manifest(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_ftc_substantiation_packet(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="tex_compliance_engine",
            advertiser_entity_id="vortexblack",
            claims=_ftc_claims(),
            review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
            review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            issued_at=issued_at,
        )
        assert emitted.record.framework is ComplianceFramework.FTC_SECTION_5
        assert emitted.record.c2pa_manifest_id == signed_manifest.claim.instance_id
        assert emitted.record.signature_b64
        assert emitted.record.record_hash

    def test_packet_carries_all_claims(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_ftc_substantiation_packet(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="tex_compliance_engine",
            advertiser_entity_id="vortexblack",
            claims=_ftc_claims(),
            review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
            review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            issued_at=issued_at,
        )
        assert len(emitted.record.disclosure_payload["claims"]) == 2

    def test_emit_appends_single_policy_decision_to_ledger(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        # Acceptance criterion: each evidence record is appended as ONE
        # POLICY_DECISION event regardless of how many claims it carries.
        emit_ftc_substantiation_packet(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="tex_compliance_engine",
            advertiser_entity_id="vortexblack",
            claims=_ftc_claims(),
            review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
            review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            issued_at=issued_at,
        )
        assert len(ledger) == 1
        evt = ledger.stream_after(0)[0]
        assert evt.kind == EventKind.POLICY_DECISION.value
        assert ledger.verify_chain(from_sequence=1, to_sequence=1) is True

    def test_empty_claims_rejected(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        with pytest.raises(ValidationError):
            emit_ftc_substantiation_packet(
                c2pa_manifest_id=signed_manifest.claim.instance_id,
                content_hash=content_hash,
                manifest=signed_manifest,
                ledger=ledger,
                provenance=provenance,
                actor_entity_id="tex_compliance_engine",
                advertiser_entity_id="vortexblack",
                claims=(),
                review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
                review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
                issued_at=issued_at,
            )

    def test_payload_validates_against_machine_readable_schema(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        emitted = emit_ftc_substantiation_packet(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="tex_compliance_engine",
            advertiser_entity_id="vortexblack",
            claims=_ftc_claims(),
            review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
            review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            issued_at=issued_at,
        )
        FTCSubstantiationPayload.model_validate(emitted.record.disclosure_payload)
        schema = ftc_payload_schema()
        assert schema["type"] == "object"
        assert "claims" in schema["properties"]
        assert "advertiser_entity_id" in schema["properties"]
        assert "review_period_start" in schema["properties"]


# --- cross-cutting -----------------------------------------------------------


class TestCrossCutting:
    def test_three_emissions_chain_into_one_ledger(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        # All three frameworks emit into the same ledger, in sequence.
        # The chain must verify end-to-end.
        emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        emit_sb942_disclosure(
            **_sb942_call_kwargs(signed_manifest, ledger, provenance, content_hash, issued_at),
        )
        emit_ftc_substantiation_packet(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="tex_compliance_engine",
            advertiser_entity_id="vortexblack",
            claims=_ftc_claims(),
            review_period_start=datetime(2026, 4, 1, tzinfo=UTC),
            review_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            issued_at=issued_at,
        )

        assert len(ledger) == 3
        kinds = [e.kind for e in ledger.stream_after(0)]
        assert kinds == [EventKind.POLICY_DECISION.value] * 3
        assert ledger.verify_chain(from_sequence=1, to_sequence=3) is True

    def test_algorithm_agility_no_hardcoded_algorithm(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
    ):
        # The signing_algorithm tag on the record must come from the
        # provenance object, not a literal in the emit logic. We assert
        # this two ways:
        #   (1) the record carries the algorithm of the provider it was
        #       given (ECDSA-P256 here);
        #   (2) the emit_* modules don't string-literal an algorithm
        #       value into the record-construction call site (the only
        #       acceptable references are imports / docstrings / TODOs).
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        assert emitted.record.signing_algorithm == SignatureAlgorithm.ECDSA_P256.value

        # Architectural check: no compliance emit_* module bakes an
        # algorithm enum literal into its record construction. The only
        # place an algorithm value should appear is via the provenance's
        # signature_algorithm_for() call in _common.py.
        from pathlib import Path
        compliance_root = Path("src/tex/compliance")
        for path in compliance_root.rglob("*.py"):
            if path.name == "_common.py":
                continue  # the central dispatcher; algorithm lookup lives here
            text = path.read_text()
            # Strip docstrings / comments crudely — any remaining
            # algorithm-enum-name literal would be a hardcoded baking.
            stripped = "\n".join(
                line for line in text.splitlines()
                if not line.strip().startswith(("#", '"', "'"))
            )
            for sentinel in ("ECDSA_P256", "ML_DSA_65", "ED25519"):
                # We allow imports, but we reject standalone string
                # constants like ``"ecdsa-p256"`` in record-construction
                # code paths. This is a soft architectural fence: the
                # only place the algorithm value is allowed to be
                # *embedded* (vs derived) is _common.py.
                assert f'"{sentinel.lower().replace("_", "-")}"' not in stripped, (
                    f"hardcoded algorithm literal in {path}: {sentinel}"
                )

    def test_frontier_flag_off_blocks_emission_when_enforced(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
        monkeypatch,
    ):
        # Default: TEX_FRONTIER_COMPLIANCE is unset (off). Without
        # enforce_frontier_flag=True, emission proceeds — that's the
        # "library-friendly default" so existing pipeline + tests
        # don't need env vars.
        monkeypatch.delenv("TEX_FRONTIER_COMPLIANCE", raising=False)
        emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
        )
        # With enforce_frontier_flag=True and the flag still off,
        # emission must raise.
        with pytest.raises(RuntimeError, match="TEX_FRONTIER_COMPLIANCE"):
            emit_article_50_evidence(
                c2pa_manifest_id=signed_manifest.claim.instance_id,
                content_hash=content_hash,
                manifest=signed_manifest,
                ledger=ledger,
                provenance=provenance,
                actor_entity_id="agent_sdr_1",
                marking_layers=_full_compliance_layers(),
                cumulative_criteria=_full_compliance_criteria(),
                issued_at=issued_at,
                enforce_frontier_flag=True,
            )

    def test_frontier_flag_on_permits_emission_when_enforced(
        self, signed_manifest, ledger, provenance, content_hash, issued_at,
        monkeypatch,
    ):
        monkeypatch.setenv("TEX_FRONTIER_COMPLIANCE", "1")
        emitted = emit_article_50_evidence(
            c2pa_manifest_id=signed_manifest.claim.instance_id,
            content_hash=content_hash,
            manifest=signed_manifest,
            ledger=ledger,
            provenance=provenance,
            actor_entity_id="agent_sdr_1",
            marking_layers=_full_compliance_layers(),
            cumulative_criteria=_full_compliance_criteria(),
            issued_at=issued_at,
            enforce_frontier_flag=True,
        )
        assert emitted.record.framework is ComplianceFramework.EU_AI_ACT_ARTICLE_50

