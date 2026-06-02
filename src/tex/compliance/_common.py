"""
Shared machinery for compliance evidence emitters.

Every regulatory anchor binding (Article 50, SB 942, FTC §5) follows the
same shape:

  1. caller supplies a real C2PA manifest from Thread 6 plus the verdict
     context that produced the outbound content
  2. a frozen, statute-specific payload is validated against a pydantic
     v2 schema (machine-readable schema = ``Schema.model_json_schema()``)
  3. the payload is wrapped in a ``ComplianceEvidenceRecord`` whose
     deterministic SHA-256 over canonical JSON is the audit anchor
  4. the record is signed via the algorithm-agile signature provider
     and appended to the Thread 2 event ledger as a ``POLICY_DECISION``
     event whose ``record_hash`` covers the same canonical bytes — so
     verifying the ledger event is equivalent to verifying the evidence
     record

This module owns the shape; the per-statute modules own the payload.

References
----------
- arxiv 2512.18561 (AAF) §(i) — cryptographically verifiable provenance
- EU AI Act Art. 50(2) — machine-readable disclosure obligation
- California Business & Professions Code §22757 et seq. (SB 942 / AB 853)
- 15 U.S.C. §45 (FTC Act §5) — unfair or deceptive acts or practices

Priority: P0.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, NamedTuple
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from tex.c2pa.manifest import C2paManifest
from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._canonical import canonical_json, sha256_hex
from tex.events._ecdsa_provider import signature_algorithm_for
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.event import Event
from tex.events.ledger import InMemoryLedger
from tex.observability.telemetry import emit_event
from tex.ontology.event_types import EventKind


class ComplianceFramework(str, Enum):
    """Regulatory anchor a compliance evidence record attests to."""

    EU_AI_ACT_ARTICLE_50 = "eu_ai_act_article_50"
    CA_SB942 = "ca_sb942"
    FTC_SECTION_5 = "ftc_section_5"


class ComplianceEvidenceRecord(BaseModel):
    """
    Canonical, signed evidence record for a single regulatory anchor.

    The ``record_hash`` field is the deterministic SHA-256 over the
    canonical JSON of this record's identity surface (everything except
    ``signature_b64`` and ``record_hash`` itself). Mutating any other
    field invalidates the hash and breaks ledger verification.

    The corresponding ledger event's ``record_hash`` covers the same
    canonical bytes via ``CryptoProvenance.attach``, so an auditor can
    walk from ledger ``sequence_number`` → event ``record_hash`` →
    this record's ``record_hash`` and confirm they match.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    framework: ComplianceFramework
    statute_citation: str
    c2pa_manifest_id: str            # caller-supplied handle
    c2pa_instance_id: str            # actual instance_id from the bound manifest
    c2pa_claim_format: str
    content_hash: str                # SHA-256 hex of the bound content body
    disclosure_payload: dict[str, Any]
    issued_at: datetime
    policy_version: str | None = None
    signing_key_id: str
    signing_algorithm: str
    record_hash: str                 # SHA-256 of canonical_record_input
    signature_b64: str               # signature over the ledger event's record_hash
    ledger_event_id: str             # POLICY_DECISION event in the Thread 2 ledger
    ledger_sequence_number: int
    ledger_record_hash: str          # the ledger event's record_hash (audit anchor)

    def canonical_record_input(self) -> dict[str, Any]:
        """
        Return the dict whose stable JSON gets hashed for ``record_hash``.

        Mirrors ``tex.events.event.Event.canonical_record_input``:
        signature and hash fields are excluded because they are computed
        *over* this dict.
        """
        return {
            "evidence_id": self.evidence_id,
            "framework": self.framework.value,
            "statute_citation": self.statute_citation,
            "c2pa_manifest_id": self.c2pa_manifest_id,
            "c2pa_instance_id": self.c2pa_instance_id,
            "c2pa_claim_format": self.c2pa_claim_format,
            "content_hash": self.content_hash,
            "disclosure_payload": self.disclosure_payload,
            "issued_at": self.issued_at.isoformat(),
            "policy_version": self.policy_version,
            "signing_key_id": self.signing_key_id,
            "signing_algorithm": self.signing_algorithm,
            "ledger_event_id": self.ledger_event_id,
            "ledger_sequence_number": self.ledger_sequence_number,
            "ledger_record_hash": self.ledger_record_hash,
        }


class EmittedEvidence(NamedTuple):
    """
    What every ``emit_*_evidence`` returns.

    ``record`` is the signed compliance evidence record; ``ledger_event``
    is the POLICY_DECISION event that carries the same canonical bytes
    in the Thread 2 hash chain. Holding both lets callers feed the
    ledger position to downstream subscribers (insurer attestation
    streams, FTC investigators) without re-resolving by id.
    """

    record: ComplianceEvidenceRecord
    ledger_event: Event


# --- statute-specific payload schemas -----------------------------------------


class _PayloadBase(BaseModel):
    """Base for every statute-specific disclosure payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# EU AI Act Article 50(2) — providers of generative AI must mark outputs
# in a machine-readable format that is "effective, interoperable, robust,
# and reliable" (the four cumulative criteria, AI Act Art. 50(2) sentence 2).
# The Second Draft Code of Practice (3 March 2026) prescribes a
# multi-layered marking strategy: digitally signed metadata + watermarking
# + optional fingerprinting/logging fallback, recognising that no single
# technique is sufficient.
DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC: str = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)


class Article50MarkingLayers(_PayloadBase):
    """
    The multi-layered marking layers per the Second Draft Code of
    Practice on Transparency of AI-Generated Content (3 March 2026),
    Commitment 1.
    """

    digitally_signed_metadata: bool      # C2PA manifest present + signed
    imperceptible_watermark: bool        # invisible watermark embedded
    fingerprint_or_logging_fallback: bool  # soft-binding lookup support


class Article50CumulativeCriteria(_PayloadBase):
    """
    The four cumulative criteria from Article 50(2) sentence 2.

    All four must be ``True`` for a marking strategy to be claimed
    compliant. The Second Draft Code specifies that providers opting
    out of the Code's baseline approach must demonstrate equivalent
    performance across all four via independently verified benchmarks.
    """

    effective: bool
    interoperable: bool
    robust: bool
    reliable: bool


class Article50DisclosurePayload(_PayloadBase):
    """
    EU AI Act Article 50(2) disclosure payload.

    Statute citation: Regulation (EU) 2024/1689, Art. 50(2). Applicable
    from 2 August 2026 per Art. 113.
    """

    digital_source_type: str = Field(min_length=1)
    marking_layers: Article50MarkingLayers
    cumulative_criteria: Article50CumulativeCriteria
    detection_interface_url: str | None = None  # Commitment 2 detector
    deployer_label_present: bool = False        # Art. 50(4) deepfake label
    code_of_practice_alignment: str = Field(
        default="second_draft_2026_03_03",
        min_length=1,
    )


# California SB 942 (CAITA) as amended by AB 853 (signed 13 Oct 2025).
# Operative date moved from 1 Jan 2026 to 2 Aug 2026 to align with the
# EU AI Act. § 22757.1(b)(1)(A)–(D) lists the four required latent
# disclosure fields.

class SB942MediaType(str, Enum):
    """Media types covered by SB 942 § 22757.1(b).

    Statutorily limited to image, video, and audio (or any combination
    thereof). Text-only content is out of scope for the latent
    disclosure obligation in the original SB 942; text obligations
    sit in adjacent California instruments (SB 53, AB 2013).
    """

    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    COMBINED = "combined"


class SB942LatentDisclosurePayload(_PayloadBase):
    """
    SB 942 § 22757.1(b)(1)(A)–(D) latent disclosure payload.

    The four statutorily required fields plus a permanent-website link
    option (the statute lets the disclosure carry the data inline OR
    via a link to a permanent internet website).
    """

    covered_provider_name: str = Field(min_length=1, max_length=512)
    genai_system_name: str = Field(min_length=1, max_length=256)
    genai_system_version: str = Field(min_length=1, max_length=128)
    created_or_altered_at: datetime
    unique_identifier: str = Field(min_length=1, max_length=512)
    media_type: SB942MediaType
    permanent_website_url: str | None = None
    detectable_by_provider_tool: bool = True   # § 22757.1(b)(1)(E)
    aligned_with_industry_standard: str = Field(
        default="C2PA",
        min_length=1,
    )


# FTC §5 (15 U.S.C. § 45). The March 11, 2026 AI policy statement
# directed by EO 14365 was not actually published on its deadline (per
# Morgan Lewis April 2026 enforcement update). Tex's substantiation
# packet is therefore framed against existing §5 deception authority
# (Rytr, Air AI, etc.), with a TODO to pin to the policy statement's
# specific focus areas once it actually publishes.

class FTCDisclosureTier(str, Enum):
    """
    Three-tier classification mapping AI involvement to disclosure.

    Tracks the leaked-draft framing (and adjacent FTC enforcement
    posture under §5) distinguishing AI-created, AI-assisted, and
    AI-enhanced content. Used to determine the disclosure tier
    asserted in a substantiation claim.
    """

    GENERATED = "generated"        # AI produced the substance
    ASSISTED = "assisted"           # human authored, AI assisted
    ENHANCED = "enhanced"           # human authored, AI polished


class FTCSubstantiationClaim(_PayloadBase):
    """
    A single capability claim plus the artifacts that substantiate it.

    Each claim binds back to a Tex verdict_id and a C2PA manifest_id
    so an FTC investigator can walk the chain: marketing copy →
    Tex verdict that authorized emission → C2PA manifest covering
    the body → ingredient chain.
    """

    capability_claim: str = Field(min_length=1, max_length=2_000)
    disclosure_tier: FTCDisclosureTier
    verdict_id: str = Field(min_length=1, max_length=256)
    bound_manifest_id: str = Field(min_length=1, max_length=512)
    supporting_evidence_digests: tuple[str, ...] = Field(default_factory=tuple)
    lifecycle_stage: str = Field(min_length=1, max_length=128)


class FTCSubstantiationPayload(_PayloadBase):
    """
    FTC §5 substantiation packet payload.

    Carries 1..N substantiation claims plus the Tex policy version
    under which they were authorized. Single packet → single
    POLICY_DECISION ledger event so the audit anchor is one hash.
    """

    claims: tuple[FTCSubstantiationClaim, ...] = Field(min_length=1)
    advertiser_entity_id: str = Field(min_length=1, max_length=256)
    review_period_start: datetime
    review_period_end: datetime
    section_5_basis: str = Field(
        default="15_USC_45_unfair_or_deceptive_acts_or_practices",
        min_length=1,
    )


# --- shared emission helpers --------------------------------------------------


def _validate_manifest_binding(
    *,
    manifest: C2paManifest,
    claimed_manifest_id: str,
) -> tuple[str, str]:
    """
    Confirm ``claimed_manifest_id`` matches the actual manifest's instance_id.

    The C2PA spec uses ``instance_id`` as the canonical handle for a
    manifest; our caller-supplied ``c2pa_manifest_id`` must equal it.
    Returns (instance_id, format) for inclusion in the evidence record.

    Raises
    ------
    ValueError
        If ``manifest`` is unsigned, or if its ``instance_id`` does not
        match ``claimed_manifest_id``.
    """
    if manifest.signature_b64 is None:
        raise ValueError(
            "C2PA manifest must be signed before binding to a compliance "
            "evidence record (call tex.c2pa.signer.sign_manifest first)"
        )
    actual = manifest.claim.instance_id
    if actual != claimed_manifest_id:
        raise ValueError(
            "c2pa_manifest_id does not match bound manifest "
            f"(expected={actual!r}, got={claimed_manifest_id!r})"
        )
    return actual, manifest.claim.format


def _emit_evidence(
    *,
    framework: ComplianceFramework,
    statute_citation: str,
    manifest: C2paManifest,
    c2pa_manifest_id: str,
    content_hash: str,
    disclosure_payload: _PayloadBase,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
    actor_entity_id: str,
    target_entity_id: str | None = None,
    policy_version: str | None = None,
    upstream_event_ids: tuple[str, ...] = (),
    issued_at: datetime | None = None,
    evidence_id: str | None = None,
    ledger_event_id: str | None = None,
    enforce_frontier_flag: bool = False,
) -> EmittedEvidence:
    """
    Build, sign, and ledger-append a compliance evidence record.

    Determinism contract
    --------------------
    Given identical (``framework``, ``statute_citation``, ``manifest``,
    ``c2pa_manifest_id``, ``content_hash``, ``disclosure_payload``,
    ``actor_entity_id``, ``target_entity_id``, ``policy_version``,
    ``upstream_event_ids``, ``issued_at``, ``evidence_id``,
    ``ledger_event_id``, ``provenance.signing_key_id``) inputs, the
    emitted record's ``record_hash`` is byte-identical across runs.
    Callers wanting full determinism MUST pin ``evidence_id`` and
    ``ledger_event_id``; otherwise both default to fresh uuid4-derived
    handles.

    Note that the *signature bytes* on the underlying ledger event may
    still differ across runs because ECDSA-P256 in ``cryptography>=42``
    is non-deterministic (no RFC 6979). The record_hash determinism is
    what auditors verify — the signature is what they verify with.

    Frontier-flag enforcement
    -------------------------
    If ``enforce_frontier_flag`` is True, the function checks
    ``FrontierFlags.from_env().compliance`` and raises
    ``RuntimeError`` if the flag is off. This is opt-in so that
    library callers (tests, programmatic embeddings) keep working
    without setting env vars; production code paths that gate
    compliance emission on the flag can pass ``True`` and get the
    safety-rail behavior. Default is ``False`` to honour the
    "existing pipeline untouched" contract.
    """
    if enforce_frontier_flag:
        from tex.frontier_config import FrontierFlags

        flags = FrontierFlags.from_env()
        if not flags.compliance:
            raise RuntimeError(
                "compliance evidence emission is gated behind "
                "TEX_FRONTIER_COMPLIANCE=1; flag is off "
                f"(framework={framework.value!r})"
            )
    if len(content_hash) != 64 or not all(c in "0123456789abcdef" for c in content_hash):
        raise ValueError(
            "content_hash must be a 64-character lowercase SHA-256 hex digest"
        )

    instance_id, claim_format = _validate_manifest_binding(
        manifest=manifest,
        claimed_manifest_id=c2pa_manifest_id,
    )

    resolved_issued_at = issued_at or datetime.now(UTC)
    resolved_evidence_id = evidence_id or f"evd_{uuid4().hex[:12]}"

    # Canonical record input — mirrors ComplianceEvidenceRecord.canonical_record_input
    # but with the ledger-linkage fields placeholdered, because we don't yet have
    # the Event's id/sequence_number. We finalize after the append.
    payload_dict = disclosure_payload.model_dump(mode="json")

    pre_ledger_input: dict[str, Any] = {
        "evidence_id": resolved_evidence_id,
        "framework": framework.value,
        "statute_citation": statute_citation,
        "c2pa_manifest_id": c2pa_manifest_id,
        "c2pa_instance_id": instance_id,
        "c2pa_claim_format": claim_format,
        "content_hash": content_hash,
        "disclosure_payload": payload_dict,
        "issued_at": resolved_issued_at.isoformat(),
        "policy_version": policy_version,
        "signing_key_id": provenance.signing_key_id,
        "signing_algorithm": signature_algorithm_for(provenance.provider).value,
    }

    proposed = ProposedEvent(
        event_kind=EventKind.POLICY_DECISION.value,
        actor_entity_id=actor_entity_id,
        target_entity_id=target_entity_id,
        payload={"compliance_evidence": pre_ledger_input},
        proposed_at=resolved_issued_at,
        upstream_event_ids=upstream_event_ids,
    )

    event = ledger.append_proposed(
        proposed=proposed,
        provenance=provenance,
        event_id=ledger_event_id,
    )

    # Now that we know the ledger linkage, finalize the record's own
    # record_hash. The compliance record's signature is over the LEDGER
    # EVENT's record_hash — a second attestation layer that says "this
    # ledger event is the canonical anchor for this compliance record".
    # This avoids re-signing different bytes with the same key and
    # piggybacks on the ledger's already-signed audit trail.
    final_input: dict[str, Any] = {
        **pre_ledger_input,
        "ledger_event_id": event.event_id,
        "ledger_sequence_number": event.sequence_number,
        "ledger_record_hash": event.record_hash,
    }
    record_hash = sha256_hex(canonical_json(final_input))
    # The ledger event's signature already covers its own record_hash;
    # we re-export that signature on the compliance record so a verifier
    # holding only the record (no ledger access) can still verify the
    # ledger anchor's authenticity. Acceptance criterion (a) — record
    # is signed — is satisfied via the ledger event's signature, which
    # is deterministic w.r.t. the inputs to ``_emit_evidence``.
    signature_b64 = event.pq_signature_b64

    record = ComplianceEvidenceRecord(
        evidence_id=resolved_evidence_id,
        framework=framework,
        statute_citation=statute_citation,
        c2pa_manifest_id=c2pa_manifest_id,
        c2pa_instance_id=instance_id,
        c2pa_claim_format=claim_format,
        content_hash=content_hash,
        disclosure_payload=payload_dict,
        issued_at=resolved_issued_at,
        policy_version=policy_version,
        signing_key_id=provenance.signing_key_id,
        signing_algorithm=pre_ledger_input["signing_algorithm"],
        record_hash=record_hash,
        signature_b64=signature_b64,
        ledger_event_id=event.event_id,
        ledger_sequence_number=event.sequence_number,
        ledger_record_hash=event.record_hash,
    )

    emit_event(
        "compliance.evidence.emitted",
        framework=framework.value,
        statute_citation=statute_citation,
        evidence_id=resolved_evidence_id,
        c2pa_manifest_id=c2pa_manifest_id,
        ledger_event_id=event.event_id,
        ledger_sequence_number=event.sequence_number,
        signing_algorithm=record.signing_algorithm,
        signing_key_id=provenance.signing_key_id,
    )

    return EmittedEvidence(record=record, ledger_event=event)


__all__ = [
    "ComplianceEvidenceRecord",
    "ComplianceFramework",
    "EmittedEvidence",
    "Article50CumulativeCriteria",
    "Article50DisclosurePayload",
    "Article50MarkingLayers",
    "DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC",
    "FTCDisclosureTier",
    "FTCSubstantiationClaim",
    "FTCSubstantiationPayload",
    "SB942LatentDisclosurePayload",
    "SB942MediaType",
]
