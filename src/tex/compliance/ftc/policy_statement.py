"""
FTC §5 AI Substantiation Packet.

EO 14365 (signed 11 December 2025, "Ensuring a National Policy Framework
for Artificial Intelligence") directed the FTC Chairman to publish, within
90 days, a policy statement on the application of FTC Act §5 to AI models.
The deadline lapsed on 11 March 2026 and **the statement was not actually
published on the deadline** (per Morgan Lewis, "AI Enforcement Accelerates
as Federal Policy Stalls and States Step In", April 2026). The White House
issued a separate National Policy Framework on 20 March 2026 — legislative
recommendations, not the §5 policy statement.

What this means operationally
-----------------------------
The FTC continues to enforce §5 AI cases under existing authority — Rytr
LLC, the Air AI matter, and the Operation AI Comply sweep all proceed
under §5 without the policy statement. Tex's substantiation packet is
therefore framed against the existing §5 framework (15 U.S.C. § 45,
prohibition on unfair or deceptive acts or practices), with TODO hooks
to pin to the policy statement's specific focus areas once / if it
publishes.

Tex evidence supports defenses against
--------------------------------------
- Capability-overclaim cases (the "AI-powered" claim without substance)
- Undisclosed-AI-content cases (failure to label AI-generated material)
- Automated-decision-making transparency obligations
- AI-content disclosure failures (three-tier: generated / assisted /
  enhanced)

The packet binds each capability claim to (a) the Tex verdict that
authorized the marketing copy, (b) the C2PA manifest covering the
delivered body, and (c) any supporting evidence digests an investigator
would need to walk the substantiation chain.

References
----------
- 15 U.S.C. § 45 — FTC Act §5 (unfair or deceptive acts or practices)
- Executive Order 14365 (11 December 2025)
- White House National Policy Framework for Artificial Intelligence
  (20 March 2026) — context only, not binding
- FTC v. Rytr LLC; FTC Operation AI Comply

Priority: P0.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from tex.c2pa.manifest import C2paManifest
from tex.compliance._common import (
    ComplianceFramework,
    EmittedEvidence,
    FTCSubstantiationClaim,
    FTCSubstantiationPayload,
    _emit_evidence,
)
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger


_STATUTE_CITATION: str = "15_USC_§45_FTC_Act_§5"


def emit_ftc_substantiation_packet(
    *,
    c2pa_manifest_id: str,
    content_hash: str,
    manifest: C2paManifest,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
    actor_entity_id: str,
    advertiser_entity_id: str,
    claims: Iterable[FTCSubstantiationClaim],
    review_period_start: datetime,
    review_period_end: datetime,
    target_entity_id: str | None = None,
    section_5_basis: str = "15_USC_45_unfair_or_deceptive_acts_or_practices",
    policy_version: str | None = None,
    upstream_event_ids: tuple[str, ...] = (),
    issued_at: datetime | None = None,
    evidence_id: str | None = None,
    ledger_event_id: str | None = None,
    enforce_frontier_flag: bool = False,
) -> EmittedEvidence:
    """
    Produce an FTC substantiation packet binding Tex verdicts to the AI
    capability claims being made.

    A single packet covers 1..N capability claims for a single
    advertiser entity over a single review period. Each claim binds to:

      - a Tex ``verdict_id`` (the PERMIT/ABSTAIN/FORBID decision that
        authorized the claim being made in marketing copy)
      - a C2PA ``bound_manifest_id`` (the manifest covering the
        delivered content body)
      - 0..N supporting evidence digests (capability test results,
        red-team artifacts, training-data summaries — whatever the
        substantiation chain rests on)

    A single ``POLICY_DECISION`` event covers the whole packet so the
    audit anchor is one ledger sequence number, regardless of how many
    claims it contains.

    Parameters
    ----------
    c2pa_manifest_id
        The manifest covering the *packet-level* representative content
        (typically the marketing collateral the claims appear in).
        Per-claim manifests are in ``claims[i].bound_manifest_id``.
    content_hash
        SHA-256 hex of the bound packet-level content body.
    manifest, ledger, provenance, actor_entity_id
        See ``emit_article_50_evidence``.
    advertiser_entity_id
        The legal entity making the capability claims (e.g. the
        Tex customer's brand).
    claims
        1..N substantiation claims. Empty raises ``ValidationError``.
    review_period_start, review_period_end
        Inclusive window covered by this packet (e.g. one calendar
        quarter of marketing campaigns).
    section_5_basis
        Defaults to the canonical 15 U.S.C. § 45 citation. Pin to a
        specific policy-statement focus area if/when the FTC actually
        publishes the EO 14365 policy statement.

    TODO(P0): assemble: capability-claim audit + verdict trail + C2PA manifests
        — DONE: claims tuple binds verdict_id + bound_manifest_id +
        supporting_evidence_digests; packet binds an outer manifest +
        review window.
    TODO(spec-track): if the FTC AI policy statement publishes after
        the March 11 2026 lapse, replace ``section_5_basis`` with
        a pinned reference to the named focus area
        (AI Marketing / Consumer Data / Automated Decision-Making /
        Disclosure / Model Deletion).
    TODO(P1): wire the supporting_evidence_digests to the Thread 6
        ingredient chain so an investigator can walk from a digest to
        the source artifact in one hop.
    """
    claims_tuple = tuple(claims)
    payload = FTCSubstantiationPayload(
        claims=claims_tuple,
        advertiser_entity_id=advertiser_entity_id,
        review_period_start=review_period_start,
        review_period_end=review_period_end,
        section_5_basis=section_5_basis,
    )

    return _emit_evidence(
        framework=ComplianceFramework.FTC_SECTION_5,
        statute_citation=_STATUTE_CITATION,
        manifest=manifest,
        c2pa_manifest_id=c2pa_manifest_id,
        content_hash=content_hash,
        disclosure_payload=payload,
        ledger=ledger,
        provenance=provenance,
        actor_entity_id=actor_entity_id,
        target_entity_id=target_entity_id,
        policy_version=policy_version,
        upstream_event_ids=upstream_event_ids,
        issued_at=issued_at,
        evidence_id=evidence_id,
        ledger_event_id=ledger_event_id,
        enforce_frontier_flag=enforce_frontier_flag,
    )


def ftc_payload_schema() -> dict[str, Any]:
    """
    Return the machine-readable JSON Schema for FTC substantiation
    packet payloads.
    """
    return FTCSubstantiationPayload.model_json_schema()


__all__ = [
    "emit_ftc_substantiation_packet",
    "ftc_payload_schema",
    "FTCSubstantiationClaim",
]
