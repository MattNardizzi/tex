"""
California SB 942 — California AI Transparency Act (CAITA), as amended by
AB 853 (signed 13 October 2025).

Operative date moved from 1 January 2026 to **2 August 2026** by AB 853 to
align with the EU AI Act application date. As of May 2026 the latent
disclosure obligation is not yet operative; Tex emits compliant evidence
ahead of the 2 August 2026 enforcement date so customers ship with
provenance from day one.

§ 22757.1(b)(1)(A)–(D) latent disclosure required fields
--------------------------------------------------------
A latent disclosure embedded in image / video / audio / combined-media
content must convey, either inline or via a permanent-website link, all
of the following:

  (A) name of the covered provider
  (B) name of the GenAI system
  (C) version of the GenAI system that created or altered the content
  (D) time and date of the content's creation or alteration
  (E) unique identifier

It must additionally be detectable by the provider's AI detection tool
(§ 22757.1(b)(1)(E) cross-reference) and aligned with generally accepted
industry standards (C2PA being the canonical referent).

AB 853 expansions (NOT yet implemented in this module — see TODO list)
----------------------------------------------------------------------
- Large online platform obligations effective 1 January 2027
- GenAI hosting platform obligations effective 1 January 2027
- Capture device manufacturer obligations effective 1 January 2028

Penalties
---------
$5,000 per violation, per day. Civil action by the California Attorney
General, city attorney, or county counsel.

References
----------
- California Business & Professions Code § 22757 et seq.
- AB 853 (Oct 2025) — amends SB 942
- C2PA Specification 2.x
- IPTC ``digitalSourceType`` controlled vocabulary

Priority: P0.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tex.c2pa.manifest import C2paManifest
from tex.compliance._common import (
    ComplianceFramework,
    EmittedEvidence,
    SB942LatentDisclosurePayload,
    SB942MediaType,
    _emit_evidence,
)
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger


_STATUTE_CITATION: str = "Cal_Bus_&_Prof_Code_§22757.1(b)(1)"


def emit_sb942_disclosure(
    *,
    c2pa_manifest_id: str,
    content_hash: str,
    manifest: C2paManifest,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
    actor_entity_id: str,
    covered_provider_name: str,
    genai_system_name: str,
    genai_system_version: str,
    created_or_altered_at: datetime,
    unique_identifier: str,
    media_type: SB942MediaType,
    target_entity_id: str | None = None,
    permanent_website_url: str | None = None,
    detectable_by_provider_tool: bool = True,
    aligned_with_industry_standard: str = "C2PA",
    policy_version: str | None = None,
    upstream_event_ids: tuple[str, ...] = (),
    issued_at: datetime | None = None,
    evidence_id: str | None = None,
    ledger_event_id: str | None = None,
    enforce_frontier_flag: bool = False,
) -> EmittedEvidence:
    """
    Produce an SB 942 § 22757.1(b)(1) latent disclosure evidence record.

    The record asserts that the four statutorily required fields plus
    the detection-tool / industry-standard requirements are satisfied
    for one piece of AI-generated image, video, audio, or combined
    media content. Like Article 50, the record:

      - binds to a real, signed C2PA manifest from Thread 6
      - is signed via the algorithm-agile provider on ``provenance``
      - is appended to the Thread 2 event ledger as a single
        ``POLICY_DECISION`` event

    SB 942 § 22757.1(b) applies only to image/video/audio/combined media
    — NOT text-only. Text obligations sit in adjacent California
    instruments (SB 53, AB 2013). Callers passing text-only content
    should use those modules instead.

    Parameters
    ----------
    c2pa_manifest_id
        Must equal ``manifest.claim.instance_id``.
    content_hash
        SHA-256 hex of the bound content body.
    manifest, ledger, provenance, actor_entity_id
        See ``emit_article_50_evidence``.
    covered_provider_name
        Statutory field § 22757.1(b)(1)(A). The legal name of the
        covered provider (e.g. ``"VortexBlack, Inc."``).
    genai_system_name, genai_system_version
        Statutory fields § 22757.1(b)(1)(B)/(C). Should match the
        ``softwareAgent`` block on the bound C2PA actions assertion.
    created_or_altered_at
        Statutory field § 22757.1(b)(1)(D). Should match the C2PA
        claim's ``created_at`` / actions ``when`` value.
    unique_identifier
        Statutory field § 22757.1(b)(1)(E). A globally unique
        identifier for this content instance — using the C2PA
        ``instance_id`` is acceptable and the simplest mapping.
    media_type
        Which subset of § 22757.1(b) the content falls under.
    permanent_website_url
        Optional. The statute permits the four fields to be carried
        either inline OR via a link to a permanent internet website;
        a non-None value asserts the latter.
    detectable_by_provider_tool
        Asserts the latent disclosure is detectable by the covered
        provider's free AI detection tool (§ 22757(a)).

    Notes on completed wiring:

    - **SB 942 disclosure record bound to C2PA manifest (wired):**
      C2PA manifest binding + four required fields (covered_provider_name,
      genai_system_name+version, created_or_altered_at, unique_identifier)
      + media_type + permanent-website-link option + detection-tool flag.

    Tracking notes (future statutory phases):

    - **TODO(AB-853-2027):** emit large-online-platform redistribution record
      when AB 853 extension obligations come into force on 1 January 2027
      (provenance-data detection + UI display + user-inspect).
    - **TODO(AB-853-2028):** emit capture-device manufacturer attestation
      when AB 853 extension obligations come into force on 1 January 2028.
    - **TODO(spec-track):** if the California AG publishes implementing
      regulations naming a specific industry standard (currently
      ``"C2PA"`` is a sensible default), pin to the named standard.
    """
    payload = SB942LatentDisclosurePayload(
        covered_provider_name=covered_provider_name,
        genai_system_name=genai_system_name,
        genai_system_version=genai_system_version,
        created_or_altered_at=created_or_altered_at,
        unique_identifier=unique_identifier,
        media_type=media_type,
        permanent_website_url=permanent_website_url,
        detectable_by_provider_tool=detectable_by_provider_tool,
        aligned_with_industry_standard=aligned_with_industry_standard,
    )

    return _emit_evidence(
        framework=ComplianceFramework.CA_SB942,
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


def sb942_payload_schema() -> dict[str, Any]:
    """
    Return the machine-readable JSON Schema for SB 942 latent disclosure
    payloads.
    """
    return SB942LatentDisclosurePayload.model_json_schema()


__all__ = [
    "emit_sb942_disclosure",
    "sb942_payload_schema",
    "SB942MediaType",
]
