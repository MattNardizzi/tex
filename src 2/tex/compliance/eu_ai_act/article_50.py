"""
EU AI Act Article 50: Transparency for AI-Generated Content.

Enforcement begins August 2, 2026. Requires machine-readable disclosure on
AI-generated content. C2PA Content Credentials are the de-facto compliant
mechanism.

Article 50(2) — providers of generative AI systems (including GPAI) must
ensure outputs are "marked in a machine-readable format and detectable as
artificially generated or manipulated", and that technical solutions are
"effective, interoperable, robust, and reliable" (the four cumulative
criteria, sentence 2).

The Second Draft Code of Practice on Transparency of AI-Generated Content
(3 March 2026) operationalises this with a multi-layered marking strategy
(Commitment 1) and detection-tool obligations (Commitment 2). The third /
final Code is expected June 2026, ahead of the 2 August 2026 application
date.

Tex strategy
------------
Tex satisfies Article 50(2) for outbound AI content by binding a signed
C2PA manifest (digitally signed metadata layer of Commitment 1) to the
Tex verdict that authorized emission, and emitting an Article 50
evidence record that can be handed to a notified body or AI Office
investigator as proof of marking.

References
----------
- Regulation (EU) 2024/1689 (the AI Act), Art. 50 and Art. 113
- Second Draft Code of Practice on Transparency of AI-Generated Content,
  3 March 2026 — Commitments 1 (multi-layered marking) and 2 (detection)
- IPTC ``digitalSourceType`` controlled vocabulary, term
  ``trainedAlgorithmicMedia``
- C2PA Specification 2.x

Priority: P0.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tex.c2pa.manifest import C2paManifest
from tex.compliance._common import (
    DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
    Article50CumulativeCriteria,
    Article50DisclosurePayload,
    Article50MarkingLayers,
    ComplianceFramework,
    EmittedEvidence,
    _emit_evidence,
)
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger


_STATUTE_CITATION: str = "Regulation_(EU)_2024/1689_Article_50(2)"


def emit_article_50_evidence(
    *,
    c2pa_manifest_id: str,
    content_hash: str,
    manifest: C2paManifest,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
    actor_entity_id: str,
    marking_layers: Article50MarkingLayers,
    cumulative_criteria: Article50CumulativeCriteria,
    target_entity_id: str | None = None,
    detection_interface_url: str | None = None,
    deployer_label_present: bool = False,
    policy_version: str | None = None,
    upstream_event_ids: tuple[str, ...] = (),
    issued_at: datetime | None = None,
    evidence_id: str | None = None,
    ledger_event_id: str | None = None,
    enforce_frontier_flag: bool = False,
    code_of_practice_alignment: str = "second_draft_2026_03_03",
) -> EmittedEvidence:
    """
    Produce an Article 50 compliance evidence record.

    The record asserts that a single piece of AI-generated content is
    marked in a machine-readable format meeting the four cumulative
    criteria of Article 50(2) sentence 2. The record:

      - binds to a real, signed C2PA manifest from Thread 6 (the
        digitally signed metadata layer of the Second Draft Code's
        Commitment 1 multi-layered marking strategy)
      - declares which marking layers are active (signed metadata,
        watermark, fingerprint/logging fallback)
      - declares the four cumulative criteria self-assessment
      - is signed via the algorithm-agile provider on ``provenance``
        (ECDSA-P256 today; ML-DSA-65 once liboqs lands)
      - is appended to the Thread 2 event ledger as a single
        ``POLICY_DECISION`` event whose ``record_hash`` is the audit
        anchor

    The evidence record is what Tex hands to an EU AI Office
    investigator or notified body. The ledger event is what Tex hands
    to an insurer streaming attestation feed.

    Parameters
    ----------
    c2pa_manifest_id
        Caller-supplied handle. Must equal ``manifest.claim.instance_id``
        — verified at emission time (a mismatch raises ``ValueError``).
    content_hash
        SHA-256 hex (64 lowercase hex chars) of the bound content body.
        Should mirror the body hash already inside the C2PA claim's
        delivery block; Tex re-asserts it at the evidence layer so the
        evidence record is self-contained.
    manifest
        The signed C2PA manifest. Unsigned manifests are rejected.
    ledger, provenance
        The Thread 2 ledger and crypto-provenance attacher. The
        provenance's signing provider drives the algorithm tag on the
        emitted record (``signing_algorithm``).
    actor_entity_id
        The Tex-side actor (typically the agent that produced the
        content, e.g. ``"agent_sdr_42"``).
    marking_layers
        Which Commitment 1 marking layers are active. At minimum
        ``digitally_signed_metadata`` MUST be True (Tex supplies it via
        the bound manifest). Watermarking / fingerprinting are caller-
        attested.
    cumulative_criteria
        The four-criteria self-assessment per Article 50(2) sentence 2.
        All four must be ``True`` to claim Code-aligned compliance; a
        provider with any False MUST be prepared to demonstrate
        equivalent performance via independently verified benchmarks.
    detection_interface_url
        Optional URL of the Commitment 2 detector (Article 50 verifiers
        require providers to expose a free detection interface).
    deployer_label_present
        Whether an Article 50(4) deepfake / public-interest-text label
        is also present (deployer obligation).
    code_of_practice_alignment
        Which Code of Practice draft the assessment is aligned to.
        Defaults to the 3 March 2026 second draft. Update to
        ``"final_2026_06"`` once the final Code publishes.

    Notes on completed wiring:

    - **C2PA manifest binding (wired):** ``manifest`` is required, signature
      is required, and ``instance_id`` is verified to equal
      ``c2pa_manifest_id`` so the Article 50 record is cryptographically
      bound to the disclosed content.
    - **Machine-readable disclosure flag (wired):**
      ``Article50DisclosurePayload.digital_source_type`` is set to the IPTC
      ``trainedAlgorithmicMedia`` URI per the Code of Practice §1.1.

    Tracking notes (not blocking):

    - **TODO(spec-track):** pin against the FINAL Code of Practice when
      published in June 2026; the four cumulative criteria are statutory but
      the operationalisation may tighten under the Code's final text.
    - **TODO(P1):** add an explicit ``benchmarks_passed`` field once the
      AI Office publishes its measurement methodology.
    """
    payload = Article50DisclosurePayload(
        digital_source_type=DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
        marking_layers=marking_layers,
        cumulative_criteria=cumulative_criteria,
        detection_interface_url=detection_interface_url,
        deployer_label_present=deployer_label_present,
        code_of_practice_alignment=code_of_practice_alignment,
    )

    return _emit_evidence(
        framework=ComplianceFramework.EU_AI_ACT_ARTICLE_50,
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


def article_50_payload_schema() -> dict[str, Any]:
    """
    Return the machine-readable JSON Schema for Article 50 disclosure
    payloads.

    Used by ``tests/frontier/test_compliance.py`` to verify records
    validate against the statute's structural schema. Available for
    auditors who want to validate evidence records out-of-band.
    """
    return Article50DisclosurePayload.model_json_schema()


__all__ = [
    "emit_article_50_evidence",
    "article_50_payload_schema",
    "Article50CumulativeCriteria",
    "Article50MarkingLayers",
]
