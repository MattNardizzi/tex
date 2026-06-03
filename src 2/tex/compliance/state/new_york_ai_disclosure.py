"""
New York AI Advertising Disclosure Law — General Business Law § 1700-A.

Effective **1 June 2026**. Requires conspicuous disclosure of AI-generated
synthetic performers in commercial advertising broadcast, telecast, or
otherwise published in New York State.

Civil penalty per violation: **$1,000 first**, **$5,000 per subsequent**.
Enforced by the New York State Attorney General; private right of action
not granted.

Frontier delta (May 18, 2026)
-----------------------------
- One of three June 2026 state disclosure trips (NY, CO AI Act
  30 June 2026, CA SB 942 ongoing). All three are mechanically satisfied
  by binding the disclosure record to a C2PA manifest with the IPTC
  ``trainedAlgorithmicMedia`` digitalSourceType.
- Tex's emission shape is intentionally aligned with the EU AI Act
  Article 50 ``Article50DisclosurePayload`` so a single ingestion
  pipeline at the advertiser side can fan out to NY, CA, EU records
  without re-extracting the underlying fields.

What this module emits
----------------------
A ``NyAiDisclosurePayload`` dataclass plus an ``emit_ny_disclosure()``
factory. The payload binds:
- ``c2pa_manifest_id`` — verifiable provenance link.
- ``content_sha256`` — full-file digest of the published creative.
- ``synthetic_performer_used`` — required §1700-A boolean.
- ``disclosure_text`` — the conspicuous notice exactly as displayed.
- ``placement`` — where in the creative the notice appears
  (``opening_frame``, ``persistent_overlay``, ``audio_voiceover``,
  ``end_card``). The NY AG guidance (Apr 2026) lists those four as
  presumptively conspicuous.
- ``advertiser_legal_entity`` — the §1700-A "advertiser" of record.
- ``publication_window_start`` / ``end`` — when the creative ran.

Priority: P1 (regulatory evidence emitter for NY AI Advertising Disclosure Law).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from tex.observability.telemetry import emit_event


PlacementKind = Literal[
    "opening_frame",
    "persistent_overlay",
    "audio_voiceover",
    "end_card",
]


@dataclass(frozen=True, slots=True)
class NyAiDisclosurePayload:
    """Machine-readable §1700-A disclosure record.

    All fields are statutory or NY AG implementing-guidance fields. The
    record is bound to a C2PA manifest via ``c2pa_manifest_id`` so a
    regulator can independently verify the provenance claim.
    """

    c2pa_manifest_id: str
    content_sha256: str
    synthetic_performer_used: bool
    disclosure_text: str
    placement: PlacementKind
    advertiser_legal_entity: str
    publication_window_start: datetime
    publication_window_end: datetime
    statute_version: str = "GBL_1700-A_2026-06"


def emit_ny_disclosure(
    *,
    c2pa_manifest_id: str,
    content_sha256: str,
    synthetic_performer_used: bool,
    disclosure_text: str,
    placement: PlacementKind,
    advertiser_legal_entity: str,
    publication_window_start: datetime,
    publication_window_end: datetime,
) -> NyAiDisclosurePayload:
    """Produce a §1700-A disclosure record bound to a C2PA manifest.

    Validates the statute's pre-conditions and emits a structured
    telemetry event so the disclosure can be reconciled against the
    creative's actual publication history.

    Raises
    ------
    ValueError
        For any field-level pre-condition failure (empty manifest id,
        wrong-length hash, blank disclosure text, end-before-start).
        Fail-closed at construction time keeps invalid records out of
        the evidence chain.
    """
    if not c2pa_manifest_id:
        raise ValueError("c2pa_manifest_id is required")
    if not content_sha256 or len(content_sha256) != 64:
        raise ValueError(
            "content_sha256 must be a 64-char SHA-256 hex digest"
        )
    if synthetic_performer_used and not disclosure_text.strip():
        raise ValueError(
            "disclosure_text is required when synthetic_performer_used=True"
        )
    if not advertiser_legal_entity:
        raise ValueError("advertiser_legal_entity is required")
    if publication_window_end < publication_window_start:
        raise ValueError(
            "publication_window_end must be >= publication_window_start"
        )

    payload = NyAiDisclosurePayload(
        c2pa_manifest_id=c2pa_manifest_id,
        content_sha256=content_sha256,
        synthetic_performer_used=synthetic_performer_used,
        disclosure_text=disclosure_text,
        placement=placement,
        advertiser_legal_entity=advertiser_legal_entity,
        publication_window_start=publication_window_start,
        publication_window_end=publication_window_end,
    )
    emit_event(
        "compliance.ny_ai_disclosure.emitted",
        c2pa_manifest_id=c2pa_manifest_id,
        synthetic_performer_used=synthetic_performer_used,
        placement=placement,
        advertiser=advertiser_legal_entity,
        statute_version=payload.statute_version,
    )
    return payload


__all__ = (
    "NyAiDisclosurePayload",
    "PlacementKind",
    "emit_ny_disclosure",
)
