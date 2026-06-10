"""
Seal an adaptive red-team campaign into the evidence chain.

[Architecture: Layer 5 (Evidence) — proof-of-superiority tooling]

A red-team number nobody can reproduce or check is marketing. This module turns
an ``AdaptiveCampaignReport`` into a chain of signed, hash-linked
``EvidenceRecord``s — one per attacked seed plus a campaign summary — so the
result Tex publishes ("adaptive ASR = 80%, structural class = 0%") is itself a
*sealed, replayable fact*: an auditor can take the bundle, verify it offline
(``tex.bench.evidence_bundle.verify_bundle``), and know the numbers were not
edited after the fact.

What the seal delivers (and the spec it reuses)
-----------------------------------------------
- **Integrity** from the hash chain: each record commits to its payload and the
  prior record, so any reorder, deletion, or one-byte edit breaks verification.
- **Authorship** from the signature: each record carries an ECDSA-P256 signature
  (or composite ML-DSA-65 + Ed25519 when that backend is installed) taken over
  the payload, embedding its own public key so a third party verifies it with no
  call back to Tex.

The cryptographic construction is NOT reinvented here. Records are signed with
the production ``EvidenceChainSigner`` and chained with the *same* centralized
math the live recorder uses (``tex.evidence.chain._build_record_hash``). The
unit tests assert the canonical verifier (``verify_evidence_chain`` +
``verify_payload_signature``) accepts what this builds — so if this construction
ever drifted from the spec, the test would fail rather than a bad seal shipping.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from tex.adversarial.adaptive import AdaptiveCampaignReport
from tex.domain.evidence import EvidenceRecord
from tex.evidence.chain import _build_record_hash, _sha256_hex, _stable_json
from tex.evidence.seal import (
    PQ_SIGNATURE_FIELD,
    EvidenceChainSigner,
    build_evidence_chain_signer,
)

# Stable namespace so the same campaign always maps to the same logical record
# identities (only the signatures, which are randomized, differ run to run).
_NS = uuid5(NAMESPACE_URL, "tex.adversarial.adaptive.campaign")

CAMPAIGN_POLICY_VERSION = "adaptive-redteam-v1"
SEED_RECORD_TYPE = "redteam_seed_result"
SUMMARY_RECORD_TYPE = "redteam_campaign_summary"


def _seal_one(
    payload: dict,
    *,
    record_type: str,
    previous_hash: str | None,
    signer: EvidenceChainSigner,
    decision_id,
    request_id,
) -> EvidenceRecord:
    """Build one chained, signed EvidenceRecord using the production primitives.

    Mirrors ``EvidenceRecorder._append`` exactly: sign the payload, embed the
    signature block, hash the signed payload, then chain that hash to the prior
    record. (We cannot call ``_append`` — it is private to the recorder and the
    recorder owns the live decision chain — so we reuse the same public signer
    and the same centralized hash math, and let the canonical verifier be the
    oracle in tests.)
    """
    block = signer.sign_payload(payload)
    signed = dict(payload)
    signed[PQ_SIGNATURE_FIELD] = block
    payload_json = _stable_json(signed)
    payload_sha256 = _sha256_hex(payload_json)
    record_hash = _build_record_hash(
        payload_sha256=payload_sha256, previous_hash=previous_hash
    )
    return EvidenceRecord(
        decision_id=decision_id,
        request_id=request_id,
        record_type=record_type,
        payload_json=payload_json,
        payload_sha256=payload_sha256,
        previous_hash=previous_hash,
        record_hash=record_hash,
        policy_version=CAMPAIGN_POLICY_VERSION,
    )


def seal_campaign(
    report: AdaptiveCampaignReport,
    *,
    signer: EvidenceChainSigner | None = None,
) -> tuple[EvidenceRecord, ...]:
    """Seal a campaign report into a chain of signed evidence records.

    Layout: one ``redteam_seed_result`` record per seed (in report order),
    followed by one ``redteam_campaign_summary`` record carrying the per-class
    ASR. Returns the records in chain order; pass them to
    ``tex.bench.evidence_bundle.write_bundle`` / ``verify_bundle``.
    """
    if signer is None:
        signer = build_evidence_chain_signer()

    records: list[EvidenceRecord] = []
    previous_hash: str | None = None

    for result in report.results:
        payload = {
            "schema": "tex.adversarial.adaptive/seed_result.v1",
            "record_type": SEED_RECORD_TYPE,
            "seed_id": result.seed_id,
            "defense_class": result.defense_class,
            "static_verdict": result.static_verdict.value,
            "best_verdict": result.best_verdict.value,
            "bypassed": result.bypassed,
            "best_objective": result.best_objective,
            "queries_used": result.queries_used,
            "mutation_chain": list(result.mutation_chain),
            "query_budget": report.query_budget,
        }
        record = _seal_one(
            payload,
            record_type=SEED_RECORD_TYPE,
            previous_hash=previous_hash,
            signer=signer,
            decision_id=uuid5(_NS, f"seed:{result.seed_id}"),
            request_id=uuid5(_NS, f"req:{result.seed_id}"),
        )
        records.append(record)
        previous_hash = record.record_hash

    summary_payload = {
        "schema": "tex.adversarial.adaptive/campaign_summary.v1",
        "record_type": SUMMARY_RECORD_TYPE,
        "static_asr": round(report.static_asr, 6),
        "adaptive_asr": round(report.adaptive_asr, 6),
        "lexical_asr": round(report.asr_for_class("lexical"), 6),
        "structural_asr": round(report.asr_for_class("structural"), 6),
        "n_seeds": len(report.results),
        "query_budget": report.query_budget,
        "seed_ids": [r.seed_id for r in report.results],
        "methodology": "Nasr-2025 attacker-moves-second adaptive search (AgentDojo-style ASR)",
    }
    summary = _seal_one(
        summary_payload,
        record_type=SUMMARY_RECORD_TYPE,
        previous_hash=previous_hash,
        signer=signer,
        decision_id=uuid5(_NS, "summary"),
        request_id=uuid5(_NS, "req:summary"),
    )
    records.append(summary)
    return tuple(records)


@dataclass(frozen=True, slots=True)
class CampaignSummary:
    """The campaign's headline numbers, read back from the sealed summary."""

    static_asr: float
    adaptive_asr: float
    lexical_asr: float
    structural_asr: float
    n_seeds: int
    query_budget: int


def read_summary(records: tuple[EvidenceRecord, ...]) -> CampaignSummary | None:
    """Extract the campaign summary from a sealed bundle, if present."""
    for record in records:
        if record.record_type == SUMMARY_RECORD_TYPE:
            payload = json.loads(record.payload_json)
            return CampaignSummary(
                static_asr=payload["static_asr"],
                adaptive_asr=payload["adaptive_asr"],
                lexical_asr=payload["lexical_asr"],
                structural_asr=payload["structural_asr"],
                n_seeds=payload["n_seeds"],
                query_budget=payload["query_budget"],
            )
    return None


__all__ = [
    "CAMPAIGN_POLICY_VERSION",
    "CampaignSummary",
    "SEED_RECORD_TYPE",
    "SUMMARY_RECORD_TYPE",
    "read_summary",
    "seal_campaign",
]
