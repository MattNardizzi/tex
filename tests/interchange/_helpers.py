"""Shared builders for the GIX interchange tests (Wave 2 / L6).

Everything here is deterministic: record hashes derive from a salt+index,
witness clocks are injected constants, and Ed25519 keys are the only fresh
randomness (key generation, not protocol behaviour).
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from uuid import uuid4

from tex.domain.evidence import CombinedEvidence, EvidenceMaturity
from tex.interchange.gix import CheckpointPublisher, Ed25519NoteVerifier
from tex.interchange.gix_witness import Witness
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind

FIXED_CLOCK = 1_750_000_000


def record_hashes(n: int, salt: str = "gix") -> list[str]:
    """n deterministic 64-hex record hashes."""
    return [hashlib.sha256(f"{salt}:{i}".encode()).hexdigest() for i in range(n)]


def true_e_value(
    log_e: float = math.log(4.0),
    *,
    anytime: bool = True,
    null: str = "h0:drift",
    filtration: str = "f:decisions",
    maturity: EvidenceMaturity = EvidenceMaturity.RESEARCH_SOLID,
    component_ids: tuple | None = None,
) -> CombinedEvidence:
    components = component_ids if component_ids is not None else (uuid4(),)
    return CombinedEvidence(
        combiner="arithmetic_mean",
        log_e_value=log_e,
        is_true_e_value=True,
        anytime_valid=anytime,
        joint_null_hypothesis_id=null,
        filtration_id=filtration,
        maturity=maturity,
        component_ids=tuple(components),
        n_components=len(components),
    )


def abstain_evidence() -> CombinedEvidence:
    return CombinedEvidence(
        combiner="abstain",
        log_e_value=0.0,
        is_true_e_value=False,
        anytime_valid=False,
        joint_null_hypothesis_id="none",
        filtration_id="none",
        maturity=EvidenceMaturity.RESEARCH_SOLID,
    )


def decision_fact(
    claim: str = "verdict produced", evidence: CombinedEvidence | None = None
) -> SealedFact:
    return SealedFact(
        kind=SealedFactKind.DECISION,
        claim=claim,
        evidence=evidence,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
    )


def seal_decisions(ledger: SealedFactLedger, n: int, prefix: str = "decision"):
    return [ledger.append(decision_fact(claim=f"{prefix} {i}")) for i in range(n)]


def publisher_for(
    ledger: SealedFactLedger, origin: str = "orga.example/gix"
) -> CheckpointPublisher:
    return CheckpointPublisher(
        origin=origin,
        read_record_hashes=lambda: tuple(
            r.record_hash for r in ledger.list_all()
        ),
    )


def make_witnesses(
    count: int,
    trusted: dict[str, Ed25519NoteVerifier],
    clock_value: int = FIXED_CLOCK,
) -> list[Witness]:
    return [
        Witness(
            f"witness{i}.example/w",
            trusted_logs=trusted,
            clock=lambda: clock_value,
        )
        for i in range(count)
    ]
