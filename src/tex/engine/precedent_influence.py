"""
Precedent auto-resolution (the moat / Thread-C) — let a tenant's own sealed
prior human resolutions answer a current *discretionary* hard call.

[Architecture: Layer 4 (Execution Governance), the one audited caution-REDUCING
move in an otherwise strictly caution-RAISING pipeline.]

The moat thesis: the more a tenant uses Tex, the more sealed human resolutions
of genuinely-hard calls (ABSTAINs) accumulate. The system should, eventually,
answer its own future hard calls from its sealed past — so the *same edge-class*
stops escalating to a person once that person has resolved it the same way, N
times, consistently. This module is the single, narrow place that step happens.

WHY THIS IS DELIBERATELY DANGEROUS, AND HOW IT IS BOUNDED
─────────────────────────────────────────────────────────
Every other signal in the PDP is *monotone-lowering*: it may only move a verdict
toward caution (PERMIT→ABSTAIN→FORBID), never the reverse (CLAUDE.md rule 2).
This module is the explicit, conscious exception: it moves a verdict the OTHER
way (ABSTAIN→PERMIT). That is precisely why it is fenced on every side:

  1. STRUCTURAL FLOOR IS SACROSANCT. It acts *only* when ``base.verdict is
     ABSTAIN``. A deterministic/structural FORBID is a FORBID, never an ABSTAIN,
     so a floor verdict is structurally unreachable here — there is no code path
     by which precedent can soften a FORBID. This one check is the whole
     floor-safety invariant (mirrors the PQ hold's "only a PERMIT may be
     demoted" guard, inverted).
  2. DISCRETIONARY BAND ONLY (fail-closed allowlist). Not every ABSTAIN is a
     judgment call. PQ-durability, drift (risk-spine), behavioral/path contract
     violations, predictive holds, the CRC permit-region gate, and structural
     proofs all demote to ABSTAIN to record a SPECIFIC gap (a capability the
     system lacks, a live statistical alarm, a policy violation). Precedent must
     never wave those away. Each such signal stamps its own marker flag, so we
     require every uncertainty flag on the ABSTAIN to be drawn from a small,
     explicit allowlist of genuine judgment-call markers (``borderline_fused_
     score`` and friends). ANY flag outside the allowlist — including any future
     signal's marker, or none at all — refuses the resolution. Fail-closed.
  3. CAUTION-REDUCTION ONLY. The adopted verdict is always PERMIT. A consistent
     history of human *FORBID* resolutions is out of scope (that is a separate,
     caution-RAISING feature, deliberately not built here).
  4. SEALED OR IT DOES NOT HAPPEN. Influence requires a decision ledger to seal
     into. No ledger ⇒ no influence (the verdict stays ABSTAIN). There is no
     such thing as an unsealed precedent-influenced verdict: every one cites the
     driving precedents' ``record_hash`` in a sealed ``SealedFact(PRECEDENT)``.
  5. DEFAULT OFF. Gated behind ``policy.precedent_autoresolve`` (default False).
     With the flag off — or with the default ``decision_ledger=None`` PDP — this
     is a zero-cost no-op that reproduces today's behaviour bit-for-bit.

Eligibility gates (ALL required), each deterministic and replayable:
  * same tenant            — ``request.agent_identity.tenant_id`` == precedent's
  * same edge-class        — (action_type, channel, environment) match
  * human-resolved         — the precedent records a sealed HUMAN resolution
  * N consistent + identical — ≥ N (policy, floor 3) survivors, all PERMIT
  * freshness window       — resolved within policy window of request.requested_at
  * confidence threshold   — each survivor's recorded confidence ≥ policy minimum

Frontier framing (retrieved 2026-06-17): this is the inverse of *learning to
defer* / selective prediction (Mozannar 2023; "L2D to a population", Tailor
2024) — *learning to UN-defer* from an accumulated population of consistent
human resolutions. The automation-bias literature (CSET 2024; EDPS TechDispatch
2/2025) names the hazard directly — eroding the human-oversight guardrail — which
is the reason for the hard floor, the N-consistency requirement, the default-OFF
posture, and the sealed, replayable citation that makes every un-deferral
auditable after the fact. ``research-early``: the mechanism is real, live, and
replayable; it has no field-calibrated guarantee on the N/freshness thresholds.

Determinism: the verdict decision is a pure function of (base, request, policy,
retrieval_context). Only the seal is I/O, and it is observation-only and
fail-closed (an append failure degrades to "not resolved", never a crash, and —
because influence requires the seal — a failed seal means the verdict stays
ABSTAIN). ``compute_determinism_fingerprint`` does not read the routing result,
so flipping the categorical verdict here never perturbs the fingerprint.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import cost / cycle
    from tex.domain.evaluation import EvaluationRequest
    from tex.domain.policy import PolicySnapshot
    from tex.domain.retrieval import RetrievalContext, RetrievedPrecedent
    from tex.engine.router import RoutingResult
    from tex.provenance.ledger import SealedFactLedger
    from tex.provenance.models import SealedFactRecord

_logger = logging.getLogger(__name__)

__all__ = [
    "PRECEDENT_AUTORESOLVE_FLAG",
    "DISCRETIONARY_ABSTAIN_FLAGS",
    "PrecedentResolution",
    "apply_precedent_autoresolve",
    "was_precedent_autoresolved",
    "edge_class_signature",
]

# The structured marker stamped on a precedent-influenced verdict's
# ``uncertainty_flags``. Machine-readable provenance: the replay validator keys
# on this to pin the verdict, and audit reads it to know the PERMIT was adopted
# from precedent rather than scored clean.
PRECEDENT_AUTORESOLVE_FLAG = "precedent_autoresolved"

# Stable prefix for the human-readable citation reason (so audit / tests can
# locate it deterministically).
_CITATION_REASON_PREFIX = "precedent auto-resolve:"

# ── The discretionary-band allowlist (fail-closed) ────────────────────────────
# An ABSTAIN is eligible for precedent influence ONLY when every uncertainty
# flag it carries is in this set AND there is at least one. Each member denotes a
# genuine judgment-call / epistemic-gap indecision — never a capability gap, a
# statistical alarm, or a policy violation. Grounded in the live emitters:
#   * borderline_fused_score          — engine/router.py:845 (score strictly
#                                        inside [permit, forbid] — the definitional
#                                        discretionary-band marker)
#   * low_confidence_semantic_dimension — engine/router.py:840 (intent ambiguous)
#   * weak_semantic_evidence          — engine/router.py:843 (thin evidence)
#   * confidence_below_policy_minimum — engine/router.py:837 (low fused confidence)
#   * cold_start / no_behavioral_history — agent/behavioral_evaluator.py:467
#                                        (no agent history — precedent IS the history)
# CRITICAL non-members (each stamps its own marker flag, so the subset check below
# refuses any ABSTAIN they produced): PQ_NON_REPUDIATION_FLAG (capability gap),
# crc_permit_region_exceeded (calibrated statistical caution), the risk-spine flag
# (anytime-valid drift alarm), probguard / contract / path / structural markers
# (policy or proof violations), agent_pending, forbid_streak, no_retrieval_context,
# deterministic_findings_present, semantic_dominance_override. A signal-demoted
# ABSTAIN is a lowered PERMIT (score below the band) → never carries
# ``borderline_fused_score`` → its marker-only flag set is not a subset → refused.
DISCRETIONARY_ABSTAIN_FLAGS: frozenset[str] = frozenset(
    {
        "borderline_fused_score",
        "low_confidence_semantic_dimension",
        "weak_semantic_evidence",
        "confidence_below_policy_minimum",
        "cold_start",
        "no_behavioral_history",
    }
)


@dataclass(frozen=True, slots=True)
class PrecedentResolution:
    """A sealed prior HUMAN resolution, parsed from a retrieved precedent's
    ``metadata`` at the boundary so the shared ``RetrievedPrecedent`` domain
    contract stays untouched. All fields are required; a precedent missing any
    of them simply does not count (fail-closed in :func:`_parse`)."""

    tenant_id: str
    resolution_verdict: str  # the HUMAN's resolution (PERMIT/ABSTAIN/FORBID), upper-cased
    resolved_by_human: bool
    resolved_at: datetime  # tz-aware
    confidence: float
    record_hash: str  # the sealed record hash of the resolution — the citation


def edge_class_signature(
    action_type: str | None,
    channel: str | None,
    environment: str | None,
) -> tuple[str, str, str] | None:
    """The deterministic edge-class key: lower-cased (action_type, channel,
    environment). Returns None if any component is missing — an incompletely
    described case can never match, by construction (fail-closed)."""
    if action_type is None or channel is None or environment is None:
        return None
    return (action_type.strip().lower(), channel.strip().lower(), environment.strip().lower())


def was_precedent_autoresolved(uncertainty_flags: Any) -> bool:
    """True iff a decision/result carries the precedent auto-resolve marker.
    Accepts any iterable of flags (decision.uncertainty_flags or
    routing_result.uncertainty_flags)."""
    try:
        return PRECEDENT_AUTORESOLVE_FLAG in set(uncertainty_flags)
    except TypeError:
        return False


def apply_precedent_autoresolve(
    *,
    base: "RoutingResult",
    request: "EvaluationRequest",
    policy: "PolicySnapshot",
    retrieval_context: "RetrievalContext",
    decision_ledger: "SealedFactLedger | None",
) -> "RoutingResult":
    """Auto-resolve a *discretionary* ABSTAIN toward PERMIT from this tenant's
    own consistent, sealed prior human resolutions — or return ``base``
    unchanged. The verdict change is the ONLY mutation; score and confidence are
    preserved (mirrors ``_merge_soft_contract_signals``: a categorical move, not
    a re-inference). See the module docstring for the full fence.
    """
    # Lazy import keeps engine import-order identical and avoids any cycle
    # (mirrors systemic.probguard / pqcrypto.pq_durability).
    from tex.domain.verdict import Verdict

    # ── Gate 0: default OFF. ──────────────────────────────────────────────
    if not getattr(policy, "precedent_autoresolve", False):
        return base

    # ── Gate 1: the floor is sacrosanct — act ONLY on an ABSTAIN. ─────────
    # A deterministic / structural FORBID is a FORBID, so it is unreachable
    # here. A PERMIT is left alone. This single check is the floor invariant.
    if base.verdict is not Verdict.ABSTAIN:
        return base

    # ── Gate 2: sealed-or-it-does-not-happen. No ledger ⇒ no influence. ───
    if decision_ledger is None:
        return base

    # ── Gate 3: discretionary band only (fail-closed allowlist). ──────────
    flags = set(base.uncertainty_flags)
    if not flags or not flags.issubset(DISCRETIONARY_ABSTAIN_FLAGS):
        return base

    # ── Gate 4: tenant must be known to enforce same-tenant. ──────────────
    request_tenant = _request_tenant(request)
    if request_tenant is None:
        return base

    # ── Gate 5: same edge-class. ──────────────────────────────────────────
    request_edge = edge_class_signature(
        request.action_type, request.channel, request.environment
    )
    if request_edge is None:
        return base

    # ── Gather the eligible, consistent precedents. ───────────────────────
    survivors = _eligible_survivors(
        retrieval_context=retrieval_context,
        request_tenant=request_tenant,
        request_edge=request_edge,
        request_time=request.requested_at,
        freshness=timedelta(days=int(policy.precedent_autoresolve_freshness_days)),
        min_confidence=float(policy.precedent_autoresolve_min_confidence),
    )

    min_count = int(policy.precedent_autoresolve_min_count)
    if len(survivors) < min_count:
        return base

    # Consistency: the survivors must be UNANIMOUS, and unanimously PERMIT
    # (caution-reduction only). A split history is a genuine judgment call —
    # keep escalating. A unanimous FORBID history is out of scope here.
    verdicts = {res.resolution_verdict for _p, res in survivors}
    if verdicts != {Verdict.PERMIT.value}:
        return base

    # ── Resolve: ABSTAIN → PERMIT, cite, seal. ────────────────────────────
    record_hashes = sorted({res.record_hash for _p, res in survivors})
    decision_ids = sorted({p.decision_id for p, _res in survivors})

    # Seal FIRST — influence requires the seal. If the append fails, degrade to
    # "not resolved" (the verdict stays ABSTAIN); we never emit an unsealed
    # precedent-influenced verdict.
    sealed = _seal_precedent_influence(
        ledger=decision_ledger,
        request=request,
        request_tenant=request_tenant,
        request_edge=request_edge,
        record_hashes=record_hashes,
        decision_ids=decision_ids,
        consistent_count=len(survivors),
        min_count=min_count,
        freshness_days=int(policy.precedent_autoresolve_freshness_days),
        min_confidence=float(policy.precedent_autoresolve_min_confidence),
    )
    if sealed is None:
        return base

    from tex.engine.router import RoutingResult

    edge_str = "/".join(request_edge)
    citation = (
        f"{_CITATION_REASON_PREFIX} ABSTAIN→PERMIT on edge-class {edge_str} "
        f"for tenant {request_tenant} from {len(survivors)} consistent prior "
        f"human PERMIT resolution(s) (min {min_count}); "
        f"driving record_hash(es): {', '.join(record_hashes)}; "
        f"structural floor untouched"
    )
    reasons = tuple(base.reasons) + (citation,)
    flags_out = tuple(base.uncertainty_flags) + (PRECEDENT_AUTORESOLVE_FLAG,)
    scores = dict(base.scores)
    scores["precedent_autoresolve"] = 1.0

    return RoutingResult(
        verdict=Verdict.PERMIT,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=reasons,
        findings=base.findings,
        scores=scores,
        uncertainty_flags=flags_out,
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Eligibility — pure helpers
# ─────────────────────────────────────────────────────────────────────────────


def _request_tenant(request: "EvaluationRequest") -> str | None:
    identity = getattr(request, "agent_identity", None)
    if identity is None:
        return None
    tenant = getattr(identity, "tenant_id", None)
    if not isinstance(tenant, str) or not tenant.strip():
        return None
    return tenant.strip()


def _eligible_survivors(
    *,
    retrieval_context: "RetrievalContext",
    request_tenant: str,
    request_edge: tuple[str, str, str],
    request_time: datetime,
    freshness: timedelta,
    min_confidence: float,
) -> list[tuple["RetrievedPrecedent", PrecedentResolution]]:
    """Precedents that pass EVERY per-precedent gate. Each survivor is a sealed
    human resolution of the same edge-class, same tenant, fresh, and confident."""
    survivors: list[tuple[RetrievedPrecedent, PrecedentResolution]] = []
    for precedent in retrieval_context.precedents:
        res = _parse(precedent)
        if res is None:
            continue
        if not res.resolved_by_human:
            continue
        if res.tenant_id != request_tenant:
            continue
        if edge_class_signature(
            precedent.action_type, precedent.channel, precedent.environment
        ) != request_edge:
            continue
        if res.confidence < min_confidence:
            continue
        # Freshness, measured against the request time (deterministic, replayable).
        # A resolution at or before the request and within the window counts; a
        # resolution dated after the request can never be a precedent for it.
        if res.resolved_at > request_time:
            continue
        if request_time - res.resolved_at > freshness:
            continue
        survivors.append((precedent, res))
    return survivors


def _parse(precedent: "RetrievedPrecedent") -> PrecedentResolution | None:
    """Parse the sealed-human-resolution provenance from a precedent's
    ``metadata``. Returns None (the precedent simply does not count) on any
    missing / malformed field — fail-closed. The metadata keys are the wire
    contract a production precedent store must populate:

        precedent_resolution = {
            "tenant_id": str,
            "resolution_verdict": "PERMIT" | "ABSTAIN" | "FORBID",
            "resolved_by_human": bool,
            "resolved_at": ISO-8601 tz-aware datetime str (or datetime),
            "resolution_confidence": float in [0, 1],
            "record_hash": str,   # the sealed record hash of the resolution
        }

    (Reading the wire format here, rather than adding typed fields to the shared
    ``RetrievedPrecedent``, keeps this change isolated to one module.)
    """
    meta = getattr(precedent, "metadata", None)
    if not isinstance(meta, dict):
        return None
    raw = meta.get("precedent_resolution")
    if not isinstance(raw, dict):
        return None
    try:
        tenant_id = raw["tenant_id"]
        resolution_verdict = raw["resolution_verdict"]
        resolved_by_human = raw["resolved_by_human"]
        resolved_at = raw["resolved_at"]
        confidence = raw["resolution_confidence"]
        record_hash = raw["record_hash"]
    except (KeyError, TypeError):
        return None

    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None
    if not isinstance(resolution_verdict, str) or not resolution_verdict.strip():
        return None
    if not isinstance(resolved_by_human, bool):
        return None
    if not isinstance(record_hash, str) or not record_hash.strip():
        return None
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= confidence <= 1.0:
        return None

    resolved_dt = _coerce_aware_datetime(resolved_at)
    if resolved_dt is None:
        return None

    return PrecedentResolution(
        tenant_id=tenant_id.strip(),
        resolution_verdict=resolution_verdict.strip().upper(),
        resolved_by_human=resolved_by_human,
        resolved_at=resolved_dt,
        confidence=confidence,
        record_hash=record_hash.strip(),
    )


def _coerce_aware_datetime(value: Any) -> datetime | None:
    """Accept a tz-aware datetime or an ISO-8601 string; reject naive / invalid
    (fail-closed — a naive timestamp cannot be compared safely)."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None or dt.utcoffset() is None:
        return None
    return dt


# ─────────────────────────────────────────────────────────────────────────────
# The sealed PRECEDENT fact (mirrors provenance/decision_seal + pq_durability)
# ─────────────────────────────────────────────────────────────────────────────


def build_precedent_fact(
    *,
    request: "EvaluationRequest",
    request_tenant: str,
    request_edge: tuple[str, str, str],
    record_hashes: list[str],
    decision_ids: list[str],
    consistent_count: int,
    min_count: int,
    freshness_days: int,
    min_confidence: float,
) -> Any:
    """Map a precedent resolution to a ``SealedFact(PRECEDENT)``. Pure (no I/O).

    Honest claim: the seal proves AUTHORSHIP + INTEGRITY of the influence event
    and binds the driving precedents' ``record_hash`` — it does NOT prove the
    adopted verdict is *correct* (that rests on the prior human judgments it
    cites). The kind is PRECEDENT (never DECISION), so L1's seal-binding and
    L3's verdict-count filters never see it.
    """
    from tex.domain.evidence import EvidenceMaturity
    from tex.provenance.models import SealedFact, SealedFactKind

    request_id = getattr(request, "request_id", None)
    edge_str = "/".join(request_edge)
    return SealedFact(
        kind=SealedFactKind.PRECEDENT,
        subject_id=(str(request_id) if request_id is not None else None),
        claim=(
            f"discretionary ABSTAIN for request {request_id} auto-resolved to "
            f"PERMIT from {consistent_count} consistent prior human PERMIT "
            f"resolution(s) of edge-class {edge_str} (tenant {request_tenant}); "
            f"structural floor untouched; authorship+integrity sealed and the "
            f"driving precedents bound by record_hash — resolution correctness "
            f"NOT proven (it rests on the cited human judgments)"
        ),
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        detail={
            "from_verdict": "ABSTAIN",
            "to_verdict": "PERMIT",
            "edge_class": edge_str,
            "tenant_id": request_tenant,
            "consistent_count": consistent_count,
            "required_min_count": min_count,
            "freshness_days": freshness_days,
            "min_confidence": min_confidence,
            "driving_precedent_record_hashes": record_hashes,
            "driving_precedent_decision_ids": decision_ids,
        },
    )


def _seal_precedent_influence(
    *,
    ledger: "SealedFactLedger",
    request: "EvaluationRequest",
    request_tenant: str,
    request_edge: tuple[str, str, str],
    record_hashes: list[str],
    decision_ids: list[str],
    consistent_count: int,
    min_count: int,
    freshness_days: int,
    min_confidence: float,
) -> "SealedFactRecord | None":
    """Seal one PRECEDENT fact; return its PCVR, or None on failure. Fail-closed:
    a seal failure means the caller leaves the verdict ABSTAIN (no unsealed
    influence). Never raises into the verdict path."""
    try:
        return ledger.append(
            build_precedent_fact(
                request=request,
                request_tenant=request_tenant,
                request_edge=request_edge,
                record_hashes=record_hashes,
                decision_ids=decision_ids,
                consistent_count=consistent_count,
                min_count=min_count,
                freshness_days=freshness_days,
                min_confidence=min_confidence,
            )
        )
    except Exception:  # pragma: no cover - defensive; influence must never crash a verdict
        _logger.warning(
            "PRECEDENT seal failed for request %s; verdict left ABSTAIN, no influence",
            getattr(request, "request_id", "?"),
            exc_info=True,
        )
        return None
