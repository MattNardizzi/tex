"""
Tests for precedent auto-resolution (the moat / Thread-C) —
``engine/precedent_influence.py`` and its PDP + replay wiring.

These tests ARE the proof the guardrail held. They assert, at both the unit
(direct module) and integration (full PDP) level:

  (a) N consistent prior human resolutions move a *discretionary* ABSTAIN→PERMIT;
  (b) precedent can NEVER override a FORBID-floor decision (structural floor and
      a raw FORBID both stay FORBID), including under replay;
  (c) a precedent-influenced verdict is sealed citing the driving precedents'
      record_hash;
  (d) the calibration replay validator replays a precedent-influenced decision
      correctly (pins it in the band, but lets a recalibration into FORBID win);
  (e) flag OFF ⇒ behaviour identical to today (no influence, no seal);

plus the fail-closed discretionary-flag allowlist, the consistency requirement,
and the tenant / edge-class / freshness / confidence / human / ledger gates.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tex.domain.evaluation import AgentRuntimeIdentity, EvaluationRequest
from tex.domain.policy import PolicySnapshot
from tex.domain.retrieval import RetrievalContext, RetrievedPrecedent
from tex.domain.verdict import Verdict
from tex.engine.precedent_influence import (
    DISCRETIONARY_ABSTAIN_FLAGS,
    PRECEDENT_AUTORESOLVE_FLAG,
    apply_precedent_autoresolve,
    edge_class_signature,
    was_precedent_autoresolved,
)
from tex.engine.router import RoutingResult
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind

from tests.factories import make_default_policy


NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


# ── builders ──────────────────────────────────────────────────────────────


def _policy(**overrides) -> PolicySnapshot:
    base = make_default_policy().model_copy(
        update={"precedent_autoresolve": True, **overrides}
    )
    return base


def _request(
    *,
    tenant: str = "acme",
    action_type: str = "sales_email",
    channel: str = "email",
    environment: str = "production",
    requested_at: datetime = NOW,
) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content="Hi Alice, following up on our conversation.",
        recipient="alice@example.com",
        channel=channel,
        environment=environment,
        agent_identity=AgentRuntimeIdentity(tenant_id=tenant),
        requested_at=requested_at,
    )


def _precedent(
    *,
    rank: int,
    record_hash: str,
    tenant: str = "acme",
    resolution_verdict: str = "PERMIT",
    resolved_by_human: bool = True,
    resolved_at: datetime | None = None,
    confidence: float = 0.95,
    action_type: str = "sales_email",
    channel: str = "email",
    environment: str = "production",
) -> RetrievedPrecedent:
    """A retrieved precedent carrying the sealed-human-resolution wire contract
    in metadata (what a production precedent store must populate)."""
    return RetrievedPrecedent(
        decision_id=str(uuid4()),
        request_id=str(uuid4()),
        verdict=Verdict.ABSTAIN,  # the prior decision WAS a hard call (escalated)
        action_type=action_type,
        channel=channel,
        environment=environment,
        relevance_score=0.9,
        rank=rank,
        decided_at=resolved_at or (NOW - timedelta(days=10)),
        metadata={
            "precedent_resolution": {
                "tenant_id": tenant,
                "resolution_verdict": resolution_verdict,
                "resolved_by_human": resolved_by_human,
                "resolved_at": (resolved_at or (NOW - timedelta(days=10))).isoformat(),
                "resolution_confidence": confidence,
                "record_hash": record_hash,
            }
        },
    )


def _retrieval(precedents: tuple[RetrievedPrecedent, ...]) -> RetrievalContext:
    return RetrievalContext(precedents=precedents)


def _abstain(
    *, flags: tuple[str, ...] = ("borderline_fused_score",), score: float = 0.5
) -> RoutingResult:
    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=0.5,
        final_score=score,
        reasons=("fused score in discretionary band",),
        uncertainty_flags=flags,
        scores={"semantic": score},
    )


def _three_permit_precedents() -> tuple[RetrievedPrecedent, ...]:
    return (
        _precedent(rank=1, record_hash="hash_aaa"),
        _precedent(rank=2, record_hash="hash_bbb"),
        _precedent(rank=3, record_hash="hash_ccc"),
    )


def _apply(base, *, policy, request=None, retrieval=None, ledger=None):
    return apply_precedent_autoresolve(
        base=base,
        request=request or _request(),
        policy=policy,
        retrieval_context=retrieval or _retrieval(_three_permit_precedents()),
        decision_ledger=ledger if ledger is not None else SealedFactLedger(),
    )


# ════════════════════════════════════════════════════════════════════════════
# (a) N consistent precedents move a discretionary ABSTAIN → PERMIT
# ════════════════════════════════════════════════════════════════════════════


def test_n_consistent_precedents_resolve_discretionary_abstain_to_permit() -> None:
    base = _abstain()
    out = _apply(base, policy=_policy(precedent_autoresolve_min_count=3))

    assert out.verdict is Verdict.PERMIT
    assert was_precedent_autoresolved(out.uncertainty_flags)
    # The score is preserved — only the categorical verdict moved.
    assert out.final_score == base.final_score
    assert out.confidence == base.confidence
    # The discretionary band flag is retained for audit.
    assert "borderline_fused_score" in out.uncertainty_flags


def test_below_N_does_not_resolve() -> None:
    # Only 2 eligible precedents but min_count is 3.
    retrieval = _retrieval(
        (
            _precedent(rank=1, record_hash="h1"),
            _precedent(rank=2, record_hash="h2"),
        )
    )
    out = _apply(
        _abstain(), policy=_policy(precedent_autoresolve_min_count=3), retrieval=retrieval
    )
    assert out.verdict is Verdict.ABSTAIN
    assert not was_precedent_autoresolved(out.uncertainty_flags)


def test_min_count_floor_is_three() -> None:
    # The policy field enforces a hard floor of 3 — a coincidence of 1 or 2
    # can never be configured as sufficient (validated construction).
    fields = make_default_policy().model_dump()
    with pytest.raises(Exception):
        PolicySnapshot.model_validate({**fields, "precedent_autoresolve_min_count": 2})


# ════════════════════════════════════════════════════════════════════════════
# (b) precedent can NEVER override a FORBID floor
# ════════════════════════════════════════════════════════════════════════════


def test_precedent_cannot_override_forbid_floor() -> None:
    """THE floor invariant: a FORBID (the only verdict a structural/deterministic
    floor ever produces) is structurally unreachable — the resolver acts only on
    an ABSTAIN. Even with the flag ON, a ledger, and N matching PERMIT
    precedents, a FORBID is returned untouched and NOTHING is sealed."""
    ledger = SealedFactLedger()
    forbid = RoutingResult(
        verdict=Verdict.FORBID,
        confidence=1.0,
        final_score=1.0,
        reasons=("structural deny: deny:toxic_flow",),
        scores={"structural_floor": 1.0},
    )
    out = _apply(forbid, policy=_policy(), ledger=ledger)

    assert out is forbid  # returned unchanged, same object
    assert out.verdict is Verdict.FORBID
    assert not was_precedent_autoresolved(out.uncertainty_flags)
    # No PRECEDENT fact sealed — the floor never even reached the seal.
    assert ledger.list_by_kind(SealedFactKind.PRECEDENT) == ()


def test_precedent_does_not_touch_a_permit() -> None:
    permit = RoutingResult(verdict=Verdict.PERMIT, confidence=0.9, final_score=0.1)
    out = _apply(permit, policy=_policy())
    assert out is permit
    assert out.verdict is Verdict.PERMIT


# ════════════════════════════════════════════════════════════════════════════
# Discretionary-band allowlist (fail-closed) — signaled ABSTAINs are excluded
# ════════════════════════════════════════════════════════════════════════════


def test_signaled_abstain_is_not_resolved() -> None:
    """An ABSTAIN carrying ANY non-allowlisted flag (here a PQ-durability /
    CRC marker alongside the discretionary one) is refused — a capability gap
    or statistical alarm must never be waved away by precedent."""
    for marker in (
        "crc_permit_region_exceeded",
        "pq_non_repudiation_unavailable",
        "drift_eprocess_breach",
        "no_retrieval_context",
        "some_future_unknown_signal",
    ):
        base = _abstain(flags=("borderline_fused_score", marker))
        out = _apply(base, policy=_policy())
        assert out.verdict is Verdict.ABSTAIN, marker
        assert not was_precedent_autoresolved(out.uncertainty_flags), marker


def test_abstain_with_no_flags_is_not_resolved() -> None:
    # Empty flag set fails the "non-empty subset" rule (fail-closed).
    base = RoutingResult(verdict=Verdict.ABSTAIN, confidence=0.5, final_score=0.5)
    out = _apply(base, policy=_policy())
    assert out.verdict is Verdict.ABSTAIN


def test_every_allowlist_flag_is_individually_sufficient() -> None:
    for flag in DISCRETIONARY_ABSTAIN_FLAGS:
        out = _apply(_abstain(flags=(flag,)), policy=_policy())
        assert out.verdict is Verdict.PERMIT, flag


def test_signal_markers_are_disjoint_from_the_allowlist() -> None:
    """The load-bearing safety invariant, pinned: every lowering signal stamps
    its OWN marker flag, and NONE of those markers may be in the discretionary
    allowlist — otherwise a signal-demoted ABSTAIN (capability gap / statistical
    alarm / policy violation) could slip past the subset gate. If a future
    signal picks a colliding marker, this fails loudly."""
    from tex.engine.risk_spine import RISK_SPINE_FLAG
    from tex.pqcrypto.pq_durability import PQ_NON_REPUDIATION_FLAG
    from tex.systemic.probguard import RV4_RECOVERABLE_FLAG, SYSTEMIC_LOOKAHEAD_FLAG

    signal_markers = {
        PQ_NON_REPUDIATION_FLAG,
        RISK_SPINE_FLAG,
        SYSTEMIC_LOOKAHEAD_FLAG,
        RV4_RECOVERABLE_FLAG,
        "crc_permit_region_exceeded",  # engine/crc_gate.py:927 (demotion marker)
    }
    assert signal_markers.isdisjoint(DISCRETIONARY_ABSTAIN_FLAGS), (
        "a lowering-signal marker entered the discretionary allowlist — precedent "
        f"could now override a signaled ABSTAIN: {signal_markers & DISCRETIONARY_ABSTAIN_FLAGS}"
    )


# ════════════════════════════════════════════════════════════════════════════
# (e) flag OFF / no ledger ⇒ no influence
# ════════════════════════════════════════════════════════════════════════════


def test_flag_off_is_a_noop() -> None:
    ledger = SealedFactLedger()
    base = _abstain()
    out = _apply(base, policy=make_default_policy(), ledger=ledger)  # default: OFF
    assert out is base
    assert ledger.list_by_kind(SealedFactKind.PRECEDENT) == ()


def test_no_ledger_is_a_noop() -> None:
    # Sealed-or-it-does-not-happen: no ledger ⇒ no influence.
    out = apply_precedent_autoresolve(
        base=_abstain(),
        request=_request(),
        policy=_policy(),
        retrieval_context=_retrieval(_three_permit_precedents()),
        decision_ledger=None,
    )
    assert out.verdict is Verdict.ABSTAIN


# ════════════════════════════════════════════════════════════════════════════
# Eligibility gates: tenant / edge-class / freshness / confidence / human
# ════════════════════════════════════════════════════════════════════════════


def test_different_tenant_excluded() -> None:
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", tenant="other-corp")
            for i in range(3)
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


def test_different_edge_class_excluded() -> None:
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", action_type="wire_transfer")
            for i in range(3)
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


def test_stale_precedents_excluded() -> None:
    stale = NOW - timedelta(days=200)
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", resolved_at=stale)
            for i in range(3)
        )
    )
    out = _apply(
        _abstain(),
        policy=_policy(precedent_autoresolve_freshness_days=90),
        retrieval=retrieval,
    )
    assert out.verdict is Verdict.ABSTAIN


def test_future_dated_resolution_excluded() -> None:
    # A resolution dated after the request can never be its precedent.
    future = NOW + timedelta(days=1)
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", resolved_at=future)
            for i in range(3)
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


def test_low_confidence_precedents_excluded() -> None:
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", confidence=0.5)
            for i in range(3)
        )
    )
    out = _apply(
        _abstain(),
        policy=_policy(precedent_autoresolve_min_confidence=0.9),
        retrieval=retrieval,
    )
    assert out.verdict is Verdict.ABSTAIN


def test_non_human_precedents_excluded() -> None:
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", resolved_by_human=False)
            for i in range(3)
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


def test_malformed_precedent_metadata_excluded() -> None:
    # A precedent with no resolution metadata simply does not count.
    bare = RetrievedPrecedent(
        decision_id=str(uuid4()),
        request_id=str(uuid4()),
        verdict=Verdict.ABSTAIN,
        action_type="sales_email",
        channel="email",
        environment="production",
        relevance_score=0.9,
        rank=1,
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=_retrieval((bare,)))
    assert out.verdict is Verdict.ABSTAIN


# ════════════════════════════════════════════════════════════════════════════
# Consistency: only a UNANIMOUS PERMIT history resolves
# ════════════════════════════════════════════════════════════════════════════


def test_inconsistent_history_not_resolved() -> None:
    # 3 PERMIT + 1 FORBID human resolutions of the same edge-class: a split
    # history is a genuine judgment call — keep escalating.
    retrieval = _retrieval(
        (
            _precedent(rank=1, record_hash="h1", resolution_verdict="PERMIT"),
            _precedent(rank=2, record_hash="h2", resolution_verdict="PERMIT"),
            _precedent(rank=3, record_hash="h3", resolution_verdict="PERMIT"),
            _precedent(rank=4, record_hash="h4", resolution_verdict="FORBID"),
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


def test_unanimous_forbid_history_not_resolved() -> None:
    # Caution-reduction only: a unanimous FORBID history is out of scope here
    # (auto-FORBID is a separate, deliberately-unbuilt feature).
    retrieval = _retrieval(
        tuple(
            _precedent(rank=i + 1, record_hash=f"h{i}", resolution_verdict="FORBID")
            for i in range(3)
        )
    )
    out = _apply(_abstain(), policy=_policy(), retrieval=retrieval)
    assert out.verdict is Verdict.ABSTAIN


# ════════════════════════════════════════════════════════════════════════════
# (c) the influenced verdict is SEALED citing the driving record_hash(es)
# ════════════════════════════════════════════════════════════════════════════


def test_influenced_verdict_is_sealed_citing_record_hashes() -> None:
    ledger = SealedFactLedger()
    request = _request()
    out = _apply(_abstain(), policy=_policy(), request=request, ledger=ledger)
    assert out.verdict is Verdict.PERMIT

    facts = ledger.list_by_kind(SealedFactKind.PRECEDENT)
    assert len(facts) == 1
    fact = facts[0].fact
    assert fact.kind is SealedFactKind.PRECEDENT
    assert fact.subject_id == str(request.request_id)

    cited = set(fact.detail["driving_precedent_record_hashes"])
    assert cited == {"hash_aaa", "hash_bbb", "hash_ccc"}
    assert fact.detail["from_verdict"] == "ABSTAIN"
    assert fact.detail["to_verdict"] == "PERMIT"
    assert fact.detail["consistent_count"] == 3

    # The citation also rides the human-readable verdict reason …
    citation_reasons = [r for r in out.reasons if "record_hash" in r]
    assert citation_reasons
    assert all(h in citation_reasons[0] for h in ("hash_aaa", "hash_bbb", "hash_ccc"))

    # … and the seal is integrity-verifiable offline.
    assert ledger.verify_chain()["intact"] is True


def test_never_seals_a_decision_kind_fact() -> None:
    # Invisible to L1 (seal-binding) and L3 (verdict-count) by construction.
    ledger = SealedFactLedger()
    _apply(_abstain(), policy=_policy(), ledger=ledger)
    assert ledger.list_by_kind(SealedFactKind.DECISION) == ()
    assert len(ledger.list_by_kind(SealedFactKind.PRECEDENT)) == 1


def test_resolution_is_deterministic() -> None:
    # Same inputs ⇒ same verdict + same cited record_hashes (the seal's own
    # fact_id/timestamp differ, but the influence DECISION is pure).
    request = _request()
    retrieval = _retrieval(_three_permit_precedents())
    a = _apply(_abstain(), policy=_policy(), request=request, retrieval=retrieval)
    b = _apply(_abstain(), policy=_policy(), request=request, retrieval=retrieval)
    assert a.verdict is b.verdict is Verdict.PERMIT
    assert [r for r in a.reasons if "record_hash" in r] == [
        r for r in b.reasons if "record_hash" in r
    ]


def test_edge_class_signature_is_case_insensitive_and_fail_closed() -> None:
    assert edge_class_signature("Sales_Email", "EMAIL", "Production") == (
        "sales_email",
        "email",
        "production",
    )
    assert edge_class_signature(None, "email", "production") is None


# ════════════════════════════════════════════════════════════════════════════
# Integration — through the real PolicyDecisionPoint
# ════════════════════════════════════════════════════════════════════════════

from tex.engine.pdp import PolicyDecisionPoint  # noqa: E402
from tex.evidence.negative_knowledge import check_count_conservation  # noqa: E402
from tex.specialists.base import SpecialistBundle, SpecialistResult  # noqa: E402


class _AbstainRouter:
    """Deterministically lands a discretionary ABSTAIN so the REAL precedent
    wiring (the pdp.py call, the seal, build_hold, the decision build) runs for
    real. The router is upstream of the unit under test, not the unit itself."""

    def route(self, **_kwargs) -> RoutingResult:
        return _abstain()


class _PrecedentRetrieval:
    def __init__(self, precedents: tuple[RetrievedPrecedent, ...]) -> None:
        self._precedents = precedents

    def retrieve(self, *, request, policy) -> RetrievalContext:
        return _retrieval(self._precedents)


class _PcasDenySpecialists:
    """Drives the genuine structural FORBID floor (pcas deny)."""

    def evaluate(self, *, request, retrieval_context) -> SpecialistBundle:
        return SpecialistBundle(
            results=(
                SpecialistResult(
                    specialist_name="pcas",
                    risk_score=1.0,
                    confidence=1.0,
                    summary="deny",
                    matched_policy_clause_ids=("deny:toxic_flow",),
                ),
            )
        )


def test_pdp_resolves_discretionary_abstain_and_raises_no_hold() -> None:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        router=_AbstainRouter(),
        retrieval_orchestrator=_PrecedentRetrieval(_three_permit_precedents()),
        decision_ledger=ledger,
    )
    result = pdp.evaluate(request=_request(), policy=_policy())

    # The discretionary ABSTAIN was auto-resolved to PERMIT …
    assert result.decision.verdict is Verdict.PERMIT
    assert PRECEDENT_AUTORESOLVE_FLAG in result.decision.uncertainty_flags
    # … so NO operator hold was raised (the glass stays clean: fewer ABSTAINs).
    assert result.decision.metadata["pdp"]["hold"] is None

    # The influence is sealed as a PRECEDENT fact (not a DECISION fact).
    precedent_facts = ledger.list_by_kind(SealedFactKind.PRECEDENT)
    assert len(precedent_facts) == 1
    assert set(
        precedent_facts[0].fact.detail["driving_precedent_record_hashes"]
    ) == {"hash_aaa", "hash_bbb", "hash_ccc"}

    # And L3 count-conservation still holds: 1 attempt, exactly 1 counted verdict.
    cons = check_count_conservation(ledger.list_all())
    assert cons.holds is True
    assert cons.n_attempts == 1
    assert (cons.n_permit, cons.n_abstain, cons.n_forbid) == (1, 0, 0)


def test_pdp_structural_floor_stays_forbid_with_flag_on() -> None:
    """End-to-end: a genuine structural-floor FORBID, with the flag ON and N
    matching PERMIT precedents in context, is NEVER softened."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        specialist_suite=_PcasDenySpecialists(),
        retrieval_orchestrator=_PrecedentRetrieval(_three_permit_precedents()),
        decision_ledger=ledger,
    )
    result = pdp.evaluate(request=_request(), policy=_policy())

    assert result.decision.verdict is Verdict.FORBID
    assert PRECEDENT_AUTORESOLVE_FLAG not in result.decision.uncertainty_flags
    assert ledger.list_by_kind(SealedFactKind.PRECEDENT) == ()


def test_pdp_flag_off_is_unchanged() -> None:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        router=_AbstainRouter(),
        retrieval_orchestrator=_PrecedentRetrieval(_three_permit_precedents()),
        decision_ledger=ledger,
    )
    # Default policy: precedent_autoresolve is OFF.
    result = pdp.evaluate(request=_request(), policy=make_default_policy())

    assert result.decision.verdict is Verdict.ABSTAIN
    assert PRECEDENT_AUTORESOLVE_FLAG not in result.decision.uncertainty_flags
    assert ledger.list_by_kind(SealedFactKind.PRECEDENT) == ()
    # An ABSTAIN still raises a hold (operator surface preserved).
    assert result.decision.metadata["pdp"]["hold"] is not None


# ════════════════════════════════════════════════════════════════════════════
# (d) the calibration replay validator replays it correctly
# ════════════════════════════════════════════════════════════════════════════

from tex.domain.decision import Decision  # noqa: E402
from tex.learning.calibrator import CalibrationRecommendation  # noqa: E402
from tex.learning.outcomes import OutcomeSummary  # noqa: E402
from tex.learning.replay import ReplayValidator  # noqa: E402


def _decision(
    *, verdict: Verdict, final_score: float, confidence: float, flags: list[str]
) -> Decision:
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=confidence,
        final_score=final_score,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi",
        content_sha256="b" * 64,
        policy_version="default-v1",
        scores={"semantic": final_score},
        uncertainty_flags=flags,
    )


def _rec(*, permit: float, forbid: float, min_conf: float) -> CalibrationRecommendation:
    summary = OutcomeSummary(
        total=10, correct_permits=8, false_permits=0,
        correct_forbids=2, false_forbids=0, abstain_reviews=0, unknown=0,
    )
    return CalibrationRecommendation(
        current_permit_threshold=0.30,
        recommended_permit_threshold=permit,
        current_forbid_threshold=0.65,
        recommended_forbid_threshold=forbid,
        current_minimum_confidence=0.60,
        recommended_minimum_confidence=min_conf,
        summary=summary,
        reasons=("test",),
        false_permit_rate=0.0,
        false_forbid_rate=0.0,
        abstain_review_rate=0.0,
        unknown_rate=0.0,
        sample_weight=0.8,
        permit_threshold_delta=permit - 0.30,
        forbid_threshold_delta=forbid - 0.65,
        minimum_confidence_delta=min_conf - 0.60,
    )


def test_replay_pins_precedent_permit_in_band() -> None:
    """A precedent-influenced PERMIT sits in the ABSTAIN band by construction.
    Replay must pin it to PERMIT (not mis-count it as a threshold-driven flip
    into ABSTAIN that never happened)."""
    decision = _decision(
        verdict=Verdict.PERMIT,
        final_score=0.50,  # squarely in the [0.30, 0.65] band
        confidence=0.50,
        flags=[PRECEDENT_AUTORESOLVE_FLAG, "borderline_fused_score"],
    )
    rep = ReplayValidator().replay(
        decisions=[decision],
        outcomes=[],
        policy=make_default_policy(),
        recommendation=_rec(permit=0.30, forbid=0.65, min_conf=0.60),
    )
    assert rep.proposed_distribution.permit == 1
    assert rep.proposed_distribution.abstain == 0
    assert rep.new_abstains == 0


def test_replay_recalibration_into_forbid_overrides_precedent() -> None:
    """If a proposed recalibration pushes the score into the FORBID region, the
    floor wins even for a precedent-influenced decision — precedent can never
    override a forbid, including under replay."""
    decision = _decision(
        verdict=Verdict.PERMIT,
        final_score=0.50,
        confidence=0.50,
        flags=[PRECEDENT_AUTORESOLVE_FLAG, "borderline_fused_score"],
    )
    rep = ReplayValidator().replay(
        decisions=[decision],
        outcomes=[],
        policy=make_default_policy(),
        recommendation=_rec(permit=0.20, forbid=0.45, min_conf=0.60),  # 0.50 >= 0.45
    )
    assert rep.proposed_distribution.forbid == 1
    assert rep.new_forbids == 1
    assert rep.proposed_distribution.permit == 0


def test_replay_without_precedent_flag_is_unchanged() -> None:
    """A band ABSTAIN with NO precedent flag still re-derives to ABSTAIN — the
    pinning is scoped strictly to flagged decisions (no behaviour change for
    everything else)."""
    decision = _decision(
        verdict=Verdict.ABSTAIN,
        final_score=0.50,
        confidence=0.50,
        flags=["borderline_fused_score"],
    )
    rep = ReplayValidator().replay(
        decisions=[decision],
        outcomes=[],
        policy=make_default_policy(),
        recommendation=_rec(permit=0.30, forbid=0.65, min_conf=0.60),
    )
    assert rep.proposed_distribution.abstain == 1
    assert rep.proposed_distribution.permit == 0
