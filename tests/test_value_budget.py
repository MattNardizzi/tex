"""
Falsifiable tests for the ledgered value-class confidentiality budget.

The budget is cadence's cumulative twin: not "how fast is this agent acting" but
"how much sealed sensitive value has this lineage moved over its whole life,
including across restarts." The three properties below are the load-bearing
claims; each must genuinely assert, not theater.

  (1) restart-non-resettability — the running total reloads from the sealed
      ledger, so destroying and rebuilding the in-process tracker does NOT reset
      the budget. The (N+1)th high-class action still trips FORBID.
  (2) value-not-count (anti-theater) — an equal-COUNT sequence of PUBLIC-class
      actions never trips the budget, proving the metric is class-weighted, not
      call-counted.
  (3) monotone-fallback — a stale/forked ledger (chain break or sequence gap)
      makes the authoritative total unverifiable; the verdict ABSTAINs end-to-end
      through the real PDP, never a silent allow.

All deterministic, no network, no model call.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tex.deterministic.value_budget import (
    BUDGET_HOLD_FLAG,
    BudgetConfig,
    BudgetLevel,
    ValueClassBudgetTracker,
    apply_budget_hold,
    assess_for_floor,
    configure_default_budget_tracker,
    observe_for_debit,
)
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.governance.private_data_exec.ifc.capability_compat import ConfidentialityLevel
from tex.policies.defaults import build_default_policy
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.specialists.base import SpecialistBundle
from tex.specialists.structural_floor import (
    BUDGET_CODE,
    BUDGET_SPECIALIST,
    detect_structural_floor,
)

from tests.factories import make_semantic_analysis


T0 = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)
AGENT = UUID("00000000-0000-4000-8000-0000000000aa")


# Budget B = 12. CONFIDENTIAL debit = 4 by default, so the 4th CONFIDENTIAL
# action (total 16 > 12) trips OVER; three (total 12) do not. PUBLIC debit = 0.
SMALL = BudgetConfig(enabled=True, max_confidential=12)


def _req(
    *,
    agent_id: UUID | None = AGENT,
    confidentiality: str | None = None,
    lineage: str | None = None,
    seconds: float = 0.0,
    content: str = "Routine status update, proceeding.",
) -> EvaluationRequest:
    block: dict[str, object] = {}
    if confidentiality is not None:
        block["confidentiality"] = confidentiality
    if lineage is not None:
        block["lineage"] = lineage
    metadata: dict[str, object] = {}
    if block:
        metadata["value_budget"] = block
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="data_export",
        content=content,
        recipient="partner@example.com",
        channel="api",
        environment="production",
        agent_id=agent_id,
        metadata=metadata,
        requested_at=T0 + timedelta(seconds=seconds),
    )


@pytest.fixture
def enable_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_BUDGET_ENABLED", "1")


# ── A. unit: class weights + accumulation ────────────────────────────────────


def test_confidential_class_accumulates_and_trips_over() -> None:
    tracker = ValueClassBudgetTracker(SMALL)  # no ledger: pure-mechanism
    levels = [
        tracker.observe(_req(confidentiality="CONFIDENTIAL", seconds=i)).level
        for i in range(4)
    ]
    # 4 each = 4,8,12,16. B=12, so only the 4th (16 > 12) is OVER.
    assert levels == [
        BudgetLevel.CLEAR,
        BudgetLevel.CLEAR,
        BudgetLevel.CLEAR,
        BudgetLevel.OVER,
    ]


def test_observe_is_idempotent_per_request_id() -> None:
    tracker = ValueClassBudgetTracker(SMALL)
    req = _req(confidentiality="RESTRICTED")  # weight 8
    a1 = tracker.observe(req)
    a2 = tracker.observe(req)  # same request_id → must NOT debit twice
    assert a1.total == 8
    assert a2.total == 8 and a2 == a1


def test_disabled_is_untracked_noop() -> None:
    tracker = ValueClassBudgetTracker(BudgetConfig(enabled=False, max_confidential=1))
    a = tracker.observe(_req(confidentiality="RESTRICTED"))
    assert a.tracked is False and a.level is BudgetLevel.CLEAR


# ── B. PROPERTY 1: restart non-resettability via the sealed ledger ───────────


def test_restart_does_not_reset_the_budget() -> None:
    """Append N CONFIDENTIAL debits to just under B through a ledger-backed
    tracker; DESTROY and rebuild the in-process tracker pointed at the SAME
    sealed ledger; the (N+1)th still FORBIDs because the total RELOADS from the
    ledger, not from in-process memory."""
    ledger = SealedFactLedger()
    cfg = BudgetConfig(enabled=True, max_confidential=12)

    tracker = ValueClassBudgetTracker(cfg, ledger=ledger)
    # 3 CONFIDENTIAL debits → total 4,8,12. All <= B=12, none OVER.
    for i in range(3):
        a = tracker.observe(_req(confidentiality="CONFIDENTIAL", lineage="task-x", seconds=i))
        assert a.level is BudgetLevel.CLEAR
        assert a.total == 4 * (i + 1)

    # The sealed ledger now holds 3 BUDGET facts for this lineage.
    budget_records = ledger.list_by_kind(SealedFactKind.BUDGET)
    assert len(budget_records) == 3

    # DESTROY the in-process tracker. A naive in-memory counter would now read 0.
    del tracker

    # Rebuild a fresh tracker over the SAME sealed ledger.
    reborn = ValueClassBudgetTracker(cfg, ledger=ledger)
    # The 4th CONFIDENTIAL debit: reloads 12 from the ledger, +4 = 16 > 12 → OVER.
    a4 = reborn.observe(_req(confidentiality="CONFIDENTIAL", lineage="task-x", seconds=99))
    assert a4.total == 16
    assert a4.level is BudgetLevel.OVER, "rebuilt tracker must reload the sealed total, not reset it"

    # And the structural-floor leg recognizes the OVER as a deterministic deny.
    configure_default_budget_tracker(cfg, ledger=ledger)
    # peek (not debit) must see the OVER total the reborn tracker just sealed.
    peeked = assess_for_floor(
        _req(confidentiality="CONFIDENTIAL", lineage="task-x", seconds=100)
    )
    assert peeked.over_budget is True


def test_floor_fires_forbid_on_over_budget() -> None:
    ledger = SealedFactLedger()
    cfg = BudgetConfig(enabled=True, max_confidential=12)
    configure_default_budget_tracker(cfg, ledger=ledger)
    # Push the lineage over B via the debit seam.
    for i in range(4):  # 4,8,12,16 → last is OVER
        observe_for_debit(_req(confidentiality="CONFIDENTIAL", lineage="lin-1", seconds=i))
    # The floor peeks the same singleton and returns a structural deny.
    floor = detect_structural_floor(
        SpecialistBundle(results=()),
        request=_req(confidentiality="CONFIDENTIAL", lineage="lin-1", seconds=5),
    )
    assert floor.fired is True
    assert BUDGET_SPECIALIST in floor.denying_specialists
    deny = next(d for d in floor.denies if d.specialist == BUDGET_SPECIALIST)
    assert deny.codes == (BUDGET_CODE,)


# ── C. PROPERTY 2: value-not-count (anti-theater) ────────────────────────────


def test_equal_count_public_actions_never_trip() -> None:
    """An equal-COUNT sequence of PUBLIC-class actions never trips B — proving the
    budget is class-metered, not call-counted. The matching CONFIDENTIAL sequence
    of the SAME length DOES trip, so the difference is the class, not the count."""
    cfg = BudgetConfig(enabled=True, max_confidential=12)

    public_tracker = ValueClassBudgetTracker(cfg)
    public_levels = [
        public_tracker.observe(_req(confidentiality="PUBLIC", seconds=i)).level
        for i in range(20)  # 20 PUBLIC actions, far more than would trip on count
    ]
    assert all(lvl is BudgetLevel.CLEAR for lvl in public_levels)
    assert public_tracker.observe(_req(confidentiality="PUBLIC", seconds=99)).total == 0

    # Same COUNT region, but CONFIDENTIAL class → trips well before 20.
    conf_tracker = ValueClassBudgetTracker(cfg)
    conf_levels = [
        conf_tracker.observe(_req(confidentiality="CONFIDENTIAL", seconds=i)).level
        for i in range(20)
    ]
    assert any(lvl is BudgetLevel.OVER for lvl in conf_levels), (
        "the class-metered sequence must trip where the equal-count PUBLIC one did not"
    )


def test_action_with_no_value_class_costs_nothing() -> None:
    tracker = ValueClassBudgetTracker(SMALL)
    # No value_budget metadata at all → PUBLIC default → zero debit.
    for i in range(50):
        a = tracker.observe(_req(seconds=i))
        assert a.level is BudgetLevel.CLEAR and a.debit == 0


# ── D. PROPERTY 3: monotone fallback on a broken/forked chain → ABSTAIN ───────


class _PermitSemantic:
    """Confidently PERMIT, so a benign request has a PERMIT baseline; lets the
    PERMIT→ABSTAIN transition the degraded hold makes be observable. No network."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.95,
            overall_confidence=0.9,
            evidence_sufficiency=0.6,
        )


def test_broken_chain_degrades_to_abstain_unit() -> None:
    """A chain break makes verify_chain() fail → the tracker reports DEGRADED, and
    the soft hold demotes a PERMIT to ABSTAIN (never a silent allow)."""
    ledger = SealedFactLedger()
    cfg = BudgetConfig(enabled=True, max_confidential=12)
    tracker = ValueClassBudgetTracker(cfg, ledger=ledger)
    tracker.observe(_req(confidentiality="CONFIDENTIAL", lineage="lin-z", seconds=0))

    # Tamper the sealed chain: corrupt the first record's previous_hash so
    # verify_chain() breaks. The ledger stores frozen pydantic records, so we
    # rebuild the entry list with one mutated record.
    entries = ledger.list_all()
    assert entries
    broken = entries[0].model_copy(update={"record_hash": "deadbeef" * 8})
    ledger._entries[0] = broken  # type: ignore[attr-defined]
    assert ledger.verify_chain()["intact"] is False

    # Now a read fails closed to DEGRADED.
    peeked = tracker.peek(_req(confidentiality="PUBLIC", lineage="lin-z", seconds=1))
    assert peeked.level is BudgetLevel.DEGRADED

    # The soft hold turns a routed PERMIT into ABSTAIN.
    configure_default_budget_tracker(cfg, ledger=ledger)
    from tex.engine.router import RoutingResult

    base = RoutingResult(
        verdict=Verdict.PERMIT,
        confidence=0.9,
        final_score=0.1,
        reasons=("clean",),
        findings=(),
        scores={},
        uncertainty_flags=(),
    )
    held = apply_budget_hold(
        base=base, request=_req(confidentiality="PUBLIC", lineage="lin-z", seconds=2)
    )
    assert held.verdict is Verdict.ABSTAIN
    assert BUDGET_HOLD_FLAG in held.uncertainty_flags


def test_forked_lineage_sequence_gap_degrades_to_abstain_through_pdp(
    enable_budget: None,
) -> None:
    """A sequence GAP for a lineage (a replay/fork that drops a sealed receipt)
    makes verify_no_gaps() report the gap; the budget is unverifiable, and the
    real PDP returns ABSTAIN — never a silent PERMIT."""
    ledger = SealedFactLedger()
    cfg = BudgetConfig(enabled=True, max_confidential=12)
    configure_default_budget_tracker(cfg, ledger=ledger)

    # Seal three debits for the lineage (identity_seq 0,1,2).
    for i in range(3):
        observe_for_debit(
            _req(confidentiality="CONFIDENTIAL", lineage="lin-fork", seconds=i)
        )
    gap_key = "default|aid:%s|lin:lin-fork" % AGENT
    assert ledger.verify_no_gaps()["complete"] is True

    # Excise the MIDDLE sealed receipt (seq 1) for this lineage — a fork/replay.
    # The chain still "verifies" for the remaining records only if re-linked, but
    # verify_no_gaps detects the missing identity_seq.
    target_seq = None
    for rec in ledger.list_for_identity(gap_key):
        if rec.fact.detail.get("identity_seq") == 1:
            target_seq = rec.sequence
    assert target_seq is not None
    # Remove the record from both the chain and the per-identity index.
    del ledger._entries[target_seq]  # type: ignore[attr-defined]
    ledger._by_identity[gap_key] = [  # type: ignore[attr-defined]
        s if s < target_seq else s - 1
        for s in ledger._by_identity[gap_key]  # type: ignore[attr-defined]
        if s != target_seq
    ]
    gaps = ledger.verify_no_gaps()
    assert gap_key in gaps["gaps"], "excising seq 1 must surface a sequence gap"

    # The real PDP now ABSTAINs for this lineage: the budget is unverifiable, so
    # the degraded hold fires PERMIT→ABSTAIN. (verify_chain may also break from
    # the excision; either way the reload returns None → DEGRADED → ABSTAIN.)
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    resp = pdp.evaluate(
        request=_req(confidentiality="PUBLIC", lineage="lin-fork", seconds=10),
        policy=policy,
    ).response
    assert resp.verdict is Verdict.ABSTAIN, "an unverifiable budget must never silently allow"


# ── E. default-OFF: zero behavior change without the flag ─────────────────────


def test_default_off_is_inert_through_pdp() -> None:
    # No TEX_BUDGET_ENABLED, default config disabled → even a flood of RESTRICTED
    # actions never trips (the seam is skipped and the tracker is untracked).
    os.environ.pop("TEX_BUDGET_ENABLED", None)
    configure_default_budget_tracker(BudgetConfig.from_env())
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    # Space actions 20s apart so the (unrelated) action-cadence breaker's 10s
    # sliding window never co-buckets them — this test isolates the value budget.
    verdicts = [
        pdp.evaluate(
            request=_req(
                confidentiality="RESTRICTED", lineage="lin-off", seconds=i * 20.0
            ),
            policy=policy,
        ).response.verdict
        for i in range(10)
    ]
    assert all(v is Verdict.PERMIT for v in verdicts)
