"""
Tests for the autonomous-attack action-cadence circuit-breaker.

Covers, end to end, the acceptance contract for ``night/circuit-breaker``:

  * a burst of N actions in T seconds from one agent deterministically trips
    ABSTAIN (soft budget) then FORBID (hard threshold);
  * normal cadence — a slow drip, a single action, anonymous/agentless traffic,
    or a different agent — is unaffected;
  * the monotone-lowering invariant holds (a cadence signal only ever lowers a
    verdict toward caution; it never raises one, never relaxes a FORBID/ABSTAIN,
    and a HARD threshold is a counted fact that fires the deterministic floor,
    while a high probabilistic score can NOT fire it);
  * the trigger reason + window stats + counterfactual are sealed into the
    verdict's reasons and finding metadata;
  * no model/semantic call sits anywhere on the new path.

Unit tests drive the tracker / recognizer / floor source / hold in isolation;
integration tests drive the real ``PolicyDecisionPoint.evaluate``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tex.deterministic.cadence import (
    CADENCE_HOLD_FLAG,
    ActionCadenceTracker,
    CadenceConfig,
    CadenceLevel,
    apply_cadence_hold,
    assess_for_floor,
    configure_default_cadence_tracker,
)
from tex.deterministic.recognizers import ActionCadenceRecognizer, default_recognizers
from tex.domain.evaluation import AgentRuntimeIdentity, EvaluationRequest
from tex.domain.severity import Severity
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.engine.router import RoutingResult
from tex.policies.defaults import build_default_policy
from tex.specialists.base import SpecialistBundle
from tex.specialists.structural_floor import (
    CADENCE_CODE,
    CADENCE_SPECIALIST,
    detect_structural_floor,
)

from tests.factories import make_semantic_analysis, make_specialist_result


# Small, fast thresholds shared by most tests: soft at 3 actions, hard at 5.
# Fan-out thresholds are pushed out of the way so action-rate tests isolate rate.
FAST = CadenceConfig(
    window_seconds=10.0,
    soft_actions=3,
    hard_actions=5,
    soft_fanout=999,
    hard_fanout=999,
)
T0 = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)
AGENT = UUID("00000000-0000-4000-8000-000000000001")


def _req(
    *,
    agent_id: UUID | None = AGENT,
    seconds: float = 0.0,
    recipient: str | None = "ops@acme.com",
    targets: tuple[str, ...] | None = None,
    content: str = "All systems nominal, proceeding.",
) -> EvaluationRequest:
    metadata: dict[str, object] = {}
    if targets is not None:
        metadata["cadence_targets"] = list(targets)
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="status_ping",
        content=content,
        recipient=recipient,
        channel="api",
        environment="production",
        agent_id=agent_id,
        metadata=metadata,
        requested_at=T0 + timedelta(seconds=seconds),
    )


# ── A. tracker unit tests ───────────────────────────────────────────────────


def test_below_soft_is_clear_and_untracked_findings_none() -> None:
    tracker = ActionCadenceTracker(FAST)
    a1 = tracker.assess(_req(seconds=0.0))
    a2 = tracker.assess(_req(seconds=0.1))
    assert a1.level is CadenceLevel.CLEAR and a1.tracked is True
    assert a2.level is CadenceLevel.CLEAR
    assert a2.action_count == 2
    assert a1.fired is False and a2.fired is False


def test_burst_rate_trips_soft_then_hard() -> None:
    tracker = ActionCadenceTracker(FAST)
    levels = [tracker.assess(_req(seconds=i * 0.1)).level for i in range(7)]
    assert levels == [
        CadenceLevel.CLEAR,
        CadenceLevel.CLEAR,
        CadenceLevel.SOFT,  # 3rd action == soft_actions
        CadenceLevel.SOFT,
        CadenceLevel.HARD,  # 5th action == hard_actions
        CadenceLevel.HARD,
        CadenceLevel.HARD,
    ]


def test_fanout_trips_independently_of_rate() -> None:
    # Few actions, but each to a distinct target: branching trips the breaker
    # even though the action rate stays under its budget.
    cfg = CadenceConfig(
        window_seconds=10.0,
        soft_actions=999,
        hard_actions=999,
        soft_fanout=3,
        hard_fanout=5,
    )
    tracker = ActionCadenceTracker(cfg)
    seen = []
    for i in range(6):
        a = tracker.assess(_req(seconds=i * 0.1, recipient=f"victim{i}@acme.com"))
        seen.append((a.distinct_targets, a.level))
    assert seen[1][1] is CadenceLevel.CLEAR  # 2 targets
    assert seen[2][1] is CadenceLevel.SOFT  # 3 distinct targets == soft_fanout
    assert seen[4][1] is CadenceLevel.HARD  # 5 distinct targets == hard_fanout


def test_window_expiry_does_not_accumulate_for_slow_drip() -> None:
    # One action every 5s with a 10s window: at most 3 ever co-reside in the
    # window, so a slow, sustained drip never trips even soft.
    tracker = ActionCadenceTracker(FAST)
    levels = [tracker.assess(_req(seconds=i * 5.0)).level for i in range(10)]
    assert all(level is CadenceLevel.CLEAR for level in levels)
    # And the final window holds only the entries within the last 10s (≤3).
    assert tracker.assess(_req(seconds=50.0)).action_count <= 3


def test_idempotent_same_request_id_does_not_double_count() -> None:
    tracker = ActionCadenceTracker(FAST)
    req = _req(seconds=0.0)
    first = tracker.assess(req)
    second = tracker.assess(req)
    third = tracker.assess(req)
    assert first == second == third
    assert first.action_count == 1  # counted exactly once across three reads


def test_untracked_without_agent_identity() -> None:
    tracker = ActionCadenceTracker(FAST)
    for i in range(10):
        a = tracker.assess(_req(agent_id=None, seconds=i * 0.1))
        assert a.tracked is False
        assert a.level is CadenceLevel.CLEAR
        assert a.action_count == 0


def test_distinct_agents_do_not_cross_contaminate() -> None:
    tracker = ActionCadenceTracker(FAST)
    other = UUID("00000000-0000-4000-8000-0000000000ff")
    # Interleave two agents; neither should push the other over budget.
    levels_a, levels_b = [], []
    for i in range(4):
        levels_a.append(tracker.assess(_req(agent_id=AGENT, seconds=i * 0.1)).level)
        levels_b.append(tracker.assess(_req(agent_id=other, seconds=i * 0.1)).level)
    # Agent A's 3rd/4th actions are soft; agent B's are independently counted.
    assert levels_a[2] is CadenceLevel.SOFT
    assert levels_b[2] is CadenceLevel.SOFT
    # 4 each — neither reaches the other's would-be hard (which needs 5 combined).
    assert CadenceLevel.HARD not in levels_a
    assert CadenceLevel.HARD not in levels_b


def test_tenant_is_part_of_the_key() -> None:
    tracker = ActionCadenceTracker(FAST)

    def runtime_req(tenant: str, seconds: float) -> EvaluationRequest:
        return EvaluationRequest(
            request_id=uuid4(),
            action_type="status_ping",
            content="proceeding",
            recipient="ops@acme.com",
            channel="api",
            environment="production",
            agent_identity=AgentRuntimeIdentity(agent_id=AGENT, tenant_id=tenant),
            requested_at=T0 + timedelta(seconds=seconds),
        )

    # Same agent_id under two tenants are distinct keys → independent windows.
    for i in range(2):
        tracker.assess(runtime_req("tenant-a", i * 0.1))
    a_third = tracker.assess(runtime_req("tenant-a", 0.3))
    b_first = tracker.assess(runtime_req("tenant-b", 0.4))
    assert a_third.action_count == 3 and a_third.level is CadenceLevel.SOFT
    assert b_first.action_count == 1 and b_first.level is CadenceLevel.CLEAR


def test_disabled_config_is_a_noop() -> None:
    tracker = ActionCadenceTracker(CadenceConfig(enabled=False, soft_actions=1, hard_actions=1))
    for i in range(10):
        a = tracker.assess(_req(seconds=i * 0.1))
        assert a.tracked is False and a.level is CadenceLevel.CLEAR


# ── B. config / env tests ───────────────────────────────────────────────────


def test_from_env_defaults_when_unset() -> None:
    cfg = CadenceConfig.from_env({})
    assert cfg.enabled is True
    assert cfg.window_seconds == 10.0
    assert (cfg.soft_actions, cfg.hard_actions) == (8, 20)
    assert (cfg.soft_fanout, cfg.hard_fanout) == (6, 15)


def test_from_env_overrides_are_parsed() -> None:
    cfg = CadenceConfig.from_env(
        {
            "TEX_CADENCE_ENABLED": "false",
            "TEX_CADENCE_WINDOW_SECONDS": "30",
            "TEX_CADENCE_SOFT_ACTIONS": "4",
            "TEX_CADENCE_HARD_ACTIONS": "9",
            "TEX_CADENCE_SOFT_FANOUT": "2",
            "TEX_CADENCE_HARD_FANOUT": "7",
        }
    )
    assert cfg.enabled is False
    assert cfg.window_seconds == 30.0
    assert (cfg.soft_actions, cfg.hard_actions) == (4, 9)
    assert (cfg.soft_fanout, cfg.hard_fanout) == (2, 7)


def test_from_env_malformed_values_fall_back_to_defaults() -> None:
    cfg = CadenceConfig.from_env(
        {
            "TEX_CADENCE_WINDOW_SECONDS": "not-a-number",
            "TEX_CADENCE_SOFT_ACTIONS": "-5",
            "TEX_CADENCE_HARD_ACTIONS": "0",
        }
    )
    # Bad → silently uses the safe defaults; never crashes, never over-aggressive.
    assert cfg.window_seconds == 10.0
    assert cfg.soft_actions == 8
    assert cfg.hard_actions == 20


def test_from_env_clamps_hard_below_soft() -> None:
    # An operator who inverts the thresholds must NOT get a breaker that FORBIDs
    # before it ABSTAINs. hard is clamped up to soft.
    cfg = CadenceConfig.from_env(
        {"TEX_CADENCE_SOFT_ACTIONS": "10", "TEX_CADENCE_HARD_ACTIONS": "3"}
    )
    assert cfg.soft_actions == 10
    assert cfg.hard_actions == 10  # clamped


# ── C. recognizer tests ─────────────────────────────────────────────────────


def test_recognizer_registered_in_defaults() -> None:
    names = [r.name for r in default_recognizers()]
    assert "action_cadence" in names
    # It runs last so it observes the action exactly once after the cheap scans.
    assert names[-1] == "action_cadence"


def test_recognizer_silent_when_clear() -> None:
    rec = ActionCadenceRecognizer(tracker=ActionCadenceTracker(FAST))
    assert rec.scan(_req(seconds=0.0)) == ()


def test_recognizer_emits_warning_on_soft_and_critical_on_hard() -> None:
    tracker = ActionCadenceTracker(FAST)
    rec = ActionCadenceRecognizer(tracker=tracker)
    # Prime to just-below soft.
    rec.scan(_req(seconds=0.0))
    rec.scan(_req(seconds=0.1))
    soft = rec.scan(_req(seconds=0.2))  # 3rd → soft
    assert len(soft) == 1
    assert soft[0].severity is Severity.WARNING
    assert soft[0].rule_name == "action_cadence"
    assert soft[0].source == "deterministic.action_cadence"
    assert soft[0].metadata["cadence_level"] == "soft"
    assert soft[0].metadata["action_count"] == 3
    assert "counterfactual" in soft[0].metadata

    rec.scan(_req(seconds=0.3))
    hard = rec.scan(_req(seconds=0.4))  # 5th → hard
    assert hard[0].severity is Severity.CRITICAL
    assert hard[0].metadata["cadence_level"] == "hard"


def test_no_model_or_semantic_call_on_the_cadence_path() -> None:
    # Structural guard: the cadence module must not import or call any LLM /
    # semantic analyzer. The whole point is a deterministic, paraphrase-proof
    # counter — a model in this path would reintroduce the arms race it avoids.
    # We scan import statements + call sites (not arbitrary text, so the benign
    # passthrough of the ``semantic_dominance_override_fired`` RoutingResult field
    # — which copies a bool, never calls a model — is not falsely flagged).
    source = Path(__file__).resolve().parents[1] / "src" / "tex" / "deterministic" / "cadence.py"
    lines = source.read_text(encoding="utf-8").splitlines()
    import_lines = [
        ln.strip().casefold()
        for ln in lines
        if ln.strip().startswith(("import ", "from "))
    ]
    for ln in import_lines:
        for forbidden in ("openai", "anthropic", "tex.semantic", "llm", "provider"):
            assert forbidden not in ln, f"cadence imports must not reference {forbidden!r}: {ln!r}"
    full = "\n".join(lines).casefold()
    # No analyzer call sites.
    for forbidden_call in (".analyze(", "semantic_analyzer", "semanticanalyzer"):
        assert forbidden_call not in full, f"cadence path must not call {forbidden_call!r}"


# ── D. structural-floor source tests (HARD → FORBID) ────────────────────────


def _drive_singleton(n: int, *, agent_id: UUID = AGENT) -> EvaluationRequest:
    """Send n actions for one agent through the shared singleton and return the
    last request (already observed as the n-th action, memoized)."""
    last = _req(agent_id=agent_id, seconds=0.0)
    for i in range(n):
        last = _req(agent_id=agent_id, seconds=i * 0.1)
        assess_for_floor(last)
    return last


def test_floor_fires_on_hard_threshold() -> None:
    configure_default_cadence_tracker(FAST)
    hard_req = _drive_singleton(5)  # 5th action == hard_actions
    out = detect_structural_floor(SpecialistBundle(results=()), request=hard_req)
    assert out.fired is True
    assert CADENCE_SPECIALIST in out.denying_specialists
    finding = next(f for f in out.findings if f.metadata.get("specialist") == CADENCE_SPECIALIST)
    assert CADENCE_CODE in finding.metadata["codes"]


def test_floor_silent_on_soft_threshold() -> None:
    configure_default_cadence_tracker(FAST)
    soft_req = _drive_singleton(3)  # soft, not hard
    out = detect_structural_floor(SpecialistBundle(results=()), request=soft_req)
    assert CADENCE_SPECIALIST not in out.denying_specialists


def test_floor_silent_without_request() -> None:
    configure_default_cadence_tracker(FAST)
    _drive_singleton(5)  # window is hot, but no request passed
    out = detect_structural_floor(SpecialistBundle(results=()))
    assert out.fired is False


def test_high_probabilistic_score_cannot_fire_cadence_floor() -> None:
    # Structural-floor discipline: only a counted threshold fires the cadence
    # deny. A single action with a sky-high specialist risk must NOT trip it.
    configure_default_cadence_tracker(FAST)
    bundle = SpecialistBundle(
        results=(make_specialist_result(name="vigil", risk_score=0.99, confidence=0.99),)
    )
    out = detect_structural_floor(bundle, request=_req(seconds=0.0))
    assert CADENCE_SPECIALIST not in out.denying_specialists


# ── E. soft-hold tests (PERMIT → ABSTAIN) ───────────────────────────────────


def _routing(verdict: Verdict) -> RoutingResult:
    return RoutingResult(
        verdict=verdict,
        confidence=0.9,
        final_score=0.1 if verdict is Verdict.PERMIT else 0.9,
        reasons=("baseline",),
        findings=(),
        scores={"deterministic": 0.0},
        uncertainty_flags=() if verdict is not Verdict.ABSTAIN else ("baseline_uncertainty",),
    )


def test_hold_demotes_permit_to_abstain_on_soft() -> None:
    configure_default_cadence_tracker(FAST)
    soft_req = _drive_singleton(3)
    out = apply_cadence_hold(base=_routing(Verdict.PERMIT), request=soft_req)
    assert out.verdict is Verdict.ABSTAIN
    assert CADENCE_HOLD_FLAG in out.uncertainty_flags
    assert any("cadence" in r.lower() for r in out.reasons)
    assert any("counterfactual" in r.lower() for r in out.reasons)
    assert out.scores["action_cadence"] == pytest.approx(0.5)


def test_hold_is_noop_when_clear() -> None:
    configure_default_cadence_tracker(FAST)
    clear_req = _drive_singleton(1)
    base = _routing(Verdict.PERMIT)
    out = apply_cadence_hold(base=base, request=clear_req)
    assert out is base  # untouched


def test_hold_never_raises_a_non_permit_verdict() -> None:
    configure_default_cadence_tracker(FAST)
    hard_req = _drive_singleton(5)  # HARD in the window
    # A base FORBID stays FORBID; a base ABSTAIN stays ABSTAIN. The hold lowers,
    # never raises or relaxes.
    forbid_base = _routing(Verdict.FORBID)
    abstain_base = _routing(Verdict.ABSTAIN)
    assert apply_cadence_hold(base=forbid_base, request=hard_req) is forbid_base
    assert apply_cadence_hold(base=abstain_base, request=hard_req) is abstain_base


def test_hold_hard_defense_in_depth_abstains_never_forbids() -> None:
    # If the structural floor were bypassed and a HARD cadence reached the soft
    # rail on a PERMIT, the hold may only lower to ABSTAIN — never raise to FORBID
    # (FORBID authority lives solely in the deterministic floor).
    configure_default_cadence_tracker(FAST)
    hard_req = _drive_singleton(5)
    out = apply_cadence_hold(base=_routing(Verdict.PERMIT), request=hard_req)
    assert out.verdict is Verdict.ABSTAIN


# ── F. integration tests through the real PDP ───────────────────────────────


class _PermitSemantic:
    """Semantic analyzer stub that confidently recommends PERMIT, so a benign
    request has a PERMIT baseline (the default fallback analyzer abstains). Lets
    the integration tests show the PERMIT→ABSTAIN transition the soft hold makes.
    No network, fully deterministic."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.95,
            overall_confidence=0.9,
            evidence_sufficiency=0.6,
        )


def test_burst_trips_permit_abstain_forbid_through_pdp() -> None:
    configure_default_cadence_tracker(FAST)
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    verdicts = [
        pdp.evaluate(request=_req(seconds=i * 0.2), policy=policy).response.verdict
        for i in range(7)
    ]
    assert verdicts == [
        Verdict.PERMIT,
        Verdict.PERMIT,
        Verdict.ABSTAIN,
        Verdict.ABSTAIN,
        Verdict.FORBID,
        Verdict.FORBID,
        Verdict.FORBID,
    ]


def test_normal_cadence_and_other_agents_unaffected() -> None:
    configure_default_cadence_tracker(FAST)
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    # Slow drip from one agent (every 5s, 10s window) stays PERMIT throughout.
    drip = [
        pdp.evaluate(request=_req(seconds=i * 5.0), policy=policy).response.verdict
        for i in range(6)
    ]
    assert all(v is Verdict.PERMIT for v in drip)
    # A different agent doing a single action is unaffected by anyone else.
    other = pdp.evaluate(
        request=_req(agent_id=uuid4(), seconds=0.3), policy=policy
    ).response.verdict
    assert other is Verdict.PERMIT


def test_anonymous_traffic_is_never_bucketed_into_a_burst() -> None:
    configure_default_cadence_tracker(FAST)
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    # Many agentless requests in one window must never trip — no identity to
    # attribute a burst to, so they are not bucketed together.
    verdicts = [
        pdp.evaluate(
            request=_req(agent_id=None, seconds=i * 0.05), policy=policy
        ).response.verdict
        for i in range(12)
    ]
    assert all(v is Verdict.PERMIT for v in verdicts)


def test_reason_and_counterfactual_and_window_stats_are_sealed() -> None:
    configure_default_cadence_tracker(FAST)
    pdp = PolicyDecisionPoint(semantic_analyzer=_PermitSemantic())
    policy = build_default_policy()
    last = None
    for i in range(5):  # 5th → HARD → FORBID
        last = pdp.evaluate(request=_req(seconds=i * 0.2), policy=policy)
    assert last is not None
    decision = last.decision
    assert decision.verdict is Verdict.FORBID

    # Reason text sealed into the durable decision.
    assert any("action-cadence circuit-breaker" in r.lower() for r in decision.reasons)
    # Structural-floor attribution sealed into decision metadata.
    sf = decision.metadata["pdp"]["structural_floor"]
    assert sf["fired"] is True
    assert CADENCE_SPECIALIST in sf["denying_specialists"]
    # Window stats + counterfactual sealed into the finding metadata.
    cadence_findings = [
        f for f in decision.findings if f.rule_name == "action_cadence"
    ]
    assert cadence_findings, "expected a sealed action_cadence finding"
    meta = cadence_findings[0].metadata
    assert meta["cadence_level"] == "hard"
    assert meta["action_count"] == 5
    assert meta["window_seconds"] == 10.0
    assert "counterfactual" in meta and meta["counterfactual"]


# ── G. monotone-lowering invariant (extends the verdict-path spec) ──────────


class _ForbidSemantic:
    """Semantic analyzer stub that confidently recommends FORBID, tripping the
    router's R1 semantic-dominance override independently of cadence."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.FORBID,
            recommended_confidence=0.95,
            dimension_score=0.95,
            overall_confidence=0.9,
            evidence_sufficiency=0.6,
        )


def test_cadence_signal_never_relaxes_a_forbid_through_pdp() -> None:
    # A request that is independently FORBID (high-confidence semantic FORBID,
    # R1 override) and that ALSO carries a soft cadence must remain FORBID — a
    # cadence signal lowers toward caution, it can never relax a verdict. The
    # soft hold only acts on a PERMIT, so it is a no-op here by construction.
    configure_default_cadence_tracker(FAST)
    pdp = PolicyDecisionPoint(semantic_analyzer=_ForbidSemantic())
    policy = build_default_policy()
    # Drive into the soft band (3 actions) — each is independently FORBID.
    verdicts = [
        pdp.evaluate(request=_req(seconds=i * 0.2), policy=policy).response.verdict
        for i in range(3)
    ]
    assert all(v is Verdict.FORBID for v in verdicts)
