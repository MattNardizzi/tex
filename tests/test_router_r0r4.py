"""
Equivalence + wiring guard for the unified R0–R4 selective-risk verdict rule
(engine/router.py).

The R0–R4 rewrite is a behaviour-PRESERVING refactor: the precedence ladder is
reorganised and every magic constant is moved into ``SelectiveRiskRule``, but no
decision changes. ``test_r0r4_matches_legacy_over_battery`` proves that against a
verbatim replica of the pre-refactor logic across a large randomised battery —
it would fail if the refactor altered a single verdict.

``test_custom_rule_changes_a_borderline_forbid`` then proves the rule object is
actually WIRED (not cosmetic): tightening a named constant changes a borderline
verdict in the expected, more-conservative direction.
"""

from __future__ import annotations

import random

from tex.domain.severity import Severity
from tex.domain.verdict import Verdict
from tex.engine.router import (
    DEFAULT_SELECTIVE_RISK_RULE,
    DecisionRouter,
    SelectiveRiskRule,
)
from tex.domain.agent_signal import (
    AgentEvaluationBundle,
    AgentIdentitySignal,
    BehavioralSignal,
    CapabilitySignal,
)
from tex.specialists.base import SpecialistBundle, SpecialistResult

from tests.factories import make_default_policy, make_finding, make_gate_result, make_semantic_analysis


def _agent_bundle(
    *,
    lifecycle: str = "ACTIVE",
    capability_violation: bool = False,
    cold_start: bool = False,
    forbid_streak: int = 0,
    risk: float = 0.05,
) -> AgentEvaluationBundle:
    """A minimal but valid agent bundle for exercising the R0/R3 agent path."""
    return AgentEvaluationBundle(
        agent_present=True,
        agent_id="agent-1",
        identity=AgentIdentitySignal(
            risk_score=risk,
            confidence=0.8,
            trust_tier="standard",
            lifecycle_status=lifecycle,
            environment_match=True,
            attestation_count=1,
            active_attestation_count=1,
            age_seconds=1000.0,
        ),
        capability=CapabilitySignal(
            risk_score=0.9 if capability_violation else 0.05,
            confidence=0.8,
            surface_unrestricted=False,
            action_permitted=not capability_violation,
            channel_permitted=True,
            environment_permitted=True,
            recipient_permitted=True,
            violated_dimensions=("action",) if capability_violation else (),
        ),
        behavioral=BehavioralSignal(
            risk_score=risk,
            confidence=0.8,
            sample_size=0 if cold_start else 50,
            cold_start=cold_start,
            novel_action_type=False,
            novel_channel=False,
            novel_recipient_domain=False,
            forbid_streak=forbid_streak,
            capability_violation_rate=0.0,
            recent_abstain_rate=0.0,
        ),
    )


# ── verbatim replica of the PRE-refactor verdict logic ──────────────────────


_LEGACY_STRUCTURAL = {
    "clawguard", "mcpshield", "planguard", "mage", "agentarmor",
    "argus", "attriguard", "vigil",
}


def _legacy_should_abstain(
    *, semantic_analysis, specialist_bundle, final_score, confidence, policy, uncertainty_flags
) -> bool:
    if semantic_analysis.recommended_verdict.verdict == Verdict.ABSTAIN:
        return True
    if confidence < policy.minimum_confidence:
        return True
    if semantic_analysis.has_low_confidence_dimension:
        return True
    if semantic_analysis.evidence_sufficiency < 0.25 and final_score >= policy.permit_threshold:
        return True
    if specialist_bundle.max_risk_score >= 0.60 and final_score < policy.forbid_threshold:
        return True
    for spec in specialist_bundle.results:
        if (
            spec.specialist_name in _LEGACY_STRUCTURAL
            and spec.risk_score >= 0.30
            and spec.matched_policy_clause_ids
            and final_score < policy.forbid_threshold
        ):
            return True
    if any(f.casefold() == "no_retrieval_context" for f in uncertainty_flags):
        if final_score >= policy.permit_threshold:
            return True
    if policy.permit_threshold < final_score < policy.forbid_threshold:
        return True
    return False


def _legacy_verdict(
    *, deterministic_result, semantic_analysis, specialist_bundle, final_score, confidence, policy, uncertainty_flags
) -> Verdict:
    if deterministic_result.blocked:
        return Verdict.FORBID
    rec = semantic_analysis.recommended_verdict
    if (
        rec.verdict == Verdict.FORBID
        and rec.confidence >= 0.85
        and semantic_analysis.max_dimension_score >= 0.90
        and semantic_analysis.evidence_sufficiency >= 0.40
    ):
        return Verdict.FORBID
    if rec.verdict == Verdict.FORBID and final_score >= policy.permit_threshold:
        return Verdict.FORBID
    if final_score >= policy.forbid_threshold:
        return Verdict.FORBID
    if _legacy_should_abstain(
        semantic_analysis=semantic_analysis,
        specialist_bundle=specialist_bundle,
        final_score=final_score,
        confidence=confidence,
        policy=policy,
        uncertainty_flags=uncertainty_flags,
    ):
        return Verdict.ABSTAIN
    if (
        final_score <= policy.permit_threshold
        and confidence >= policy.minimum_confidence
        and rec.verdict == Verdict.PERMIT
    ):
        return Verdict.PERMIT
    return Verdict.ABSTAIN


def _spec(name: str, risk: float, clause: bool) -> SpecialistResult:
    return SpecialistResult(
        specialist_name=name,
        risk_score=risk,
        confidence=0.8,
        summary="x",
        matched_policy_clause_ids=("clause:1",) if clause else (),
    )


def test_r0r4_matches_legacy_over_battery() -> None:
    router = DecisionRouter()
    policy = make_default_policy()
    rng = random.Random(20260609)

    verdict_choices = (Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID)
    spec_names = ("argus", "mage", "vigil", "genericspec", "deterministic")
    flag_choices = ((), ("no_retrieval_context",), ("weak_evidence",))

    checked = 0
    for _ in range(4000):
        blocked = rng.random() < 0.15
        gate = make_gate_result(
            findings=(make_finding(severity=Severity.CRITICAL, rule_name="r"),) if blocked else (),
            blocked=blocked,
        )
        semantic = make_semantic_analysis(
            recommended_verdict=rng.choice(verdict_choices),
            recommended_confidence=round(rng.uniform(0.3, 0.99), 2),
            dimension_score=round(rng.uniform(0.0, 1.0), 2),
            dimension_confidence=round(rng.uniform(0.3, 0.9), 2),
            overall_confidence=round(rng.uniform(0.3, 0.9), 2),
            evidence_sufficiency=round(rng.uniform(0.0, 0.9), 2),
            uncertainty_flags=rng.choice(flag_choices),
        )
        bundle = SpecialistBundle(
            results=(
                _spec(rng.choice(spec_names), round(rng.uniform(0.0, 1.0), 2), rng.random() < 0.6),
            )
        )
        final_score = round(rng.uniform(0.0, 1.0), 3)
        confidence = round(rng.uniform(0.0, 1.0), 3)
        flags = semantic.uncertainty_flags

        got = router._determine_verdict(
            deterministic_result=gate,
            semantic_analysis=semantic,
            specialist_bundle=bundle,
            final_score=final_score,
            confidence=confidence,
            policy=policy,
            uncertainty_flags=flags,
            agent_bundle=None,
        )
        expected = _legacy_verdict(
            deterministic_result=gate,
            semantic_analysis=semantic,
            specialist_bundle=bundle,
            final_score=final_score,
            confidence=confidence,
            policy=policy,
            uncertainty_flags=flags,
        )
        assert got is expected, (
            f"divergence: score={final_score} conf={confidence} "
            f"sem={semantic.recommended_verdict.verdict} got={got} exp={expected}"
        )
        checked += 1
    assert checked == 4000


def test_custom_rule_changes_a_borderline_forbid() -> None:
    """A semantic FORBID just under the default override bar (conf 0.85) lands
    at ABSTAIN by default; tightening the override confidence to 0.80 promotes
    it to a FORBID — proving the rule object drives the decision."""
    policy = make_default_policy()
    semantic = make_semantic_analysis(
        recommended_verdict=Verdict.FORBID,
        recommended_confidence=0.82,  # below default 0.85, above custom 0.80
        dimension_score=0.95,
        dimension_confidence=0.7,
        evidence_sufficiency=0.5,
    )
    bundle = SpecialistBundle(results=(_spec("genericspec", 0.0, False),))
    kw = dict(
        deterministic_result=make_gate_result(),
        semantic_analysis=semantic,
        specialist_bundle=bundle,
        final_score=0.10,  # below permit threshold so R2 soft-FORBID won't fire
        confidence=0.99,
        policy=policy,
        uncertainty_flags=(),
        agent_bundle=None,
    )
    default_router = DecisionRouter()
    assert default_router._determine_verdict(**kw) is not Verdict.FORBID

    strict = DecisionRouter(
        rule=SelectiveRiskRule(semantic_override_confidence=0.80)
    )
    assert strict._determine_verdict(**kw) is Verdict.FORBID


def test_default_rule_is_the_module_default() -> None:
    assert DecisionRouter()._rule is DEFAULT_SELECTIVE_RISK_RULE


def test_agent_path_r0_and_r3_branches_preserved() -> None:
    """The agent path (R0 quarantine/capability, R3 streak/cold-start/PENDING)
    is exercised here — the equivalence battery above runs agent-free, so this
    pins the branches the refactor copied verbatim, and confirms they still map
    as the doctrine requires."""
    router = DecisionRouter()
    policy = make_default_policy()
    clean_semantic = make_semantic_analysis(
        recommended_verdict=Verdict.PERMIT, recommended_confidence=0.9
    )
    base = dict(
        deterministic_result=make_gate_result(),
        semantic_analysis=clean_semantic,
        specialist_bundle=SpecialistBundle(results=(_spec("genericspec", 0.0, False),)),
        confidence=0.9,
        policy=policy,
        uncertainty_flags=(),
    )

    # R0: quarantine → ABSTAIN (even on a clean low-score request).
    v = router._determine_verdict(
        **base, final_score=0.0, agent_bundle=_agent_bundle(lifecycle="QUARANTINED")
    )
    assert v is Verdict.ABSTAIN

    # R0: capability violation → FORBID.
    v = router._determine_verdict(
        **base, final_score=0.0, agent_bundle=_agent_bundle(capability_violation=True)
    )
    assert v is Verdict.FORBID

    # R3: forbid streak >= 3 → ABSTAIN on otherwise-clean content.
    v = router._determine_verdict(
        **base, final_score=0.0, agent_bundle=_agent_bundle(forbid_streak=3)
    )
    assert v is Verdict.ABSTAIN

    # R3: cold-start at score >= permit*0.8 → ABSTAIN.
    cold_score = policy.permit_threshold * 0.85
    v = router._determine_verdict(
        **base, final_score=cold_score, agent_bundle=_agent_bundle(cold_start=True)
    )
    assert v is Verdict.ABSTAIN

    # R3: PENDING lifecycle at score >= permit*0.5 → ABSTAIN.
    pending_score = policy.permit_threshold * 0.6
    v = router._determine_verdict(
        **base, final_score=pending_score, agent_bundle=_agent_bundle(lifecycle="PENDING")
    )
    assert v is Verdict.ABSTAIN

    # A fully clean ACTIVE agent on a clean low score still PERMITs (the agent
    # path does not over-abstain when nothing is wrong).
    v = router._determine_verdict(
        **base, final_score=0.0, agent_bundle=_agent_bundle()
    )
    assert v is Verdict.PERMIT


def test_r0_deterministic_block_beats_everything() -> None:
    router = DecisionRouter()
    gate = make_gate_result(
        findings=(make_finding(severity=Severity.CRITICAL, rule_name="x"),),
        blocked=True,
    )
    # Even a confident semantic PERMIT and a clean low score cannot lift R0.
    v = router._determine_verdict(
        deterministic_result=gate,
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT, recommended_confidence=0.99
        ),
        specialist_bundle=SpecialistBundle(results=(_spec("genericspec", 0.0, False),)),
        final_score=0.0,
        confidence=0.99,
        policy=make_default_policy(),
        uncertainty_flags=(),
        agent_bundle=None,
    )
    assert v is Verdict.FORBID
