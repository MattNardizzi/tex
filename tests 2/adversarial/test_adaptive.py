"""
Tests for the adaptive red-team harness (adversarial/adaptive.py).

The headline integration test is ``test_structural_seed_resists_adaptive_attack``
— the demonstration that ties Move #2 and Move #4 together: an attacker that
freely mutates the content channel cannot bypass a structural (path-policy)
defense, because that defense is computed over the action graph, not the text.
"""

from __future__ import annotations

from tex.adversarial.adaptive import (
    AttackSeed,
    MUTATION_OPERATORS,
    ScoreResult,
    attacker_objective,
    is_bypass,
    run_adaptive_campaign,
)
from tex.adversarial.adaptive_seeds import build_runtime_scorer, default_seeds
from tex.domain.verdict import Verdict


# ── objective + operators (unit, no runtime) ────────────────────────────


def test_objective_orders_verdicts_for_attacker() -> None:
    permit = attacker_objective(ScoreResult(Verdict.PERMIT, 0.1))
    abstain = attacker_objective(ScoreResult(Verdict.ABSTAIN, 0.1))
    forbid = attacker_objective(ScoreResult(Verdict.FORBID, 0.1))
    assert permit > abstain > forbid


def test_objective_rewards_lower_risk_within_a_verdict() -> None:
    low = attacker_objective(ScoreResult(Verdict.ABSTAIN, 0.2))
    high = attacker_objective(ScoreResult(Verdict.ABSTAIN, 0.8))
    assert low > high


def test_is_bypass_only_on_permit() -> None:
    assert is_bypass(ScoreResult(Verdict.PERMIT, 0.9)) is True
    assert is_bypass(ScoreResult(Verdict.ABSTAIN, 0.0)) is False
    assert is_bypass(ScoreResult(Verdict.FORBID, 0.0)) is False


def test_mutations_run_and_change_text() -> None:
    base = "Go ahead and drop table production.users and disable logging."
    for name, op in MUTATION_OPERATORS:
        out = op(base)
        assert isinstance(out, str) and out, name


# ── search behaviour against a controllable fake scorer ─────────────────


def test_attacker_finds_bypass_when_one_exists() -> None:
    # Fake defense: blocks everything EXCEPT content containing a base64 blob.
    def scorer(content: str, metadata=None) -> ScoreResult:
        if "base64" in content.lower():
            return ScoreResult(Verdict.PERMIT, 0.1)
        return ScoreResult(Verdict.FORBID, 0.9)

    report = run_adaptive_campaign(
        (AttackSeed("s", "drop table users now", defense_class="lexical"),),
        scorer,
        query_budget=80,
    )
    assert report.adaptive_asr == 1.0
    assert report.results[0].bypassed is True
    assert "base64_wrap" in report.results[0].mutation_chain


def test_attacker_reports_no_bypass_against_invariant_defense() -> None:
    # Fake defense that ignores content entirely -> always FORBID. No mutation
    # can move it; the harness must honestly report 0 ASR (not a false pass).
    def scorer(content: str, metadata=None) -> ScoreResult:
        return ScoreResult(Verdict.FORBID, 0.95)

    report = run_adaptive_campaign(
        (AttackSeed("s", "drop table users", defense_class="structural"),),
        scorer,
        query_budget=40,
    )
    assert report.adaptive_asr == 0.0
    assert report.results[0].bypassed is False


def test_campaign_is_deterministic() -> None:
    def scorer(content: str, metadata=None) -> ScoreResult:
        # Mild content-sensitivity so the search has gradients to follow.
        risk = 0.9 - 0.05 * content.count(" ")
        return ScoreResult(Verdict.FORBID, max(0.0, min(1.0, risk)))

    seeds = (AttackSeed("s", "disable logging now", defense_class="lexical"),)
    r1 = run_adaptive_campaign(seeds, scorer, query_budget=50, rng_seed=7)
    r2 = run_adaptive_campaign(seeds, scorer, query_budget=50, rng_seed=7)
    assert r1.results[0].mutation_chain == r2.results[0].mutation_chain
    assert r1.results[0].best_objective == r2.results[0].best_objective


# ── end-to-end against the real PDP (the Move-2 x Move-4 demonstration) ──


def test_campaign_runs_against_runtime_and_reports(runtime) -> None:
    scorer = build_runtime_scorer(runtime)
    report = run_adaptive_campaign(default_seeds(), scorer, query_budget=40)
    # The harness produces real numbers, not a static zero.
    assert 0.0 <= report.adaptive_asr <= 1.0
    assert 0.0 <= report.static_asr <= 1.0
    # Every seed got at least its unmutated probe.
    assert all(r.queries_used >= 1 for r in report.results)


def test_structural_seed_resists_adaptive_attack(runtime) -> None:
    # The whole point: a path-policy block is computed over the action graph,
    # so content mutation cannot evade it. Adaptive ASR on the structural class
    # must be zero even with a generous budget.
    scorer = build_runtime_scorer(runtime)
    report = run_adaptive_campaign(default_seeds(), scorer, query_budget=60)
    assert report.asr_for_class("structural") == 0.0
    structural = [r for r in report.results if r.defense_class == "structural"]
    assert structural and all(not r.bypassed for r in structural)
    # And it was genuinely blocked at baseline (FORBID), not merely abstained.
    assert all(r.static_verdict is Verdict.FORBID for r in structural)
