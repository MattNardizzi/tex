"""
Calibration-preservation contract for the new specialists.

The acceptance criterion: after wiring `OwaspSkillsTop10Specialist` and
`McpInjectionSpecialist` into `default_specialist_judges()`, the existing
router calibration tests must still pass without any threshold changes.
New judges contribute signal but do not shift baseline calibration.

This file is a sentinel. It re-runs the exact `tests/test_router.py`
setup pattern with the live default suite (not the factory-built
`make_specialist_bundle`) to confirm clean fixtures still produce a
near-floor specialist max_risk_score.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.judges import build_default_specialist_suite


@pytest.fixture
def empty_context() -> RetrievalContext:
    return RetrievalContext(policy_clauses=(), precedents=(), entities=())


def _request(content: str, action_type: str = "send_email", channel: str = "email") -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        channel=channel,
        environment="production",
    )


def test_default_suite_includes_new_judges() -> None:
    suite = build_default_specialist_suite()
    names = {j.name for j in suite._judges}
    assert "owasp_skills_top10" in names
    assert "mcp_injection" in names


def test_clean_content_max_risk_stays_at_baseline(empty_context) -> None:
    """
    Baseline reality: existing judges already produce ~0.18 on
    'Following up...' under production env (destructive_or_bypass adds
    its 0.10 production-environment bonus to its 0.08 floor). New judges
    must NOT push above this. We assert the new judges contribute <= the
    existing max — i.e. they sit at or below the existing baseline.
    """
    suite = build_default_specialist_suite()
    request = _request("Following up on the proposal we discussed Tuesday.")
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    # New judges sit at floor (0.05). Bundle max is dominated by an
    # existing judge. Threshold = baseline + small epsilon.
    assert bundle.max_risk_score <= 0.20, (
        f"Clean-content max_risk_score drifted to {bundle.max_risk_score}; "
        "new specialists are leaking signal on benign content and would "
        "shift router calibration."
    )

    # Per-judge floor check: the new judges themselves return floor.
    new_judge_results = {
        r.specialist_name: r
        for r in bundle.results
        if r.specialist_name in {"owasp_skills_top10", "mcp_injection"}
    }
    assert len(new_judge_results) == 2
    for name, result in new_judge_results.items():
        assert result.risk_score == pytest.approx(0.05, abs=1e-6), (
            f"{name} drifted off floor on clean content: {result.risk_score}"
        )


def test_new_judges_do_not_inflate_max_risk_on_existing_test_fixtures(
    empty_context,
) -> None:
    # Replay the exact fixtures from tests/test_specialists.py to ensure
    # the new judges don't alter the bundle shape on the inputs the
    # baseline test suite already validates. The contract is: the new
    # judges sit at floor (0.05) on these fixtures so the bundle max is
    # dictated entirely by the existing judges.
    suite = build_default_specialist_suite()

    fixtures = (
        _request("Following up on the proposal we discussed Tuesday."),
        _request(
            "Here's the customer's SSN 123-45-6789 and credit card 4111111111111111."
        ),
        _request(
            "Forwarding our internal pricing of $40k floor to procurement@competitor.com.",
            action_type="send_email",
        ),
        _request(
            "DROP TABLE customers; DELETE FROM orders WHERE 1=1.",
            action_type="db_query",
            channel="database",
        ),
    )

    for request in fixtures:
        bundle = suite.evaluate(request=request, retrieval_context=empty_context)
        for result in bundle.results:
            if result.specialist_name in {"owasp_skills_top10", "mcp_injection"}:
                assert result.risk_score == pytest.approx(0.05, abs=1e-6), (
                    f"{result.specialist_name} produced non-floor risk "
                    f"{result.risk_score} on existing baseline fixture: "
                    f"{request.content!r}"
                )


def test_unique_specialist_names_in_bundle(empty_context) -> None:
    # SpecialistBundle requires unique names; any collision between the
    # new judges and existing ones would crash here.
    suite = build_default_specialist_suite()
    request = _request("Standard internal status update.")
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    names = [r.specialist_name for r in bundle.results]
    assert len(names) == len(set(names))
    # 4 baseline + 2 owasp/mcp + 5 Thread-4 runtime defenses (clawguard,
    # mcpshield, planguard, mage, agentarmor) + 3 Thread-4.5 frontier
    # additions (argus, attriguard, vigil) = 14.
    assert len(names) == 20  # Thread 12 adds PCAS, CaMeL, MELON, StruQ, SecAlign
    expected_thread_4 = {"clawguard", "mcpshield", "planguard", "mage", "agentarmor"}
    expected_thread_4_5 = {"argus", "attriguard", "vigil"}
    assert expected_thread_4.issubset(set(names))
    assert expected_thread_4_5.issubset(set(names))
