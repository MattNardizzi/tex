"""
RV4 path-policy bridge (tex.contracts.rv4_path) — permanent→FORBID split.

The bridge classifies each LTLf path policy into permanent (bad-prefix) vs
recoverable violations. Permanent ones are routed to the structural floor
(FORBID); recoverable ones to the predictive holds (ABSTAIN).
"""

from __future__ import annotations

from tex.contracts import rv4_path

from tests.factories import make_request


def _md(policies, trace=None, candidate=None):
    block = {"policies": policies}
    if trace is not None:
        block["trace"] = trace
    if candidate is not None:
        block["candidate_action"] = candidate
    return {"rv4_path_policies": block}


def test_no_metadata_is_neutral() -> None:
    out = rv4_path.classify(make_request())
    assert out.checked is False
    assert out.violations == ()


def test_permanent_violation_from_candidate_safety_breach() -> None:
    # Candidate action IS an external send while the policy forbids it.
    req = make_request(
        metadata=_md(
            policies=[
                {
                    "policy_id": "no_external_send",
                    "ltl_formula": "G(!(tool=external_send))",
                }
            ],
            trace=[{"state": {}, "action": {"tool": "read"}, "observation": {}}],
            candidate={"tool": "external_send"},
        )
    )
    out = rv4_path.classify(req)
    assert out.has_permanent is True
    assert out.permanent[0].policy_id == "no_external_send"
    assert not out.has_recoverable


def test_recoverable_violation_from_pending_approval() -> None:
    req = make_request(
        metadata=_md(
            policies=[
                {
                    "policy_id": "needs_approval",
                    "ltl_formula": "F(tool=human_approval)",
                }
            ],
            candidate={"tool": "issue_refund"},
        )
    )
    out = rv4_path.classify(req)
    assert out.has_recoverable is True
    assert not out.has_permanent
    assert out.recoverable[0].policy_id == "needs_approval"


def test_satisfied_policy_yields_no_violation() -> None:
    req = make_request(
        metadata=_md(
            policies=[
                {
                    "policy_id": "no_external_send",
                    "ltl_formula": "G(!(tool=external_send))",
                }
            ],
            candidate={"tool": "summarize"},
        )
    )
    out = rv4_path.classify(req)
    assert out.violations == ()


def test_malformed_formula_is_recoverable_not_forbid() -> None:
    # A parse error is uncertainty, not a proof of a bad prefix → ABSTAIN.
    req = make_request(
        metadata=_md(
            policies=[{"policy_id": "broken", "ltl_formula": "G((("}],
            candidate={"tool": "x"},
        )
    )
    out = rv4_path.classify(req)
    assert out.has_recoverable is True
    assert out.has_permanent is False
