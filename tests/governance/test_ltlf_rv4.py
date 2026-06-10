"""
RV4 four-valued semantics for path-policy LTLf (ltlf.evaluate_rv4).

Reference: Bauer, Leucker & Schallhart, "Runtime Verification for LTL and
TLTL", ACM TOSEM 20(4) Article 14, 2011 (DOI 10.1145/2000799.2000800).

The load-bearing property is SOUNDNESS of the permanent verdict: a
PERMANENTLY_VIOLATED classification must mean *no extension of the trace can
ever satisfy the formula* (a bad prefix). We prove this by brute-force
extension enumeration — the strongest falsification we can run against the
classifier, since FORBID rides on it.
"""

from __future__ import annotations

import itertools

from tex.governance.path_policy.ltlf import (
    RV4Verdict,
    evaluate,
    evaluate_rv4,
)
from tex.governance.path_policy.policy import PathStep


def _step(tool: str | None = None, **state) -> PathStep:
    action: dict[str, object] = {}
    if tool is not None:
        action["tool"] = tool
    return (dict(state), action, {})


# ── concrete classifications ────────────────────────────────────────────


def test_safety_violation_at_candidate_is_permanent() -> None:
    # G(!(tool=external_send)) with the candidate action BEING external_send:
    # a fixed past/present position violates a safety invariant — no future
    # step can cure it → permanent → FORBID.
    trace = [_step("read"), _step("external_send")]
    v = evaluate_rv4("G(!(tool=external_send))", trace)
    assert v is RV4Verdict.PERMANENTLY_VIOLATED
    assert v.is_permanent_violation


def test_liveness_obligation_unmet_is_recoverable() -> None:
    # F(tool=human_approval) with no approval yet: currently violated, but a
    # future step could satisfy it → recoverable → ABSTAIN, not FORBID.
    trace = [_step("read"), _step("issue_refund")]
    v = evaluate_rv4("F(tool=human_approval)", trace)
    assert v is RV4Verdict.CURRENTLY_VIOLATED
    assert v.is_recoverable_violation
    assert not v.is_permanent


def test_approval_before_send_permanent_when_send_without_prior_approval() -> None:
    # "G(tool=external_send -> ...)" form. With the candidate being a send and
    # no approval anywhere, the implication is violated at the send position;
    # because that position is fixed, it is permanent.
    trace = [_step("read"), _step("external_send")]
    v = evaluate_rv4(
        "G(tool=external_send -> tool=human_approval)", trace
    )
    assert v is RV4Verdict.PERMANENTLY_VIOLATED


def test_satisfied_safety_is_satisfied() -> None:
    trace = [_step("read"), _step("summarize")]
    v = evaluate_rv4("G(!(tool=external_send))", trace)
    assert v.is_satisfied


def test_satisfied_liveness_is_permanently_satisfied() -> None:
    # F(tool=approve) already satisfied by a past step → no extension unsatisfies
    # it → permanently satisfied.
    trace = [_step("approve"), _step("issue_refund")]
    v = evaluate_rv4("F(tool=approve)", trace)
    assert v is RV4Verdict.PERMANENTLY_SATISFIED


def test_empty_formula_is_satisfied() -> None:
    assert evaluate_rv4("", [_step("x")]).is_satisfied


def test_leading_next_chain_past_trace_end_is_recoverable_not_permanent() -> None:
    # Regression for the bad-prefix off-by-one: an X-chain advances the eval
    # index past the trace length, but the obligation is still satisfiable by a
    # long-enough extension — so it is RECOVERABLE, never a (false) bad prefix.
    assert evaluate_rv4("X(F(tool=a))", []) is RV4Verdict.CURRENTLY_VIOLATED
    assert evaluate_rv4("X(X(F(tool=a)))", []) is RV4Verdict.CURRENTLY_VIOLATED
    assert evaluate_rv4("X(X(X(F(tool=a))))", []) is RV4Verdict.CURRENTLY_VIOLATED
    assert evaluate_rv4("X(tool=a U tool=b)", []) is RV4Verdict.CURRENTLY_VIOLATED
    # The dual: must NOT be falsely permanently-satisfied.
    assert (
        evaluate_rv4("!(X(F(tool=a)))", []) is RV4Verdict.CURRENTLY_SATISFIED
    )


# ── the soundness proof: permanent ⟹ no extension can flip it ────────────

# A small action alphabet to build extensions from.
_ALPHABET: tuple[PathStep, ...] = (
    _step("a"),
    _step("b"),
    _step("external_send"),
    _step("human_approval"),
    _step(),  # toolless step
)

# A battery of formulas exercising every operator and combination — including
# leading X-chains nesting F / U / G, which push the eval index PAST the trace
# length (i > n) and are exactly the class the bad-prefix off-by-one missed.
_FORMULAS: tuple[str, ...] = (
    "G(!(tool=external_send))",
    "G(tool=external_send -> tool=human_approval)",
    "F(tool=human_approval)",
    "F(tool=a)",
    "X(tool=a)",
    "tool=a U tool=b",
    "G(tool=a -> F(tool=b))",
    "!(tool=a)",
    "G(!(tool=a)) | F(tool=b)",
    "G(!(tool=a)) & G(!(tool=b))",
    "tool=external_send",
    "G(tool=a)",
    # i > n stress cases (leading X-chains over F / U / G):
    "X(F(tool=a))",
    "X(X(F(tool=a)))",
    "X(tool=a U tool=b)",
    "X(G(!(tool=a)))",
    "!(X(F(tool=a)))",
    "X(X(tool=a))",
)


def _all_extensions(max_len: int) -> list[list[PathStep]]:
    exts: list[list[PathStep]] = [[]]
    for length in range(1, max_len + 1):
        for combo in itertools.product(_ALPHABET, repeat=length):
            exts.append(list(combo))
    return exts


def _all_base_traces(max_len: int) -> list[list[PathStep]]:
    traces: list[list[PathStep]] = [[]]
    for length in range(1, max_len + 1):
        for combo in itertools.product(_ALPHABET, repeat=length):
            traces.append(list(combo))
    return traces


def test_permanent_verdicts_are_sound_under_extension() -> None:
    """If RV4 says PERMANENTLY_VIOLATED, NO extension may satisfy the formula;
    if PERMANENTLY_SATISFIED, EVERY extension must satisfy it."""
    # Depth-3 extensions so X-chains as deep as X(X(F(...))) (which need 3
    # appended steps to satisfy) are actually exercised against any permanent
    # verdict — the search space the original off-by-one slipped through.
    extensions = _all_extensions(3)  # 1 + 5 + 25 + 125 = 156 extensions
    base_traces = _all_base_traces(2)
    checked_violated = 0
    checked_satisfied = 0

    for formula in _FORMULAS:
        for base in base_traces:
            v = evaluate_rv4(formula, base)
            if v is RV4Verdict.PERMANENTLY_VIOLATED:
                checked_violated += 1
                for ext in extensions:
                    extended = base + ext
                    assert not evaluate(formula, extended), (
                        f"UNSOUND permanent-violation: {formula!r} on {base!r} "
                        f"was satisfiable by extension {ext!r}"
                    )
            elif v is RV4Verdict.PERMANENTLY_SATISFIED:
                checked_satisfied += 1
                for ext in extensions:
                    extended = base + ext
                    assert evaluate(formula, extended), (
                        f"UNSOUND permanent-satisfaction: {formula!r} on {base!r} "
                        f"was falsifiable by extension {ext!r}"
                    )

    # Sanity: the battery actually exercised both permanent verdicts (so the
    # test isn't vacuously green).
    assert checked_violated > 0
    assert checked_satisfied > 0


def test_recoverable_violations_are_genuinely_recoverable() -> None:
    """Completeness spot-check: every CURRENTLY_VIOLATED verdict in the battery
    should have SOME extension that satisfies the formula (else it would be a
    missed permanent violation). We search a slightly deeper extension space."""
    extensions = _all_extensions(3)
    base_traces = _all_base_traces(2)

    for formula in _FORMULAS:
        for base in base_traces:
            v = evaluate_rv4(formula, base)
            if v is not RV4Verdict.CURRENTLY_VIOLATED:
                continue
            recoverable = any(
                evaluate(formula, base + ext) for ext in extensions
            )
            assert recoverable, (
                f"{formula!r} on {base!r} was labelled recoverable but no "
                f"extension up to depth 3 satisfies it — likely a missed "
                f"permanent violation."
            )
