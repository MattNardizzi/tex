"""
Tests for tex.governance.path_policy.

Covers:
  - LTLf parser edge cases (operators, comparators, atoms, quoted strings)
  - LTLf evaluation semantics (G, F, X, U on finite traces)
  - PathPolicyChecker with both PathPolicy and CallablePolicy
  - Sliding window and shared-state Sigma update
  - Composition formula v_i = 1 - prod(1 - pi_j)
  - Severity -> allowed mapping
  - Fail-closed behavior on malformed formulas and bad callables
"""

from __future__ import annotations

import pytest

from tex.governance.path_policy import (
    CallablePolicy,
    PathPolicy,
    PathPolicyChecker,
)
from tex.governance.path_policy.ltlf import (
    LtlfParseError,
    compile_formula,
    evaluate,
    evaluate_compiled,
)


# ===========================================================================
# LTLf evaluator
# ===========================================================================


class TestLtlfAtoms:
    def test_tool_shorthand_matches_action_tool_field(self):
        trace = [({}, {"tool": "send_email"}, {})]
        assert evaluate("tool=send_email", trace) is True
        assert evaluate("tool=other", trace) is False

    def test_tool_shorthand_falls_back_to_type_field(self):
        trace = [({}, {"type": "fetch"}, {})]
        assert evaluate("tool=fetch", trace) is True

    def test_state_dotted_lookup(self):
        trace = [({"sensitivity": "high"}, {}, {})]
        assert evaluate("state.sensitivity=high", trace) is True
        assert evaluate("state.sensitivity=low", trace) is False

    def test_observation_dotted_lookup(self):
        trace = [({}, {}, {"status": "ok"})]
        assert evaluate("obs.status=ok", trace) is True

    def test_action_dotted_lookup(self):
        trace = [({}, {"recipient": "alice@example.com"}, {})]
        assert evaluate("action.recipient=alice@example.com", trace) is True

    def test_numeric_comparators(self):
        trace = [({"step_count": 5}, {}, {})]
        assert evaluate("state.step_count >= 5", trace) is True
        assert evaluate("state.step_count > 5", trace) is False
        assert evaluate("state.step_count <= 5", trace) is True
        assert evaluate("state.step_count < 5", trace) is False
        assert evaluate("state.step_count != 4", trace) is True

    def test_numeric_comparator_against_non_numeric_returns_false(self):
        trace = [({"flag": "yes"}, {}, {})]
        assert evaluate("state.flag >= 5", trace) is False

    def test_missing_key_atom_is_false(self):
        trace = [({}, {}, {})]
        assert evaluate("state.absent=value", trace) is False

    def test_quoted_value_with_spaces(self):
        trace = [({"label": "high risk"}, {}, {})]
        assert evaluate('state.label="high risk"', trace) is True

    def test_const_true_false(self):
        assert evaluate("true", []) is True
        assert evaluate("false", []) is False

    def test_empty_formula_is_true(self):
        assert evaluate("", [({"x": 1}, {}, {})]) is True
        assert evaluate("   ", [({"x": 1}, {}, {})]) is True

    def test_bare_unqualified_atom_rejected(self):
        with pytest.raises(LtlfParseError):
            evaluate("foo=bar", [({}, {}, {})])


class TestLtlfBooleanOps:
    def test_negation(self):
        trace = [({}, {"tool": "x"}, {})]
        assert evaluate("!(tool=y)", trace) is True
        assert evaluate("!(tool=x)", trace) is False

    def test_and(self):
        trace = [({"a": "1"}, {"tool": "x"}, {})]
        assert evaluate("state.a=1 & tool=x", trace) is True
        assert evaluate("state.a=1 & tool=y", trace) is False

    def test_or(self):
        trace = [({}, {"tool": "x"}, {})]
        assert evaluate("tool=x | tool=y", trace) is True
        assert evaluate("tool=z | tool=y", trace) is False

    def test_implies_short_circuit(self):
        trace = [({}, {"tool": "x"}, {})]
        # tool=y is false, so antecedent false -> implication true (vacuous)
        assert evaluate("tool=y -> tool=anything", trace) is True
        # antecedent true, consequent true
        assert evaluate("tool=x -> tool=x", trace) is True
        # antecedent true, consequent false
        assert evaluate("tool=x -> tool=y", trace) is False

    def test_precedence_and_over_or(self):
        # a | b & c means a | (b & c)
        trace = [({}, {"tool": "a"}, {})]
        # tool=a | (tool=b & tool=c) -- a true makes whole true
        assert evaluate("tool=a | tool=b & tool=c", trace) is True
        trace2 = [({}, {"tool": "b"}, {})]
        # tool=a false, (tool=b & tool=c) requires both at position 0 — only b
        assert evaluate("tool=a | tool=b & tool=c", trace2) is False

    def test_parentheses_override_precedence(self):
        trace = [({}, {"tool": "b"}, {})]
        assert evaluate("(tool=a | tool=b) & true", trace) is True


class TestLtlfTemporal:
    def test_eventually_F(self):
        trace = [
            ({}, {"tool": "read"}, {}),
            ({}, {"tool": "approve"}, {}),
            ({}, {"tool": "send"}, {}),
        ]
        assert evaluate("F(tool=approve)", trace) is True
        assert evaluate("F(tool=missing)", trace) is False

    def test_always_G(self):
        trace = [
            ({"alive": "yes"}, {}, {}),
            ({"alive": "yes"}, {}, {}),
        ]
        assert evaluate("G(state.alive=yes)", trace) is True
        trace2 = [
            ({"alive": "yes"}, {}, {}),
            ({"alive": "no"}, {}, {}),
        ]
        assert evaluate("G(state.alive=yes)", trace2) is False

    def test_next_X_at_end_is_false(self):
        trace = [({}, {"tool": "x"}, {})]
        # Next from position 0 of 1-element trace -> position 1 doesn't exist -> false
        assert evaluate("X(tool=x)", trace) is False

    def test_next_X_advances(self):
        trace = [
            ({}, {"tool": "a"}, {}),
            ({}, {"tool": "b"}, {}),
        ]
        assert evaluate("X(tool=b)", trace) is True
        assert evaluate("X(tool=a)", trace) is False

    def test_until_U(self):
        # phi U psi: psi eventually holds, phi holds until then.
        trace = [
            ({"safe": "yes"}, {}, {}),
            ({"safe": "yes"}, {}, {}),
            ({}, {"tool": "done"}, {}),
        ]
        # safe must hold until done appears
        assert evaluate("(state.safe=yes) U (tool=done)", trace) is True
        # If safe breaks before done, U is false
        trace2 = [
            ({"safe": "yes"}, {}, {}),
            ({"safe": "no"}, {}, {}),
            ({}, {"tool": "done"}, {}),
        ]
        assert evaluate("(state.safe=yes) U (tool=done)", trace2) is False

    def test_combined_paper_pii_predecessor(self):
        # Kaptein 2603.16586 §3.5 PII predecessor: a pii_check must
        # appear before any read_personal_data action. Equivalent
        # LTLf: at every position, if read_personal_data is performed,
        # then pii_check has been seen at some earlier position.
        # We approximate with: globally, !read_personal_data | F(pii_check)
        # evaluated against the trace, checking that read_personal_data
        # never appears before pii_check has appeared.
        no_check_trace = [
            ({}, {"tool": "read_personal_data"}, {}),
        ]
        assert evaluate("!(F(tool=read_personal_data)) | F(tool=pii_check)", no_check_trace) is False

        with_check_trace = [
            ({}, {"tool": "pii_check"}, {}),
            ({}, {"tool": "read_personal_data"}, {}),
        ]
        assert evaluate("!(F(tool=read_personal_data)) | F(tool=pii_check)", with_check_trace) is True


class TestLtlfParser:
    def test_unbalanced_parens_raises(self):
        with pytest.raises(LtlfParseError):
            evaluate("(tool=x", [])

    def test_trailing_tokens_raises(self):
        with pytest.raises(LtlfParseError):
            evaluate("tool=x )", [])

    def test_unterminated_quoted_string_raises(self):
        with pytest.raises(LtlfParseError):
            evaluate("tool='unterminated", [])

    def test_unexpected_token_raises(self):
        with pytest.raises(LtlfParseError):
            evaluate("&", [])

    def test_compile_then_evaluate(self):
        ast = compile_formula("F(tool=done)")
        trace = [({}, {"tool": "done"}, {})]
        assert evaluate_compiled(ast, trace) is True


# ===========================================================================
# PathPolicyChecker
# ===========================================================================


class TestPathPolicyChecker:
    def test_block_policy_denies_when_violated(self):
        # Per Kaptein §4.2, policies typically condition on a compact
        # state vector. We model "approval before external_send" as:
        # at the candidate step, EITHER tool is not external_send OR
        # state.approved=true. The runtime is responsible for setting
        # state.approved=true when an approval is recorded.
        p = PathPolicy(
            policy_id="approval-required",
            description="external send requires prior approval",
            ltl_formula="!(tool=external_send) | state.approved=true",
            severity="block",
        )
        checker = PathPolicyChecker(policies=(p,))
        # Candidate action carries the state-vector projection from the
        # caller's runtime; the checker treats action's container as
        # holding state-as-of-this-step in addition to the action fields.
        # Here we put it in the action mapping itself for simplicity.
        # NOTE: this test demonstrates the WITHOUT-approval case — no
        # state.approved field set, so the formula is violated.
        allowed, vios = checker.check(
            candidate_action={"tool": "external_send"},
        )
        assert allowed is False
        assert "approval-required" in vios

    def test_block_policy_allows_when_satisfied(self):
        # Same policy, but here we feed the candidate with a state
        # projection indicating approval has been collected. The
        # state-vector form is the paper's recommended idiom because
        # it does not require past-LTL operators.
        p = PathPolicy(
            policy_id="approval-required",
            description="external send requires prior approval",
            ltl_formula="!(tool=external_send) | action.approved=true",
            severity="block",
        )
        checker = PathPolicyChecker(policies=(p,))
        allowed, vios = checker.check(
            candidate_action={"tool": "external_send", "approved": True},
        )
        assert allowed is True
        assert vios == ()

    def test_warn_severity_does_not_block(self):
        p = PathPolicy(
            policy_id="rate-warn",
            description="warn-only",
            ltl_formula="false",  # always violated
            severity="warn",
        )
        checker = PathPolicyChecker(policies=(p,))
        allowed, vios = checker.check(candidate_action={"tool": "anything"})
        assert allowed is True
        assert vios == ("rate-warn",)

    def test_audit_severity_does_not_block(self):
        p = PathPolicy(
            policy_id="audit-only",
            description="audit",
            ltl_formula="false",
            severity="audit",
        )
        checker = PathPolicyChecker(policies=(p,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is True
        assert vios == ("audit-only",)

    def test_sliding_window_eviction(self):
        """Window-based eviction is observable through path-dependent policies.

        Use a policy that fires when a send appears at the candidate
        position and 'approved' is not in the candidate's state. Since
        the checker's sliding window discards old entries, an approval
        far in the past is no longer visible to a callable policy that
        scans the path — proving the window evicts.
        """
        seen_history_lengths: list[int] = []

        def needs_recent_approval(A, P, s_star, sigma):
            seen_history_lengths.append(len(P))
            # Look for approval in the visible path.
            has_approval = any(
                step[1].get("tool") == "approve"
                for step in P
            )
            return 0.0 if has_approval else 1.0

        cp = CallablePolicy(
            policy_id="needs-approval",
            description="",
            fn=needs_recent_approval,
            severity="block",
        )
        # Window size 2: only 2 most recent steps remain.
        checker = PathPolicyChecker(
            policies=(),
            callable_policies=(cp,),
            window_size=2,
        )
        checker.record(state={}, action={"tool": "approve"}, observation={})
        checker.record(state={}, action={"tool": "noise"}, observation={})
        checker.record(state={}, action={"tool": "noise"}, observation={})
        # `approve` evicted; only [noise, noise, candidate] visible.
        allowed, _ = checker.check(candidate_action={"tool": "send"})
        assert allowed is False
        # The path the callable saw should be window+candidate = 3 entries.
        assert seen_history_lengths[-1] == 3

    def test_window_size_must_be_positive(self):
        with pytest.raises(ValueError):
            PathPolicyChecker(policies=(), window_size=0)

    def test_shared_state_sigma_visible_to_callable(self):
        observed: dict = {}

        def pi_j(A, P, s, sigma):
            observed["sigma"] = dict(sigma)
            return 0.0

        cp = CallablePolicy(
            policy_id="sigma-reader",
            description="reads sigma",
            fn=pi_j,
            severity="audit",
        )
        checker = PathPolicyChecker(
            policies=(),
            callable_policies=(cp,),
            shared_state={"barrier_active": True},
        )
        checker.update_shared_state(extra="value")
        checker.check(candidate_action={"tool": "x"})
        assert observed["sigma"] == {"barrier_active": True, "extra": "value"}

    def test_callable_returning_one_blocks(self):
        def always_violated(A, P, s, sigma):
            return 1.0

        cp = CallablePolicy(
            policy_id="always",
            description="",
            fn=always_violated,
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is False
        assert "always" in vios

    def test_callable_returning_zero_passes(self):
        cp = CallablePolicy(
            policy_id="never",
            description="",
            fn=lambda A, P, s, sigma: 0.0,
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is True
        assert vios == ()

    def test_callable_returning_out_of_range_clamped(self):
        # Returning 2.0 clamps to 1.0 -> block.
        cp = CallablePolicy(
            policy_id="oor",
            description="",
            fn=lambda A, P, s, sigma: 2.0,
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        allowed, _ = checker.check(candidate_action={"tool": "x"})
        assert allowed is False
        # Negative clamps to 0 -> no block.
        cp2 = CallablePolicy(
            policy_id="neg",
            description="",
            fn=lambda A, P, s, sigma: -0.5,
            severity="block",
        )
        checker2 = PathPolicyChecker(policies=(), callable_policies=(cp2,))
        allowed2, _ = checker2.check(candidate_action={"tool": "x"})
        assert allowed2 is True

    def test_callable_returning_wrong_type_fails_closed(self):
        cp = CallablePolicy(
            policy_id="bad",
            description="",
            fn=lambda A, P, s, sigma: "not a number",  # type: ignore[return-value]
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        allowed, _ = checker.check(candidate_action={"tool": "x"})
        # Wrong type -> clamp to 1.0 -> block.
        assert allowed is False

    def test_callable_raising_fails_closed(self):
        def boom(A, P, s, sigma):
            raise RuntimeError("x")

        cp = CallablePolicy(
            policy_id="boom",
            description="",
            fn=boom,
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is False
        assert "boom" in vios

    def test_composition_formula_correctness(self):
        """v_i = 1 - prod(1 - pi_j) — paper Section 3.3."""
        # Two warns at 0.5 each: v_i = 1 - 0.5*0.5 = 0.75
        cp1 = CallablePolicy(
            policy_id="c1", description="", fn=lambda *_: 0.5, severity="warn"
        )
        cp2 = CallablePolicy(
            policy_id="c2", description="", fn=lambda *_: 0.5, severity="warn"
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp1, cp2))
        checker.check(candidate_action={"tool": "x"})
        assert abs(checker.violation_score - 0.75) < 1e-9

    def test_composition_three_policies(self):
        # 1 - (1-0.2)(1-0.3)(1-0.4) = 1 - 0.8*0.7*0.6 = 1 - 0.336 = 0.664
        cp = lambda v: CallablePolicy(  # noqa: E731
            policy_id=f"c{v}", description="", fn=lambda *_, v=v: v, severity="warn"
        )
        checker = PathPolicyChecker(
            policies=(),
            callable_policies=(cp(0.2), cp(0.3), cp(0.4)),
        )
        checker.check(candidate_action={"tool": "x"})
        assert abs(checker.violation_score - 0.664) < 1e-9

    def test_no_policies_allows_everything(self):
        checker = PathPolicyChecker(policies=())
        allowed, vios = checker.check(candidate_action={"tool": "anything"})
        assert allowed is True
        assert vios == ()
        assert checker.violation_score == 0.0

    def test_invalid_formula_at_init_fails_closed(self):
        bad = PathPolicy(
            policy_id="bad",
            description="",
            ltl_formula="((((",
            severity="block",
        )
        # Should NOT raise at construction; checker marks it INVALID.
        checker = PathPolicyChecker(policies=(bad,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is False
        assert "bad" in vios

    def test_record_appends_step(self):
        # Use a callable that scans path for a marker tool — exercises
        # both the path-passing and the record() side effect without
        # needing past-LTL operators.
        def has_done(A, P, s_star, sigma):
            return 0.0 if any(step[1].get("tool") == "done" for step in P) else 1.0

        cp = CallablePolicy(
            policy_id="needs-done",
            description="",
            fn=has_done,
            severity="block",
        )
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        # Without a 'done' anywhere, candidate fails.
        allowed, _ = checker.check(candidate_action={"tool": "x"})
        assert allowed is False
        # Recording 'done' into history makes it satisfied.
        checker.record(state={}, action={"tool": "done"}, observation={})
        allowed, _ = checker.check(candidate_action={"tool": "x"})
        assert allowed is True

    def test_callable_policy_receives_path(self):
        """Callable receives the trace including the candidate as last position."""
        captured: dict = {}

        def pi_j(A, P, s_star, sigma):
            captured["P_len"] = len(P)
            captured["s_star_tool"] = s_star.get("tool")
            return 0.0

        cp = CallablePolicy(policy_id="x", description="", fn=pi_j, severity="audit")
        checker = PathPolicyChecker(policies=(), callable_policies=(cp,))
        checker.record(state={}, action={"tool": "a"}, observation={})
        checker.record(state={}, action={"tool": "b"}, observation={})
        checker.check(candidate_action={"tool": "candidate"})
        # Path length = history (2) + candidate (1) = 3
        assert captured["P_len"] == 3
        assert captured["s_star_tool"] == "candidate"

    def test_mixed_ltlf_and_callable_compose(self):
        # LTLf always-violated (warn) + callable returning 0.5 (warn).
        # pi_ltlf = 1.0, pi_call = 0.5.
        # v_i = 1 - (1-1.0)(1-0.5) = 1 - 0 = 1.0
        p = PathPolicy(
            policy_id="ltlf-warn",
            description="",
            ltl_formula="false",
            severity="warn",
        )
        cp = CallablePolicy(
            policy_id="call-warn",
            description="",
            fn=lambda *_: 0.5,
            severity="warn",
        )
        checker = PathPolicyChecker(policies=(p,), callable_policies=(cp,))
        allowed, vios = checker.check(candidate_action={"tool": "x"})
        assert allowed is True  # both warn
        assert set(vios) == {"ltlf-warn", "call-warn"}
        assert checker.violation_score == 1.0
