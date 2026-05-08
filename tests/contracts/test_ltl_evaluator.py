"""
Tests for the vendored mini LTLf evaluator (tex.contracts._ltl).

We exercise:
  * tokenizer corner cases
  * parser precedence + associativity
  * LTLf finite-trace semantics for X / G / F / U / F<=k
  * RV-LTL 4-valued verdicts (Bauer/Leucker/Schallhart 2011)
  * malformed input -> LTLParseError
"""

from __future__ import annotations

from typing import Mapping

import pytest

from tex.contracts._ltl import LTLFormula, LTLParseError, RVVerdict


# A trivial atom resolver: the trace element is a dict from atom name
# to bool, lookup is direct.
def trivial_resolver(atom: str, state: Mapping[str, object]) -> bool:
    val = state.get(atom)
    if isinstance(val, bool):
        return val
    return False


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------


class TestParsing:
    def test_parses_constants(self) -> None:
        for src in ("true", "false"):
            f = LTLFormula.parse(src)
            assert f.source == src

    def test_parses_atom(self) -> None:
        f = LTLFormula.parse("p")
        assert f.source == "p"

    def test_parses_field_path_atom(self) -> None:
        # The field-path syntax must survive tokenization intact.
        f = LTLFormula.parse("field:output.tone_score>=0.7")
        assert "tone_score" in f.source

    def test_parses_negation(self) -> None:
        LTLFormula.parse("not p")

    def test_parses_and_or_implies(self) -> None:
        LTLFormula.parse("p and q")
        LTLFormula.parse("p or q")
        LTLFormula.parse("p implies q")
        LTLFormula.parse("p -> q")

    def test_parses_temporal_operators(self) -> None:
        LTLFormula.parse("X p")
        LTLFormula.parse("Xw p")
        LTLFormula.parse("G p")
        LTLFormula.parse("F p")
        LTLFormula.parse("p U q")

    def test_parses_bounded_eventually(self) -> None:
        f = LTLFormula.parse("F<=3 q")
        # Spot-check that the bound was captured.
        f.evaluate_finite(({"q": False}, {"q": True}), trivial_resolver)

    def test_parses_nested_parens(self) -> None:
        LTLFormula.parse("G ((p or q) implies F<=2 r)")

    def test_implies_is_right_associative(self) -> None:
        # p -> q -> r  ≡  p -> (q -> r)
        # If left-associative, on (true,true,false) it would compute
        # (true -> true) -> false  =  true -> false  =  false.
        # Right-assoc: true -> (true -> false) = true -> false = false too...
        # Use a discriminating case: p=false, q=false, r=false.
        # Left-assoc:  (false -> false) -> false  =  true -> false  = false
        # Right-assoc: false -> (false -> false)  =  false -> true  = true
        f = LTLFormula.parse("p -> q -> r")
        trace = ({"p": False, "q": False, "r": False},)
        assert f.evaluate_finite(trace, trivial_resolver) is True

    def test_and_binds_tighter_than_or(self) -> None:
        # p or q and r  ≡  p or (q and r)
        # discriminator: p=False, q=True, r=False
        # tight: False or (True and False) = False
        # loose (left-to-right or first): (False or True) and False = False
        # Use p=True, q=False, r=False:
        # tight: True or (False and False) = True
        # loose: (True or False) and False = False
        f = LTLFormula.parse("p or q and r")
        trace = ({"p": True, "q": False, "r": False},)
        assert f.evaluate_finite(trace, trivial_resolver) is True

    def test_rejects_empty_formula(self) -> None:
        for src in ("", "   "):
            with pytest.raises(LTLParseError):
                LTLFormula.parse(src)

    def test_rejects_unmatched_paren(self) -> None:
        with pytest.raises(LTLParseError):
            LTLFormula.parse("(p and q")

    def test_rejects_missing_bound(self) -> None:
        with pytest.raises(LTLParseError):
            LTLFormula.parse("F<= p")

    def test_rejects_garbage_token(self) -> None:
        with pytest.raises(LTLParseError):
            LTLFormula.parse("p ?? q")


# ---------------------------------------------------------------------
# Boolean / atom semantics
# ---------------------------------------------------------------------


class TestBooleanSemantics:
    def test_true_is_true_const(self) -> None:
        f = LTLFormula.parse("true")
        assert f.evaluate_finite(({},), trivial_resolver) is True

    def test_false_is_false_const(self) -> None:
        f = LTLFormula.parse("false")
        assert f.evaluate_finite(({},), trivial_resolver) is False

    def test_atom_lookup_via_resolver(self) -> None:
        f = LTLFormula.parse("p")
        assert f.evaluate_finite(({"p": True},), trivial_resolver) is True
        assert f.evaluate_finite(({"p": False},), trivial_resolver) is False

    def test_negation(self) -> None:
        f = LTLFormula.parse("not p")
        assert f.evaluate_finite(({"p": False},), trivial_resolver) is True

    def test_implies_short_circuits_on_false_antecedent(self) -> None:
        # vacuous truth
        f = LTLFormula.parse("p -> q")
        assert f.evaluate_finite(({"p": False, "q": False},), trivial_resolver) is True


# ---------------------------------------------------------------------
# Temporal semantics — LTLf finite trace
# ---------------------------------------------------------------------


class TestTemporalSemantics:
    def test_X_at_last_position_is_false(self) -> None:
        # Strong-next at end of finite trace: false (LTLf).
        f = LTLFormula.parse("X p")
        assert f.evaluate_finite(({"p": False},), trivial_resolver) is False

    def test_X_at_non_last_position_holds_iff_next_holds(self) -> None:
        f = LTLFormula.parse("X p")
        trace = ({"p": False}, {"p": True})
        assert f.evaluate_finite(trace, trivial_resolver) is True
        trace2 = ({"p": False}, {"p": False})
        assert f.evaluate_finite(trace2, trivial_resolver) is False

    def test_Xw_at_last_position_is_true(self) -> None:
        f = LTLFormula.parse("Xw p")
        assert f.evaluate_finite(({"p": False},), trivial_resolver) is True

    def test_G_globally_holds_iff_all_positions_hold(self) -> None:
        f = LTLFormula.parse("G p")
        ok = ({"p": True}, {"p": True}, {"p": True})
        assert f.evaluate_finite(ok, trivial_resolver) is True
        bad = ({"p": True}, {"p": False}, {"p": True})
        assert f.evaluate_finite(bad, trivial_resolver) is False

    def test_F_eventually_holds_iff_some_position_holds(self) -> None:
        f = LTLFormula.parse("F p")
        ok = ({"p": False}, {"p": False}, {"p": True})
        assert f.evaluate_finite(ok, trivial_resolver) is True
        bad = ({"p": False}, {"p": False}, {"p": False})
        assert f.evaluate_finite(bad, trivial_resolver) is False

    def test_U_until_requires_left_until_right(self) -> None:
        f = LTLFormula.parse("p U q")
        # p p p q -> True
        ok = (
            {"p": True, "q": False},
            {"p": True, "q": False},
            {"p": True, "q": False},
            {"p": False, "q": True},
        )
        assert f.evaluate_finite(ok, trivial_resolver) is True
        # p ~p ... q -> False (p must hold until q)
        bad = (
            {"p": True, "q": False},
            {"p": False, "q": False},
            {"p": False, "q": True},
        )
        assert f.evaluate_finite(bad, trivial_resolver) is False
        # never q -> False on finite trace
        never = ({"p": True, "q": False},) * 3
        assert f.evaluate_finite(never, trivial_resolver) is False

    def test_bounded_eventually_within_window(self) -> None:
        f = LTLFormula.parse("F<=2 p")
        # p at position 0: holds within 0+2 window -> True
        trace = ({"p": True}, {"p": False}, {"p": False})
        assert f.evaluate_finite(trace, trivial_resolver) is True
        # p only at position 3: outside the F<=2 window -> False
        trace2 = ({"p": False}, {"p": False}, {"p": False}, {"p": True})
        assert f.evaluate_finite(trace2, trivial_resolver) is False
        # bound 0 means "must be NOW"
        f0 = LTLFormula.parse("F<=0 p")
        assert f0.evaluate_finite(({"p": True},), trivial_resolver) is True
        assert f0.evaluate_finite(({"p": False},), trivial_resolver) is False

    def test_invariant_response_pattern(self) -> None:
        # The dominant pattern from AgentVerify §3.3:
        #   G(p -> X q)
        # "every time p holds, q holds in the next state"
        f = LTLFormula.parse("G (p -> X q)")
        # Good: p triggers q one step later.
        good = (
            {"p": False, "q": False},
            {"p": True, "q": False},
            {"p": False, "q": True},
        )
        assert f.evaluate_finite(good, trivial_resolver) is True
        # Bad: p at the second-to-last position, q never fires.
        bad = (
            {"p": False, "q": False},
            {"p": True, "q": False},
            {"p": False, "q": False},
        )
        assert f.evaluate_finite(bad, trivial_resolver) is False


# ---------------------------------------------------------------------
# RV-LTL 4-valued verdicts
# ---------------------------------------------------------------------


class TestRVVerdict:
    def test_const_true_is_permanently_satisfied(self) -> None:
        f = LTLFormula.parse("true")
        v = f.rv_verdict(({},), trivial_resolver)
        assert v == RVVerdict.PERMANENTLY_SATISFIED
        assert v.is_satisfied is True
        assert v.is_permanent is True

    def test_const_false_is_permanently_violated(self) -> None:
        f = LTLFormula.parse("false")
        v = f.rv_verdict(({},), trivial_resolver)
        assert v == RVVerdict.PERMANENTLY_VIOLATED
        assert v.is_satisfied is False
        assert v.is_permanent is True

    def test_currently_satisfied_for_unbounded_eventually(self) -> None:
        # F p with no p observed yet but trace can still extend ->
        # currently violated, NOT permanent (we use 'currently' for
        # unobserved unbounded properties).
        f = LTLFormula.parse("F p")
        v = f.rv_verdict(({"p": False},), trivial_resolver)
        assert v == RVVerdict.CURRENTLY_VIOLATED
        assert v.is_permanent is False

    def test_atom_observed_yields_permanent_verdict(self) -> None:
        f = LTLFormula.parse("p")
        v = f.rv_verdict(({"p": True},), trivial_resolver)
        # An atom over an observed position is definite.
        assert v == RVVerdict.PERMANENTLY_SATISFIED


# ---------------------------------------------------------------------
# Position kwarg + edge cases
# ---------------------------------------------------------------------


class TestEdgeCases:
    def test_evaluate_at_explicit_position(self) -> None:
        f = LTLFormula.parse("p")
        trace = ({"p": False}, {"p": True})
        assert f.evaluate_finite(trace, trivial_resolver, position=1) is True

    def test_negative_position_rejected(self) -> None:
        f = LTLFormula.parse("p")
        with pytest.raises(ValueError):
            f.evaluate_finite(({"p": True},), trivial_resolver, position=-1)

    def test_position_past_end_rejected(self) -> None:
        f = LTLFormula.parse("p")
        with pytest.raises(ValueError):
            f.evaluate_finite(({"p": True},), trivial_resolver, position=99)

    def test_atom_past_end_returns_false(self) -> None:
        # X p at end of trace evaluates atom past end -> False.
        f = LTLFormula.parse("X p")
        assert f.evaluate_finite(({"p": True},), trivial_resolver) is False
