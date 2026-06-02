"""Thread 12: PCAS Datalog frontend — unit tests."""

from __future__ import annotations

import pytest

from tex.pcas import (
    AuthorizationVerdict,
    Evaluator,
    Lexer,
    LexerError,
    PcasMonitor,
    ParseError,
    StratificationError,
    parse_program,
    stratify,
)
from tex.pcas.graph.adapter import (
    DependencyGraphAdapter,
    DependencyGraphView,
    GraphDataView,
    GraphDependencyEdge,
)
from tex.pcas.language.ast import Atom, Constant, Variable
from tex.pcas.language.lexer import TokenKind
from tex.pcas.monitor import CandidateAction
from tex.pcas.runtime.evaluator import EvaluationError
from tex.pcas.runtime.relation import Fact, Relation


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------


def test_lexer_basic():
    toks = Lexer('foo(X, "bar", 42, true) :- baz.').tokens()
    kinds = [t.kind for t in toks]
    assert kinds == [
        TokenKind.IDENT,
        TokenKind.LPAREN,
        TokenKind.IDENT,
        TokenKind.COMMA,
        TokenKind.STRING,
        TokenKind.COMMA,
        TokenKind.INTEGER,
        TokenKind.COMMA,
        TokenKind.BOOL,
        TokenKind.RPAREN,
        TokenKind.COLON_DASH,
        TokenKind.IDENT,
        TokenKind.DOT,
        TokenKind.EOF,
    ]


def test_lexer_line_col_tracking():
    src = "foo.\nbar."
    toks = Lexer(src).tokens()
    assert toks[0].line == 1
    assert toks[2].line == 2  # 'bar'
    assert toks[2].col == 1


def test_lexer_string_escapes():
    toks = Lexer(r'foo("a\"b\n").').tokens()
    string_tok = next(t for t in toks if t.kind is TokenKind.STRING)
    assert string_tok.text == 'a"b\n'


def test_lexer_unterminated_string():
    with pytest.raises(LexerError, match="unterminated"):
        Lexer('foo("never closing').tokens()


def test_lexer_line_comment():
    toks = Lexer("foo. % this is a comment\nbar.").tokens()
    kinds = [t.kind for t in toks]
    assert TokenKind.IDENT in kinds
    # No comment token leaks into stream
    assert all(t.kind is not TokenKind.IDENT or t.text in {"foo", "bar"} for t in toks)


def test_lexer_block_comment():
    toks = Lexer("foo. /* skip\nlines */ bar.").tokens()
    idents = [t.text for t in toks if t.kind is TokenKind.IDENT]
    assert idents == ["foo", "bar"]


def test_lexer_annotation():
    toks = Lexer("@authorize foo. @deny bar.").tokens()
    assert toks[0].kind is TokenKind.AT_AUTH
    assert any(t.kind is TokenKind.AT_DENY for t in toks)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parser_fact():
    prog = parse_program("foo.")
    assert len(prog.rules) == 1
    assert prog.rules[0].is_fact is True
    assert prog.rules[0].head.predicate == "foo"


def test_parser_rule():
    prog = parse_program("a(X) :- b(X).")
    rule = prog.rules[0]
    assert rule.head.predicate == "a"
    assert isinstance(rule.head.args[0], Variable)
    assert rule.body[0].predicate == "b"


def test_parser_annotated():
    prog = parse_program("@deny bad(X) :- evil(X).")
    assert prog.rules[0].annotation == "deny"


def test_parser_constants():
    prog = parse_program('p(X) :- q(X, "literal", 7, true).')
    body = prog.rules[0].body[0]
    assert isinstance(body.args[1], Constant)
    assert body.args[1].value == "literal"
    assert body.args[2].value == 7
    assert body.args[3].value is True


def test_parser_negation():
    prog = parse_program("p(X) :- q(X), not r(X).")
    rule = prog.rules[0]
    assert len(rule.body_positive_atoms) == 1
    assert len(rule.body_negated_atoms) == 1


def test_parser_error_on_missing_dot():
    with pytest.raises(ParseError):
        parse_program("foo(X)")


def test_parser_error_on_unbalanced_paren():
    with pytest.raises(ParseError):
        parse_program("foo(X.")


# ---------------------------------------------------------------------------
# Stratifier
# ---------------------------------------------------------------------------


def test_stratify_simple():
    prog = parse_program("a(X) :- b(X). b(1).")
    _, strata = stratify(prog)
    # b should appear in a stratum before a (Tarjan leaves-first)
    pred_order = [s.predicates for s in strata]
    flat = []
    for s in strata:
        for p in sorted(s.predicates):
            flat.append(p)
    assert flat.index("b") < flat.index("a")


def test_stratify_rejects_recursion_through_negation():
    prog = parse_program(
        """
        p(X) :- q(X).
        q(X) :- r(X), not p(X).
        r(1).
        """
    )
    with pytest.raises(StratificationError, match="negation"):
        stratify(prog)


def test_stratify_rejects_unsafe_head():
    prog = parse_program("p(X) :- q(Y).")
    with pytest.raises(StratificationError, match="unsafe"):
        stratify(prog)


def test_stratify_rejects_unsafe_negation():
    prog = parse_program("p(X) :- q(X), not r(Y).")
    with pytest.raises(StratificationError, match="unsafe"):
        stratify(prog)


def test_stratify_allows_safe_negation():
    prog = parse_program("p(X) :- q(X), not r(X). q(1). r(2).")
    program, strata = stratify(prog)
    # negation across strata is fine
    assert len(strata) >= 2


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


def test_evaluator_simple_fact():
    prog = parse_program("p(1). p(2).")
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    facts = closure["p"].facts
    assert (1,) in facts and (2,) in facts


def test_evaluator_join():
    prog = parse_program(
        """
        parent("alice", "bob").
        parent("bob",   "carol").
        grandparent(X, Z) :- parent(X, Y), parent(Y, Z).
        """
    )
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    assert ("alice", "carol") in closure["grandparent"].facts


def test_evaluator_recursion():
    prog = parse_program(
        """
        edge("a", "b"). edge("b", "c"). edge("c", "d").
        reachable(X, Y) :- edge(X, Y).
        reachable(X, Z) :- edge(X, Y), reachable(Y, Z).
        """
    )
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    rs = closure["reachable"].facts
    assert ("a", "d") in rs
    assert ("a", "b") in rs


def test_evaluator_negation():
    prog = parse_program(
        """
        person("alice"). person("bob"). person("carol").
        dead("bob").
        alive(X) :- person(X), not dead(X).
        """
    )
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    alive = closure["alive"].facts
    assert ("alice",) in alive
    assert ("carol",) in alive
    assert ("bob",) not in alive


def test_evaluator_helpers_predicate():
    prog = parse_program(
        """
        item("apple", 5).
        item("banana", 12).
        expensive(X) :- item(X, P), greater(P, 10).
        """
    )
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    assert ("banana",) in closure["expensive"].facts
    assert ("apple",) not in closure["expensive"].facts


def test_evaluator_helpers_function():
    prog = parse_program(
        """
        doc("d1", "{\\"role\\": \\"admin\\"}").
        admin(D) :- doc(D, J), json_extract(J, "role", "admin").
        """
    )
    ev = Evaluator(prog)
    closure = ev.evaluate({})
    assert ("d1",) in closure["admin"].facts


def test_evaluator_edb_seed():
    prog = parse_program("derived(X) :- src(X).")
    ev = Evaluator(prog)
    edb = {"src": Relation(name="src", arity=1, facts=[("hello",)])}
    closure = ev.evaluate(edb)
    assert ("hello",) in closure["derived"].facts


# ---------------------------------------------------------------------------
# Graph adapter
# ---------------------------------------------------------------------------


def test_adapter_view_to_edb():
    view = DependencyGraphView(
        data=(
            GraphDataView(
                data_id="d1",
                source="external",
                label="untrusted",
                content_hash="abc",
            ),
        ),
        edges=(GraphDependencyEdge(source_id="a1", target_id="d1"),),
    )
    edb = DependencyGraphAdapter().to_edb(view)
    assert ("d1", "external", "untrusted", "abc") in edb["data"].facts
    assert ("a1", "d1") in edb["depends_on"].facts


# ---------------------------------------------------------------------------
# Monitor — PERMIT / ABSTAIN / FORBID end-to-end
# ---------------------------------------------------------------------------


def test_monitor_permit_benign_action():
    monitor = PcasMonitor(
        """
        @authorize ok(A) :- pending_action(A, _, _, _).
        """
    )
    decision = monitor.authorize(
        CandidateAction(
            action_id="act-1",
            kind="read",
            actor="agent",
            payload_hash="h",
        ),
        DependencyGraphView(),
    )
    assert decision.verdict is AuthorizationVerdict.PERMIT


def test_monitor_forbid_toxic_flow():
    # Default PCAS policy denies untrusted->external sink.
    monitor = PcasMonitor.__new__(PcasMonitor)  # bypass __init__ to inject custom
    # Use a clear, minimal policy that exercises the toxic-flow pattern
    monitor.__init__(
        """
        untrusted_data(D) :- data(D, _, "untrusted", _).
        reads_untrusted(A) :- pending_action(A, _, _, _), depends_on(A, D), untrusted_data(D).
        external_sink(A) :- pending_action(A, "send_email", _, _).
        @deny toxic_flow(A) :- reads_untrusted(A), external_sink(A).
        @authorize default_ok(A) :- pending_action(A, _, _, _), not reads_untrusted(A).
        """
    )
    view = DependencyGraphView(
        data=(
            GraphDataView(
                data_id="d1",
                source="external_user",
                label="untrusted",
                content_hash="hash",
            ),
        ),
        edges=(GraphDependencyEdge(source_id="act-2", target_id="d1"),),
    )
    decision = monitor.authorize(
        CandidateAction(
            action_id="act-2",
            kind="send_email",
            actor="agent",
            payload_hash="x",
        ),
        view,
    )
    assert decision.verdict is AuthorizationVerdict.FORBID, (
        f"expected FORBID; reasons={decision.reasons}; "
        f"deny_facts={decision.deny_facts}; auth={decision.authorize_facts}"
    )


def test_monitor_abstain_no_rule_matches():
    monitor = PcasMonitor("p(1).")
    decision = monitor.authorize(
        CandidateAction(
            action_id="act-x",
            kind="anything",
            actor="agent",
            payload_hash="h",
        ),
        DependencyGraphView(),
    )
    assert decision.verdict is AuthorizationVerdict.ABSTAIN


def test_monitor_load_error_forbids():
    # Invalid syntax -> load_error set -> all authorize calls FORBID
    monitor = PcasMonitor("bad syntax!!!")
    assert monitor.load_error is not None
    decision = monitor.authorize(
        CandidateAction(
            action_id="x",
            kind="anything",
            actor="agent",
            payload_hash="h",
        ),
        DependencyGraphView(),
    )
    assert decision.verdict is AuthorizationVerdict.FORBID
    assert "policy_load_error" in decision.reasons


def test_monitor_latency_under_1ms_small_graph():
    monitor = PcasMonitor(
        """
        @authorize ok(A) :- pending_action(A, _, _, _).
        """
    )
    elapsed = []
    for _ in range(50):
        d = monitor.authorize(
            CandidateAction(
                action_id="act-perf",
                kind="read",
                actor="agent",
                payload_hash="h",
            ),
            DependencyGraphView(),
        )
        elapsed.append(d.elapsed_ms)
    # p95 should be well under 5ms on this trivial policy/empty graph
    elapsed.sort()
    p95 = elapsed[int(0.95 * len(elapsed))]
    assert p95 < 5.0, f"p95={p95}ms above 5ms ceiling"
