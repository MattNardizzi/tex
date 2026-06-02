"""
Tests for tex.contracts._atoms — the predicate atom resolver.

Coverage of the 14 ContractSpec operators (arxiv 2602.22302 §5.1):
  ==, !=, >, >=, <, <=, ~contains, ~not_contains, ~matches, ~in,
  ~not_in, ~between, ~exists.
(``expr`` is intentionally not implemented in this thread — it has its
own security model; documented as a TODO in _atoms.py.)

Plus the namespace router: field, state, kind, capability, actor,
upstream, drift.
"""

from __future__ import annotations

import pytest

from tex.contracts._atoms import (
    ContractContext,
    _parse_atom,
    make_resolver,
    trace_for,
)
from tests.contracts.conftest import make_event, make_state


class TestAtomParsing:
    def test_field_with_eq(self) -> None:
        a = _parse_atom("field:output.pii_detected==false")
        assert (a.namespace, a.path, a.op, a.literal) == (
            "field", "output.pii_detected", "==", "false"
        )

    def test_state_with_lt(self) -> None:
        a = _parse_atom("state:sliding_window_compromise_ratio<0.1")
        assert (a.namespace, a.path, a.op, a.literal) == (
            "state", "sliding_window_compromise_ratio", "<", "0.1"
        )

    def test_kind_tag_only(self) -> None:
        a = _parse_atom("kind:agent_emits_output")
        assert a.namespace == "kind"
        assert a.literal == "agent_emits_output"
        assert a.op is None

    def test_capability_tag_only(self) -> None:
        a = _parse_atom("capability:read_pii")
        assert a.namespace == "capability"
        assert a.literal == "read_pii"

    def test_actor_tag_only(self) -> None:
        a = _parse_atom("actor:alice")
        assert a.literal == "alice"

    def test_upstream_tag_only(self) -> None:
        a = _parse_atom("upstream:event-123")
        assert a.literal == "event-123"

    def test_drift_with_lt(self) -> None:
        a = _parse_atom("drift:ftc_risk<0.5")
        assert a.namespace == "drift"
        assert a.path == "ftc_risk"
        assert a.literal == "0.5"

    def test_bare_atom_treated_as_state_bool(self) -> None:
        a = _parse_atom("compromised")
        # Bare atom -> state:compromised==true
        assert (a.namespace, a.path, a.op, a.literal) == ("state", "compromised", "==", "true")

    def test_unknown_namespace_rejected(self) -> None:
        with pytest.raises(ValueError):
            _parse_atom("nope:foo==bar")

    def test_missing_operator_rejected(self) -> None:
        with pytest.raises(ValueError):
            _parse_atom("field:foo")


# ---------------------------------------------------------------------
# Operator semantics
# ---------------------------------------------------------------------


def _ctx(payload: dict, **state_kwargs: object) -> ContractContext:
    return ContractContext(
        proposed_event=make_event(payload=payload),
        state=make_state(**state_kwargs),  # type: ignore[arg-type]
    )


def _resolve(atom: str, payload: dict | None = None, **state_kwargs: object) -> bool:
    ctx = _ctx(payload or {}, **state_kwargs)
    resolver = make_resolver(ctx)
    trace = trace_for(ctx)
    return resolver(atom, trace[0])


class TestComparisonOperators:
    def test_eq_numeric(self) -> None:
        assert _resolve("field:score==0.7", {"score": 0.7})
        assert not _resolve("field:score==0.7", {"score": 0.6})

    def test_eq_string(self) -> None:
        assert _resolve("field:tool_id==read", {"tool_id": "read"})
        assert not _resolve("field:tool_id==read", {"tool_id": "write"})

    def test_eq_bool_literal(self) -> None:
        assert _resolve("field:safe==true", {"safe": True})
        assert _resolve("field:safe==false", {"safe": False})

    def test_neq(self) -> None:
        assert _resolve("field:tool_id!=delete", {"tool_id": "read"})
        assert not _resolve("field:tool_id!=delete", {"tool_id": "delete"})

    def test_gt(self) -> None:
        assert _resolve("field:score>0.5", {"score": 0.7})
        assert not _resolve("field:score>0.5", {"score": 0.5})

    def test_gte(self) -> None:
        assert _resolve("field:score>=0.5", {"score": 0.5})

    def test_lt(self) -> None:
        assert _resolve("field:score<0.5", {"score": 0.4})

    def test_lte(self) -> None:
        assert _resolve("field:score<=0.5", {"score": 0.5})


class TestSetOperators:
    def test_in(self) -> None:
        assert _resolve("field:tool_id~in:read,write,list", {"tool_id": "write"})
        assert not _resolve("field:tool_id~in:read,write,list", {"tool_id": "delete"})

    def test_not_in(self) -> None:
        assert _resolve("field:tool_id~not_in:delete,destroy", {"tool_id": "read"})
        assert not _resolve("field:tool_id~not_in:delete,destroy", {"tool_id": "delete"})


class TestStringOperators:
    def test_contains(self) -> None:
        assert _resolve("field:text~contains:credit", {"text": "credit-card"})
        assert not _resolve("field:text~contains:credit", {"text": "debit"})

    def test_not_contains(self) -> None:
        assert _resolve("field:text~not_contains:ssn", {"text": "harmless content"})

    def test_matches_regex(self) -> None:
        assert _resolve(r"field:text~matches:\d{3}-\d{2}", {"text": "abc 123-45 def"})
        assert not _resolve(r"field:text~matches:\d{3}-\d{2}", {"text": "no digits"})


class TestRangeAndExistsOperators:
    def test_between_inclusive(self) -> None:
        assert _resolve("field:score~between:0.5,0.9", {"score": 0.7})
        assert _resolve("field:score~between:0.5,0.9", {"score": 0.5})
        assert _resolve("field:score~between:0.5,0.9", {"score": 0.9})
        assert not _resolve("field:score~between:0.5,0.9", {"score": 0.4})

    def test_between_rejects_malformed(self) -> None:
        with pytest.raises(ValueError):
            _resolve("field:x~between:1", {"x": 0.5})

    def test_exists_zero_arg(self) -> None:
        assert _resolve("field:something~exists", {"something": "anything"})
        assert not _resolve("field:missing~exists", {})


# ---------------------------------------------------------------------
# Namespace routing
# ---------------------------------------------------------------------


class TestNamespaces:
    def test_kind_matches_event_kind(self) -> None:
        ctx = ContractContext(
            proposed_event=make_event(kind="agent_invokes_tool"),
            state=make_state(),
        )
        resolver = make_resolver(ctx)
        trace = trace_for(ctx)
        assert resolver("kind:agent_invokes_tool", trace[0])
        assert not resolver("kind:agent_emits_output", trace[0])

    def test_actor_matches(self) -> None:
        ctx = ContractContext(
            proposed_event=make_event(actor="alice"),
            state=make_state(),
        )
        resolver = make_resolver(ctx)
        assert resolver("actor:alice", {})
        assert not resolver("actor:bob", {})

    def test_capability_matches(self) -> None:
        ctx = ContractContext(
            proposed_event=make_event(),
            state=make_state(active_capabilities=("read", "write")),
        )
        resolver = make_resolver(ctx)
        assert resolver("capability:read", {})
        assert not resolver("capability:delete", {})

    def test_upstream_matches(self) -> None:
        ctx = ContractContext(
            proposed_event=make_event(upstream=("e1", "e2")),
            state=make_state(),
        )
        resolver = make_resolver(ctx)
        assert resolver("upstream:e1", {})
        assert not resolver("upstream:e3", {})

    def test_drift_signal_lookup(self) -> None:
        assert _resolve(
            "drift:ftc_risk<0.5",
            payload={},
            drift_signals={"ftc_risk": 0.3},
        )
        assert not _resolve(
            "drift:ftc_risk<0.5",
            payload={},
            drift_signals={"ftc_risk": 0.6},
        )

    def test_state_path_lookup(self) -> None:
        assert _resolve(
            "state:active_governance_graph_id==policy-v1",
            payload={},
            governance_graph_id="policy-v1",
        )
        assert _resolve(
            "state:sliding_window_compromise_ratio<0.5",
            payload={},
            compromise_ratio=0.3,
        )

    def test_missing_field_path_returns_false(self) -> None:
        # Lookup on a missing path -> None -> compares as False.
        assert not _resolve("field:does.not.exist==anything", {"output": {}})


# ---------------------------------------------------------------------
# Helper coverage
# ---------------------------------------------------------------------


class TestHelpers:
    def test_trace_for_returns_one_element(self) -> None:
        ctx = ContractContext(
            proposed_event=make_event(payload={"x": 1}),
            state=make_state(),
        )
        trace = trace_for(ctx)
        assert len(trace) == 1
