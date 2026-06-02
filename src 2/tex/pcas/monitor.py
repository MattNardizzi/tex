"""
PCAS reference monitor.

The reference monitor is the policy-enforcement front door. Given:

- a compiled ``Evaluator`` (program + helper registry),
- an ``Action`` describing the candidate next agent action,
- a ``DependencyGraphView`` of the current system state,

it computes a verdict in {PERMIT, ABSTAIN, FORBID} grounded in:

1. Materialize the EDB from the dependency view, then *add* the
   candidate action as a fact in ``pending_action/1`` (a synthetic
   relation the policy can target). Policies opt into seeing the
   candidate by referring to ``pending_action`` in body atoms.
2. Run the stratified evaluator to closure.
3. Inspect ``authorize/1`` and ``deny/1`` head facts grounded on the
   action ID:
   - ``deny`` present                            -> FORBID (fail-closed)
   - ``deny`` absent, ``authorize`` present      -> PERMIT
   - neither present                             -> ABSTAIN
   This matches PCAS §4.4.1 authorization-flow with the fail-closed
   correction we apply system-wide.

The monitor never throws on policy semantic failure; it converts
EvaluationError / StratificationError / ParseError into FORBID with a
diagnostic reason. Operational truth: the only way a policy issue
becomes a PERMIT is if the policy *explicitly* authorizes the
candidate action.

Latency target: < 1 ms p99 on graphs with <= 100 nodes / 500 edges,
which is the regime PCAS reports in arxiv 2602.16708 Table 3.
"""

from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event
from tex.pcas.graph.adapter import DependencyGraphAdapter, DependencyGraphView
from tex.pcas.language.lexer import LexerError
from tex.pcas.language.parser import ParseError, parse_program
from tex.pcas.language.stratify import StratificationError
from tex.pcas.runtime.evaluator import EvaluationError, Evaluator
from tex.pcas.runtime.relation import FactValue, Relation


class AuthorizationVerdict(str, Enum):
    """Three-state verdict matching Tex's PDP semantics."""

    PERMIT = "PERMIT"
    ABSTAIN = "ABSTAIN"
    FORBID = "FORBID"


class CandidateAction(BaseModel):
    """The action under adjudication."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=128)
    payload_hash: str = Field(min_length=1, max_length=128)


class PolicyDecision(BaseModel):
    """Structured monitor output, suitable for direct evidence emission."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: AuthorizationVerdict
    action_id: str
    reasons: tuple[str, ...] = ()
    authorize_facts: tuple[tuple[FactValue, ...], ...] = ()
    deny_facts: tuple[tuple[FactValue, ...], ...] = ()
    elapsed_ms: float = Field(ge=0.0)
    diagnostic: str | None = Field(default=None, max_length=2_000)
    policy_source: str | None = Field(default=None, max_length=200)


class PcasMonitor:
    """
    The reference monitor. Construct with a compiled policy program
    (source text), then call ``authorize(action, graph)`` per request.

    Construction parses + stratifies the policy once. If the policy
    fails to parse or stratify, *all* subsequent ``authorize`` calls
    return FORBID with the diagnostic — fail-closed by design.
    """

    __slots__ = ("_source", "_evaluator", "_load_error", "_adapter")

    def __init__(self, policy_source: str, *, name: str | None = None) -> None:
        self._source = name or "<inline>"
        self._adapter = DependencyGraphAdapter()
        self._evaluator: Evaluator | None = None
        self._load_error: str | None = None

        try:
            program = parse_program(policy_source, name=self._source)
            self._evaluator = Evaluator(program)
        except (LexerError, ParseError, StratificationError, EvaluationError) as exc:
            self._load_error = str(exc)
            emit_event(
                "pcas.monitor.load_failed",
                source=self._source,
                error=str(exc),
            )

    @property
    def evaluator(self) -> Evaluator | None:
        return self._evaluator

    @property
    def load_error(self) -> str | None:
        return self._load_error

    @property
    def source_name(self) -> str:
        return self._source

    # ------------------------------------------------------------- authorize

    def authorize(
        self, action: CandidateAction, graph: DependencyGraphView
    ) -> PolicyDecision:
        """Adjudicate ``action`` against the policy and current ``graph``."""
        start = time.perf_counter()

        if self._load_error is not None or self._evaluator is None:
            return PolicyDecision(
                verdict=AuthorizationVerdict.FORBID,
                action_id=action.action_id,
                reasons=("policy_load_error",),
                authorize_facts=(),
                deny_facts=(),
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
                diagnostic=self._load_error or "no evaluator",
                policy_source=self._source,
            )

        edb = self._adapter.to_edb(graph)
        # Inject the candidate action so the policy can reason about it.
        # Schema:
        #   pending_action(ActionId, Kind, Actor, PayloadHash)
        edb["pending_action"] = Relation(
            name="pending_action",
            arity=4,
            facts=[
                (
                    action.action_id,
                    action.kind,
                    action.actor,
                    action.payload_hash,
                )
            ],
        )
        # Also mirror it as a row in ``action`` so existing rules over
        # ``action/4`` see the candidate without needing to be rewritten.
        existing_action = edb.get("action")
        if existing_action is None:
            edb["action"] = Relation(name="action", arity=4, facts=[
                (action.action_id, action.kind, action.actor, action.payload_hash)
            ])
        else:
            edb["action"] = existing_action.with_facts([
                (action.action_id, action.kind, action.actor, action.payload_hash)
            ])

        try:
            closure = self._evaluator.evaluate(edb)
        except EvaluationError as exc:
            return PolicyDecision(
                verdict=AuthorizationVerdict.FORBID,
                action_id=action.action_id,
                reasons=("evaluation_error",),
                authorize_facts=(),
                deny_facts=(),
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
                diagnostic=str(exc),
                policy_source=self._source,
            )

        authorize_preds = self._evaluator.program.authorize_predicates
        deny_preds = self._evaluator.program.deny_predicates

        authorize_facts: list[tuple[FactValue, ...]] = []
        deny_facts: list[tuple[FactValue, ...]] = []
        reasons: list[str] = []

        for pred in authorize_preds:
            rel = closure.get(pred)
            if rel is None:
                continue
            for fact in rel.facts:
                if fact and fact[0] == action.action_id:
                    authorize_facts.append(fact)
                    reasons.append(f"authorize:{pred}")

        for pred in deny_preds:
            rel = closure.get(pred)
            if rel is None:
                continue
            for fact in rel.facts:
                if fact and fact[0] == action.action_id:
                    deny_facts.append(fact)
                    reasons.append(f"deny:{pred}")

        if deny_facts:
            verdict = AuthorizationVerdict.FORBID
        elif authorize_facts:
            verdict = AuthorizationVerdict.PERMIT
        else:
            verdict = AuthorizationVerdict.ABSTAIN
            reasons.append("no_matching_rule")

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        emit_event(
            "pcas.monitor.decided",
            action_id=action.action_id,
            verdict=verdict.value,
            elapsed_ms=elapsed_ms,
            policy_source=self._source,
        )

        return PolicyDecision(
            verdict=verdict,
            action_id=action.action_id,
            reasons=tuple(reasons),
            authorize_facts=tuple(authorize_facts),
            deny_facts=tuple(deny_facts),
            elapsed_ms=elapsed_ms,
            diagnostic=None,
            policy_source=self._source,
        )


__all__ = [
    "AuthorizationVerdict",
    "CandidateAction",
    "PcasMonitor",
    "PolicyDecision",
]
