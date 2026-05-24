"""
PCAS — Policy Compiler for Agentic Systems.

Datalog-derived policy language over the PCAS dependency graph, with
deterministic enforcement as a reference monitor.

This is the first production-grade implementation of the PCAS architecture
described in arxiv 2602.16708 (Palumbo/Choudhary/Choi/Chalasani/
Christodorescu/Jha, Wisconsin + Google, Feb 18 2026). The paper ships
algorithmic descriptions; the authors' supplemental code has not been
released. Microsoft Agent Governance Toolkit (Apr 2 2026) ships sub-ms
policy enforcement but **no Datalog frontend, no recursive queries, no
causal-provenance graph traversal** — per PCAS Table 1, only PCAS supports
the four-of-four combination (expressive language + recursive + causal +
multi-agent + deterministic).

Architecture
------------
- ``language.ast``      — typed AST for the policy language
- ``language.lexer``    — tokenizer, RFC-style line/col tracking
- ``language.parser``   — recursive-descent parser → ``Program``
- ``language.stratify`` — dependency analysis, stratification check
                          (rejects recursion-through-negation per Apt-Blair-
                          Walker stratifiability test; arxiv 1909.08246)
- ``runtime.relation``  — typed tuple sets with index support
- ``runtime.evaluator`` — semi-naive bottom-up evaluator with stratified
                          negation (Bancilhon-Maier-Ramakrishnan-Sagiv 1986)
- ``runtime.helpers``   — Python FFI surface for built-ins
                          (json_extract, descended_from, equals, ...)
- ``graph.adapter``     — dependency-graph view over Tex's
                          ``tex.graph.temporal_kg`` and the IFC
                          ``ProvenanceGraph`` from Thread 11
- ``monitor``           — PCAS reference monitor that authorizes Actions
                          against a compiled policy
- ``specialist``        — ``PcasSpecialist`` exposing monitor verdicts to
                          the PDP

Core relations exposed to policies (subset of PCAS §4.5.1)
----------------------------------------------------------
- ``action(ActionId, Kind, Actor, Payload)``
- ``message(MsgId, Sender, Receiver, Content)``
- ``tool_call(CallId, Tool, Caller, Args, Result)``
- ``data(DataId, Source, Label, Content)``
- ``depends_on(X, Y)``    — direct dependency edge
- ``derived_from(X, Y)``  — transitive: depends_on*
- ``approved(Subject, Approver, At)``
- ``role(Actor, RoleName)``

Helper functions (subset of PCAS §4.5.2)
----------------------------------------
- ``json_extract(Value, Path) -> Value``
- ``equals(X, Y) -> Bool``
- ``not_equals(X, Y) -> Bool``
- ``before(EventA, EventB) -> Bool``
- ``has_label(DataId, Label) -> Bool``

Rule annotations (PCAS §4.5.3)
------------------------------
``@authorize`` heads license an action; ``@deny`` heads veto it; both
co-existing on the same action -> deny wins (fail-closed; matches PCAS
authorization-flow §4.4.1).

Engineering targets
-------------------
- p99 evaluation latency < 1ms on graphs <= 1k nodes / 10k edges
- 100% Python stdlib runtime (no datalog binding required)
- Pydantic v2 strict models; ConfigDict(frozen=True, extra='forbid') everywhere
- Algorithm agility hooks via ``tex.pqcrypto.algorithm_agility`` for any
  serialized policy artifact

Priority: P0 — wired into the live PDP via ``PcasSpecialist``.
"""

from tex.pcas.language.ast import (
    Atom,
    Constant,
    HelperCall,
    NegatedAtom,
    Program,
    Rule,
    RuleAnnotation,
    Term,
    Variable,
)
from tex.pcas.language.lexer import Lexer, LexerError, Token, TokenKind
from tex.pcas.language.parser import Parser, ParseError, parse_program
from tex.pcas.language.stratify import (
    StratificationError,
    Stratum,
    stratify,
)
from tex.pcas.runtime.evaluator import EvaluationError, Evaluator
from tex.pcas.runtime.helpers import (
    HELPER_REGISTRY,
    HelperFunction,
    register_helper,
)
from tex.pcas.runtime.relation import Fact, Relation
from tex.pcas.graph.adapter import DependencyGraphAdapter
from tex.pcas.monitor import (
    AuthorizationVerdict,
    PcasMonitor,
    PolicyDecision,
)

__all__ = [
    # AST
    "Atom",
    "Constant",
    "HelperCall",
    "NegatedAtom",
    "Program",
    "Rule",
    "RuleAnnotation",
    "Term",
    "Variable",
    # Lex / Parse / Stratify
    "Lexer",
    "LexerError",
    "Token",
    "TokenKind",
    "Parser",
    "ParseError",
    "parse_program",
    "StratificationError",
    "Stratum",
    "stratify",
    # Runtime
    "EvaluationError",
    "Evaluator",
    "HELPER_REGISTRY",
    "HelperFunction",
    "register_helper",
    "Fact",
    "Relation",
    # Graph adapter
    "DependencyGraphAdapter",
    # Monitor
    "AuthorizationVerdict",
    "PcasMonitor",
    "PolicyDecision",
]
