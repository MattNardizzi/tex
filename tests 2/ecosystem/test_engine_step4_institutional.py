"""
Integration test for Thread 2 — institutional governance-graph LTS
wired into ``EcosystemEngine.evaluate()`` step 4.

Covers
------
* Backward compatibility: engine constructed without ``governance_graph``
  or ``oracle`` behaves identically to the pre-Thread-2 engine.
* Step 4 legal-transition pass: engine produces PERMIT and the
  governance log records a positive ``is_legal=true`` assessment.
* Step 4 illegal-transition FORBID: engine returns FORBID with rationale
  naming the (from_state, triggered_by) pair.
* Subagent inheritance per arxiv 2605.08460: a subagent of a suspended
  parent is evaluated under ``suspended`` even when its direct state is
  ``active``.
* Fail-closed semantics: oracle errors return FORBID, never PERMIT.
* Governance log signature provider is whichever
  ``_pq_signing.select_institutional_signing_provider`` chose; the
  test asserts the algorithm appears on the recorded payload.

References
----------
- arxiv 2601.11369 (Bracale Syrnikov et al., Jan 2026), §4.2 — LTS
  framing of the institutional regime
- arxiv 2605.08460 (Cai/Zhang/Hei, May 8 2026) — subagent-spawn
  inheritance threat model
- FRONTIER_DELTA_thread_2.md
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.institutional.governance_graph import GovernanceGraph
from tex.institutional.oracle import GovernanceOracle
from tex.ontology.entity_types import EntityKind, EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# ---------------------------------------------------------------- fixtures

NOW = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def signing_provider():
    return default_signature_provider()


@pytest.fixture
def signing_keypair(signing_provider):
    return signing_provider.generate_keypair("test-key-thread2")


@pytest.fixture
def provenance(signing_keypair, signing_provider) -> CryptoProvenance:
    return CryptoProvenance(
        signing_key=signing_keypair, signing_provider=signing_provider
    )


@pytest.fixture
def graph() -> InMemoryTemporalKG:
    return InMemoryTemporalKG()


@pytest.fixture
def projection(graph) -> StateProjection:
    return StateProjection(graph=graph)


@pytest.fixture
def ledger(signing_keypair, signing_provider) -> InMemoryLedger:
    return InMemoryLedger(
        verifying_public_key=signing_keypair.public_key,
        signing_provider=signing_provider,
    )


@pytest.fixture
def ontology_validator(ledger) -> OntologyValidator:
    return OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    )


def _register_agent(graph: InMemoryTemporalKG, agent_id: str, **extra: Any) -> str:
    attrs = {"registered_at": NOW - timedelta(minutes=1)}
    attrs.update(extra)
    graph.add_entity(entity_id=agent_id, kind="agent", attrs=attrs)
    return agent_id


def _register_tool(graph: InMemoryTemporalKG, tool_id: str) -> str:
    graph.add_entity(
        entity_id=tool_id,
        kind="tool",
        attrs={"registered_at": NOW - timedelta(minutes=1)},
    )
    return tool_id


# ---------- governance manifests targeted at ontology event kinds -----------
#
# The Cournot fixture (tests/institutional/fixtures/cournot_market.yaml)
# uses governance-control ``triggered_by`` values (``probable_violation``,
# ``expiry_tick``, ...). Step 4 fires on every proposed event using
# ``proposed.event_kind`` as the trigger — to exercise the legality
# enforcement we author a small operator-style manifest whose
# ``triggered_by`` values ARE ontology event kinds.


def _manifest_dict_with_action_triggers() -> dict[str, Any]:
    """
    Three legal-state manifest exercising ontology-kind triggers.

    States: active, fined, suspended.
    Edge 1: active --agent_invokes_tool--> active  (legal, no sanction)
    Edge 2: fined --agent_invokes_tool--> fined    (illegal: sanctioned
                                                    with fine_tier1 — the
                                                    oracle returns
                                                    (False, "fine_tier1")
                                                    per §6.2.1)
    Edge 3: suspended --agent_invokes_tool--> suspended (no edge declared
                                                         → no_edge → FORBID
                                                         "transition not legal")

    Suspended is modeled by SIMPLY omitting any outgoing edge from
    ``suspended`` with ``agent_invokes_tool`` as the trigger. The oracle
    returns ``(False, None)`` and step 4 produces FORBID.
    """
    return {
        "schema_version": "v1",
        "graph_id": "thread2_action_kind_manifest",
        "version": "1.0.0",
        "interpreter": {
            "name": "tex.institutional.oracle_controller",
            "version": "1.0.0",
        },
        "states": [
            {"state_id": "active", "description": "baseline"},
            {"state_id": "fined", "description": "penalised"},
            {"state_id": "suspended", "description": "removed"},
        ],
        "sanctions": [
            {
                "sanction_id": "fine_tier1",
                "description": "First fine",
                "cost_to_actor": 200.0,
                "cost_to_system": 0.0,
                "enforcement_action": "fine",
                "tier": 1,
                "fine_rate": 0.35,
                "fine_floor": 200.0,
            },
        ],
        "restorative_paths": [],
        "transitions": [
            {
                "rule_id": "ACTION_active",
                "from_state": "active",
                "to_state": "active",
                "triggered_by": EventKind.AGENT_INVOKES_TOOL.value,
                "edge_key": (
                    f"ACTION_active:active->active"
                ),
            },
            {
                "rule_id": "ACTION_fined",
                "from_state": "fined",
                "to_state": "fined",
                "triggered_by": EventKind.AGENT_INVOKES_TOOL.value,
                "sanction_id": "fine_tier1",
                "edge_key": "ACTION_fined:fined->fined",
            },
        ],
    }


@pytest.fixture
def governance_graph_action_kinds() -> GovernanceGraph:
    return GovernanceGraph.from_dict(_manifest_dict_with_action_triggers())


@pytest.fixture
def oracle(governance_graph_action_kinds) -> GovernanceOracle:
    return GovernanceOracle(
        graph=governance_graph_action_kinds,
        signals=(),  # no Oracle signals — we drive transitions directly
        rule_id_for_signal=None,
    )


# ---------------------------------------------------------------- engine builders


def _build_engine(
    *,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
    governance_graph=None,
    oracle=None,
    institutional_states=None,
) -> EcosystemEngine:
    return EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        enabled=True,
        governance_graph=governance_graph,
        oracle=oracle,
        institutional_states=institutional_states,
    )


def _propose_tool_call(actor: str, tool: str) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=actor,
        target_entity_id=tool,
        payload={"tool_id": tool, "arguments": {"q": "hello"}},
        proposed_at=NOW,
    )


# ============================================================ TESTS ===========


class TestBackwardCompat:
    """Engine without governance_graph + oracle behaves identically to pre-T2."""

    def test_no_oracle_yields_permit(
        self, ontology_validator, graph, projection, ledger, provenance
    ):
        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
        )
        actor = _register_agent(graph, "agent_baseline")
        tool = _register_tool(graph, "tool_baseline")
        verdict = engine.evaluate(_propose_tool_call(actor, tool))
        assert verdict.kind == EcosystemVerdictKind.PERMIT
        # Axis score for governance-graph legality should be 1.0 (unchanged
        # from pre-Thread-2 _NEUTRAL_AXIS_SCORES default).
        assert verdict.axis_scores.governance_graph_legality == 1.0


class TestStep4LegalTransition:
    """active state + agent_invokes_tool → PERMIT, log records is_legal=True."""

    def test_legal_transition_yields_permit_and_signed_log_entry(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
        oracle,
    ):
        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=oracle,
            institutional_states={"agent_legal": "active"},
        )
        actor = _register_agent(graph, "agent_legal")
        tool = _register_tool(graph, "tool_legal")

        verdict = engine.evaluate(_propose_tool_call(actor, tool))

        assert verdict.kind == EcosystemVerdictKind.PERMIT, verdict.rationale
        assert verdict.axis_scores.governance_graph_legality == 1.0

        # Governance log should have one entry: the positive
        # is_legal=True step-4 assessment.
        log = engine._governance_log
        assert log is not None
        assert len(log) == 1
        assert log.verify_chain() is True

        records = log.all_records()
        assert len(records) == 1
        payload = records[0].payload
        assert payload["is_legal"] is True
        assert payload["proposed_event_kind"] == EventKind.AGENT_INVOKES_TOOL.value
        assert payload["effective_institutional_state"] == "active"
        # PQ algorithm identifier should be one of the selection-chain
        # outcomes from ``tex.pqcrypto.algorithm_agility``. The default
        # selector prefers BLAKE3+ML-DSA-65 (algorithm-agile signing
        # context binding, arxiv 2605.06788) when available, and falls
        # back through ML-DSA-65 native → hybrid ML-DSA-65 + Ed25519
        # → classical ECDSA-P256 as the algorithm-agility ladder
        # degrades.
        assert payload["signing_algorithm"] in {
            "blake3-ml-dsa-65",
            "ml-dsa-65",
            "hybrid-ml-dsa-65-ed25519",
            "ecdsa-p256",
        }


class TestStep4IllegalTransitionForbid:
    """Actor in ``fined`` state + manifest-declared sanction → FORBID."""

    def test_sanctioned_edge_returns_forbid_with_rationale(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
        oracle,
    ):
        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=oracle,
            institutional_states={"agent_fined": "fined"},
        )
        actor = _register_agent(graph, "agent_fined")
        tool = _register_tool(graph, "tool_fined")

        verdict = engine.evaluate(_propose_tool_call(actor, tool))

        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert "step 4 governance LTS" in verdict.rationale
        assert "'fined'" in verdict.rationale
        assert "fine_tier1" in verdict.rationale

        # Governance log should have one entry: the illegal-transition
        # assessment.
        log = engine._governance_log
        assert log is not None
        records = log.all_records()
        assert len(records) == 1
        assert records[0].payload["is_legal"] is False
        assert records[0].payload["sanction_id"] == "fine_tier1"

    def test_undeclared_edge_returns_forbid_no_sanction(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
        oracle,
    ):
        # State 'suspended' has NO outgoing edge for agent_invokes_tool
        # → oracle returns (False, None) → FORBID with rationale "not legal"
        # but no sanction_id segment.
        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=oracle,
            institutional_states={"agent_suspended": "suspended"},
        )
        actor = _register_agent(graph, "agent_suspended")
        tool = _register_tool(graph, "tool_suspended")

        verdict = engine.evaluate(_propose_tool_call(actor, tool))

        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert "step 4 governance LTS" in verdict.rationale
        assert "'suspended'" in verdict.rationale


class TestSubagentInheritance:
    """arxiv 2605.08460 — subagent of suspended parent inherits suspension."""

    def test_subagent_of_suspended_parent_is_blocked(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
        oracle,
    ):
        # Parent agent registered with no spawn relationship.
        _register_agent(graph, "agent_parent")
        # Child agent registered with spawned_by attribute pointing at
        # the suspended parent.
        _register_agent(graph, "agent_child", spawned_by="agent_parent")
        _register_tool(graph, "tool_child")

        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=oracle,
            # Child's DIRECT state is active, parent is suspended.
            # Inheritance must elevate child's effective state to
            # suspended → no edge for agent_invokes_tool → FORBID.
            institutional_states={
                "agent_parent": "suspended",
                "agent_child": "active",
            },
        )

        verdict = engine.evaluate(
            _propose_tool_call("agent_child", "tool_child")
        )

        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert "inherited from 'agent_parent'" in verdict.rationale
        assert "direct state was 'active'" in verdict.rationale

        # Governance log records the inheritance trail.
        records = engine._governance_log.all_records()
        assert len(records) == 1
        p = records[0].payload
        assert p["effective_institutional_state"] == "suspended"
        assert p["direct_institutional_state"] == "active"
        assert p["inherited_from"] == "agent_parent"
        assert p["spawn_chain_length"] == 1

    def test_subagent_of_active_parent_proceeds(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
        oracle,
    ):
        _register_agent(graph, "agent_parent2")
        _register_agent(graph, "agent_child2", spawned_by="agent_parent2")
        _register_tool(graph, "tool_child2")

        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=oracle,
            institutional_states={
                "agent_parent2": "active",
                "agent_child2": "active",
            },
        )

        verdict = engine.evaluate(
            _propose_tool_call("agent_child2", "tool_child2")
        )
        assert verdict.kind == EcosystemVerdictKind.PERMIT


class TestFailClosed:
    """Standing-orders §3: oracle errors default to FORBID, never PERMIT."""

    def test_oracle_raising_yields_forbid(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        governance_graph_action_kinds,
    ):
        class _ExplodingOracle:
            def evaluate_transition(self, **_kwargs):
                raise RuntimeError("simulated oracle failure")

        engine = _build_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            governance_graph=governance_graph_action_kinds,
            oracle=_ExplodingOracle(),
            institutional_states={"agent_x": "active"},
        )
        _register_agent(graph, "agent_x")
        _register_tool(graph, "tool_x")

        verdict = engine.evaluate(_propose_tool_call("agent_x", "tool_x"))
        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert "fail-closed" in verdict.rationale
