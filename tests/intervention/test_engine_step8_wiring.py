"""
Tests for tex.ecosystem.engine — Step 8 intervention selection (Thread 8).

These exercise the engine-level wiring rather than the InterventionEngine
unit semantics (those are in tests/intervention/test_engine.py). The
focus here is the Step 8 branch logic in EcosystemEngine.evaluate():

- Default (no calc) preserves Thread 1-7 PERMIT behavior byte-for-byte.
- With calc + candidates + axes-clean: PERMIT.
- With calc + candidates + axes-dirty + satisfying intervention -> SANCTION,
  recommended_intervention_id populated.
- With calc + candidates + axes-dirty + RESTORATIVE_PATH chosen -> REMEDIATE.
- With calc + candidates + axes-dirty + no satisfier -> FORBID
  (FAIL-CLOSED), recommended_intervention_id None.
- target_compromise_ratio validation.

Axes-dirty is forced by passing a fake ``contracts`` collaborator whose
``compliance_scores`` returns a low C_hard (so
contract_violation_severity >= 0.5). This is cleaner than wiring a real
DriftSignalRegistry; the axis-derived-FORBID predicate considers any of
the three risk axes, so any of them being above 0.5 fires the gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterator

import pytest

from tex.contracts.runtime_enforcement import ComplianceScores
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
from tex.intervention.kinds import Intervention, InterventionKind
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# ---------------------------------------------------------------- fixtures


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def signing_provider():
    return default_signature_provider()


@pytest.fixture
def signing_keypair(signing_provider):
    return signing_provider.generate_keypair("test-key-step8")


@pytest.fixture
def provenance(signing_keypair, signing_provider) -> CryptoProvenance:
    return CryptoProvenance(
        signing_key=signing_keypair, signing_provider=signing_provider,
    )


@pytest.fixture
def graph() -> InMemoryTemporalKG:
    return InMemoryTemporalKG()


@pytest.fixture
def projection(graph: InMemoryTemporalKG) -> StateProjection:
    return StateProjection(graph=graph)


@pytest.fixture
def ledger(signing_keypair, signing_provider) -> InMemoryLedger:
    return InMemoryLedger(
        verifying_public_key=signing_keypair.public_key,
        signing_provider=signing_provider,
    )


@pytest.fixture
def ontology_validator(ledger: InMemoryLedger) -> OntologyValidator:
    return OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    )


@pytest.fixture
def registered_actor(graph: InMemoryTemporalKG, now: datetime) -> str:
    actor_id = "agent_X"
    graph.add_entity(
        entity_id=actor_id,
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return actor_id


@pytest.fixture
def registered_tool(graph: InMemoryTemporalKG, now: datetime) -> str:
    tool_id = "tool_Y"
    graph.add_entity(
        entity_id=tool_id,
        kind="tool",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return tool_id


@pytest.fixture
def proposed_event(
    registered_actor: str, registered_tool: str, now: datetime
) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=registered_actor,
        target_entity_id=registered_tool,
        payload={"tool_id": registered_tool, "arguments": {"q": "hello"}},
        proposed_at=now,
    )


# ----------------------------- contracts collaborator (ducktyped per engine) --


@dataclass
class FakeContracts:
    """Duck-types tex.contracts.runtime_enforcement.ContractEnforcer.

    Returns a constant ComplianceScores result so we can deterministically
    drive the contract_violation_severity axis above the 0.5 FORBID
    threshold (severity = 1 - min(c_hard, c_soft)).
    """

    c_hard: float = 1.0
    c_soft: float = 1.0

    def compliance_scores(
        self, *, agent_id, proposed_event, current_state
    ) -> ComplianceScores:  # noqa: D401
        return ComplianceScores(
            c_hard=self.c_hard,
            c_soft=self.c_soft,
            contracts_evaluated=1,
            constraints_evaluated=1,
        )


def _high_severity_contracts() -> FakeContracts:
    """C_hard = 0 -> contract_violation_severity = 1.0 (above 0.5 gate)."""
    return FakeContracts(c_hard=0.0, c_soft=1.0)


def _clean_contracts() -> FakeContracts:
    """C_hard = C_soft = 1 -> severity 0.0 (below gate)."""
    return FakeContracts(c_hard=1.0, c_soft=1.0)


# --------------------------------------------------------------- helper builder


def _make_engine(
    *,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
    contracts_collaborator=None,
    intervention_calc=None,
    candidate_interventions=(),
    restorative_executor=None,
    auto_execute_restorative=False,
    target_compromise_ratio=None,
) -> EcosystemEngine:
    return EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        contracts=contracts_collaborator,
        intervention_calc=intervention_calc,
        candidate_interventions=candidate_interventions,
        restorative_executor=restorative_executor,
        auto_execute_restorative=auto_execute_restorative,
        target_compromise_ratio=target_compromise_ratio,
        enabled=True,
    )


# ============================================================================
# Backward compatibility (Thread 8 disabled by default)
# ============================================================================


class TestBackwardCompatNoCalc:
    def test_default_engine_permits_clean_event(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.PERMIT
        assert verdict.recommended_intervention_id is None
        assert verdict.axis_scores.bounded_compromise_score == 0.0

    def test_no_calc_dirty_axes_still_permits(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        # Without a calc wired, the axis-derived FORBID gate never
        # fires. High contract severity is recorded in axes but the
        # verdict is still PERMIT (legacy Thread 1-7 behavior).
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_high_severity_contracts(),
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.PERMIT
        assert verdict.recommended_intervention_id is None
        # The axis IS populated, even though the gate didn't fire.
        assert verdict.axis_scores.contract_violation_severity == 1.0


# ============================================================================
# Step 8 wired: axes-clean stays PERMIT
# ============================================================================


class TestStep8AxesClean:
    def test_calc_wired_axes_clean_still_permits(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        cand = (
            Intervention(
                intervention_id="iv_unused",
                kind=InterventionKind.TRUST_SCORE_REDUCE,
                target_entity_id="agent_X",
                parameters={},
                expected_cost_to_system=0.05,
                expected_cost_to_adversary=20.0,
                rationale="never selected",
            ),
        )
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_clean_contracts(),
            intervention_calc=calc,
            candidate_interventions=cand,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.PERMIT
        assert verdict.recommended_intervention_id is None


# ============================================================================
# Step 8 wired: axes-dirty SANCTION
# ============================================================================


class TestStep8AxesDirtySanction:
    def test_high_severity_with_satisfying_candidate_yields_sanction(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        cand = (
            Intervention(
                intervention_id="iv_weak",
                kind=InterventionKind.REWARD_SHAPE,
                target_entity_id="agent_X",
                parameters={},
                expected_cost_to_system=0.01,
                expected_cost_to_adversary=0.5,
                rationale="cheap, fails bound",
            ),
            Intervention(
                intervention_id="iv_strong",
                kind=InterventionKind.TRUST_SCORE_REDUCE,
                target_entity_id="agent_X",
                parameters={"delta": -0.3},
                expected_cost_to_system=0.05,
                expected_cost_to_adversary=20.0,
                rationale="satisfies bound",
            ),
        )
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_high_severity_contracts(),
            intervention_calc=calc,
            candidate_interventions=cand,
            target_compromise_ratio=0.5,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.SANCTION
        assert verdict.recommended_intervention_id == "iv_strong"
        assert verdict.axis_scores.bounded_compromise_score > 0.0
        assert verdict.evidence_record_id is not None


# ============================================================================
# Step 8 wired: REMEDIATE for blocking kinds
# ============================================================================


class TestStep8AxesDirtyRemediate:
    def test_quarantine_yields_remediate_no_ledger_append(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        cand = (
            Intervention(
                intervention_id="iv_quar",
                kind=InterventionKind.QUARANTINE,
                target_entity_id="agent_X",
                parameters={"duration": 5},
                expected_cost_to_system=0.20,
                expected_cost_to_adversary=30.0,
                rationale="quarantine blocks event",
            ),
        )
        records_before = len(ledger.stream_after(-1))
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_high_severity_contracts(),
            intervention_calc=calc,
            candidate_interventions=cand,
            target_compromise_ratio=0.5,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.REMEDIATE
        assert verdict.recommended_intervention_id == "iv_quar"
        # REMEDIATE does NOT append the proposed_event to the main
        # ledger.
        records_after = len(ledger.stream_after(-1))
        assert records_after == records_before
        assert verdict.ecosystem_state_hash_after is None


# ============================================================================
# Step 8 wired: no satisfier -> FAIL-CLOSED FORBID
# ============================================================================


class TestStep8FailClosed:
    def test_no_candidate_satisfies_yields_forbid_no_recommendation(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        cand = (
            Intervention(
                intervention_id="iv_too_weak",
                kind=InterventionKind.REWARD_SHAPE,
                target_entity_id="agent_X",
                parameters={},
                expected_cost_to_system=0.01,
                expected_cost_to_adversary=0.5,
                rationale="weak",
            ),
        )
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_high_severity_contracts(),
            intervention_calc=calc,
            candidate_interventions=cand,
            target_compromise_ratio=0.1,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert verdict.recommended_intervention_id is None
        assert "no candidate intervention satisfies" in verdict.rationale

    def test_empty_candidate_set_yields_forbid_on_dirty_axes(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
        proposed_event,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        engine = _make_engine(
            ontology_validator=ontology_validator,
            graph=graph,
            projection=projection,
            ledger=ledger,
            provenance=provenance,
            contracts_collaborator=_high_severity_contracts(),
            intervention_calc=calc,
            candidate_interventions=(),
            target_compromise_ratio=0.5,
        )
        verdict = engine.evaluate(proposed_event)
        assert verdict.kind == EcosystemVerdictKind.FORBID
        assert verdict.recommended_intervention_id is None


# ============================================================================
# Step 8 wired: target_compromise_ratio validation
# ============================================================================


class TestStep8TargetRatio:
    def test_invalid_target_ratio_in_constructor_raises(
        self,
        ontology_validator,
        graph,
        projection,
        ledger,
        provenance,
    ) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="target_compromise_ratio"):
            _make_engine(
                ontology_validator=ontology_validator,
                graph=graph,
                projection=projection,
                ledger=ledger,
                provenance=provenance,
                intervention_calc=calc,
                target_compromise_ratio=1.5,
            )
