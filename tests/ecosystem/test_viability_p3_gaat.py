"""
Tests for Thread 7.1 RiskGate viability index + GAAT enforcement tiers
+ P3 monotonic restriction + OpenTelemetry span schema.

Coverage
--------
* EcosystemAxisScores.viability_index computed property
* RiskGate B̂(x) = max(U, SB, RG) decomposition
* GAAT L0..L4 enforcement tiers
* P3 monotonic restriction: floor never relaxes without recovery
* record_recovery clears the floor
* OpenTelemetry attribute schema is GAAT-compatible
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Iterator

import pytest

from tex.causal.chief import HierarchicalCausalGraph
from tex.contracts.contract import BehavioralContract
from tex.contracts.runtime_enforcement import ContractEnforcer
from tex.drift.signal_registry import DriftSignalRegistry
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import (
    EcosystemAxisScores,
    EcosystemVerdict,
    EcosystemVerdictKind,
    GraduatedEnforcementLevel,
    _graduated_level_from_viability,
)
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.observability.governance_span import (
    GAAT_ACTION_TABLE,
    GAAT_SPAN_SCHEMA_VERSION,
    verdict_to_otel_attributes,
)
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator
from tex.systemic.probguard import DTMCModel
from tex.systemic.risk_evaluator import SystemicRiskEvaluator


# ----- viability_index axiomatic correctness ------------------------------


def test_viability_index_zero_risk_is_one() -> None:
    """All axes at min-risk → viability == 1.0."""
    ax = EcosystemAxisScores(
        contract_violation_severity=0.0,
        governance_graph_legality=1.0,
        causal_attribution_confidence=0.5,
        drift_delta=0.0,
        systemic_risk_under_event=0.0,
        bounded_compromise_score=0.0,
    )
    assert ax.viability_index == 1.0


def test_viability_index_max_risk_is_zero() -> None:
    """drift_delta=1 → viability=0 regardless of other axes."""
    ax = EcosystemAxisScores(
        contract_violation_severity=0.0,
        governance_graph_legality=1.0,
        causal_attribution_confidence=0.5,
        drift_delta=1.0,
        systemic_risk_under_event=0.0,
        bounded_compromise_score=0.0,
    )
    assert ax.viability_index == 0.0


def test_viability_index_clamped_unit_interval() -> None:
    """Sweep many axis combinations; viability stays in [0, 1]."""
    for cs in (0.0, 0.5, 1.0):
        for gl in (0.0, 0.5, 1.0):
            for dd in (-0.5, 0.0, 0.3, 1.0, 1.5):
                for sr in (0.0, 0.5, 1.0):
                    ax = EcosystemAxisScores(
                        contract_violation_severity=cs,
                        governance_graph_legality=gl,
                        causal_attribution_confidence=0.5,
                        drift_delta=dd,
                        systemic_risk_under_event=sr,
                        bounded_compromise_score=0.0,
                    )
                    assert 0.0 <= ax.viability_index <= 1.0


def test_viability_index_max_decomposition() -> None:
    """viability_index = 1 - max(U, SB, RG)."""
    ax = EcosystemAxisScores(
        contract_violation_severity=0.3,  # → SB candidate
        governance_graph_legality=0.4,    # → SB candidate (1-0.4=0.6)
        causal_attribution_confidence=0.5,
        drift_delta=0.2,                  # → U
        systemic_risk_under_event=0.1,    # → RG
        bounded_compromise_score=0.0,
    )
    # max(0.2, max(0.3, 0.6), 0.1) = 0.6 → viability = 0.4
    assert abs(ax.viability_index - 0.4) < 1e-9


# ----- GAAT enforcement-level mapping --------------------------------------


def test_graduated_level_thresholds() -> None:
    """GAAT L0..L4 boundaries match published Theorem 3 table."""
    assert _graduated_level_from_viability(0.95) == GraduatedEnforcementLevel.L0_ALLOW
    assert _graduated_level_from_viability(0.90) == GraduatedEnforcementLevel.L0_ALLOW
    assert _graduated_level_from_viability(0.85) == GraduatedEnforcementLevel.L1_ALERT
    assert _graduated_level_from_viability(0.70) == GraduatedEnforcementLevel.L1_ALERT
    assert _graduated_level_from_viability(0.60) == GraduatedEnforcementLevel.L2_FLAG
    assert _graduated_level_from_viability(0.50) == GraduatedEnforcementLevel.L2_FLAG
    assert _graduated_level_from_viability(0.40) == GraduatedEnforcementLevel.L3_REDIRECT
    assert _graduated_level_from_viability(0.25) == GraduatedEnforcementLevel.L3_REDIRECT
    assert _graduated_level_from_viability(0.10) == GraduatedEnforcementLevel.L4_QUARANTINE
    assert _graduated_level_from_viability(0.00) == GraduatedEnforcementLevel.L4_QUARANTINE


def test_graduated_level_on_axis_scores() -> None:
    ax = EcosystemAxisScores(
        contract_violation_severity=0.0,
        governance_graph_legality=1.0,
        causal_attribution_confidence=0.5,
        drift_delta=0.05,
        systemic_risk_under_event=0.05,
        bounded_compromise_score=0.0,
    )
    # viability = 1 - 0.05 = 0.95 → L0_ALLOW
    assert ax.graduated_level == GraduatedEnforcementLevel.L0_ALLOW


# ----- engine P3 monotonic restriction -------------------------------------


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def wired_engine(now: datetime) -> Iterator[EcosystemEngine]:
    """Engine with all Thread 7 collaborators + P3 restriction on."""
    sp = default_signature_provider()
    kp = sp.generate_keypair("test-p3")
    prov = CryptoProvenance(signing_key=kp, signing_provider=sp)
    graph = InMemoryTemporalKG()
    graph.add_entity(
        entity_id="agent_p3",
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    graph.add_entity(
        entity_id="tool_p3",
        kind="tool",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    ledger = InMemoryLedger(
        verifying_public_key=kp.public_key, signing_provider=sp,
    )
    contract = BehavioralContract.make(
        contract_id="p3_test",
        agent_id="agent_p3",
        description="test",
        precondition_ltl="true",
        covered_event_kinds=("*",),
    )
    engine = EcosystemEngine(
        ontology=OntologyValidator(
            entity_registry=EntityTypeRegistry(),
            event_registry=EventTypeRegistry(),
            event_lookup=ledger,
        ),
        graph=graph,
        projection=StateProjection(graph=graph),
        events=ledger,
        provenance=prov,
        contracts=ContractEnforcer(contracts=(contract,)),
        causal=HierarchicalCausalGraph(),
        drift=DriftSignalRegistry(seed_defaults=True),
        systemic=SystemicRiskEvaluator(model=DTMCModel()),
        enabled=True,
        monotonic_restriction=True,
    )
    yield engine


def _propose(when: datetime) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id="agent_p3",
        target_entity_id="tool_p3",
        payload={"tool_id": "tool_p3", "arguments": {"q": "1"}},
        proposed_at=when,
    )


def test_p3_floor_recorded_on_first_evaluation(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    """First evaluation records the actor's viability as the floor."""
    assert wired_engine.viability_floor_for("agent_p3") is None
    verdict = wired_engine.evaluate(_propose(now))
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    floor = wired_engine.viability_floor_for("agent_p3")
    assert floor is not None
    assert 0.0 <= floor <= 1.0


def test_p3_floor_only_decreases(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    """The floor monotonically decreases (or stays the same) across
    evaluations until ``record_recovery`` is called."""
    floors: list[float] = []
    for i in range(10):
        wired_engine.evaluate(_propose(now + timedelta(seconds=i)))
        floors.append(wired_engine.viability_floor_for("agent_p3"))
    for i in range(1, len(floors)):
        assert floors[i] <= floors[i - 1] + 1e-9, (
            f"floor relaxed: {floors[i-1]} → {floors[i]}"
        )


def test_p3_record_recovery_clears_floor(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    """After ``record_recovery``, the floor returns to None."""
    wired_engine.evaluate(_propose(now))
    assert wired_engine.viability_floor_for("agent_p3") is not None
    wired_engine.record_recovery(actor_entity_id="agent_p3")
    assert wired_engine.viability_floor_for("agent_p3") is None


def test_p3_off_by_default() -> None:
    """``monotonic_restriction`` default is False — backward compat."""
    sp = default_signature_provider()
    kp = sp.generate_keypair("test-p3-default")
    prov = CryptoProvenance(signing_key=kp, signing_provider=sp)
    g = InMemoryTemporalKG()
    ledger = InMemoryLedger(
        verifying_public_key=kp.public_key, signing_provider=sp,
    )
    engine = EcosystemEngine(
        ontology=OntologyValidator(
            entity_registry=EntityTypeRegistry(),
            event_registry=EventTypeRegistry(),
            event_lookup=ledger,
        ),
        graph=g,
        projection=StateProjection(graph=g),
        events=ledger,
        provenance=prov,
        enabled=True,
    )
    assert engine.monotonic_restriction is False


# ----- OpenTelemetry span schema -------------------------------------------


def test_otel_attributes_have_gaat_governance_keys(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    """GAAT GTS §III.A required keys all present."""
    verdict = wired_engine.evaluate(_propose(now))
    attrs = verdict_to_otel_attributes(verdict)
    assert "governance.decision" in attrs
    assert "governance.enforcement_level" in attrs
    assert "governance.viability_index" in attrs
    assert attrs["governance.decision"] in {
        "permit", "abstain", "forbid", "sanction", "remediate",
    }


def test_otel_attributes_include_six_tex_axes(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    verdict = wired_engine.evaluate(_propose(now))
    attrs = verdict_to_otel_attributes(verdict)
    for axis_key in (
        "tex.axis.contract_violation_severity",
        "tex.axis.governance_graph_legality",
        "tex.axis.causal_attribution_confidence",
        "tex.axis.drift_delta",
        "tex.axis.systemic_risk_under_event",
        "tex.axis.bounded_compromise_score",
    ):
        assert axis_key in attrs
        assert isinstance(attrs[axis_key], float)


def test_otel_attributes_have_schema_version(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    verdict = wired_engine.evaluate(_propose(now))
    attrs = verdict_to_otel_attributes(verdict)
    assert attrs["tex.governance.schema_version"] == GAAT_SPAN_SCHEMA_VERSION


def test_otel_attributes_merge_additional(
    wired_engine: EcosystemEngine, now: datetime,
) -> None:
    """Additional caller-supplied attrs are merged in."""
    verdict = wired_engine.evaluate(_propose(now))
    attrs = verdict_to_otel_attributes(
        verdict, additional={"tenant.id": "acme", "request.id": "req_123"},
    )
    assert attrs["tenant.id"] == "acme"
    assert attrs["request.id"] == "req_123"


def test_gaat_action_table_complete() -> None:
    """Every L0..L4 level has an action mapping per GAAT §III.A Table I."""
    for level in GraduatedEnforcementLevel:
        assert level.value in GAAT_ACTION_TABLE
    assert GAAT_ACTION_TABLE["L0_allow"] == "ALLOW"
    assert GAAT_ACTION_TABLE["L4_quarantine"] == "QUARANTINE"
