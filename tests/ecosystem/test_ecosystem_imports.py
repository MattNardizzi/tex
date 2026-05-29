"""
Smoke tests proving every ecosystem-layer package is importable and stubbed.
"""

from __future__ import annotations

import importlib

import pytest


ECOSYSTEM_PACKAGES: tuple[str, ...] = (
    # ecosystem core
    "tex.ecosystem",
    "tex.ecosystem.engine",
    "tex.ecosystem.proposed_event",
    "tex.ecosystem.verdict",
    "tex.ecosystem.state",
    # ontology
    "tex.ontology",
    "tex.ontology.entity_types",
    "tex.ontology.event_types",
    "tex.ontology.validator",
    "tex.ontology.airo",
    "tex.ontology.role_ontology",
    "tex.ontology.interaction_ontology",
    "tex.ontology.governance_ontology",
    # graph
    "tex.graph",
    "tex.graph.temporal_kg",
    "tex.graph.projection",
    "tex.graph.query",
    # events
    "tex.events",
    "tex.events.event",
    "tex.events.ledger",
    "tex.events.crypto_provenance",
    # causal
    "tex.causal",
    "tex.causal.chief",
    "tex.causal.arm",
    "tex.causal.counterfactual",
    # institutional
    "tex.institutional",
    "tex.institutional.governance_graph",
    "tex.institutional.oracle",
    "tex.institutional.controller",
    "tex.institutional.sanctions",
    "tex.institutional.governance_log",
    # drift
    "tex.drift",
    "tex.drift.change_point",
    "tex.drift.emergent_norm",
    "tex.drift.signal_registry",
    # intervention
    "tex.intervention",
    "tex.intervention.engine",
    "tex.intervention.bounded_compromise",
    "tex.intervention.kinds",
    "tex.intervention.restorative",
    # contracts
    "tex.contracts",
    "tex.contracts.contract",
    "tex.contracts.runtime_enforcement",
    "tex.contracts.violation",
    # systemic
    "tex.systemic",
    "tex.systemic.risk_evaluator",
    "tex.systemic.digital_twin",
    "tex.systemic.cascade_predictor",
    # config
    "tex.ecosystem_config",
)


@pytest.mark.parametrize("module_name", ECOSYSTEM_PACKAGES)
def test_module_importable(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert module is not None


def test_ecosystem_flags_consistent() -> None:
    from tex.ecosystem_config import EcosystemFlags
    flags = EcosystemFlags.from_env()
    assert isinstance(flags.any_enabled(), bool)


def test_verdict_kinds_extend_action_verdict() -> None:
    """Ecosystem verdict adds SANCTION + REMEDIATE on top of PERMIT/ABSTAIN/FORBID."""
    from tex.ecosystem.verdict import EcosystemVerdictKind
    kinds = {k.value for k in EcosystemVerdictKind}
    assert {"permit", "abstain", "forbid", "sanction", "remediate"} == kinds


def test_event_kinds_cover_taxonomy() -> None:
    """Event taxonomy covers action, capability, policy, governance, lifecycle, drift, boundary."""
    from tex.ontology.event_types import EventKind
    kinds = {k.value for k in EventKind}
    # Sample assertions across taxonomy categories
    assert "agent_invokes_tool" in kinds
    assert "capability_granted" in kinds
    assert "denial_event" in kinds
    assert "governance_graph_transition" in kinds
    assert "change_point_detected" in kinds
    assert "outbound_content_emitted" in kinds


def test_intervention_kinds_present() -> None:
    from tex.intervention.kinds import InterventionKind
    kinds = {k.value for k in InterventionKind}
    assert "capability_revoke" in kinds
    assert "trust_score_reduce" in kinds
    assert "human_approval_gate" in kinds
    assert "restorative_path" in kinds
