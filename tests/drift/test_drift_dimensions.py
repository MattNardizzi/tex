"""
Tests for the Rath 2026 three-dimension drift taxonomy
(arxiv 2601.04170 §3, Thread 7.1 extension to evaluate_drift).

Coverage
--------
* DriftEvaluation exposes semantic_drift / coordination_drift /
  behavioral_drift / dominant_dimension fields.
* drift_delta = max(three dimensions).
* tool_call events trigger semantic_drift (Rath: intent surface).
* agent-to-agent messages trigger coordination_drift.
* denial events trigger behavioral_drift.
* dominant_dimension reflects which axis carried the highest score.
* Backward compatibility: existing code reading only drift_delta works.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.drift.signal_registry import (
    DriftEvaluation,
    DriftSignalRegistry,
    _SIGNAL_TO_DIMENSION,
    evaluate_drift,
)
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def state(now: datetime) -> EcosystemState:
    return EcosystemState(
        snapshot_at=now,
        state_hash="0" * 64,
        active_agent_ids=("agent_1",),
        active_tool_ids=("tool_x",),
        active_capability_ids=(),
        active_governance_graph_id="g0",
    )


# ----- field surface --------------------------------------------------------


def test_drift_evaluation_has_three_dimension_fields() -> None:
    """Verify the Rath 2026 taxonomy fields exist on DriftEvaluation."""
    ev = DriftEvaluation(
        drift_delta=0.5,
        semantic_drift=0.5,
        coordination_drift=0.2,
        behavioral_drift=0.1,
        signals_evaluated=(),
        change_point_detected=False,
        anytime_valid_p_value=0.5,
        dominant_lambda=0.0,
        dominant_dimension="semantic",
    )
    assert ev.semantic_drift == 0.5
    assert ev.coordination_drift == 0.2
    assert ev.behavioral_drift == 0.1
    assert ev.dominant_dimension == "semantic"


def test_drift_evaluation_default_dimension_fields() -> None:
    """Backward compatibility: callers that don't set the new fields
    get sensible defaults."""
    ev = DriftEvaluation(
        drift_delta=0.0,
        signals_evaluated=(),
        change_point_detected=False,
        anytime_valid_p_value=1.0,
        dominant_lambda=0.0,
    )
    assert ev.semantic_drift == 0.0
    assert ev.coordination_drift == 0.0
    assert ev.behavioral_drift == 0.0
    assert ev.dominant_dimension is None


def test_signal_to_dimension_map_covers_seven_defaults() -> None:
    """Every default signal except the auxiliary ones has a Rath
    dimension assignment. (capability_used is the alias of
    tool_call_rate_per_agent and isn't a default signal itself.)"""
    assert "tool_call_rate_per_agent" in _SIGNAL_TO_DIMENSION
    assert "cross_agent_message_rate" in _SIGNAL_TO_DIMENSION
    assert "capability_grant_rate" in _SIGNAL_TO_DIMENSION
    assert "denial_rate_per_agent" in _SIGNAL_TO_DIMENSION
    assert "outbound_content_volume_per_tenant" in _SIGNAL_TO_DIMENSION
    assert "average_path_depth" in _SIGNAL_TO_DIMENSION
    assert "average_compromise_score" in _SIGNAL_TO_DIMENSION
    # All assigned to one of the three Rath axes.
    for dim in _SIGNAL_TO_DIMENSION.values():
        assert dim in ("semantic", "coordination", "behavioral")


# ----- end-to-end dimension routing ----------------------------------------


def test_tool_call_event_triggers_semantic_drift(
    state: EcosystemState, now: datetime,
) -> None:
    """Per the Rath taxonomy, tool-call rate is an intent-surface
    signal → semantic drift dimension."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="agent_invokes_tool",
        actor_entity_id="agent_1",
        target_entity_id="tool_x",
        payload={},
        proposed_at=now,
    )
    # Drive 15 events to accumulate evidence
    for _ in range(15):
        result = evaluate_drift(
            proposed=proposed, state_before=state, registry=reg,
        )
    assert result.semantic_drift > 0.0
    assert result.dominant_dimension == "semantic"


def test_cross_agent_message_triggers_coordination_drift(
    state: EcosystemState, now: datetime,
) -> None:
    """Cross-agent messages are a coordination signal in the Rath
    taxonomy."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="agent_to_agent_message",
        actor_entity_id="agent_1",
        target_entity_id="agent_2",
        payload={},
        proposed_at=now,
    )
    for _ in range(15):
        result = evaluate_drift(
            proposed=proposed, state_before=state, registry=reg,
        )
    assert result.coordination_drift > 0.0
    assert result.dominant_dimension == "coordination"


def test_denial_event_triggers_behavioral_drift(
    state: EcosystemState, now: datetime,
) -> None:
    """Denial events signal an agent in a frustration/exploration
    regime → behavioral drift dimension (Rath unintended strategy)."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="denial_event",
        actor_entity_id="agent_1",
        payload={},
        proposed_at=now,
    )
    for _ in range(15):
        result = evaluate_drift(
            proposed=proposed, state_before=state, registry=reg,
        )
    assert result.behavioral_drift > 0.0
    assert result.dominant_dimension == "behavioral"


def test_drift_delta_equals_max_of_three_dimensions(
    state: EcosystemState, now: datetime,
) -> None:
    """drift_delta = max(semantic, coordination, behavioral) by design."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="agent_invokes_tool",
        actor_entity_id="agent_1",
        target_entity_id="tool_x",
        payload={},
        proposed_at=now,
    )
    for _ in range(10):
        r = evaluate_drift(
            proposed=proposed, state_before=state, registry=reg,
        )
    assert r.drift_delta == max(
        r.semantic_drift, r.coordination_drift, r.behavioral_drift,
    )


def test_dimension_score_clamped_to_unit_interval(
    state: EcosystemState, now: datetime,
) -> None:
    """All three dimension scores are bounded in [0, 1]."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="agent_invokes_tool",
        actor_entity_id="agent_1",
        target_entity_id="tool_x",
        payload={},
        proposed_at=now,
    )
    for _ in range(50):
        r = evaluate_drift(
            proposed=proposed, state_before=state, registry=reg,
        )
        assert 0.0 <= r.semantic_drift <= 1.0
        assert 0.0 <= r.coordination_drift <= 1.0
        assert 0.0 <= r.behavioral_drift <= 1.0


def test_no_drift_means_none_dimension(
    state: EcosystemState, now: datetime,
) -> None:
    """Irrelevant event kind → no signal probed → dominant_dimension=None."""
    reg = DriftSignalRegistry(seed_defaults=True)
    proposed = ProposedEvent(
        event_kind="not_in_probe_map",
        actor_entity_id="agent_1",
        payload={},
        proposed_at=now,
    )
    r = evaluate_drift(
        proposed=proposed, state_before=state, registry=reg,
    )
    assert r.dominant_dimension is None
    assert r.semantic_drift == 0.0
    assert r.coordination_drift == 0.0
    assert r.behavioral_drift == 0.0
