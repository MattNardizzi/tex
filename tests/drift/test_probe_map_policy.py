"""
Tests for the declarative ProbeMapPolicy (Thread 7.1).

Replaces the hardcoded probe map with a layered exact/substring
classifier inspired by GAAT's OPA Rego rules and RiskGate's
extensible classifier interface.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.drift.signal_registry import (
    DEFAULT_PROBE_MAP_POLICY,
    ProbeMapPolicy,
    SIGNAL_DENIAL_RATE_PER_AGENT,
    SIGNAL_TOOL_CALL_RATE_PER_AGENT,
    _probe_signals_for,
)
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState


@pytest.fixture
def state() -> EcosystemState:
    return EcosystemState(
        snapshot_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        state_hash="0" * 64,
        active_agent_ids=("a",),
        active_tool_ids=("t",),
        active_capability_ids=(),
        active_governance_graph_id="g0",
    )


def _propose(event_kind: str) -> ProposedEvent:
    return ProposedEvent(
        event_kind=event_kind,
        actor_entity_id="a",
        payload={},
        proposed_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
    )


# ----- ProbeMapPolicy.classify ---------------------------------------------


def test_classify_exact_match() -> None:
    assert (
        DEFAULT_PROBE_MAP_POLICY.classify("agent_invokes_tool")
        == SIGNAL_TOOL_CALL_RATE_PER_AGENT
    )
    assert (
        DEFAULT_PROBE_MAP_POLICY.classify("denial_event")
        == SIGNAL_DENIAL_RATE_PER_AGENT
    )


def test_classify_substring_fallback() -> None:
    """Event kinds with no exact match fall back to substring rules."""
    # Novel name with substring "tool_call"
    assert (
        DEFAULT_PROBE_MAP_POLICY.classify("vendor_x.tool_call.v2")
        == SIGNAL_TOOL_CALL_RATE_PER_AGENT
    )
    # Substring "denial"
    assert (
        DEFAULT_PROBE_MAP_POLICY.classify("custom.denial.event")
        == SIGNAL_DENIAL_RATE_PER_AGENT
    )


def test_classify_no_match_returns_none() -> None:
    assert DEFAULT_PROBE_MAP_POLICY.classify("totally_unrelated_thing") is None


def test_classify_case_insensitive_substring() -> None:
    """Substring match is case-insensitive."""
    assert (
        DEFAULT_PROBE_MAP_POLICY.classify("Agent.TOOL_CALL.Outbound")
        is not None
    )


# ----- custom policy overrides ---------------------------------------------


def test_custom_policy_overrides_default(state: EcosystemState) -> None:
    """Operators can register custom event kinds without touching code."""
    custom = ProbeMapPolicy(
        exact_rules=(
            ("vendor.x.weirdo", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ),
        substring_rules=(),
    )
    proposed = _propose("vendor.x.weirdo")
    result = _probe_signals_for(proposed, state, custom)
    assert SIGNAL_TOOL_CALL_RATE_PER_AGENT in result


def test_custom_policy_no_match(state: EcosystemState) -> None:
    custom = ProbeMapPolicy(
        exact_rules=(("only.this.one", SIGNAL_DENIAL_RATE_PER_AGENT),),
        substring_rules=(),
    )
    proposed = _propose("agent_invokes_tool")  # not in custom
    result = _probe_signals_for(proposed, state, custom)
    assert result == {}


def test_default_policy_used_when_none(state: EcosystemState) -> None:
    """``_probe_signals_for(..., policy=None)`` uses default."""
    proposed = _propose("agent_invokes_tool")
    result = _probe_signals_for(proposed, state, None)
    assert SIGNAL_TOOL_CALL_RATE_PER_AGENT in result


def test_policy_is_frozen() -> None:
    """ProbeMapPolicy is hashable/immutable per dataclass(frozen=True)."""
    p = ProbeMapPolicy(
        exact_rules=(("x", "y"),), substring_rules=(),
    )
    # Frozen dataclasses raise on attribute set.
    with pytest.raises((AttributeError, Exception)):
        p.exact_rules = ()  # type: ignore[misc]


def test_substring_rules_ordered_first_match_wins() -> None:
    """When multiple substring rules match, the first wins."""
    policy = ProbeMapPolicy(
        exact_rules=(),
        substring_rules=(
            ("foo", "signal_a"),
            ("foobar", "signal_b"),  # would also match "foobar" event
        ),
    )
    # "foobar" contains both "foo" and "foobar"; first rule wins.
    assert policy.classify("foobar_event") == "signal_a"
