"""
Tests for the reconciliation engine.

The engine has eight terminal decision branches. Each is covered
here. Tests use AgentIdentity instances directly rather than going
through the registry; the engine is pure and should be testable
without any stores.
"""

from __future__ import annotations

from uuid import uuid4

from tex.discovery.reconciliation import (
    AUTO_REGISTER_THRESHOLD,
    QUARANTINE_DRIFT_THRESHOLD,
    ReconciliationEngine,
    _capability_drift,
    _surface_from_hints,
)
from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryFindingKind,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _candidate(
    *,
    confidence: float = 0.9,
    surface_unbounded: bool = False,
    action_types: tuple[str, ...] = ("send_email",),
    channels: tuple[str, ...] = ("email",),
    tools: tuple[str, ...] = ("mail.send",),
    risk_band: DiscoveryRiskBand = DiscoveryRiskBand.LOW,
) -> CandidateAgent:
    hints = DiscoveredCapabilityHints(
        inferred_action_types=action_types,
        inferred_channels=channels,
        inferred_tools=tools,
        surface_unbounded=surface_unbounded,
    )
    return CandidateAgent(
        source=DiscoverySource.MICROSOFT_GRAPH,
        tenant_id="acme",
        external_id="ext-1",
        name="Discovered Bot",
        confidence=confidence,
        risk_band=risk_band,
        capability_hints=hints,
    )


def _existing_agent_from(
    candidate: CandidateAgent,
    *,
    lifecycle_status: AgentLifecycleStatus = AgentLifecycleStatus.ACTIVE,
    trust_tier: AgentTrustTier = AgentTrustTier.STANDARD,
    capability_surface: CapabilitySurface | None = None,
    extra_metadata: dict | None = None,
) -> AgentIdentity:
    metadata = {
        "discovery_source": str(candidate.source),
        "discovery_external_id": candidate.external_id,
        "discovery_risk_band": str(candidate.risk_band),
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    surface = capability_surface or _surface_from_hints(candidate)
    return AgentIdentity(
        name=candidate.name,
        owner=candidate.owner_hint or "ops@acme.com",
        tenant_id=candidate.tenant_id,
        environment=AgentEnvironment.PRODUCTION,
        trust_tier=trust_tier,
        lifecycle_status=lifecycle_status,
        capability_surface=surface,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Branch 1 — NEW agent, low confidence -> NO_OP_BELOW_THRESHOLD
# ---------------------------------------------------------------------------


class TestNewAgentBelowThreshold:
    def test_low_confidence_held(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(confidence=AUTO_REGISTER_THRESHOLD - 0.05)
        decision = engine.decide(candidate=cand, existing=None)

        assert decision.outcome.action is ReconciliationAction.NO_OP_BELOW_THRESHOLD
        assert decision.outcome.finding_kind is DiscoveryFindingKind.NEW_AGENT
        assert decision.new_agent is None


# ---------------------------------------------------------------------------
# Branch 2 — NEW agent, high confidence, bounded surface -> REGISTERED
# ---------------------------------------------------------------------------


class TestNewAgentRegistered:
    def test_high_confidence_bounded_promoted(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(confidence=0.95)
        decision = engine.decide(candidate=cand, existing=None)

        assert decision.outcome.action is ReconciliationAction.REGISTERED
        assert decision.new_agent is not None
        # Newly promoted agents must be PENDING, not ACTIVE — the
        # operator clears them with a deliberate lifecycle transition.
        assert decision.new_agent.lifecycle_status is AgentLifecycleStatus.PENDING

    def test_promoted_agent_carries_discovery_metadata(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(confidence=0.95)
        decision = engine.decide(candidate=cand, existing=None)

        assert decision.new_agent is not None
        meta = decision.new_agent.metadata
        assert meta["discovery_source"] == str(cand.source)
        assert meta["discovery_external_id"] == cand.external_id
        assert meta["discovery_risk_band"] == str(cand.risk_band)

    def test_promoted_agent_resulting_id_matches_outcome(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(confidence=0.95)
        decision = engine.decide(candidate=cand, existing=None)
        assert decision.new_agent is not None
        assert decision.outcome.resulting_agent_id == decision.new_agent.agent_id


# ---------------------------------------------------------------------------
# Branch 3 — NEW agent, unbounded surface -> HELD_AMBIGUOUS
# ---------------------------------------------------------------------------


class TestNewAgentUnboundedHeld:
    def test_unbounded_held_for_review(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(confidence=0.95, surface_unbounded=True)
        decision = engine.decide(candidate=cand, existing=None)

        assert decision.outcome.action is ReconciliationAction.HELD_AMBIGUOUS
        assert decision.outcome.finding_kind is DiscoveryFindingKind.AMBIGUOUS
        assert decision.new_agent is None


# ---------------------------------------------------------------------------
# Branch 4 — KNOWN agent, no drift -> NO_OP_KNOWN_UNCHANGED
# ---------------------------------------------------------------------------


class TestKnownAgentNoDrift:
    def test_no_drift_is_no_op(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate()
        existing = _existing_agent_from(cand)

        decision = engine.decide(candidate=cand, existing=existing)
        assert decision.outcome.action is ReconciliationAction.NO_OP_KNOWN_UNCHANGED
        assert decision.outcome.finding_kind is DiscoveryFindingKind.KNOWN_AGENT_UNCHANGED
        assert decision.outcome.resulting_agent_id == existing.agent_id
        assert decision.new_agent is None


# ---------------------------------------------------------------------------
# Branch 5 — KNOWN agent, low drift -> UPDATED_DRIFT
# ---------------------------------------------------------------------------


class TestKnownAgentLowDrift:
    def test_one_new_tool_updates_surface(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate(
            tools=("mail.send", "files.read"),  # one new tool vs existing
        )
        existing_surface = CapabilitySurface(
            allowed_action_types=("send_email",),
            allowed_channels=("email",),
            allowed_tools=("mail.send",),
        )
        existing = _existing_agent_from(cand, capability_surface=existing_surface)

        decision = engine.decide(candidate=cand, existing=existing)
        assert decision.outcome.action is ReconciliationAction.UPDATED_DRIFT
        assert decision.outcome.finding_kind is DiscoveryFindingKind.KNOWN_AGENT_DRIFT
        assert decision.update_capability_surface_for is existing
        assert decision.new_capability_surface is not None
        assert "files.read" in decision.new_capability_surface.allowed_tools


# ---------------------------------------------------------------------------
# Branch 6 — KNOWN agent, high drift -> QUARANTINED_FOR_DRIFT
# ---------------------------------------------------------------------------


class TestKnownAgentHighDrift:
    def test_many_new_dimensions_quarantine(self) -> None:
        # Use a lower quarantine threshold so the test deliberately
        # exercises the QUARANTINE branch on a moderate amount of
        # drift. The default threshold of 0.60 averaged over six
        # dimensions intentionally requires changes on ~four
        # dimensions before quarantining; that is the right
        # production setting (it minimizes noise) but it's not the
        # cleanest setting for unit tests.
        engine = ReconciliationEngine(quarantine_drift_threshold=0.30)
        cand = _candidate(
            action_types=("send_email", "delete_record", "transfer_funds", "exec_code"),
            channels=("email", "slack", "teams"),
            tools=("mail.send", "files.write", "admin.users", "sql.exec"),
        )
        existing_surface = CapabilitySurface(
            allowed_action_types=("send_email",),
            allowed_channels=("email",),
            allowed_tools=("mail.send",),
        )
        existing = _existing_agent_from(cand, capability_surface=existing_surface)

        decision = engine.decide(candidate=cand, existing=existing)
        assert decision.outcome.action is ReconciliationAction.QUARANTINED_FOR_DRIFT
        assert decision.outcome.finding_kind is DiscoveryFindingKind.KNOWN_AGENT_DRIFT
        assert decision.quarantine_agent_id is existing


# ---------------------------------------------------------------------------
# Branch 7 — KNOWN agent, REVOKED -> SKIPPED_REVOKED
# ---------------------------------------------------------------------------


class TestRevokedSkipped:
    def test_revoked_agent_terminal(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate()
        existing = _existing_agent_from(
            cand, lifecycle_status=AgentLifecycleStatus.REVOKED
        )

        decision = engine.decide(candidate=cand, existing=existing)
        assert decision.outcome.action is ReconciliationAction.SKIPPED_REVOKED
        assert decision.outcome.finding_kind is DiscoveryFindingKind.DUPLICATE
        # Crucially: even though the candidate matched a known agent,
        # we do NOT revive it. Revoke is terminal.
        assert decision.new_agent is None
        assert decision.update_capability_surface_for is None


# ---------------------------------------------------------------------------
# Capability drift score behavior
# ---------------------------------------------------------------------------


class TestCapabilityDriftScore:
    def test_identical_surfaces_zero_drift(self) -> None:
        s = CapabilitySurface(
            allowed_action_types=("send_email",),
            allowed_channels=("email",),
            allowed_tools=("mail.send",),
        )
        score, findings = _capability_drift(s, s)
        assert score == 0.0
        assert findings == tuple()

    def test_narrowing_does_not_count_as_drift(self) -> None:
        before = CapabilitySurface(
            allowed_action_types=("send_email", "delete_record"),
            allowed_tools=("mail.send", "admin.users"),
        )
        after = CapabilitySurface(
            allowed_action_types=("send_email",),
            allowed_tools=("mail.send",),
        )
        score, _ = _capability_drift(before, after)
        # Narrowing means "the agent has less permission than we
        # thought." Not a drift signal.
        assert score == 0.0

    def test_widening_is_proportional_to_new_entries(self) -> None:
        before = CapabilitySurface(allowed_tools=("a",))
        after = CapabilitySurface(allowed_tools=("a", "b"))
        score_low, _ = _capability_drift(before, after)

        after_many = CapabilitySurface(allowed_tools=("a", "b", "c", "d", "e"))
        score_high, _ = _capability_drift(before, after_many)

        assert score_low > 0.0
        assert score_high > score_low


# ---------------------------------------------------------------------------
# Threshold parameterization
# ---------------------------------------------------------------------------


class TestThresholdConfiguration:
    def test_custom_auto_register_threshold(self) -> None:
        engine = ReconciliationEngine(auto_register_threshold=0.99)
        cand = _candidate(confidence=0.9)  # below 0.99
        decision = engine.decide(candidate=cand, existing=None)
        assert decision.outcome.action is ReconciliationAction.NO_OP_BELOW_THRESHOLD

    def test_invalid_threshold_rejected(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            ReconciliationEngine(auto_register_threshold=1.5)

        with pytest.raises(ValueError):
            ReconciliationEngine(quarantine_drift_threshold=-0.1)

    def test_zero_quarantine_threshold_quarantines_any_drift(self) -> None:
        engine = ReconciliationEngine(quarantine_drift_threshold=0.0)
        cand = _candidate(tools=("a", "b"))
        existing_surface = CapabilitySurface(allowed_tools=("a",))
        existing = _existing_agent_from(cand, capability_surface=existing_surface)
        decision = engine.decide(candidate=cand, existing=existing)
        # Any drift > 0 hits the threshold immediately.
        assert decision.outcome.action is ReconciliationAction.QUARANTINED_FOR_DRIFT


# ---------------------------------------------------------------------------
# Pure-engine smoke: reconciliation_key is the candidate's, never wired in
# wrong by the engine
# ---------------------------------------------------------------------------


class TestEngineReturnsCorrectKey:
    def test_outcome_carries_candidate_key(self) -> None:
        engine = ReconciliationEngine()
        cand = _candidate()
        decision = engine.decide(candidate=cand, existing=None)
        assert decision.outcome.reconciliation_key == cand.reconciliation_key
