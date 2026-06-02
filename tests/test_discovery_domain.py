"""
Tests for the discovery domain models.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from tex.domain.agent import AgentEnvironment, AgentTrustTier
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryFindingKind,
    DiscoveryLedgerEntry,
    DiscoveryRiskBand,
    DiscoveryScanRun,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)


class TestDiscoveryRiskBand:
    def test_low_band_proposes_standard_trust(self) -> None:
        assert (
            DiscoveryRiskBand.LOW.suggested_trust_tier is AgentTrustTier.STANDARD
        )

    def test_higher_bands_propose_unverified(self) -> None:
        for band in (
            DiscoveryRiskBand.MEDIUM,
            DiscoveryRiskBand.HIGH,
            DiscoveryRiskBand.CRITICAL,
        ):
            assert band.suggested_trust_tier is AgentTrustTier.UNVERIFIED


class TestDiscoveredCapabilityHints:
    def test_string_tuples_normalized_lowercase_and_deduped(self) -> None:
        hints = DiscoveredCapabilityHints(
            inferred_action_types=("send_email", "Send_Email", "DELETE_RECORD"),
            inferred_channels=("Email", "email", "slack"),
        )
        assert hints.inferred_action_types == ("delete_record", "send_email")
        assert hints.inferred_channels == ("email", "slack")

    def test_default_is_neutral(self) -> None:
        hints = DiscoveredCapabilityHints()
        assert hints.inferred_action_types == tuple()
        assert hints.surface_unbounded is False

    def test_unbounded_is_explicit(self) -> None:
        hints = DiscoveredCapabilityHints(surface_unbounded=True)
        assert hints.surface_unbounded is True

    def test_string_input_for_tuple_field_rejected(self) -> None:
        with pytest.raises((ValidationError, TypeError)):
            DiscoveredCapabilityHints(inferred_action_types="send_email")


class TestCandidateAgent:
    def _make(self, **overrides) -> CandidateAgent:
        defaults = dict(
            source=DiscoverySource.MICROSOFT_GRAPH,
            tenant_id="acme",
            external_id="abc-123",
            name="SDR Bot",
            confidence=0.9,
        )
        defaults.update(overrides)
        return CandidateAgent(**defaults)

    def test_reconciliation_key_is_stable(self) -> None:
        c = self._make()
        assert c.reconciliation_key == "microsoft_graph:acme:abc-123"

    def test_reconciliation_key_lowercases_external_id(self) -> None:
        c = self._make(external_id="ABC-123")
        assert c.reconciliation_key == "microsoft_graph:acme:abc-123"

    def test_tenant_id_lowercased_and_stripped(self) -> None:
        c = self._make(tenant_id="  ACME  ")
        assert c.tenant_id == "acme"

    def test_blank_external_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._make(external_id="   ")

    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._make(name="")

    def test_confidence_must_be_in_zero_one(self) -> None:
        with pytest.raises(ValidationError):
            self._make(confidence=1.2)
        with pytest.raises(ValidationError):
            self._make(confidence=-0.01)

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._make(discovered_at=datetime.now())

    def test_last_seen_after_discovered_normalized_down(self) -> None:
        future = datetime.now(UTC) + timedelta(days=1)
        c = self._make(last_seen_active_at=future)
        # Validator clamps last_seen_active_at to discovered_at when in the
        # future, so audit invariants hold.
        assert c.last_seen_active_at == c.discovered_at

    def test_environment_default_is_production(self) -> None:
        c = self._make()
        assert c.environment_hint is AgentEnvironment.PRODUCTION

    def test_evidence_round_trips(self) -> None:
        evidence = {"scopes": ["mail.send"], "kind": "declarativeagent"}
        c = self._make(evidence=evidence)
        assert c.evidence == evidence

    def test_tags_normalized(self) -> None:
        c = self._make(tags=["Microsoft", "microsoft", "  Copilot "])
        assert c.tags == ("copilot", "microsoft")


class TestReconciliationOutcome:
    def test_empty_findings_default(self) -> None:
        outcome = ReconciliationOutcome(
            candidate_id=_uuid(),
            reconciliation_key="microsoft_graph:acme:abc",
            finding_kind=DiscoveryFindingKind.NEW_AGENT,
            action=ReconciliationAction.NO_OP_BELOW_THRESHOLD,
            confidence=0.5,
        )
        assert outcome.findings == tuple()
        assert outcome.resulting_agent_id is None

    def test_findings_normalized(self) -> None:
        outcome = ReconciliationOutcome(
            candidate_id=_uuid(),
            reconciliation_key="microsoft_graph:acme:abc",
            finding_kind=DiscoveryFindingKind.NEW_AGENT,
            action=ReconciliationAction.REGISTERED,
            confidence=0.9,
            findings=("auto-promoted", "  ", "extra detail "),
        )
        assert outcome.findings == ("auto-promoted", "extra detail")


class TestDiscoveryScanRun:
    def test_completed_must_be_after_started(self) -> None:
        started = datetime.now(UTC)
        with pytest.raises(ValidationError):
            DiscoveryScanRun(
                started_at=started,
                completed_at=started - timedelta(seconds=1),
            )

    def test_duration_seconds_computed(self) -> None:
        started = datetime.now(UTC)
        completed = started + timedelta(seconds=1.5)
        run = DiscoveryScanRun(started_at=started, completed_at=completed)
        assert run.duration_seconds == pytest.approx(1.5)


class TestDiscoveryLedgerEntry:
    def test_minimal_entry_constructible(self) -> None:
        cand = CandidateAgent(
            source=DiscoverySource.MICROSOFT_GRAPH,
            tenant_id="acme",
            external_id="abc",
            name="Bot",
            confidence=0.9,
        )
        outcome = ReconciliationOutcome(
            candidate_id=cand.candidate_id,
            reconciliation_key=cand.reconciliation_key,
            finding_kind=DiscoveryFindingKind.NEW_AGENT,
            action=ReconciliationAction.NO_OP_BELOW_THRESHOLD,
            confidence=0.5,
        )
        entry = DiscoveryLedgerEntry(
            sequence=0,
            candidate=cand,
            outcome=outcome,
            payload_sha256="a" * 64,
            previous_hash=None,
            record_hash="b" * 64,
        )
        assert entry.previous_hash is None
        assert entry.sequence == 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _uuid():
    from uuid import uuid4

    return uuid4()
