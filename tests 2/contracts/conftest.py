"""
Shared fixtures and factories for tex.contracts tests.

Factories live here (rather than the global tests/factories.py) so the
contracts test module is self-contained and easy to grep — every helper
needed to build a EcosystemState, a ProposedEvent, or a ledger pair is
in this one file.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Mapping

import pytest

# Import tex.contracts first to satisfy the tex.events ↔ tex.ecosystem
# circular-import workaround — same pattern used by
# tests/drift/test_ledger_emission.py (which imports tex.drift first).
import tex.contracts  # noqa: F401  # side-effect import for module load order

from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger


@pytest.fixture(autouse=True)
def _silence_telemetry() -> None:
    """Don't pollute test output with the structured logs."""
    logging.getLogger("tex").setLevel(logging.CRITICAL)


def make_state(
    *,
    state_hash: str = "0" * 64,
    active_agents: tuple[str, ...] = ("alice", "bob"),
    active_tools: tuple[str, ...] = ("read", "write", "delete"),
    active_capabilities: tuple[str, ...] = ("cap_read",),
    drift_signals: dict[str, float] | None = None,
    compromise_ratio: float = 0.0,
    governance_graph_id: str = "policy-v1",
) -> EcosystemState:
    """Build a frozen EcosystemState snapshot for a test."""
    return EcosystemState(
        snapshot_at=datetime.now(UTC),
        state_hash=state_hash,
        active_agent_ids=active_agents,
        active_tool_ids=active_tools,
        active_capability_ids=active_capabilities,
        active_governance_graph_id=governance_graph_id,
        aggregate_drift_signals=dict(drift_signals or {}),
        sliding_window_compromise_ratio=compromise_ratio,
    )


def make_event(
    *,
    kind: str = "agent_emits_output",
    actor: str = "alice",
    target: str | None = None,
    payload: Mapping[str, Any] | None = None,
    upstream: tuple[str, ...] = (),
) -> ProposedEvent:
    """Build a ProposedEvent for a test."""
    return ProposedEvent(
        event_kind=kind,
        actor_entity_id=actor,
        target_entity_id=target,
        payload=dict(payload or {}),
        proposed_at=datetime.now(UTC),
        upstream_event_ids=upstream,
    )


def ledger_with_provenance() -> tuple[InMemoryLedger, CryptoProvenance]:
    """Mirror the helper used in tests/drift/test_ledger_emission.py."""
    provider = EcdsaP256Provider()
    keypair = provider.generate_keypair("contracts-test-key")
    provenance = CryptoProvenance(signing_key=keypair, signing_provider=provider)
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key, signing_provider=provider
    )
    return ledger, provenance
