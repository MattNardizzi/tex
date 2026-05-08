"""
Tests for tex.ecosystem.engine — EcosystemEngine evaluate() and attest_state().

Coverage
--------
* Disabled engine: inert PERMIT, no mutation, env-var driven.
* Enabled engine wiring: missing P0 collaborators rejected at construction.
* evaluate() Step 1 — ontology rejection on unknown event_kind / payload schema.
* evaluate() Step 2 — unknown actor in graph rejected.
* evaluate() PERMIT path — ledger append, graph add_event, state hash advances.
* evaluate() determinism — pre-state hash matches projection at proposed_at.
* attest_state() — must be enabled; rejects naive datetimes; rejects inverted
  ranges; produces parseable, signature-verifiable SCITT-shaped envelopes;
  Merkle root advances when events are added; pinned empty-window root.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Iterator

import pytest

from tex.ecosystem._attestation import (
    ATTESTATION_ENVELOPE_TYPE,
    ATTESTATION_PAYLOAD_TYPE,
    parse_envelope,
)
from tex.ecosystem._window import empty_root
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.events._canonical import canonical_json, sha256_hex
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.event import genesis_ledger_hash
from tex.events.ledger import InMemoryLedger
from tex.events._ecdsa_provider import default_signature_provider
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.ontology.entity_types import EntityKind, EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# ---------------------------------------------------------------- fixtures


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def signing_provider():
    """ECDSA-P256 provider; default until ML-DSA-65 lands via Thread 4."""
    return default_signature_provider()


@pytest.fixture
def signing_keypair(signing_provider):
    return signing_provider.generate_keypair("test-key-engine")


@pytest.fixture
def provenance(signing_keypair, signing_provider) -> CryptoProvenance:
    return CryptoProvenance(
        signing_key=signing_keypair, signing_provider=signing_provider
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
    """Register an agent entity so the actor passes step-2 graph check."""
    actor_id = "agent_1"
    graph.add_entity(
        entity_id=actor_id,
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return actor_id


@pytest.fixture
def registered_tool(graph: InMemoryTemporalKG, now: datetime) -> str:
    tool_id = "search_v1"
    graph.add_entity(
        entity_id=tool_id,
        kind="tool",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return tool_id


@pytest.fixture
def engine(
    ontology_validator: OntologyValidator,
    graph: InMemoryTemporalKG,
    projection: StateProjection,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
) -> EcosystemEngine:
    return EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        enabled=True,
    )


@pytest.fixture
def disabled_engine(
    ontology_validator: OntologyValidator,
    graph: InMemoryTemporalKG,
    projection: StateProjection,
    ledger: InMemoryLedger,
    provenance: CryptoProvenance,
) -> EcosystemEngine:
    return EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        enabled=False,
    )


@pytest.fixture
def env_clean() -> Iterator[None]:
    """Save/restore TEX_ECOSYSTEM around tests that mutate it."""
    prior = os.environ.get("TEX_ECOSYSTEM")
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("TEX_ECOSYSTEM", None)
        else:
            os.environ["TEX_ECOSYSTEM"] = prior


def _propose_tool_call(
    *,
    actor: str,
    tool: str,
    when: datetime,
    upstream: tuple[str, ...] = (),
) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=actor,
        target_entity_id=tool,
        payload={"tool_id": tool, "arguments": {"q": "hello"}},
        proposed_at=when,
        upstream_event_ids=upstream,
    )


# ---------------------------------------------------------- disabled engine


def test_disabled_engine_returns_inert_permit_no_mutation(
    disabled_engine: EcosystemEngine,
    graph: InMemoryTemporalKG,
    ledger: InMemoryLedger,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    pre_state_hash = graph.state_hash(now)
    pre_ledger_len = len(ledger)

    verdict = disabled_engine.evaluate(proposed)

    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.ecosystem_state_hash_before == "ecosystem_disabled"
    assert verdict.ecosystem_state_hash_after is None
    assert verdict.evidence_record_id is None
    assert "disabled" in verdict.rationale.lower()
    # No mutation
    assert graph.state_hash(now) == pre_state_hash
    assert len(ledger) == pre_ledger_len


def test_disabled_engine_via_env_var_unset(
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
    env_clean,
) -> None:
    os.environ.pop("TEX_ECOSYSTEM", None)
    eng = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
    )
    assert eng.enabled is False


def test_enabled_engine_via_env_var(
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
    env_clean,
) -> None:
    os.environ["TEX_ECOSYSTEM"] = "1"
    eng = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
    )
    assert eng.enabled is True


def test_enabled_engine_missing_collaborators_raises() -> None:
    with pytest.raises(ValueError, match="missing P0 collaborators"):
        EcosystemEngine(enabled=True)


# ---------------------------------------------------------- evaluate(): step 1


def test_evaluate_unknown_event_kind_forbids(
    engine: EcosystemEngine, registered_actor: str, now: datetime
) -> None:
    bad = ProposedEvent(
        event_kind="not_a_real_kind",
        actor_entity_id=registered_actor,
        payload={},
        proposed_at=now,
    )
    verdict = engine.evaluate(bad)
    assert verdict.kind == EcosystemVerdictKind.FORBID
    assert "ontology" in verdict.rationale
    assert "unknown event_kind" in verdict.rationale
    assert verdict.evidence_record_id is None


def test_evaluate_payload_schema_violation_forbids(
    engine: EcosystemEngine,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    """AGENT_INVOKES_TOOL requires tool_id in the payload."""
    bad = ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=registered_actor,
        target_entity_id=registered_tool,
        payload={"arguments": {}},  # missing tool_id
        proposed_at=now,
    )
    verdict = engine.evaluate(bad)
    assert verdict.kind == EcosystemVerdictKind.FORBID
    assert "ontology" in verdict.rationale


# ---------------------------------------------------------- evaluate(): step 2


def test_evaluate_unknown_actor_in_graph_forbids(
    engine: EcosystemEngine,
    registered_tool: str,
    now: datetime,
) -> None:
    """Step 2 requires the actor be a registered ecosystem entity."""
    proposed = _propose_tool_call(
        actor="ghost_agent",  # never registered in graph
        tool=registered_tool,
        when=now,
    )
    verdict = engine.evaluate(proposed)
    assert verdict.kind == EcosystemVerdictKind.FORBID
    assert "unknown actor" in verdict.rationale
    assert "ghost_agent" in verdict.rationale


# ---------------------------------------------------------- evaluate(): PERMIT


def test_evaluate_permit_appends_to_ledger(
    engine: EcosystemEngine,
    ledger: InMemoryLedger,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    pre_len = len(ledger)

    verdict = engine.evaluate(proposed)

    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.evidence_record_id is not None
    assert len(ledger) == pre_len + 1
    stored = ledger.get(verdict.evidence_record_id)
    assert stored is not None
    assert stored.kind == EventKind.AGENT_INVOKES_TOOL.value
    assert stored.actor_entity_id == registered_actor


def test_evaluate_permit_advances_state_hash(
    engine: EcosystemEngine,
    graph: InMemoryTemporalKG,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    pre_hash = graph.state_hash(now)
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    verdict = engine.evaluate(proposed)
    post_hash = graph.state_hash(now)
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.ecosystem_state_hash_before == pre_hash
    assert verdict.ecosystem_state_hash_after == post_hash
    assert pre_hash != post_hash, "graph mutation must advance state hash"


def test_evaluate_permit_pre_state_hash_matches_projection(
    engine: EcosystemEngine,
    projection: StateProjection,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    """ecosystem_state_hash_before must equal projection.project_at(proposed_at)."""
    pre_state = projection.project_at(now)
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    verdict = engine.evaluate(proposed)
    assert verdict.ecosystem_state_hash_before == pre_state.state_hash


def test_evaluate_permit_axis_scores_neutral_for_p0(
    engine: EcosystemEngine,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    verdict = engine.evaluate(proposed)
    s = verdict.axis_scores
    assert s.contract_violation_severity == 0.0
    assert s.governance_graph_legality == 1.0  # legal under default LTS
    assert s.causal_attribution_confidence == 0.0
    assert s.drift_delta == 0.0
    assert s.systemic_risk_under_event == 0.0
    assert s.bounded_compromise_score == 0.0


def test_evaluate_two_permits_sequence_monotonically(
    engine: EcosystemEngine,
    ledger: InMemoryLedger,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    p1 = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    v1 = engine.evaluate(p1)
    p2 = _propose_tool_call(
        actor=registered_actor,
        tool=registered_tool,
        when=now + timedelta(seconds=1),
    )
    v2 = engine.evaluate(p2)
    assert v1.kind == v2.kind == EcosystemVerdictKind.PERMIT
    e1 = ledger.get(v1.evidence_record_id)
    e2 = ledger.get(v2.evidence_record_id)
    assert e1 is not None and e2 is not None
    assert e2.sequence_number == e1.sequence_number + 1
    assert e2.previous_ledger_hash == e1.record_hash


def test_evaluate_pluggable_signing_provider_carries_through(
    ontology_validator,
    graph,
    projection,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
    signing_provider,
) -> None:
    """Signing the ledger entry must use the wired provider, not a default."""
    fresh_keypair = signing_provider.generate_keypair("alt-engine-key")
    fresh_provenance = CryptoProvenance(
        signing_key=fresh_keypair, signing_provider=signing_provider
    )
    fresh_ledger = InMemoryLedger(
        verifying_public_key=fresh_keypair.public_key,
        signing_provider=signing_provider,
    )
    eng = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=fresh_ledger,
        provenance=fresh_provenance,
        enabled=True,
    )
    proposed = _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    verdict = eng.evaluate(proposed)
    stored = fresh_ledger.get(verdict.evidence_record_id)
    assert stored is not None
    assert stored.pq_signing_key_id == "alt-engine-key"


def test_evaluate_unregistered_target_yields_abstain_with_durable_ledger_record(
    engine: EcosystemEngine,
    ledger: InMemoryLedger,
    registered_actor: str,
    now: datetime,
) -> None:
    """
    The ledger captures the event before the graph does. If the graph
    rejects the edge (e.g., target not registered), the verdict is
    ABSTAIN — operator repairs the graph and replays. The ledger record
    remains durable per AAF §4.2.
    """
    proposed = ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=registered_actor,
        target_entity_id="unregistered_tool_xyz",
        payload={"tool_id": "unregistered_tool_xyz"},
        proposed_at=now,
    )
    pre_len = len(ledger)
    verdict = engine.evaluate(proposed)
    assert verdict.kind == EcosystemVerdictKind.ABSTAIN
    assert verdict.evidence_record_id is not None
    assert "graph rejected" in verdict.rationale
    # Ledger DID grow — record is durable even though graph rejected.
    assert len(ledger) == pre_len + 1


def test_evaluate_ledger_append_failure_yields_forbid(
    engine: EcosystemEngine,
    ledger: InMemoryLedger,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    """
    Engine handles LedgerAppendError gracefully — e.g., upstream_event_id
    references a non-existent ledger entry.
    """
    bad = ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=registered_actor,
        target_entity_id=registered_tool,
        payload={"tool_id": registered_tool},
        proposed_at=now,
        # Skip ontology check by NOT supplying upstream_event_ids that
        # would fail there (validator only checks via injected lookup);
        # supply one that exists in the validator-known sense but not in
        # the ledger. Simplest: a well-formed but never-stored id.
        upstream_event_ids=("evt_does_not_exist",),
    )
    pre_len = len(ledger)
    verdict = engine.evaluate(bad)
    # Validator may catch this first via EventLookup; both outcomes are FORBID,
    # which is what we care about.
    assert verdict.kind == EcosystemVerdictKind.FORBID
    assert len(ledger) == pre_len  # nothing recorded


# --------------------------------------------------------- attest_state() basics


def test_attest_state_disabled_engine_raises(
    disabled_engine: EcosystemEngine,
) -> None:
    with pytest.raises(RuntimeError, match="enabled"):
        disabled_engine.attest_state(
            period_start_iso="2026-05-01T00:00:00+00:00",
            period_end_iso="2026-05-31T23:59:59+00:00",
        )


def test_attest_state_naive_datetime_rejected(
    engine: EcosystemEngine,
) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        engine.attest_state(
            period_start_iso="2026-05-01T00:00:00",
            period_end_iso="2026-05-31T23:59:59+00:00",
        )


def test_attest_state_end_before_start_rejected(
    engine: EcosystemEngine,
) -> None:
    with pytest.raises(ValueError, match=">= period_start_iso"):
        engine.attest_state(
            period_start_iso="2026-05-31T00:00:00+00:00",
            period_end_iso="2026-05-01T00:00:00+00:00",
        )


def test_attest_state_malformed_iso_rejected(
    engine: EcosystemEngine,
) -> None:
    with pytest.raises(ValueError, match="not a valid ISO"):
        engine.attest_state(
            period_start_iso="not a date",
            period_end_iso="2026-05-31T00:00:00+00:00",
        )


# --------------------------------------------------------- attest_state() empty


def test_attest_state_empty_window_pinned_merkle_root(
    engine: EcosystemEngine,
) -> None:
    """Empty window: window_merkle_root == empty_root() (SHA-256 of "")."""
    packet = engine.attest_state(
        period_start_iso="2026-01-01T00:00:00+00:00",
        period_end_iso="2026-01-02T00:00:00+00:00",
    )
    envelope, _, _, _ = parse_envelope(packet)
    payload = envelope["payload"]
    assert payload["window_merkle_root"] == empty_root()
    assert payload["event_count_in_window"] == 0
    assert payload["first_sequence_in_window"] is None
    assert payload["last_sequence_in_window"] is None
    assert payload["ledger_head_sequence"] == 0
    assert payload["ledger_head_record_hash"] == genesis_ledger_hash()


def test_attest_state_envelope_carries_scitt_compatible_fields(
    engine: EcosystemEngine,
) -> None:
    packet = engine.attest_state(
        period_start_iso="2026-01-01T00:00:00+00:00",
        period_end_iso="2026-01-02T00:00:00+00:00",
    )
    envelope, _, _, _ = parse_envelope(packet)
    assert envelope["envelope_type"] == ATTESTATION_ENVELOPE_TYPE
    assert envelope["payload_type"] == ATTESTATION_PAYLOAD_TYPE
    cwt = envelope["cwt_claims"]
    assert cwt["iss"] == "tex"
    assert cwt["sub"] == "ecosystem"
    assert cwt["nbf"].startswith("2026-01-01")
    assert cwt["exp"].startswith("2026-01-02")
    # iat is when we signed; assert it's an ISO string with timezone.
    assert "+" in cwt["iat"] or cwt["iat"].endswith("Z")


# ------------------------------------------------------ attest_state() with events


def test_attest_state_with_events_includes_merkle_root_and_seqs(
    engine: EcosystemEngine,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    # Admit two PERMITted events inside the window.
    engine.evaluate(
        _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    )
    engine.evaluate(
        _propose_tool_call(
            actor=registered_actor,
            tool=registered_tool,
            when=now + timedelta(seconds=5),
        )
    )

    packet = engine.attest_state(
        period_start_iso=(now - timedelta(minutes=1)).isoformat(),
        period_end_iso=(now + timedelta(minutes=1)).isoformat(),
    )
    envelope, _, _, _ = parse_envelope(packet)
    payload = envelope["payload"]
    assert payload["event_count_in_window"] == 2
    assert payload["first_sequence_in_window"] == 1
    assert payload["last_sequence_in_window"] == 2
    assert payload["window_merkle_root"] != empty_root()
    assert payload["ledger_head_sequence"] == 2


def test_attest_state_window_root_changes_when_event_added(
    engine: EcosystemEngine,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    period_start = (now - timedelta(minutes=1)).isoformat()
    period_end = (now + timedelta(minutes=10)).isoformat()

    engine.evaluate(
        _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    )
    packet1 = engine.attest_state(
        period_start_iso=period_start, period_end_iso=period_end
    )
    env1, _, _, _ = parse_envelope(packet1)

    engine.evaluate(
        _propose_tool_call(
            actor=registered_actor,
            tool=registered_tool,
            when=now + timedelta(seconds=2),
        )
    )
    packet2 = engine.attest_state(
        period_start_iso=period_start, period_end_iso=period_end
    )
    env2, _, _, _ = parse_envelope(packet2)

    assert env1["payload"]["window_merkle_root"] != env2["payload"]["window_merkle_root"]
    assert env1["payload"]["state_hash_at_end"] != env2["payload"]["state_hash_at_end"]


# ------------------------------------------------------ attest_state() signature


def test_attest_state_signature_verifies(
    engine: EcosystemEngine,
    signing_keypair,
    signing_provider,
    registered_actor: str,
    registered_tool: str,
    now: datetime,
) -> None:
    engine.evaluate(
        _propose_tool_call(actor=registered_actor, tool=registered_tool, when=now)
    )
    packet = engine.attest_state(
        period_start_iso=(now - timedelta(minutes=1)).isoformat(),
        period_end_iso=(now + timedelta(minutes=1)).isoformat(),
    )
    envelope_dict, signature, key_id, algorithm = parse_envelope(packet)

    assert key_id == signing_keypair.key_id
    assert algorithm == signing_keypair.algorithm.value

    # Reconstruct the canonical bytes and verify against the public key.
    envelope_sha256 = sha256_hex(canonical_json(envelope_dict))
    assert signing_provider.verify(
        envelope_sha256.encode("utf-8"),
        signature,
        signing_keypair.public_key,
    )


def test_attest_state_signature_fails_if_envelope_tampered(
    engine: EcosystemEngine,
    signing_keypair,
    signing_provider,
    now: datetime,
) -> None:
    packet = engine.attest_state(
        period_start_iso="2026-01-01T00:00:00+00:00",
        period_end_iso="2026-01-02T00:00:00+00:00",
    )
    envelope_dict, signature, _, _ = parse_envelope(packet)
    # Tamper.
    envelope_dict["payload"]["event_count_in_window"] = 99
    tampered_sha256 = sha256_hex(canonical_json(envelope_dict))
    assert not signing_provider.verify(
        tampered_sha256.encode("utf-8"),
        signature,
        signing_keypair.public_key,
    )
