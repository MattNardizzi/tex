"""
Tests for tex.ecosystem.bridge — six-layer router ↔ ecosystem engine.

Acceptance criterion (Thread 10): emitting a verdict from the existing
six-layer router creates a VERDICT_EMITTED event in the ecosystem ledger.

These tests prove that and surrounding contract behavior:

* RoutingResult shape -> ProposedEvent shape (event_kind, payload, session_id).
* End-to-end: bridge.emit_verdict() with engine enabled writes a
  VERDICT_EMITTED to the ledger and returns a PERMIT EcosystemVerdict.
* Default-off behavior: with the engine disabled the bridge is a no-op
  on the ledger — proving the existing six-layer pipeline runs unchanged.
* Numeric round-trip via the int-x10000 fixed-point convention.
* All three Verdict kinds (PERMIT, ABSTAIN, FORBID) survive the bridge.
* Reserved-key collision in extra_payload raises.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tex.domain.verdict import Verdict
from tex.ecosystem.bridge import (
    EcosystemBridge,
    routing_result_to_proposed_event,
)
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.engine.router import RoutingResult
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# --------------------------------------------------------------- fixtures


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 7, 14, 0, 0, tzinfo=UTC)


@pytest.fixture
def routing_permit() -> RoutingResult:
    return RoutingResult(
        verdict=Verdict.PERMIT,
        confidence=0.9123,
        final_score=0.1234,
        reasons=("looks fine",),
        uncertainty_flags=(),
        findings=(),
        scores={
            "deterministic": 0.0,
            "specialists": 0.05,
            "semantic": 0.1,
            "criticality": 0.2,
        },
        asi_findings=(),
        semantic_dominance_override_fired=False,
    )


@pytest.fixture
def routing_abstain() -> RoutingResult:
    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=0.5,
        final_score=0.4,
        reasons=("borderline",),
        uncertainty_flags=("borderline_fused_score",),
        findings=(),
        scores={"deterministic": 0.1, "specialists": 0.4, "semantic": 0.4},
        asi_findings=(),
        semantic_dominance_override_fired=False,
    )


@pytest.fixture
def routing_forbid() -> RoutingResult:
    return RoutingResult(
        verdict=Verdict.FORBID,
        confidence=0.95,
        final_score=0.85,
        reasons=("blocked by deterministic gate",),
        uncertainty_flags=(),
        findings=(),
        scores={"deterministic": 1.0, "specialists": 0.7, "semantic": 0.8},
        asi_findings=(),
        semantic_dominance_override_fired=True,
    )


def _make_engine(*, enabled: bool):
    """Build a fully-wired engine + the actor entity needed by step 2."""
    provider = default_signature_provider()
    keypair = provider.generate_keypair("bridge-test-key")
    provenance = CryptoProvenance(signing_key=keypair, signing_provider=provider)
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key, signing_provider=provider
    )
    graph = InMemoryTemporalKG()
    projection = StateProjection(graph=graph)
    ontology = OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    )
    eng = EcosystemEngine(
        ontology=ontology,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        enabled=enabled,
    )
    return eng, ledger, graph


@pytest.fixture
def enabled_setup(now: datetime):
    """Engine + ledger + graph with one registered agent ready to act."""
    eng, ledger, graph = _make_engine(enabled=True)
    actor = "agent_bridge"
    graph.add_entity(
        entity_id=actor,
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return eng, ledger, graph, actor


@pytest.fixture
def disabled_setup(now: datetime):
    eng, ledger, graph = _make_engine(enabled=False)
    actor = "agent_bridge"
    graph.add_entity(
        entity_id=actor,
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return eng, ledger, graph, actor


# ---------------------------------------------- routing_result_to_proposed_event


def test_bridge_produces_verdict_emitted_event_kind(
    routing_permit: RoutingResult, now: datetime
) -> None:
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
    )
    assert proposed.event_kind == EventKind.VERDICT_EMITTED.value
    assert proposed.actor_entity_id == "agent_x"
    assert proposed.proposed_at == now


def test_bridge_payload_carries_action_verdict(
    routing_permit: RoutingResult, now: datetime
) -> None:
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
    )
    assert proposed.payload["verdict"] == "PERMIT"


def test_bridge_payload_uses_int_fixed_point_for_floats(
    routing_permit: RoutingResult, now: datetime
) -> None:
    """canonical_json rejects floats; bridge encodes scores as int*10000."""
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
    )
    assert proposed.payload["confidence_x10000"] == round(0.9123 * 10_000)
    assert proposed.payload["final_score_x10000"] == round(0.1234 * 10_000)
    assert proposed.payload["layer_scores_x10000"]["specialists"] == 500
    # No raw floats anywhere.
    for value in proposed.payload.values():
        assert not isinstance(value, float)
    for value in proposed.payload["layer_scores_x10000"].values():
        assert not isinstance(value, float)


def test_bridge_preserves_request_id_as_session_id(
    routing_permit: RoutingResult, now: datetime
) -> None:
    request_id = str(uuid4())
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
        request_id=request_id,
    )
    assert proposed.session_id == request_id


def test_bridge_carries_upstream_event_ids(
    routing_permit: RoutingResult, now: datetime
) -> None:
    upstream = ("evt_aaa111aaa111", "evt_bbb222bbb222")
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
        upstream_event_ids=upstream,
    )
    assert proposed.upstream_event_ids == upstream


def test_bridge_extra_payload_is_merged(
    routing_permit: RoutingResult, now: datetime
) -> None:
    proposed = routing_result_to_proposed_event(
        routing_result=routing_permit,
        actor_entity_id="agent_x",
        proposed_at=now,
        extra_payload={"trace_id": "abcd1234", "tenant": "vortexblack"},
    )
    assert proposed.payload["trace_id"] == "abcd1234"
    assert proposed.payload["tenant"] == "vortexblack"
    # Reserved keys still present
    assert proposed.payload["verdict"] == "PERMIT"


def test_bridge_extra_payload_collision_raises(
    routing_permit: RoutingResult, now: datetime
) -> None:
    with pytest.raises(ValueError, match="reserved keys"):
        routing_result_to_proposed_event(
            routing_result=routing_permit,
            actor_entity_id="agent_x",
            proposed_at=now,
            extra_payload={"verdict": "FAKE"},
        )


@pytest.mark.parametrize(
    "verdict_fixture",
    ["routing_permit", "routing_abstain", "routing_forbid"],
)
def test_bridge_handles_all_three_verdict_kinds(
    verdict_fixture: str, now: datetime, request: pytest.FixtureRequest
) -> None:
    """Action verdicts of any kind must produce a valid VERDICT_EMITTED event."""
    routing_result: RoutingResult = request.getfixturevalue(verdict_fixture)
    proposed = routing_result_to_proposed_event(
        routing_result=routing_result,
        actor_entity_id="agent_x",
        proposed_at=now,
    )
    assert proposed.event_kind == EventKind.VERDICT_EMITTED.value
    assert proposed.payload["verdict"] == routing_result.verdict.value


# --------------------------------------------------------- end-to-end (acceptance)


def test_bridge_end_to_end_creates_verdict_emitted_in_ledger(
    enabled_setup, routing_permit: RoutingResult, now: datetime
) -> None:
    """
    Acceptance test: Routing a six-layer RoutingResult through the
    EcosystemBridge writes a VERDICT_EMITTED event to the ecosystem ledger.
    """
    engine, ledger, _, actor = enabled_setup
    bridge = EcosystemBridge(engine=engine)

    pre_len = len(ledger)
    verdict = bridge.emit_verdict(
        routing_result=routing_permit,
        actor_entity_id=actor,
        proposed_at=now,
        request_id="req-acceptance-1",
    )

    # Ecosystem layer admitted it.
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.evidence_record_id is not None

    # Ledger gained exactly one record.
    assert len(ledger) == pre_len + 1

    # That record is a VERDICT_EMITTED event with the right wiring.
    # NB: session_id lives on ProposedEvent only — Thread 2's Event model
    # does not carry it onto the canonical record (it's not part of the
    # tamper surface). The bridge surfaces it via telemetry instead.
    stored = ledger.get(verdict.evidence_record_id)
    assert stored is not None
    assert stored.kind == EventKind.VERDICT_EMITTED.value
    assert stored.actor_entity_id == actor
    assert stored.payload["verdict"] == "PERMIT"
    assert stored.payload["confidence_x10000"] == round(
        routing_permit.confidence * 10_000
    )


def test_bridge_disabled_engine_is_noop_on_ledger(
    disabled_setup, routing_permit: RoutingResult, now: datetime
) -> None:
    """
    With TEX_ECOSYSTEM disabled, the bridge must not mutate the ledger or
    graph — proving the existing six-layer pipeline is unchanged.
    """
    engine, ledger, graph, actor = disabled_setup
    bridge = EcosystemBridge(engine=engine)

    pre_ledger_len = len(ledger)
    pre_state = graph.state_hash(now)

    verdict = bridge.emit_verdict(
        routing_result=routing_permit,
        actor_entity_id=actor,
        proposed_at=now,
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.evidence_record_id is None
    assert len(ledger) == pre_ledger_len
    assert graph.state_hash(now) == pre_state


def test_bridge_records_are_chained(
    enabled_setup, routing_permit: RoutingResult, now: datetime
) -> None:
    """Two consecutive bridge emissions produce a properly chained ledger."""
    engine, ledger, _, actor = enabled_setup
    bridge = EcosystemBridge(engine=engine)

    v1 = bridge.emit_verdict(
        routing_result=routing_permit, actor_entity_id=actor, proposed_at=now
    )
    v2 = bridge.emit_verdict(
        routing_result=routing_permit,
        actor_entity_id=actor,
        proposed_at=now + timedelta(seconds=1),
    )
    e1 = ledger.get(v1.evidence_record_id)
    e2 = ledger.get(v2.evidence_record_id)
    assert e1 is not None and e2 is not None
    assert e2.previous_ledger_hash == e1.record_hash
    assert e2.sequence_number == e1.sequence_number + 1
    assert ledger.verify_chain(from_sequence=1, to_sequence=2) is True


def test_bridge_with_unregistered_actor_results_in_forbid(
    enabled_setup, routing_permit: RoutingResult, now: datetime
) -> None:
    """Step 2 actor check still applies when the bridge invokes evaluate."""
    engine, ledger, _, _ = enabled_setup
    bridge = EcosystemBridge(engine=engine)

    pre_len = len(ledger)
    verdict = bridge.emit_verdict(
        routing_result=routing_permit,
        actor_entity_id="ghost",
        proposed_at=now,
    )
    assert verdict.kind == EcosystemVerdictKind.FORBID
    assert verdict.evidence_record_id is None
    assert len(ledger) == pre_len  # nothing recorded
