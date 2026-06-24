"""
Unit tests for the P11/P0 GOVERNANCE-STREAM plane sensor.

Proves the WHITE-SPACE leg (ARCHITECTURE.md §8 P11/P0; RESEARCH_LOG.md §1 P11/P0,
N3): an agent that asks Tex's PDP for a decision is self-discovered by the act of
asking. The sensor taps a configurable decision-event source (an in-process hook
or a decision-log iterator) and emits one ``Incidence(plane=GOVERNANCE_STREAM)``
per event whose footprint is ``{pdp_agent_id, agent_external_id, otel_trace_id,
tool_name, billing_account, decided_at}``. It ALSO feeds the P0 coverage-health
token-conservation residual (a positive shadow-volume signal). It MUST degrade to
EMPTY (never raise) when no source is configured.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_governance_stream.py -q
"""

from __future__ import annotations

from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.governance_stream import (
    GovernanceStreamSensor,
    build_governance_stream_sensor,
)
from tex.discovery.engine.sensors.registry import build_active_sensors


# ---------------------------------------------------------------------------
# Fixtures: a planted decision-event stream (the shape the PDP / OTel / billing
# rails emit). One PDP-calling agent + a shadow billing account with a positive
# token-conservation residual.
# ---------------------------------------------------------------------------


def _decision_events() -> list[dict]:
    """A small planted governance-decision log (decision-log iterator shape)."""
    return [
        {
            "agent": "AssayPilot",
            "agent_id": "add23f99-ee57-44a3-888a-85df2127974b",
            "pdp_agent_id": "spiffe://tex/AssayPilot",
            "otel_trace_id": "trace-aaa-001",
            "tool_name": "file_write",
            "billing_account": "acct-clean",
            "verdict": "PERMIT",
            "ts": 1782242461.21,
            # conserving books: billed == span + network → no residual
            "billing_tokens": 1000,
            "otel_span_tokens": 700,
            "network_implied_tokens": 300,
        },
        {
            "agent": "AssayPilot",
            "agent_id": "add23f99-ee57-44a3-888a-85df2127974b",
            "trace_id": "trace-aaa-002",
            "action_type": "model_invoke",
            "account": "acct-clean",
            "verdict": "PERMIT",
            "timestamp": "2026-06-23T12:00:00Z",
            "billing_tokens": 500,
            "otel_span_tokens": 200,
            "network_implied_tokens": 300,
        },
        {
            # A DIFFERENT agent on a SHADOW billing account whose billed tokens
            # exceed the span+network total → positive token-conservation
            # residual (N3): provably-billed inference no telemetry accounts for.
            "agent": "GhostWriter",
            "billing_account": "acct-shadow",
            "tool_name": "model_invoke",
            "ts": 1782242999.0,
            "billing_tokens": 9000,
            "otel_span_tokens": 1000,
            "network_implied_tokens": 0,
        },
    ]


# ---------------------------------------------------------------------------
# P11 — the governance-stream plane emits correct Incidence for a planted agent.
# ---------------------------------------------------------------------------


def test_emits_governance_stream_incidence_for_planted_agent() -> None:
    sensor = GovernanceStreamSensor(source=_decision_events)
    incs = list(sensor.sense(SenseContext()))

    p11 = [i for i in incs if i.plane_id is PlaneId.GOVERNANCE_STREAM]
    # One P11 incidence per decision event (3 events).
    assert len(p11) == 3

    every = p11[0]
    assert every.plane_id is PlaneId.GOVERNANCE_STREAM
    assert every.footprint.plane_id is PlaneId.GOVERNANCE_STREAM
    assert every.admissibility is Admissibility.OBSERVED
    assert 0.0 <= every.catchability <= 1.0
    assert every.observed_at.tzinfo is not None

    # The footprint carries the mandated keys; agent_external_id is the
    # IDENTITY-grade cross-plane fusion join key.
    assayp = next(i for i in p11 if i.footprint.key("agent_external_id") == "AssayPilot")
    assert assayp.footprint.key(FootprintField.PDP_AGENT_ID) == "spiffe://tex/AssayPilot"
    assert assayp.footprint.key(FootprintField.OTEL_TRACE_ID) == "trace-aaa-001"
    assert assayp.footprint.key(FootprintField.TOOL_NAME) == "file_write"
    assert assayp.footprint.key(FootprintField.BILLING_ACCOUNT) == "acct-clean"
    assert assayp.footprint.attr("decided_at") is not None
    assert assayp.footprint.attr("verdict") == "PERMIT"
    # raw_evidence_ref points at the trace for receipts.
    assert assayp.raw_evidence_ref == "trace-aaa-001"


def test_alias_resolution_reads_otel_and_billing_vocabularies() -> None:
    """The second AssayPilot event uses trace_id/action_type/account aliases."""
    sensor = GovernanceStreamSensor(source=_decision_events, emit_coverage_health=False)
    p11 = [i for i in sensor.sense(SenseContext()) if i.plane_id is PlaneId.GOVERNANCE_STREAM]
    aliased = next(i for i in p11 if i.footprint.key(FootprintField.OTEL_TRACE_ID) == "trace-aaa-002")
    assert aliased.footprint.key(FootprintField.TOOL_NAME) == "model_invoke"
    assert aliased.footprint.key(FootprintField.BILLING_ACCOUNT) == "acct-clean"


def test_governance_stream_fuses_to_one_entity_on_identity_key() -> None:
    """Two AssayPilot governance sightings fuse to ONE SieveEntity (the join key
    is the IDENTITY-grade agent_external_id), proving cross-plane fusibility."""
    sensor = GovernanceStreamSensor(source=_decision_events, emit_coverage_health=False)
    incs = list(sensor.sense(SenseContext()))
    entities = resolve(incs)
    labels = {e.label for e in entities}
    assert "AssayPilot" in labels
    assayp = next(e for e in entities if e.label == "AssayPilot")
    # Both AssayPilot governance footprints collapsed into ONE entity.
    assert len(assayp.incidences) == 2
    # GhostWriter resolves to its own distinct entity.
    assert "GhostWriter" in labels


# ---------------------------------------------------------------------------
# P0 — token-conservation residual is a positive shadow-volume signal (N3).
# ---------------------------------------------------------------------------


def test_emits_p0_token_conservation_residual_only_for_shadow_account() -> None:
    sensor = GovernanceStreamSensor(source=_decision_events, emit_coverage_health=True)
    incs = list(sensor.sense(SenseContext()))
    p0 = [i for i in incs if i.plane_id is PlaneId.COVERAGE_HEALTH]

    # Exactly ONE residual: acct-clean conserves (billed == span+network),
    # acct-shadow does NOT (9000 - 1000 - 0 = 8000 billed-but-unseen).
    assert len(p0) == 1
    residual = p0[0]
    assert residual.footprint.key(FootprintField.BILLING_ACCOUNT) == "acct-shadow"
    assert residual.footprint.key("coverage_signal") == "token_conservation_residual"
    assert float(residual.footprint.attr("residual_tokens")) == 8000.0
    assert residual.admissibility is Admissibility.PLATFORM_ATTESTED


def test_coverage_health_disabled_emits_no_p0() -> None:
    sensor = GovernanceStreamSensor(source=_decision_events, emit_coverage_health=False)
    incs = list(sensor.sense(SenseContext()))
    assert all(i.plane_id is not PlaneId.COVERAGE_HEALTH for i in incs)


# ---------------------------------------------------------------------------
# DEGRADE-TO-EMPTY — the non-negotiable default-safe contract.
# ---------------------------------------------------------------------------


def test_degrades_to_empty_when_no_source_configured() -> None:
    sensor = GovernanceStreamSensor(source=None)
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_when_source_callable_raises() -> None:
    def _boom() -> list[dict]:
        raise RuntimeError("source unavailable")

    sensor = GovernanceStreamSensor(source=_boom)
    # Never raises; degrades to fewer incidences (here zero).
    assert list(sensor.sense(SenseContext())) == []


def test_degrades_to_empty_on_empty_and_malformed_rows() -> None:
    # Empty iterable → nothing.
    assert list(GovernanceStreamSensor(source=[]).sense(SenseContext())) == []
    # Malformed rows (non-mappings / no agent handle) are skipped, never raise.
    malformed = ["not-a-dict", 42, {"unrelated": "x"}, {"verdict": "PERMIT"}]
    incs = list(GovernanceStreamSensor(source=lambda: malformed).sense(SenseContext()))
    assert incs == []


def test_iterable_source_is_consumed_directly() -> None:
    """A decision-log iterator (a plain iterable, not a callable) is accepted."""
    sensor = GovernanceStreamSensor(source=_decision_events(), emit_coverage_health=False)
    p11 = [i for i in sensor.sense(SenseContext()) if i.plane_id is PlaneId.GOVERNANCE_STREAM]
    assert len(p11) == 3


# ---------------------------------------------------------------------------
# REGISTRY — flag-gated OFF by default; env-built factory is default-safe inert.
# ---------------------------------------------------------------------------


def test_flag_gated_off_by_default_in_registry() -> None:
    # No flags → no governance-stream sensor built (default-safe on merge-to-main).
    assert build_active_sensors({}) == []


def test_registry_factory_is_inert_without_a_wired_hook() -> None:
    """Enabling TEX_SIEVE_P11_OTEL builds the sensor, but with no in-process hook
    wired it has no source and senses NOTHING — flag-on must not crash or fake."""
    sensors = build_active_sensors({"TEX_SIEVE_P11_OTEL": "1"})
    gov = [s for s in sensors if s.plane_id is PlaneId.GOVERNANCE_STREAM]
    assert len(gov) == 1
    assert list(gov[0].sense(SenseContext())) == []


def test_build_factory_directly_degrades_empty() -> None:
    sensor = build_governance_stream_sensor({"TEX_SIEVE_P11_OTEL": "1"})
    assert isinstance(sensor, GovernanceStreamSensor)
    assert list(sensor.sense(SenseContext())) == []
