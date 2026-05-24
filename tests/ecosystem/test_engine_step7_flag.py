"""
Tests for tex.ecosystem.engine — Step 7 systemic-risk axis under the
``TEX_ECOSYSTEM_SYSTEMIC`` env flag (Thread 7).

Coverage
--------
* Flag default off → systemic axis 0.0, no scorer called
* Flag on + no scorer wired → systemic axis 0.0, telemetry only
* Flag on + scorer raises NotImplementedError → axis 0.0, engine PERMITs
* Flag on + scorer returns 0.7 → axis 0.7 verbatim, engine PERMITs
* Flag on + scorer returns out-of-bounds → axis clamped to [0, 1]
* Flag on + scorer raises generic exception → axis 0.0, engine PERMITs
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Iterator

import pytest

from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.events.crypto_provenance import CryptoProvenance
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# ---- fixtures (copied from test_engine.py for isolation) -----------------


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def signing_provider():
    return default_signature_provider()


@pytest.fixture
def signing_keypair(signing_provider):
    return signing_provider.generate_keypair("test-key-step7-flag")


@pytest.fixture
def provenance(signing_keypair, signing_provider) -> CryptoProvenance:
    return CryptoProvenance(
        signing_key=signing_keypair, signing_provider=signing_provider,
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
    actor_id = "agent_step7"
    graph.add_entity(
        entity_id=actor_id,
        kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return actor_id


@pytest.fixture
def registered_tool(graph: InMemoryTemporalKG, now: datetime) -> str:
    tool_id = "tool_step7"
    graph.add_entity(
        entity_id=tool_id,
        kind="tool",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return tool_id


@pytest.fixture
def env_clean() -> Iterator[None]:
    """Save / restore TEX_ECOSYSTEM_SYSTEMIC around each test."""
    prior = os.environ.get("TEX_ECOSYSTEM_SYSTEMIC")
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop("TEX_ECOSYSTEM_SYSTEMIC", None)
        else:
            os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = prior


def _propose(actor: str, tool: str, when: datetime) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=actor,
        target_entity_id=tool,
        payload={"tool_id": tool, "arguments": {"q": "x"}},
        proposed_at=when,
    )


# ---- fake systemic scorers used by tests ---------------------------------


class _RaiseNotImplemented:
    def score(self, *, state) -> float:
        raise NotImplementedError("systemic risk score")


class _ReturnConstant:
    def __init__(self, value: float) -> None:
        self._value = value

    def score(self, *, state) -> float:
        return self._value


class _RaiseGeneric:
    def score(self, *, state) -> float:
        raise RuntimeError("boom")


# ---- actual tests --------------------------------------------------------


def test_flag_default_off_systemic_axis_zero(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Default flag = '0' → axis 0.0 regardless of whether a scorer is wired."""
    os.environ.pop("TEX_ECOSYSTEM_SYSTEMIC", None)
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_ReturnConstant(0.9),  # wired but flag off
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.axis_scores.systemic_risk_under_event == 0.0


def test_flag_on_no_scorer_axis_zero(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Flag on but ``systemic=None`` → axis 0.0, engine PERMITs."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=None,
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.axis_scores.systemic_risk_under_event == 0.0


def test_flag_on_not_implemented_axis_zero_engine_permits(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Today's reality: flag on, scorer wired but ``NotImplementedError``.
    Axis is honestly 0.0, engine continues to PERMIT (does NOT abort)."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_RaiseNotImplemented(),
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.axis_scores.systemic_risk_under_event == 0.0


def test_flag_on_scorer_returns_value(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Thread 9 simulation: scorer returns a clean float."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_ReturnConstant(0.7),
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.axis_scores.systemic_risk_under_event == pytest.approx(0.7)


def test_flag_on_scorer_returns_over_one_clamped(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Defensive clamp: scorer returning 1.5 produces axis = 1.0."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_ReturnConstant(1.5),
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.axis_scores.systemic_risk_under_event == 1.0


def test_flag_on_scorer_returns_negative_clamped(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Defensive clamp: scorer returning -0.3 produces axis = 0.0."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_ReturnConstant(-0.3),
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.axis_scores.systemic_risk_under_event == 0.0


def test_flag_on_scorer_raises_generic_axis_zero(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Scorer raises a non-NotImplementedError exception → axis 0.0,
    engine continues. The systemic axis is not a hard gate; it is an
    input to the (Thread-8) composition gate."""
    os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = "1"
    engine = EcosystemEngine(
        ontology=ontology_validator,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        systemic=_RaiseGeneric(),
        enabled=True,
    )
    verdict = engine.evaluate(
        _propose(registered_actor, registered_tool, now)
    )
    assert verdict.kind == EcosystemVerdictKind.PERMIT
    assert verdict.axis_scores.systemic_risk_under_event == 0.0


def test_flag_value_other_than_one_treated_as_off(
    env_clean,
    now,
    registered_actor,
    registered_tool,
    ontology_validator,
    graph,
    projection,
    ledger,
    provenance,
) -> None:
    """Any value other than exactly "1" is treated as off — defense
    against typo'd flag values silently enabling expensive paths."""
    for flag_val in ("0", "true", "yes", "on", "", "01", "1 "):
        os.environ["TEX_ECOSYSTEM_SYSTEMIC"] = flag_val
        engine = EcosystemEngine(
            ontology=ontology_validator,
            graph=graph,
            projection=projection,
            events=ledger,
            provenance=provenance,
            systemic=_ReturnConstant(0.7),
            enabled=True,
        )
        verdict = engine.evaluate(
            _propose(registered_actor, registered_tool, now)
        )
        assert verdict.axis_scores.systemic_risk_under_event == 0.0, (
            f"flag value {flag_val!r} should be treated as off but axis = "
            f"{verdict.axis_scores.systemic_risk_under_event}"
        )
