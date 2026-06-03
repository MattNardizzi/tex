"""
Regression tests for KNOWN_BUGS.md Bug #2.

The historic defect: ``tex.ecosystem.engine`` defaulted ``TEX_ECOSYSTEM_SYSTEMIC``
to "1" (on), while ``tex.ecosystem_config.EcosystemFlags.from_env`` parsed
the same env var with default "0" (off). Two readers of the same flag
returned opposite booleans when the env var was unset.

Resolution: a single canonical parser, ``tex.ecosystem_config.is_flag_on``,
is the only place the flag is read. Both modules import it.

These tests pin the contract so the drift cannot reappear:

* Unset → False from every reader.
* "1" → True from every reader.
* Any value other than exactly "1" → False from every reader.
* The engine's read of the systemic flag is observable in telemetry on
  every evaluate(), regardless of state.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Iterator

import pytest

from tex.ecosystem_config import EcosystemFlags, is_flag_on
from tex.ecosystem.engine import EcosystemEngine, _ENV_FLAG_SYSTEMIC
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.verdict import EcosystemVerdictKind
from tex.events.crypto_provenance import CryptoProvenance
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.observability import telemetry
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


# ---- canonical parser semantics (Bug #2 root cause) ----------------------


_FLAG = "TEX_ECOSYSTEM_SYSTEMIC"


@pytest.fixture
def env_restore() -> Iterator[None]:
    prior = os.environ.get(_FLAG)
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop(_FLAG, None)
        else:
            os.environ[_FLAG] = prior


class TestCanonicalFlagParser:
    """``is_flag_on`` is the single source of truth."""

    def test_unset_is_false(self, env_restore) -> None:
        os.environ.pop(_FLAG, None)
        assert is_flag_on(_FLAG) is False

    def test_exact_one_is_true(self, env_restore) -> None:
        os.environ[_FLAG] = "1"
        assert is_flag_on(_FLAG) is True

    @pytest.mark.parametrize(
        "value",
        ["0", "true", "TRUE", "yes", "on", "", " ", "1 ", " 1", "01", "10"],
    )
    def test_strict_equality_against_typos(
        self, env_restore, value: str
    ) -> None:
        os.environ[_FLAG] = value
        assert is_flag_on(_FLAG) is False, (
            f"flag value {value!r} must be treated as off"
        )


class TestEcosystemFlagsAgreesWithEngine:
    """The dataclass reader and the engine reader must never disagree."""

    def test_unset_both_off(self, env_restore) -> None:
        os.environ.pop(_FLAG, None)
        flags = EcosystemFlags.from_env()
        assert flags.systemic is False
        assert is_flag_on(_ENV_FLAG_SYSTEMIC) is False

    def test_one_both_on(self, env_restore) -> None:
        os.environ[_FLAG] = "1"
        flags = EcosystemFlags.from_env()
        assert flags.systemic is True
        assert is_flag_on(_ENV_FLAG_SYSTEMIC) is True

    @pytest.mark.parametrize("value", ["0", "true", "yes", "", "01"])
    def test_non_one_both_off(self, env_restore, value: str) -> None:
        os.environ[_FLAG] = value
        flags = EcosystemFlags.from_env()
        assert flags.systemic is False
        assert is_flag_on(_ENV_FLAG_SYSTEMIC) is False


# ---- engine telemetry observability (the audit-plane contract) -----------


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def signing_provider():
    return default_signature_provider()


@pytest.fixture
def signing_keypair(signing_provider):
    return signing_provider.generate_keypair("test-key-bug2-regression")


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
def actor(graph: InMemoryTemporalKG, now: datetime) -> str:
    actor_id = "agent_bug2_regression"
    graph.add_entity(
        entity_id=actor_id, kind="agent",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return actor_id


@pytest.fixture
def tool(graph: InMemoryTemporalKG, now: datetime) -> str:
    tool_id = "tool_bug2_regression"
    graph.add_entity(
        entity_id=tool_id, kind="tool",
        attrs={"registered_at": now - timedelta(minutes=1)},
    )
    return tool_id


def _propose(actor_id: str, tool_id: str, when: datetime) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=actor_id,
        target_entity_id=tool_id,
        payload={"tool_id": tool_id, "arguments": {"q": "x"}},
        proposed_at=when,
    )


class _ConstantScorer:
    def __init__(self, value: float) -> None:
        self._value = value

    def score(self, *, state) -> float:
        return self._value


class TestTelemetryOnEveryPath:
    """Audit-plane contract: every evaluate() emits exactly one Step-7
    telemetry event, distinguishable by event name + reason field, so a
    misconfigured flag is observable in production logs without a code
    change.
    """

    def _capture(self, monkeypatch) -> list[tuple[str, dict]]:
        captured: list[tuple[str, dict]] = []

        def _fake_emit(name: str, **kwargs):
            captured.append((name, kwargs))

        monkeypatch.setattr(telemetry, "emit_event", _fake_emit)
        # The engine module imports the symbol at top-level, so patch
        # the bound name there too.
        import tex.ecosystem.engine as eng
        monkeypatch.setattr(eng, "emit_event", _fake_emit)
        return captured

    def _build_engine(self, scorer, **kw) -> EcosystemEngine:
        return EcosystemEngine(
            ontology=kw["ontology_validator"],
            graph=kw["graph"],
            projection=kw["projection"],
            events=kw["ledger"],
            provenance=kw["provenance"],
            systemic=scorer,
            enabled=True,
        )

    def test_flag_unset_emits_skipped_with_reason(
        self, env_restore, monkeypatch, now, actor, tool,
        ontology_validator, graph, projection, ledger, provenance,
    ) -> None:
        os.environ.pop(_FLAG, None)
        captured = self._capture(monkeypatch)
        engine = self._build_engine(
            _ConstantScorer(0.5),
            ontology_validator=ontology_validator, graph=graph,
            projection=projection, ledger=ledger, provenance=provenance,
        )
        engine.evaluate(_propose(actor, tool, now))
        step7 = [(n, k) for n, k in captured if n.startswith("ecosystem.engine.step7.")]
        assert any(
            n.endswith("systemic_skipped") and k.get("reason") == "flag_off"
            for n, k in step7
        ), step7

    def test_flag_on_with_scorer_emits_scored(
        self, env_restore, monkeypatch, now, actor, tool,
        ontology_validator, graph, projection, ledger, provenance,
    ) -> None:
        os.environ[_FLAG] = "1"
        captured = self._capture(monkeypatch)
        engine = self._build_engine(
            _ConstantScorer(0.4),
            ontology_validator=ontology_validator, graph=graph,
            projection=projection, ledger=ledger, provenance=provenance,
        )
        engine.evaluate(_propose(actor, tool, now))
        step7 = [(n, k) for n, k in captured if n.startswith("ecosystem.engine.step7.")]
        assert any(
            n.endswith("systemic_scored") and k.get("systemic_risk") == pytest.approx(0.4)
            for n, k in step7
        ), step7

    def test_flag_on_no_scorer_emits_skipped_with_deployment_bug_reason(
        self, env_restore, monkeypatch, now, actor, tool,
        ontology_validator, graph, projection, ledger, provenance,
    ) -> None:
        os.environ[_FLAG] = "1"
        captured = self._capture(monkeypatch)
        engine = EcosystemEngine(
            ontology=ontology_validator, graph=graph,
            projection=projection, events=ledger, provenance=provenance,
            systemic=None, enabled=True,
        )
        engine.evaluate(_propose(actor, tool, now))
        step7 = [(n, k) for n, k in captured if n.startswith("ecosystem.engine.step7.")]
        # Operator-visible signal: flag is on but no scorer is wired,
        # which is a deployment bug and must be distinguishable from
        # the routine flag-off path.
        assert any(
            n.endswith("systemic_skipped")
            and k.get("reason") == "flag_on_but_no_collaborator"
            for n, k in step7
        ), step7


class TestDefaultOffAxisZero:
    """The headline behavioural contract: unset env var → axis = 0.0,
    even when a scorer is wired. This is the OWASP / Google Cloud
    fail-safe-defaults posture for safety-critical paths.
    """

    def test_unset_axis_zero_even_with_scorer(
        self, env_restore, now, actor, tool,
        ontology_validator, graph, projection, ledger, provenance,
    ) -> None:
        os.environ.pop(_FLAG, None)
        engine = EcosystemEngine(
            ontology=ontology_validator, graph=graph,
            projection=projection, events=ledger, provenance=provenance,
            systemic=_ConstantScorer(0.9),  # would score 0.9 if honored
            enabled=True,
        )
        verdict = engine.evaluate(_propose(actor, tool, now))
        assert verdict.kind == EcosystemVerdictKind.PERMIT
        assert verdict.axis_scores.systemic_risk_under_event == 0.0
