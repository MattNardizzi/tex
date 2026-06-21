"""Fixtures for the L1 calibration-flywheel tests.

Self-contained builders (real domain objects + real in-memory stores — never a
mock of the unit under test) and a calibration sandbox whose directory BOTH the
seal hook's default feed and the gate's default feed resolve to, via
``TEX_PRESENCE_CALIBRATION_DIR``. That env-routed agreement is the real production
contract (writer and reader find the same per-tenant file), so the end-to-end
tests exercise it rather than threading an explicit feed everywhere.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from tex.domain.agent import ActionLedgerEntry, AgentIdentity, AgentLifecycleStatus
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.presence.memory import PresenceCalibrationFeed
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry

# A trace with a single sharp anomaly at index 3. Transductive CP (in-trace
# quantile) localizes a WIDE region here; a tenant whose confirmed errors score
# ~0.5 calibrates a higher threshold that tightens the region down to the peak.
ANOMALY_TRACE = (0.1, 0.2, 0.15, 0.95, 0.2, 0.1)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_decision(*, final_score: float, n: int = 0) -> Decision:
    return Decision(
        request_id=uuid4(),
        verdict=Verdict.FORBID,
        confidence=0.9,
        final_score=final_score,
        action_type="send_email",
        channel="email",
        environment="prod",
        content_excerpt=f"decision {n}",
        content_sha256=_sha(f"dec-{n}-{final_score}"),
        policy_version="v1",
    )


def make_agent(name: str = "alpha") -> AgentIdentity:
    return AgentIdentity(
        name=name, owner="acme", tenant_id="acme",
        lifecycle_status=AgentLifecycleStatus.ACTIVE,
    )


def make_action(agent_id: UUID, *, final_score: float, n: int = 0) -> ActionLedgerEntry:
    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict="PERMIT",
        action_type="send_email",
        channel="email",
        environment="prod",
        final_score=final_score,
        confidence=0.8,
        content_sha256=_sha(f"action-{agent_id}-{n}"),
    )


def build_state(scores=ANOMALY_TRACE):
    """A minimal app-state double carrying ONE agent's action trace, scored by
    ``scores``. Returns ``(state, agent_id)``. The gate recomputes the root-cause
    region from these real ledger rows."""
    registry = InMemoryAgentRegistry()
    agent = make_agent()
    registry.save(agent)

    ledger = InMemoryActionLedger()
    for i, s in enumerate(scores):
        ledger.append(make_action(agent.agent_id, final_score=s, n=i))

    state = SimpleNamespace(action_ledger=ledger, agent_registry=registry)
    return state, agent.agent_id


@pytest.fixture
def calib_dir(tmp_path, monkeypatch):
    """Point the SHARED default calibration dir at a tmp sandbox so the seal hook's
    default feed and the gate's default feed agree on every tenant's file. Also
    clear any ambient global calibration path so legacy-mode tests start clean."""
    d = tmp_path / "calib"
    monkeypatch.setenv("TEX_PRESENCE_CALIBRATION_DIR", str(d))
    monkeypatch.delenv("TEX_CONFORMAL_CALIBRATION_PATH", raising=False)
    return d


@pytest.fixture
def feed(calib_dir) -> PresenceCalibrationFeed:
    """A feed on the same dir the default feed resolves to (so assertions made
    through this handle reflect exactly what the gate's default feed will read)."""
    return PresenceCalibrationFeed(base_dir=str(calib_dir))
