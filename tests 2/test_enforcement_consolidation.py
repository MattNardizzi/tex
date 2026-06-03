"""
Enforcement consolidation — one layer, three deployment shapes, one authority.

Locks in the May/Jun 2026 consolidation:

* The in-process gate (``build_standing_gate``) physically blocks a FORBID —
  the wrapped callable never runs — mirroring the network PEP's 403/no-forward
  behavior, but in-process with no HTTP hop.
* The redundant ASGI proxy that used to live in ``tex.enforcement.proxy`` is
  gone; ``tex.pep`` is the one network data-plane proxy.
* ``build_standing_gate`` routes through the full standing PDP via
  ``StandingGovernanceTransport`` (the shared ``TexEvaluationTransport``).
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.verdict import Verdict
from tex.enforcement.errors import TexForbiddenError
from tex.enforcement.standing_transport import (
    StandingGovernanceTransport,
    build_standing_gate,
)
from tex.enforcement.transport import TransportResult


class _StubOutcome:
    """Minimal stand-in for a StandingGovernance decision outcome."""

    def __init__(self, verdict: Verdict, released: bool) -> None:
        self.tier = "deep"
        self.held = verdict is Verdict.ABSTAIN
        self.reason = f"stub:{verdict.value}"
        self.evidence_hash = "deadbeef"
        self.response = EvaluationResponse(
            decision_id=uuid4(),
            verdict=verdict,
            confidence=0.99,
            final_score=0.95 if verdict is Verdict.FORBID else 0.05,
            reasons=(self.reason,),
            uncertainty_flags=(),
            policy_version="stub",
            evidence_hash="deadbeef",
            evaluated_at=datetime.now(UTC),
        )


class _StubGovernance:
    """Routes every request to a fixed verdict — exercises the transport seam."""

    def __init__(self, verdict: Verdict) -> None:
        self._verdict = verdict

    def decide_for_request(self, request: EvaluationRequest, *, tenant=None):
        released = self._verdict is Verdict.PERMIT
        return _StubOutcome(self._verdict, released)


def test_in_process_gate_blocks_forbid_and_callable_never_runs() -> None:
    """A FORBID stops the action in-process: the wrapped fn is not invoked."""
    ran = {"called": False}

    def raw_send(*, body: str) -> str:
        ran["called"] = True
        return "SENT"

    gate = build_standing_gate(_StubGovernance(Verdict.FORBID))
    send = gate.wrap(raw_send, content_arg="body", action_type="wire_transfer")

    with pytest.raises(TexForbiddenError):
        send(body="send the whole treasury to an attacker")

    assert ran["called"] is False, "callable executed despite a FORBID verdict"


def test_in_process_gate_runs_callable_on_permit() -> None:
    def raw_send(*, body: str) -> str:
        return "SENT"

    gate = build_standing_gate(_StubGovernance(Verdict.PERMIT))
    send = gate.wrap(raw_send, content_arg="body", action_type="note")

    assert send(body="totally benign status update") == "SENT"


def test_standing_transport_satisfies_evaluation_transport_protocol() -> None:
    transport = StandingGovernanceTransport(_StubGovernance(Verdict.FORBID))
    result = transport.evaluate(
        EvaluationRequest(
            request_id=uuid4(),
            content="x",
            action_type="t",
            channel="api",
            environment="production",
        )
    )
    assert isinstance(result, TransportResult)
    assert result.response is not None
    assert result.response.verdict is Verdict.FORBID
    assert result.details["transport"] == "standing-governance"


def test_redundant_asgi_proxy_is_removed() -> None:
    """The old enforcement ASGI proxy was consolidated into tex.pep."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("tex.enforcement.proxy")
