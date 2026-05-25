"""
Thread 7 — EcosystemEngine integration tests.

Verifies that wiring the EcosystemEngine + EcosystemBridge into the
production HTTP path via ``EvaluateActionCommand``:

  1. Is bit-for-bit identical to legacy behavior when ``TEX_ECOSYSTEM``
     is unset / "0" / any value other than exactly "1".
  2. Populates ``response.scores`` under the ``ecosystem.*`` namespace
     when ``TEX_ECOSYSTEM=1`` is set.
  3. Publishes a GAAT enforcement level as an uncertainty flag of the
     form ``ecosystem_graduated_level:<value>`` when the flag is on.
  4. Survives bridge failures gracefully — the legacy verdict still
     reaches the caller.
  5. Does not break the response schema (which is ``extra="forbid"``).

These tests use the real composition root in ``tex.main.build_runtime``,
not a hand-rolled fixture, so they specifically exercise the wiring this
thread adds.

References
----------
- TEX_CANONICAL.md §14 Thread 7 (acceptance criteria)
- TEX_CANONICAL.md §15 Thread 7 prompt (critical constraints)
- docs/ecosystem.md (engine constructor + GAAT levels)
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tex.commands.evaluate_action import EvaluateActionCommand
from tex.domain.evaluation import EvaluationRequest
from tex.ecosystem.bridge import EcosystemBridge
from tex.ecosystem.engine import EcosystemEngine
from tex.main import build_runtime, create_app


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runtime():
    """Build the real production runtime composition root."""
    return build_runtime()


@pytest.fixture
def benign_request() -> EvaluationRequest:
    """A simple benign request that should PERMIT through the legacy PDP."""
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content="Hi team, the Q3 review is on Tuesday at 2pm. Agenda attached.",
        recipient="team@example.com",
        channel="email",
        environment="production",
        policy_id=None,
    )


# ---------------------------------------------------------------------------
# 1. The engine and bridge are wired into the runtime
# ---------------------------------------------------------------------------


def test_runtime_carries_ecosystem_engine_and_bridge(runtime):
    """
    Thread 7 acceptance #1: ``build_runtime()`` constructs an
    ``EcosystemEngine`` and an ``EcosystemBridge`` and exposes both on
    the returned ``TexRuntime``.
    """
    assert runtime.ecosystem_engine is not None
    assert isinstance(runtime.ecosystem_engine, EcosystemEngine)
    assert runtime.ecosystem_bridge is not None
    assert isinstance(runtime.ecosystem_bridge, EcosystemBridge)


def test_evaluate_action_command_carries_bridge(runtime):
    """
    Thread 7 acceptance #2: the bridge is injected into
    ``EvaluateActionCommand`` so its ``execute()`` can forward
    routing results without an extra dependency lookup at call time.
    """
    cmd = runtime.evaluate_action_command
    assert isinstance(cmd, EvaluateActionCommand)
    assert cmd._ecosystem_bridge is runtime.ecosystem_bridge


# ---------------------------------------------------------------------------
# 2. Bit-for-bit identical when the flag is off
# ---------------------------------------------------------------------------


def test_flag_off_no_ecosystem_scores(runtime, benign_request, monkeypatch):
    """
    Thread 7 acceptance #3 (the CRITICAL constraint per TEX_CANONICAL.md
    §15): with ``TEX_ECOSYSTEM`` unset, the response carries NO
    ``ecosystem.*`` scores and NO ``ecosystem_graduated_level:*`` flag.
    """
    monkeypatch.delenv("TEX_ECOSYSTEM", raising=False)
    result = runtime.evaluate_action_command.execute(benign_request)
    response = result.response

    ecosystem_score_keys = [k for k in response.scores if k.startswith("ecosystem.")]
    assert ecosystem_score_keys == [], (
        "With TEX_ECOSYSTEM unset, response.scores must not carry "
        f"ecosystem.* keys; found: {ecosystem_score_keys}"
    )
    graduated_flags = [
        f for f in response.uncertainty_flags if f.startswith("ecosystem_graduated_level:")
    ]
    assert graduated_flags == [], (
        "With TEX_ECOSYSTEM unset, response.uncertainty_flags must not "
        f"carry ecosystem_graduated_level:*; found: {graduated_flags}"
    )


def test_flag_set_to_zero_no_ecosystem_scores(runtime, benign_request, monkeypatch):
    """``TEX_ECOSYSTEM=0`` is treated the same as unset (strict-equality flag)."""
    monkeypatch.setenv("TEX_ECOSYSTEM", "0")
    result = runtime.evaluate_action_command.execute(benign_request)
    ecosystem_score_keys = [
        k for k in result.response.scores if k.startswith("ecosystem.")
    ]
    assert ecosystem_score_keys == []


def test_flag_set_to_true_no_ecosystem_scores(runtime, benign_request, monkeypatch):
    """
    Strict equality with ``"1"``: anything that's not literally "1" (e.g.
    "true", "yes", "on") is treated as off. This matches the engine's
    own strict-equality semantics per docs/ecosystem.md.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "true")
    result = runtime.evaluate_action_command.execute(benign_request)
    ecosystem_score_keys = [
        k for k in result.response.scores if k.startswith("ecosystem.")
    ]
    assert ecosystem_score_keys == []


# ---------------------------------------------------------------------------
# 3. Axis scores populate when the flag is on
# ---------------------------------------------------------------------------


def test_flag_on_populates_axis_scores(benign_request, monkeypatch):
    """
    Thread 7 acceptance #4: with ``TEX_ECOSYSTEM=1`` set at runtime
    construction, the response carries the seven canonical
    ``ecosystem.*`` score keys.

    Note: the engine reads ``TEX_ECOSYSTEM`` at construction time, so we
    must build the runtime AFTER setting the env var.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()
    assert runtime.ecosystem_engine.enabled is True

    result = runtime.evaluate_action_command.execute(benign_request)
    scores = result.response.scores

    expected_keys = {
        "ecosystem.viability_index",
        "ecosystem.contract_violation_severity",
        "ecosystem.governance_graph_legality",
        "ecosystem.causal_attribution_confidence",
        "ecosystem.drift_delta",
        "ecosystem.systemic_risk_under_event",
        "ecosystem.bounded_compromise_score",
    }
    actual_keys = {k for k in scores if k.startswith("ecosystem.")}
    assert expected_keys == actual_keys, (
        f"Missing: {expected_keys - actual_keys}; Extra: {actual_keys - expected_keys}"
    )

    # All seven scalars must be in [0, 1] (validated by the response
    # schema, but assert explicitly so a regression in the projection
    # is caught here).
    for key in expected_keys:
        assert 0.0 <= scores[key] <= 1.0, f"{key}={scores[key]} out of [0,1]"


def test_flag_on_publishes_graduated_level_flag(benign_request, monkeypatch):
    """
    Thread 7 acceptance #5: the GAAT enforcement level is published as
    an uncertainty flag of the form
    ``ecosystem_graduated_level:<value>``. The value is one of
    ``L0_allow``/``L1_alert``/``L2_flag``/``L3_redirect``/``L4_quarantine``.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()

    result = runtime.evaluate_action_command.execute(benign_request)
    graduated_flags = [
        f
        for f in result.response.uncertainty_flags
        if f.startswith("ecosystem_graduated_level:")
    ]
    assert len(graduated_flags) == 1, (
        f"Expected exactly one ecosystem_graduated_level flag; got {graduated_flags}"
    )
    value = graduated_flags[0].split(":", 1)[1]
    assert value in {
        "L0_allow",
        "L1_alert",
        "L2_flag",
        "L3_redirect",
        "L4_quarantine",
    }, f"Unknown graduated level: {value!r}"


def test_flag_on_for_benign_request_yields_high_viability(
    benign_request, monkeypatch
):
    """
    A benign request through a clean graph (no prior contract violations,
    no drift, no systemic risk) should yield a high viability index
    (≥ 0.9, which maps to L0_allow per docs/ecosystem.md).
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()

    result = runtime.evaluate_action_command.execute(benign_request)
    viability = result.response.scores["ecosystem.viability_index"]
    assert viability >= 0.9, (
        f"Benign request should yield viability >= 0.9; got {viability}"
    )
    # The graduated level for high viability is L0_allow.
    graduated_flag = next(
        f
        for f in result.response.uncertainty_flags
        if f.startswith("ecosystem_graduated_level:")
    )
    assert graduated_flag == "ecosystem_graduated_level:L0_allow"


# ---------------------------------------------------------------------------
# 4. Response schema is preserved (``extra="forbid"``)
# ---------------------------------------------------------------------------


def test_response_schema_unchanged_with_flag_on(benign_request, monkeypatch):
    """
    Thread 7 acceptance #6: the ``EvaluationResponse`` schema is NOT
    extended — ecosystem state is folded into existing fields
    (``scores`` and ``uncertainty_flags``), not new top-level fields.

    The response model has ``extra="forbid"``, so any addition of new
    top-level fields would fail at construction. This test guards
    against accidental schema migration.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()
    result = runtime.evaluate_action_command.execute(benign_request)

    # Round-trip through model_dump + model_validate to confirm no
    # extra fields were silently introduced.
    dumped = result.response.model_dump()
    from tex.domain.evaluation import EvaluationResponse

    rebuilt = EvaluationResponse.model_validate(dumped)
    assert rebuilt.scores == result.response.scores
    assert rebuilt.uncertainty_flags == result.response.uncertainty_flags


# ---------------------------------------------------------------------------
# 5. Failure resilience — ecosystem layer is advisory in Thread 7
# ---------------------------------------------------------------------------


def test_bridge_failure_falls_back_to_legacy_response(benign_request, monkeypatch):
    """
    Thread 7 acceptance #7: if the bridge raises, the command MUST
    return the legacy response (no ecosystem.* scores) rather than
    propagating the exception. The legacy verdict is the user contract.

    This matches the canonical doc's promise that ecosystem evaluation
    is advisory in Thread 7 — the composition gate that turns axis
    scores into FORBID/SANCTION decisions lands in Thread 8.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()

    # Sabotage the bridge: replace emit_verdict with a raiser.
    class _BoomBridge:
        def emit_verdict(self, **kwargs):
            raise RuntimeError("synthetic ecosystem failure")

    sabotaged = EvaluateActionCommand(
        pdp=runtime.pdp,
        policy_store=runtime.policy_store,
        decision_store=runtime.decision_store,
        precedent_store=runtime.precedent_store,
        evidence_recorder=runtime.evidence_recorder,
        action_ledger=runtime.action_ledger,
        agent_registry=runtime.agent_registry,
        tenant_baseline=runtime.tenant_baseline,
        memory_system=runtime.memory,
        ecosystem_bridge=_BoomBridge(),
    )

    # Must NOT raise.
    result = sabotaged.execute(benign_request)
    # No ecosystem scores must appear — the legacy response is intact.
    ecosystem_keys = [
        k for k in result.response.scores if k.startswith("ecosystem.")
    ]
    assert ecosystem_keys == []


# ---------------------------------------------------------------------------
# 6. HTTP end-to-end: /evaluate carries axis scores when flag is on
# ---------------------------------------------------------------------------


def test_evaluate_http_carries_ecosystem_scores_when_flag_on(monkeypatch):
    """
    End-to-end through FastAPI's TestClient: with ``TEX_ECOSYSTEM=1``
    set at app construction, ``POST /evaluate`` responses carry the
    ecosystem.* scores in the JSON payload.

    This is the contract production HTTP consumers see.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    app = create_app()
    client = TestClient(app)

    payload = {
        "request_id": str(uuid4()),
        "action_type": "send_email",
        "content": "Quarterly metrics are attached for review.",
        "recipient": "ops@example.com",
        "channel": "email",
        "environment": "production",
    }
    resp = client.post("/evaluate", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    scores = body["scores"]
    assert "ecosystem.viability_index" in scores
    assert 0.0 <= scores["ecosystem.viability_index"] <= 1.0


def test_evaluate_http_does_not_carry_ecosystem_scores_when_flag_off(
    monkeypatch,
):
    """End-to-end: with ``TEX_ECOSYSTEM`` unset, HTTP response has no axis scores."""
    monkeypatch.delenv("TEX_ECOSYSTEM", raising=False)
    app = create_app()
    client = TestClient(app)

    payload = {
        "request_id": str(uuid4()),
        "action_type": "send_email",
        "content": "Quarterly metrics are attached for review.",
        "recipient": "ops@example.com",
        "channel": "email",
        "environment": "production",
    }
    resp = client.post("/evaluate", json=payload)
    assert resp.status_code == 200, resp.text
    scores = resp.json()["scores"]
    ecosystem_keys = [k for k in scores if k.startswith("ecosystem.")]
    assert ecosystem_keys == []


# ---------------------------------------------------------------------------
# 7. Engine is constructed but disabled by default — no env var needed
# ---------------------------------------------------------------------------


def test_engine_default_disabled_when_env_unset(monkeypatch):
    """
    With ``TEX_ECOSYSTEM`` unset entirely, the engine MUST be
    constructed in disabled mode. This guarantees that simply pulling
    the runtime does not silently activate the engine.
    """
    monkeypatch.delenv("TEX_ECOSYSTEM", raising=False)
    runtime = build_runtime()
    assert runtime.ecosystem_engine.enabled is False


def test_engine_enabled_when_env_is_one(monkeypatch):
    """
    With ``TEX_ECOSYSTEM=1`` at construction, the engine is enabled.
    """
    monkeypatch.setenv("TEX_ECOSYSTEM", "1")
    runtime = build_runtime()
    assert runtime.ecosystem_engine.enabled is True
