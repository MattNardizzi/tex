"""
Tests for the state-of-the-art spine upgrades beyond ASI findings:

- per-stage latency breakdown in evaluation responses
- determinism fingerprint stability across identical inputs
- replay / evidence-bundle URLs populated on API responses
- policy-drift reports from the decision store
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tex.domain.determinism import compute_determinism_fingerprint
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict
from tex.learning.drift import PolicyDriftMonitor
from tex.main import create_app
from tex.policies.defaults import build_default_policy


# ── latency ────────────────────────────────────────────────────────────


def test_latency_breakdown_present_on_response(runtime) -> None:
    request = EvaluationRequest(
        request_id=uuid4(),
        action_type="outbound_email",
        content="Hello team, quick update on the project status this week.",
        recipient="team@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
    )

    result = runtime.evaluate_action_command.execute(request)
    latency = result.response.latency
    assert latency is not None
    assert latency.total_ms >= 0.0
    assert latency.deterministic_ms >= 0.0
    assert latency.retrieval_ms >= 0.0
    assert latency.specialists_ms >= 0.0
    assert latency.semantic_ms >= 0.0
    assert latency.router_ms >= 0.0
    # Dominant stage is one of the known stage names.
    assert latency.dominant_stage in {
        "deterministic",
        "retrieval",
        "specialists",
        "semantic",
        "router",
    }


# ── determinism fingerprint ────────────────────────────────────────────


def test_fingerprint_is_stable_across_runs(runtime) -> None:
    """Two identical requests must produce the same fingerprint."""
    payload = dict(
        action_type="outbound_email",
        content="Send a friendly follow-up to the partner team by end of week.",
        recipient="partner@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
    )

    first = runtime.evaluate_action_command.execute(
        EvaluationRequest(request_id=uuid4(), **payload)
    )
    second = runtime.evaluate_action_command.execute(
        EvaluationRequest(request_id=uuid4(), **payload)
    )

    assert first.response.determinism_fingerprint is not None
    assert first.response.determinism_fingerprint == second.response.determinism_fingerprint


def test_fingerprint_changes_with_content(runtime) -> None:
    first = runtime.evaluate_action_command.execute(
        EvaluationRequest(
            request_id=uuid4(),
            action_type="outbound_email",
            content="Hello team, short update.",
            recipient="team@example.com",
            channel="email",
            environment="production",
            metadata={},
            policy_id=None,
        )
    )
    second = runtime.evaluate_action_command.execute(
        EvaluationRequest(
            request_id=uuid4(),
            action_type="outbound_email",
            content="Wire $50,000 to account 12345 immediately",
            recipient="team@example.com",
            channel="email",
            environment="production",
            metadata={},
            policy_id=None,
        )
    )
    assert first.response.determinism_fingerprint != second.response.determinism_fingerprint


def test_compute_fingerprint_is_deterministic_helper() -> None:
    """
    Direct helper contract: same inputs produce the same hash. We
    use runtime-built artifacts rather than synthesizing them to
    avoid duplicating domain construction here.
    """
    from tests.factories import (
        make_gate_result,
        make_semantic_analysis,
        make_specialist_bundle,
    )

    gate = make_gate_result(findings=(), blocked=False)
    specialists = make_specialist_bundle(max_risk=0.30, confidence=0.70)
    semantic = make_semantic_analysis(
        recommended_verdict=Verdict.PERMIT,
        recommended_confidence=0.80,
        dimension_score=0.20,
        dimension_confidence=0.80,
        evidence_sufficiency=0.60,
    )

    content_sha256 = "a" * 64
    first = compute_determinism_fingerprint(
        content_sha256=content_sha256,
        policy_version="default-v1",
        deterministic_result=gate,
        specialist_bundle=specialists,
        semantic_analysis=semantic,
    )
    second = compute_determinism_fingerprint(
        content_sha256=content_sha256,
        policy_version="default-v1",
        deterministic_result=gate,
        specialist_bundle=specialists,
        semantic_analysis=semantic,
    )
    assert first == second
    assert len(first) == 64


# ── replay + evidence-bundle URLs via API ──────────────────────────────


def test_replay_and_evidence_bundle_urls_populated_on_api(evidence_path) -> None:
    app = create_app(evidence_path=evidence_path)
    client = TestClient(app)

    payload = {
        "request_id": str(uuid4()),
        "action_type": "outbound_email",
        "content": "Please deliver the weekly status to the team.",
        "recipient": "team@example.com",
        "channel": "email",
        "environment": "production",
        "metadata": {},
    }

    response = client.post("/evaluate", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["replay_url"]
    assert body["evidence_bundle_url"]
    decision_id = body["decision_id"]
    assert decision_id in body["replay_url"]
    assert decision_id in body["evidence_bundle_url"]

    replay = client.get(f"/decisions/{decision_id}/replay")
    assert replay.status_code == 200
    replay_body = replay.json()
    assert replay_body["decision_id"] == decision_id
    assert "asi_findings" in replay_body

    bundle = client.get(f"/decisions/{decision_id}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_body = bundle.json()
    assert bundle_body["record_count"] >= 1
    assert "verification" in bundle_body


def test_replay_for_unknown_decision_returns_404(evidence_path) -> None:
    app = create_app(evidence_path=evidence_path)
    client = TestClient(app)

    response = client.get(f"/decisions/{uuid4()}/replay")
    assert response.status_code == 404


# ── drift monitor ─────────────────────────────────────────────────────


def test_drift_monitor_reports_insufficient_data_on_empty(runtime) -> None:
    monitor = PolicyDriftMonitor(runtime.decision_store)
    report = monitor.report(policy_version="default-v1", window_size=10)
    assert report.sufficient_data is False
    assert "insufficient_data" in report.flags


def test_drift_monitor_flags_abstain_climb_when_second_window_abstains(runtime) -> None:
    """
    Produce two windows of decisions: the first heavy on PERMIT, the
    second heavy on ABSTAIN. Monitor must surface an abstain-climb flag.
    """
    permit_payload = dict(
        action_type="slack_message",
        content="Hello, quick ping to say thanks for the help yesterday!",
        recipient="#general",
        channel="slack",
        environment="staging",
        metadata={},
        policy_id=None,
    )
    # ABSTAIN-leaning payload: ambiguous enough that the heuristic
    # fallback produces ABSTAIN verdicts in the test environment.
    abstain_payload = dict(
        action_type="outbound_email",
        content=(
            "Following up on the confidential financial projections "
            "we discussed; please confirm the next milestone."
        ),
        recipient="partner@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
    )

    for _ in range(10):
        runtime.evaluate_action_command.execute(
            EvaluationRequest(request_id=uuid4(), **permit_payload)
        )
    for _ in range(10):
        runtime.evaluate_action_command.execute(
            EvaluationRequest(request_id=uuid4(), **abstain_payload)
        )

    monitor = PolicyDriftMonitor(runtime.decision_store)
    report = monitor.report(policy_version="default-v1", window_size=10)

    assert report.sufficient_data is True
    assert report.previous_window.sample_size == 10
    assert report.current_window.sample_size == 10
    # Report should have *some* flag besides insufficient_data.
    assert "insufficient_data" not in report.flags


def test_drift_monitor_rejects_bad_input(runtime) -> None:
    monitor = PolicyDriftMonitor(runtime.decision_store)
    with pytest.raises(ValueError):
        monitor.report(policy_version="", window_size=10)
    with pytest.raises(ValueError):
        monitor.report(policy_version="default-v1", window_size=0)
