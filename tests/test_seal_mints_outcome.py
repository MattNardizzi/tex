"""
Thread A — auto-seal a human resolution into a labeled outcome.

The moat is the accumulating corpus of *human-resolved ABSTAINs*. Before this
wire, resolving a held decision sealed the act but never minted a labeled
calibration outcome — the fuel was generated and dropped on the floor. These
tests pin the closed loop:

  1. Sealing a held decision via POST /decisions/{id}/seal mints an
     OutcomeRecord that is (a) ingested into the live feedback loop, (b) at
     human-reviewer trust, and (c) parent-linked by hash to the sealed
     resolution — asserted against the real store and the real evidence chain.
  2. The (machine verdict, human act) → (kind, was_safe, override, label)
     mapping is correct for every combination, including the override cases
     (FORBID approved → FALSE_FORBID, PERMIT refused → FALSE_PERMIT).
  3. Capture is never silently skippable: a capture failure still seals but
     surfaces an explicit warning; the flag-off path is explicitly reported.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tex.api.outcome_autoseal import map_resolution_to_outcome
from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeKind, OutcomeLabel, OutcomeRecord
from tex.domain.outcome_trust import OutcomeSourceType, OutcomeTrustLevel, VerificationMethod
from tex.domain.verdict import Verdict
from tex.main import create_app


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _decision(verdict: Verdict, *, score: float = 0.5) -> Decision:
    """A persistable Decision in any verdict state (ABSTAIN needs a flag)."""
    return Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=score if verdict is not Verdict.PERMIT else 0.1,
        action_type="send_email",
        channel="email",
        environment="production",
        content_excerpt="hello",
        content_sha256="a" * 64,
        policy_version="v1",
        reasons=(["needs human"] if verdict is not Verdict.PERMIT else []),
        uncertainty_flags=(["low_conf"] if verdict is Verdict.ABSTAIN else []),
    )


def _seed_and_seal(client: TestClient, decision: Decision, *, verdict: str, note: str | None = "reviewed"):
    """Seed a decision into the live store, then seal it via the route."""
    client.app.state.decision_store.save(decision)
    return client.post(
        f"/decisions/{decision.decision_id}/seal",
        json={"verdict": verdict, "resolved_by": "operator@example.com", "note": note},
    )


# --------------------------------------------------------------------------- #
# 1. The closed loop, end-to-end through the route
# --------------------------------------------------------------------------- #


def test_sealing_held_decision_mints_ingested_human_trust_parent_linked_outcome():
    client = TestClient(create_app())
    held = _decision(Verdict.ABSTAIN)

    sealed = _seed_and_seal(client, held, verdict="approved")
    assert sealed.status_code == 201
    body = sealed.json()

    # Backward-compatible: the original seal anchor is still present.
    assert len(body["anchor_sha256"]) == 64
    assert body["human_verdict"] == "approved"

    cap = body["outcome_capture"]
    assert cap["status"] == "captured"
    # Labeled correctly: a resolved ABSTAIN is an ABSTAIN_REVIEW; approving
    # releases the action (RELEASED) and is NOT an override of an abstain.
    assert cap["outcome_label"] == OutcomeLabel.ABSTAIN_REVIEW.value
    assert cap["outcome_kind"] == OutcomeKind.RELEASED.value
    assert cap["human_override"] is False
    assert cap["was_safe"] is True
    # Routed into the feedback loop and promoted to the tier a human reviewer
    # earns (VALIDATED — calibration-eligible).
    assert cap["ingested"] is True
    assert cap["quarantined"] is False
    assert cap["trust_level"] == OutcomeTrustLevel.VALIDATED.value
    assert cap["reputation_updated"] is True
    # Provably tied to the sealed act: the outcome's parent link IS the
    # resolution's record_hash.
    assert cap["parent_record_hash"] == body["anchor_sha256"]
    assert len(cap["outcome_evidence_hash"]) == 64

    # The outcome is actually in the live store (same instance the
    # orchestrator persists through), at human-reviewer / audit-sign-off trust.
    stored = client.app.state.outcome_store.list_for_decision(held.decision_id)
    assert len(stored) == 1
    out = stored[0]
    assert out.source_type is OutcomeSourceType.HUMAN_REVIEWER
    assert out.verification_method is VerificationMethod.AUDIT_SIGN_OFF
    assert out.trust_level is OutcomeTrustLevel.VALIDATED
    assert out.label is OutcomeLabel.ABSTAIN_REVIEW
    assert out.reporter == "operator@example.com"
    assert str(out.outcome_id) == cap["outcome_id"]
    assert out.confidence_score == 1.0

    # The outcome evidence row exists in the chain, parent-linked by hash.
    records = client.app.state.evidence_recorder.read_all()
    outcome_rows = [r for r in records if r.record_type == "outcome"
                    and str(r.decision_id) == str(held.decision_id)]
    assert len(outcome_rows) == 1
    payload = client.app.state.evidence_recorder.decode_payload(outcome_rows[0])
    assert payload["parent_evidence_hash"] == body["anchor_sha256"]
    assert payload["label"] == OutcomeLabel.ABSTAIN_REVIEW.value
    assert payload["metadata"]["auto_sealed"] is True
    assert payload["metadata"]["human_verdict"] == "approved"


def test_refused_hold_is_blocked_outcome_was_unsafe():
    client = TestClient(create_app())
    held = _decision(Verdict.ABSTAIN)
    body = _seed_and_seal(client, held, verdict="refused").json()
    cap = body["outcome_capture"]
    assert cap["status"] == "captured"
    assert cap["outcome_kind"] == OutcomeKind.BLOCKED.value
    assert cap["outcome_label"] == OutcomeLabel.ABSTAIN_REVIEW.value
    assert cap["was_safe"] is False
    assert cap["human_override"] is False


def test_held_hold_is_escalated_outcome_safety_unknown():
    client = TestClient(create_app())
    held = _decision(Verdict.ABSTAIN)
    cap = _seed_and_seal(client, held, verdict="held").json()["outcome_capture"]
    assert cap["status"] == "captured"
    assert cap["outcome_kind"] == OutcomeKind.ESCALATED.value
    assert cap["was_safe"] is None
    # safety unknown ⇒ reputation is not updated (no ground-truth comparison).
    assert cap["reputation_updated"] is False


# --------------------------------------------------------------------------- #
# 2. Override semantics — reversing a TERMINAL verdict is an override
# --------------------------------------------------------------------------- #


def test_human_approves_a_forbid_is_false_forbid_override():
    client = TestClient(create_app())
    forbid = _decision(Verdict.FORBID, score=0.95)
    cap = _seed_and_seal(client, forbid, verdict="approved").json()["outcome_capture"]
    assert cap["status"] == "captured"
    assert cap["outcome_kind"] == OutcomeKind.OVERRIDDEN.value
    assert cap["human_override"] is True
    assert cap["outcome_label"] == OutcomeLabel.FALSE_FORBID.value
    assert cap["was_safe"] is True


def test_human_refuses_a_permit_is_false_permit_override():
    client = TestClient(create_app())
    permit = _decision(Verdict.PERMIT)
    cap = _seed_and_seal(client, permit, verdict="refused").json()["outcome_capture"]
    assert cap["status"] == "captured"
    assert cap["outcome_kind"] == OutcomeKind.OVERRIDDEN.value
    assert cap["human_override"] is True
    assert cap["outcome_label"] == OutcomeLabel.FALSE_PERMIT.value
    assert cap["was_safe"] is False


@pytest.mark.parametrize(
    "decision_verdict,human,exp_kind,exp_safe,exp_override,exp_label",
    [
        (Verdict.ABSTAIN, "approved", OutcomeKind.RELEASED, True, False, OutcomeLabel.ABSTAIN_REVIEW),
        (Verdict.ABSTAIN, "refused", OutcomeKind.BLOCKED, False, False, OutcomeLabel.ABSTAIN_REVIEW),
        (Verdict.ABSTAIN, "held", OutcomeKind.ESCALATED, None, False, OutcomeLabel.ABSTAIN_REVIEW),
        (Verdict.FORBID, "approved", OutcomeKind.OVERRIDDEN, True, True, OutcomeLabel.FALSE_FORBID),
        (Verdict.FORBID, "refused", OutcomeKind.BLOCKED, False, False, OutcomeLabel.CORRECT_FORBID),
        (Verdict.PERMIT, "approved", OutcomeKind.RELEASED, True, False, OutcomeLabel.CORRECT_PERMIT),
        (Verdict.PERMIT, "refused", OutcomeKind.OVERRIDDEN, False, True, OutcomeLabel.FALSE_PERMIT),
    ],
)
def test_mapping_matches_validator_label_for_every_combo(
    decision_verdict, human, exp_kind, exp_safe, exp_override, exp_label
):
    kind, was_safe, override = map_resolution_to_outcome(
        decision_verdict=decision_verdict, human_verdict=human
    )
    assert (kind, was_safe, override) == (exp_kind, exp_safe, exp_override)
    # The OVERRIDDEN ⇒ human_override invariant holds by construction, and the
    # label the domain classifier derives matches the table.
    assert override == (kind is OutcomeKind.OVERRIDDEN)
    out = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=decision_verdict,
        outcome_kind=kind,
        was_safe=was_safe,
        human_override=override,
    )
    assert out.label is exp_label  # constructs without ValidationError too


# --------------------------------------------------------------------------- #
# 3. Capture is never silently skippable
# --------------------------------------------------------------------------- #


def test_capture_failure_still_seals_but_warns_loudly():
    client = TestClient(create_app())
    # Simulate a broken/missing learning stack on this app instance.
    client.app.state.learning_orchestrator = None
    held = _decision(Verdict.ABSTAIN)

    sealed = _seed_and_seal(client, held, verdict="approved")
    # The human's act is NOT lost — the seal still succeeds...
    assert sealed.status_code == 201
    cap = sealed.json()["outcome_capture"]
    # ...but the failure is explicit, not swallowed.
    assert cap["status"] == "degraded"
    assert cap["warning"]
    # And nothing was minted into the store.
    assert client.app.state.outcome_store.list_for_decision(held.decision_id) == ()


def test_flag_off_disables_mint_and_reports_it(monkeypatch):
    monkeypatch.setenv("TEX_AUTOSEAL_OUTCOME", "0")
    client = TestClient(create_app())
    held = _decision(Verdict.ABSTAIN)

    sealed = _seed_and_seal(client, held, verdict="approved")
    assert sealed.status_code == 201
    cap = sealed.json()["outcome_capture"]
    assert cap["status"] == "disabled"
    # No outcome minted when the operator opts out.
    assert client.app.state.outcome_store.list_for_decision(held.decision_id) == ()


def test_unknown_decision_still_404_with_capture_wired():
    client = TestClient(create_app())
    resp = client.post(
        f"/decisions/{uuid4()}/seal",
        json={"verdict": "approved", "resolved_by": "x"},
    )
    assert resp.status_code == 404
