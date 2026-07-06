"""
Tests for the Layer-5 evidence completion wires (June 2026):

  1. Post-quantum chain signer (tex.evidence.seal) — composite ML-DSA-65 +
     Ed25519 when a backend is present, honest classical fallback otherwise.
  2. SCITT refusal receipt on FORBID, recorded inline in the evidence chain.
  3. The verdict-seal endpoint: POST /decisions/{id}/seal — a held decision
     sealed by a named human act, returning a verifiable anchor.

These exercise the live wiring, not the dormant library: the recorder embeds
the signature, the gate builds the refusal context, and the API seals.
"""

from __future__ import annotations

import json
import tempfile
from uuid import uuid4

import pytest

from tex.commands.evaluate_action import EvaluateActionCommand
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.evidence.recorder import EvidenceRecorder
from tex.evidence.seal import (
    PQ_SIGNATURE_FIELD,
    build_evidence_chain_signer,
    verify_payload_signature,
)
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


def _decision(verdict: Verdict, *, score: float, reasons: list[str]) -> Decision:
    return Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=score,
        action_type="send_email",
        channel="email",
        environment="production",
        content_excerpt="hello",
        content_sha256="a" * 64,
        policy_version="v1",
        reasons=reasons,
        uncertainty_flags=(["low_conf"] if verdict is Verdict.ABSTAIN else []),
    )


# --------------------------------------------------------------------------- #
# 1. Post-quantum chain signer
# --------------------------------------------------------------------------- #


def test_chain_signer_round_trip_and_tamper():
    d = tempfile.mkdtemp()
    signer = build_evidence_chain_signer(key_dir=d)
    # A decision-shaped payload carries floats; signing must not choke on them.
    payload = {"record_type": "decision", "final_score": 0.731, "verdict": "FORBID"}
    payload[PQ_SIGNATURE_FIELD] = signer.sign_payload(payload)

    assert verify_payload_signature(payload) is True

    tampered = dict(payload)
    tampered["verdict"] = "PERMIT"
    assert verify_payload_signature(tampered) is False


def test_chain_signer_persists_key_across_builds():
    d = tempfile.mkdtemp()
    a = build_evidence_chain_signer(key_dir=d)
    b = build_evidence_chain_signer(key_dir=d)
    assert a.key.key_id == b.key.key_id
    assert a.algorithm == b.algorithm


def test_chain_signer_fallback_is_honestly_labelled():
    # Forcing ECDSA as the preferred algorithm simulates a host without an
    # ML-DSA backend. The label must be the classical algorithm, never the
    # post-quantum one — a signature is never mislabelled.
    d = tempfile.mkdtemp()
    signer = build_evidence_chain_signer(
        key_dir=d, preferred_algorithm=SignatureAlgorithm.ECDSA_P256
    )
    assert signer.is_post_quantum is False
    payload = {"x": 1}
    payload[PQ_SIGNATURE_FIELD] = signer.sign_payload(payload)
    assert payload[PQ_SIGNATURE_FIELD]["algorithm"] == SignatureAlgorithm.ECDSA_P256.value
    assert verify_payload_signature(payload) is True


def test_missing_signature_block_does_not_verify():
    assert verify_payload_signature({"no": "signature"}) is False


# --------------------------------------------------------------------------- #
# 2. Recorder embeds the signature; backward compatible without a signer
# --------------------------------------------------------------------------- #


def test_recorder_without_signer_is_unchanged():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl")  # no chain_signer
    record = rec.record_decision(_decision(Verdict.PERMIT, score=0.1, reasons=[]))
    payload = json.loads(record.payload_json)
    assert PQ_SIGNATURE_FIELD not in payload
    assert len(record.record_hash) == 64


def test_recorder_with_signer_embeds_verifiable_signature():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl", chain_signer=build_evidence_chain_signer(key_dir=d))
    record = rec.record_decision(_decision(Verdict.FORBID, score=0.95, reasons=["blocked"]))
    payload = json.loads(record.payload_json)
    assert PQ_SIGNATURE_FIELD in payload
    assert verify_payload_signature(payload) is True


def test_human_resolution_seal_is_signed_and_linked():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl", chain_signer=build_evidence_chain_signer(key_dir=d))
    held = _decision(Verdict.ABSTAIN, score=0.5, reasons=["needs human"])
    decision_rec = rec.record_decision(held)
    seal = rec.record_human_resolution(
        held,
        verdict="approved",
        resolved_by="operator@example.com",
        note="reviewed",
        parent_evidence_hash=decision_rec.record_hash,
    )
    payload = json.loads(seal.payload_json)
    assert payload["record_type"] == "human_resolution"
    assert payload["human_verdict"] == "approved"
    assert payload["resolved_by"] == "operator@example.com"
    assert payload["parent_evidence_hash"] == decision_rec.record_hash
    assert seal.previous_hash == decision_rec.record_hash
    assert verify_payload_signature(payload) is True


def test_human_resolution_rejects_bad_input():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl")
    held = _decision(Verdict.ABSTAIN, score=0.5, reasons=["x"])
    with pytest.raises(ValueError):
        rec.record_human_resolution(held, verdict="maybe", resolved_by="x")
    with pytest.raises(ValueError):
        rec.record_human_resolution(held, verdict="approved", resolved_by="  ")


# --------------------------------------------------------------------------- #
# 3. SCITT refusal receipt on FORBID
# --------------------------------------------------------------------------- #


def test_refusal_context_only_on_forbid():
    forbid = EvaluateActionCommand._build_refusal_context(
        _decision(Verdict.FORBID, score=0.95, reasons=["destructive action blocked"])
    )
    assert forbid is not None
    assert forbid.refusal_event.event_type == "PRE_GENERATION"
    assert forbid.refusal_event.rationale == "destructive action blocked"

    assert EvaluateActionCommand._build_refusal_context(
        _decision(Verdict.PERMIT, score=0.1, reasons=[])
    ) is None
    assert EvaluateActionCommand._build_refusal_context(
        _decision(Verdict.ABSTAIN, score=0.5, reasons=["x"])
    ) is None


def test_forbid_record_carries_scitt_block():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl", chain_signer=build_evidence_chain_signer(key_dir=d))
    forbid = _decision(Verdict.FORBID, score=0.95, reasons=["destructive action blocked"])
    ctx = EvaluateActionCommand._build_refusal_context(forbid)
    record = rec.record_decision(forbid, c2pa_context=ctx)
    payload = json.loads(record.payload_json)
    assert "scitt" in payload
    assert payload["scitt"]["spec"] == "draft-kamimura-scitt-refusal-events-02"
    assert payload["scitt"]["refusal_event"]["rationale"] == "destructive action blocked"
    # Still signed and still verifiable with the scitt block present.
    assert verify_payload_signature(payload) is True


def test_permit_record_has_no_scitt():
    d = tempfile.mkdtemp()
    rec = EvidenceRecorder(d + "/ev.jsonl")
    permit = _decision(Verdict.PERMIT, score=0.1, reasons=[])
    ctx = EvaluateActionCommand._build_refusal_context(permit)
    payload = json.loads(rec.record_decision(permit, c2pa_context=ctx).payload_json)
    assert "scitt" not in payload


# --------------------------------------------------------------------------- #
# 4. Verdict-seal endpoint (POST /decisions/{id}/seal)
# --------------------------------------------------------------------------- #


def test_seal_endpoint_end_to_end():
    from fastapi.testclient import TestClient
    from tex.main import create_app

    client = TestClient(create_app())

    ev = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "content": "Following up on our meeting.",
            "channel": "email",
            "environment": "production",
            "recipient": "buyer@target.example",
        },
    )
    assert ev.status_code == 200
    decision_id = ev.json()["decision_id"]

    sealed = client.post(
        f"/decisions/{decision_id}/seal",
        json={"verdict": "approved", "resolved_by": "operator@example.com", "note": "ok"},
    )
    assert sealed.status_code == 201
    body = sealed.json()
    assert body["human_verdict"] == "approved"
    assert body["resolved_by"] == "operator@example.com"
    assert len(body["anchor_sha256"]) == 64
    assert body["pq_signature"] is not None
    assert body["pq_signature"]["public_key_b64"]

    # Unknown decision -> 404; bad verdict -> 422.
    assert client.post(
        f"/decisions/{uuid4()}/seal",
        json={"verdict": "approved", "resolved_by": "x"},
    ).status_code == 404
    assert client.post(
        f"/decisions/{decision_id}/seal",
        json={"verdict": "maybe", "resolved_by": "x"},
    ).status_code == 422


# --------------------------------------------------------------------------- #
# 5. Sealing resolves the held queue (the sealed hold stops re-surfacing)
# --------------------------------------------------------------------------- #


def _held(decision_id: str, *, tenant: str = "default"):
    from tex.provenance.feed import HeldDecision

    return HeldDecision(
        agent_id=uuid4(),
        kind="pdp_abstain",
        confidence=0.5,
        note="needs a human",
        decision_id=decision_id,
        tenant_id=tenant,
    )


def test_resolve_decision_drops_matching_held_and_is_idempotent():
    from tex.provenance.feed import HeldDecisionSink

    sink = HeldDecisionSink()
    did = str(uuid4())
    other = str(uuid4())
    sink.append(_held(did))
    sink.append(_held(other))

    # First seal drops exactly the one matching hold...
    assert sink.resolve_decision(did) == 1
    remaining = {h.decision_id for h in sink.peek()}
    assert remaining == {other}

    # ...sealing the same id again removes nothing (idempotent, no error)...
    assert sink.resolve_decision(did) == 0
    # ...and an id that never had a sink entry is a no-op, not a raise.
    assert sink.resolve_decision(str(uuid4())) == 0
    # An empty / missing id is a safe no-op too.
    assert sink.resolve_decision("") == 0


def test_resolve_decision_is_tenant_scoped():
    from tex.provenance.feed import HeldDecisionSink

    sink = HeldDecisionSink()
    did = str(uuid4())
    sink.append(_held(did, tenant="acme"))

    # A different tenant cannot resolve acme's hold...
    assert sink.resolve_decision(did, tenant="globex") == 0
    assert len(sink) == 1
    # ...acme resolves its own...
    assert sink.resolve_decision(did, tenant="acme") == 1
    assert len(sink) == 0

    # The operator/fleet scope (None / "default") may resolve any tenant's hold.
    sink.append(_held(did, tenant="acme"))
    assert sink.resolve_decision(did, tenant=None) == 1
    assert len(sink) == 0


def test_seal_endpoint_removes_the_hold_from_the_live_sink():
    from fastapi.testclient import TestClient

    from tex.main import create_app

    app = create_app()
    client = TestClient(app)

    ev = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "content": "Following up on our meeting.",
            "channel": "email",
            "environment": "production",
            "recipient": "buyer@target.example",
        },
    )
    assert ev.status_code == 200
    decision_id = ev.json()["decision_id"]

    # Put a real held row for this decision into the live sink the vigil
    # headline and /held both read.
    sink = app.state.held_decision_sink
    sink.append(_held(decision_id))
    assert any(h.decision_id == decision_id for h in sink.peek())

    sealed = client.post(
        f"/decisions/{decision_id}/seal",
        json={"verdict": "approved", "resolved_by": "operator@example.com"},
    )
    assert sealed.status_code == 201

    # The sealed hold no longer re-surfaces: /held drops it and the headline
    # stops counting it (both read this sink).
    assert not any(h.decision_id == decision_id for h in sink.peek())
