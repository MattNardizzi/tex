"""
The /v1/ask pipeline must answer ONLY from sealed facts. These tests drive
``voice_ask.answer_question`` against a seeded decision store and assert the
spoken answer is byte-identical to the sealed count, that every un-groundable
question resolves to a fixed honest-decline (never a guessed number), and that a
record query asserting a wrong verdict is refused.
"""

from __future__ import annotations

import hashlib
import types
from uuid import UUID, uuid4

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore
from tex.voice import answer_forms, voice_ask


def _decision(verdict: Verdict, *, decision_id: UUID | None = None, content: str = "x") -> Decision:
    sha = hashlib.sha256(content.encode()).hexdigest()
    # An ABSTAIN decision must carry at least one uncertainty flag (domain rule).
    flags = ["low_confidence"] if verdict is Verdict.ABSTAIN else []
    return Decision(
        decision_id=decision_id or uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.5,
        action_type="send_email",
        channel="email",
        environment="production",
        content_excerpt=content,
        content_sha256=sha,
        policy_version="test-1",
        uncertainty_flags=flags,
        evidence_hash="e" * 64,
    )


def _request_with(store: InMemoryDecisionStore) -> types.SimpleNamespace:
    state = types.SimpleNamespace(decision_store=store)
    return types.SimpleNamespace(app=types.SimpleNamespace(state=state))


def test_dimension_answer_is_byte_identical_to_sealed_count() -> None:
    store = InMemoryDecisionStore()
    for _ in range(3):
        store.save(_decision(Verdict.FORBID))
    store.save(_decision(Verdict.PERMIT))  # not forbidden — must not be counted
    req = _request_with(store)

    out = voice_ask.answer_question(req, transcript="how many actions were forbidden", tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert out.answer == "3 actions were forbidden in the recent window."
    assert out.routed_dimension == "execution"
    assert out.object is None  # a count is meaning, not a handle
    assert out.attestation_anchor and len(out.attestation_anchor) == 64
    assert out.gate["verdict"] == "PERMIT"


def test_human_decision_count() -> None:
    store = InMemoryDecisionStore()
    for _ in range(2):
        store.save(_decision(Verdict.ABSTAIN))
    req = _request_with(store)
    out = voice_ask.answer_question(req, transcript="what is waiting on a human decision", tenant=None)
    assert out.answer == "2 actions are waiting on a human decision."
    assert out.verdict is Verdict.PERMIT


def test_no_route_abstains_with_fixed_sentence() -> None:
    req = _request_with(InMemoryDecisionStore())
    out = voice_ask.answer_question(req, transcript="qwerty zxcvb foobar", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE
    assert out.object is None


def test_empty_transcript_abstains() -> None:
    req = _request_with(InMemoryDecisionStore())
    out = voice_ask.answer_question(req, transcript="", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_ROUTE


def test_record_not_found_abstains() -> None:
    req = _request_with(InMemoryDecisionStore())
    missing = str(uuid4())
    out = voice_ask.answer_question(req, transcript=f"tell me about decision {missing}", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_RECORD


def test_record_found_permits_with_hash_object() -> None:
    store = InMemoryDecisionStore()
    did = uuid4()
    dec = _decision(Verdict.FORBID, decision_id=did, content="sensitive")
    store.save(dec)
    req = _request_with(store)

    out = voice_ask.answer_question(req, transcript=f"what about decision {did}", tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert out.answer == f"Decision {did} resolved to FORBID."
    assert out.object == {"value": dec.content_sha256, "kind": "hash"}
    assert out.proof_ref["kind"] == "decision"


def test_record_query_asserting_wrong_verdict_is_refused() -> None:
    store = InMemoryDecisionStore()
    did = uuid4()
    store.save(_decision(Verdict.FORBID, decision_id=did))
    req = _request_with(store)

    # The speaker asserts "permit" about a record that was FORBID → FORBID.
    out = voice_ask.answer_question(req, transcript=f"was decision {did} a permit", tenant=None)
    assert out.verdict is Verdict.FORBID
    assert out.answer == answer_forms.FORBID_CONTRADICTION
    assert out.object is None


def test_dimension_with_no_sealed_fact_abstains() -> None:
    # Empty store → execution facts headline still renders "0 ..."; but a
    # dimension whose store is absent (monitoring needs connector_health_store,
    # not attached here) yields empty facts → honest decline.
    req = _request_with(InMemoryDecisionStore())
    out = voice_ask.answer_question(req, transcript="are any connectors not reporting", tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_FACT


def test_every_outcome_is_attested() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(Verdict.FORBID))
    req = _request_with(store)
    # Drive several outcomes and confirm the attestation chain grows + verifies.
    voice_ask.answer_question(req, transcript="how many forbidden", tenant=None)
    voice_ask.answer_question(req, transcript="qwerty", tenant=None)
    attestor = req.app.state.voice_attestor
    assert len(attestor) == 2
    assert attestor.verify_chain()["intact"] is True
    assert attestor.verify_signatures()["valid"] is True
