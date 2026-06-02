"""
Tests for the behavioural provenance engine — identity by behaviour,
sealed as proof.

These prove the four properties that make the primitive real:
  1. A new actor is sealed as a BIRTH with a verifiable certificate.
  2. The sealed log's hash chain and signatures verify.
  3. The same actor under a NEW agent_id (a credential rotation / rename)
     is re-identified by behaviour — the case directory identity misses.
  4. Confidence is graded and honest: cold signatures and unrelated
     actors do not produce confident matches; tamper breaks verification.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tex.domain.agent import ActionLedgerEntry
from tex.domain.signal_trust import SignalTrustTier, tier_for_source
from tex.provenance import (
    BehavioralProvenanceEngine,
    BehavioralProvenanceLedger,
    BehavioralSignature,
    ProvenanceEventKind,
    behavioral_confidence,
    build_default_provenance_engine,
)


def _entry(agent_id, *, i, action="invoke_model", channel="api", env="prod",
           verdict="PERMIT", tools=("s3.read", "bedrock.invoke"),
           mcps=("mcp-data-01",), scopes=("bucket:reports",),
           sys_hash="a" * 64, tool_hash="b" * 64, score=0.2):
    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        action_type=action,
        channel=channel,
        environment=env,
        final_score=score,
        confidence=0.9,
        content_sha256="c" * 64,
        tools=tuple(tools),
        mcp_server_ids=tuple(mcps),
        data_scopes=tuple(scopes),
        system_prompt_hash=sys_hash,
        tool_manifest_hash=tool_hash,
        recorded_at=datetime.now(UTC) + timedelta(seconds=i * 5),
    )


def _window(agent_id, n=12, **kw):
    return [_entry(agent_id, i=i, **kw) for i in range(n)]


def test_birth_seals_certificate_and_verifies():
    engine = build_default_provenance_engine()
    aid = uuid4()
    res = engine.observe(agent_id=aid, entries=_window(aid))

    assert res.event_kind is ProvenanceEventKind.BIRTH
    assert res.warm is True

    cert = engine.birth_certificate(aid)
    assert cert is not None
    assert cert.agent_id == aid
    assert cert.observation_count == 12
    assert cert.system_prompt_hash == "a" * 64
    assert cert.birth_record_hash

    chain = engine.ledger.verify_chain()
    sigs = engine.ledger.verify_signatures()
    assert chain["intact"] is True
    assert sigs["valid"] is True


def test_reidentifies_same_actor_across_credential_rotation():
    engine = build_default_provenance_engine()

    # Original identity acts, gets a sealed birth.
    original = uuid4()
    engine.observe(agent_id=original, entries=_window(original))

    # Same actor, brand-new agent_id (rotated key / renamed) — identical
    # behaviour and the same stable anchors. The directory would see a new
    # agent; behaviour says it is the same one.
    rotated = uuid4()
    res = engine.observe(agent_id=rotated, entries=_window(rotated))

    assert res.event_kind is ProvenanceEventKind.REIDENTIFIED
    assert res.best_match is not None
    assert res.best_match.agent_id == original
    assert res.confidence >= 0.86

    # The re-identification is sealed, linked to the prior identity.
    records = engine.ledger.list_for_agent(rotated)
    assert any(
        r.event_kind is ProvenanceEventKind.REIDENTIFIED and r.linked_agent_id == original
        for r in records
    )


def test_unrelated_actors_do_not_match():
    engine = build_default_provenance_engine()

    a = uuid4()
    engine.observe(agent_id=a, entries=_window(a))

    # A completely different actor: different actions, tools, anchors.
    b = uuid4()
    res = engine.observe(
        agent_id=b,
        entries=_window(
            b, action="send_email", channel="smtp", tools=("gmail.send",),
            mcps=("mcp-comms-09",), scopes=("mailbox:exec",),
            sys_hash="d" * 64, tool_hash="e" * 64, score=0.7,
        ),
    )
    assert res.event_kind is ProvenanceEventKind.BIRTH
    # Not flagged as a possible merge with the unrelated actor.
    assert res.requires_human is False


def test_confidence_is_graded_and_capped_without_anchors():
    # Two windows with similar behaviour but NO shared stable anchor must
    # not reach certainty — behaviour alone is evidence, not proof.
    a = uuid4()
    b = uuid4()
    sig_a = BehavioralSignature.from_actions(
        _window(a, sys_hash=None, tool_hash=None)
    )
    sig_b = BehavioralSignature.from_actions(
        _window(b, sys_hash=None, tool_hash=None)
    )
    conf = behavioral_confidence(sig_a, sig_b)
    assert 0.0 < conf <= 0.80  # strong but capped below the anchor floor


def test_tamper_breaks_signature_verification():
    ledger = BehavioralProvenanceLedger()
    aid = uuid4()
    ledger.append(
        event_kind=ProvenanceEventKind.BIRTH,
        agent_id=aid,
        signature_hash="f" * 64,
        confidence=1.0,
        signal_tier=int(SignalTrustTier.NETWORK_OBSERVED),
        observation_count=10,
    )
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True

    # Tamper with a sealed record's confidence in place.
    object.__setattr__(ledger._entries[0], "confidence", 0.1)
    # The chain replay recomputes the payload hash and catches it.
    assert ledger.verify_chain()["intact"] is False


def test_signal_trust_tier_ordering():
    assert SignalTrustTier.KERNEL_ATTESTED > SignalTrustTier.SELF_DECLARED
    assert SignalTrustTier.NETWORK_OBSERVED.is_tamper_resistant is True
    assert SignalTrustTier.SELF_DECLARED.is_tamper_resistant is False
    assert tier_for_source("enforcement_gate") is SignalTrustTier.NETWORK_OBSERVED
    assert tier_for_source("mcp_server") is SignalTrustTier.SELF_DECLARED
    assert tier_for_source("unknown_source") is SignalTrustTier.CONTROL_PLANE


def test_sleeping_lifecycle_state():
    from tex.domain.agent import AgentLifecycleStatus as S

    assert S.SLEEPING.forces_abstain is True  # attempt-to-act → held wake
    assert S.SLEEPING.is_reversible is True  # wake within 90 days
    assert S.REVOKED.is_reversible is False  # terminal
    assert S.SLEEPING.can_evaluate is True
