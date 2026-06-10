"""
SealedFactLedger — the typed, proof-carrying generalization of the
transparency log (PCVR).

Pins the sealed-truth-object contract:

  * a SealedFact of any kind can be sealed, optionally carrying a
    CombinedEvidence e-value proof;
  * the hash chain proves integrity (reordering / deletion / payload tamper —
    including tamper INSIDE the embedded proof — breaks replay);
  * the per-record signature proves authorship (offline, public key only);
  * the existing BehavioralProvenanceLedger is untouched and still works.

The crypto honesty: the live signer is ECDSA-P256; the chain (not a lone
signature) proves integrity. These tests check both, separately.
"""

from __future__ import annotations

import math
from uuid import uuid4

from tex.domain.evidence import (
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.provenance.ledger import BehavioralProvenanceLedger, SealedFactLedger
from tex.provenance.models import (
    ProvenanceEventKind,
    SealedFact,
    SealedFactKind,
)


def _combined_proof() -> "object":
    items = [
        TexEvidence(
            stream_id="drift",
            kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=math.log(20.0),
            null_hypothesis_id="drift:no_regime_change",
            filtration_id="drift:risk_stream",
            sequentially_predictable=True,
        )
    ]
    return compose_arithmetic_mean(items)


def _decision_fact(*, claim: str = "decision X resolved to ABSTAIN") -> SealedFact:
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=str(uuid4()),
        claim=claim,
        evidence=_combined_proof(),
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        detail={"verdict": "ABSTAIN"},
    )


def _identity_fact() -> SealedFact:
    # a fact with NO e-value proof (an IDENTITY birth) — must still seal.
    return SealedFact(
        kind=SealedFactKind.IDENTITY,
        subject_id=str(uuid4()),
        claim="agent born; behavioural signature anchored",
        maturity=EvidenceMaturity.PRODUCTION,
    )


# --------------------------------------------------------------------------- #
# append + read
# --------------------------------------------------------------------------- #
def test_append_returns_chained_signed_pcvr() -> None:
    led = SealedFactLedger()
    r0 = led.append(_decision_fact())
    r1 = led.append(_identity_fact())

    assert r0.sequence == 0 and r0.previous_hash is None
    assert r1.sequence == 1 and r1.previous_hash == r0.record_hash
    assert r0.signing_key_id == led.signing_key_id
    assert len(led) == 2


def test_list_by_kind() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    led.append(_identity_fact())
    led.append(_decision_fact())
    assert len(led.list_by_kind(SealedFactKind.DECISION)) == 2
    assert len(led.list_by_kind(SealedFactKind.IDENTITY)) == 1
    assert led.list_by_kind(SealedFactKind.BLAME) == ()


def test_fact_carries_evidence_proof() -> None:
    led = SealedFactLedger()
    rec = led.append(_decision_fact())
    assert rec.fact.evidence is not None
    assert rec.fact.evidence.is_true_e_value is True
    # the proof's e-value round-trips through the sealed record
    assert rec.fact.evidence.e_value > 1.0


# --------------------------------------------------------------------------- #
# chain integrity
# --------------------------------------------------------------------------- #
def test_chain_intact_on_clean_log() -> None:
    led = SealedFactLedger()
    for _ in range(5):
        led.append(_decision_fact())
    res = led.verify_chain()
    assert res == {"intact": True, "checked": 5, "break_at": None}


def test_chain_detects_payload_tamper() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    led.append(_decision_fact())
    # Tamper: swap the wrapped fact for one with a different claim, keeping the
    # stale hashes — replay must catch it because payload_sha256 is recomputed.
    tampered = led._entries[1].model_copy(
        update={"fact": _decision_fact(claim="decision X resolved to PERMIT")}
    )
    led._entries[1] = tampered
    res = led.verify_chain()
    assert res["intact"] is False
    assert res["break_at"] == 1


def test_chain_detects_reorder() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    led.append(_identity_fact())
    led._entries[0], led._entries[1] = led._entries[1], led._entries[0]
    assert led.verify_chain()["intact"] is False


# --------------------------------------------------------------------------- #
# signature authenticity
# --------------------------------------------------------------------------- #
def test_signatures_valid_and_verifiable_with_public_key_only() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    led.append(_identity_fact())
    pub = led.public_key_pem
    res = led.verify_signatures(pub)
    assert res == {"valid": True, "checked": 2, "invalid_at": None}


def test_signature_detects_record_hash_tamper() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    bad = led._entries[0].model_copy(update={"record_hash": "0" * 64})
    led._entries[0] = bad
    assert led.verify_signatures()["valid"] is False


# --------------------------------------------------------------------------- #
# the existing behavioural ledger is untouched
# --------------------------------------------------------------------------- #
def test_behavioral_ledger_still_works() -> None:
    led = BehavioralProvenanceLedger()
    led.append(
        event_kind=ProvenanceEventKind.BIRTH,
        agent_id=uuid4(),
        signature_hash="abc",
    )
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True
