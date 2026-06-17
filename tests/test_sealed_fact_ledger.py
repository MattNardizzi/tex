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

import base64
import math
from uuid import uuid4

import pytest

from tex.domain.evidence import (
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.ml_dsa import active_backend_id
from tex.provenance.ledger import BehavioralProvenanceLedger, SealedFactLedger
from tex.provenance.models import (
    ProvenanceEventKind,
    SealedFact,
    SealedFactKind,
)

_HAS_PQ = active_backend_id() is not None
_ECDSA = SignatureAlgorithm.ECDSA_P256.value
_MLDSA = SignatureAlgorithm.ML_DSA_65.value


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


# --------------------------------------------------------------------------- #
# post-quantum dual signing (ECDSA-P256 + ML-DSA-65, FIPS 204)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_new_seals_are_dual_signed() -> None:
    led = SealedFactLedger()
    assert led.is_dual_signed is True
    assert [k.algorithm for k in led.seal_public_keys] == [_ECDSA, _MLDSA]

    rec = led.append(_decision_fact())
    assert rec.seal_envelope is not None
    assert rec.seal_envelope.is_dual is True
    assert rec.seal_envelope.algorithms() == (_ECDSA, _MLDSA)
    # the legacy ECDSA field is mirrored byte-for-byte in the envelope (the
    # backward-compatible signature is reused, not re-signed)
    assert rec.signature_b64 == rec.seal_envelope.signature_for(_ECDSA).signature_b64

    res = led.verify_seal_envelopes()
    assert res == {
        "dual_signed": True,
        "ecdsa_valid": True,
        "pq_valid": True,
        "checked": 1,
        "invalid_at": None,
        "mismatch_at": None,
    }


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_dual_signing_leaves_the_hash_chain_byte_identical() -> None:
    # THE backward-compat invariant (requirement 2): adding the ML-DSA signature
    # must not change payload_sha256 or record_hash. Two ledgers sharing one
    # ECDSA key — one dual-signed, one legacy ECDSA-only — must produce identical
    # chains over identical facts.
    shared = EcdsaP256Provider().generate_keypair("shared-ecdsa")
    facts = [_decision_fact(claim=f"verdict {i}") for i in range(4)]

    dual = SealedFactLedger(signing_key=shared, enable_pq=True)
    legacy = SealedFactLedger(signing_key=shared, enable_pq=False)
    dual_recs = [dual.append(f) for f in facts]
    legacy_recs = [legacy.append(f) for f in facts]

    assert dual.is_dual_signed is True
    assert legacy.is_dual_signed is False
    for d, leg in zip(dual_recs, legacy_recs, strict=True):
        assert d.payload_sha256 == leg.payload_sha256
        assert d.record_hash == leg.record_hash
        assert d.previous_hash == leg.previous_hash
    # the dual ledger carries envelopes; the legacy one does not
    assert all(r.seal_envelope is not None for r in dual_recs)
    assert all(r.seal_envelope is None for r in legacy_recs)
    # both chains verify
    assert dual.verify_chain()["intact"] is True
    assert legacy.verify_chain()["intact"] is True


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_verify_seal_envelopes_catches_pq_tamper() -> None:
    led = SealedFactLedger()
    led.append(_decision_fact())
    rec = led._entries[0]
    env = rec.seal_envelope
    pq = env.signature_for(_MLDSA)
    raw = bytearray(base64.b64decode(pq.signature_b64))
    raw[0] ^= 0x01
    from tex.provenance.models import SealEnvelope, SealSignature

    bad_env = SealEnvelope(
        seal_version=env.seal_version,
        signatures=(
            env.signature_for(_ECDSA),
            SealSignature(
                algorithm=_MLDSA,
                key_id=pq.key_id,
                signature_b64=base64.b64encode(bytes(raw)).decode("ascii"),
            ),
        ),
    )
    led._entries[0] = rec.model_copy(update={"seal_envelope": bad_env})

    # the chain and the legacy ECDSA signature are untouched (envelope is not in
    # the chain) — but the envelope check catches the PQ tamper.
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True
    res = led.verify_seal_envelopes()
    assert res["pq_valid"] is False
    assert res["mismatch_at"] == 0


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_behavioral_ledger_is_dual_signed_too() -> None:
    led = BehavioralProvenanceLedger()
    led.append(
        event_kind=ProvenanceEventKind.BIRTH, agent_id=uuid4(), signature_hash="abc"
    )
    assert led.is_dual_signed is True
    assert led._entries[0].seal_envelope.is_dual is True
    assert led.verify_signatures()["valid"] is True  # ECDSA path unchanged
    assert led.verify_seal_envelopes()["pq_valid"] is True


def test_pq_can_be_disabled_for_legacy_ecdsa_only() -> None:
    # Honest fallback path: a ledger explicitly without PQ behaves exactly like
    # before — no envelope, ECDSA-only — so existing verifiers are unaffected.
    led = SealedFactLedger(enable_pq=False)
    assert led.is_dual_signed is False
    assert led.pq_public_key is None
    rec = led.append(_decision_fact())
    assert rec.seal_envelope is None
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True
