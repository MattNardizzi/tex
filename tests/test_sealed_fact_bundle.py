"""
Offline evidence bundle + standalone verifier (the court-exhibit core).

Pins the verifier contract that matters in front of an auditor:

  * a bundle round-trips through plain JSON (portable, no Tex runtime needed);
  * a clean bundle verifies against the PINNED key — chain intact, signatures
    valid, compositions re-derived from components -> fully_replayable;
  * pinning is load-bearing: a wrong pinned key, or a bundle re-signed by an
    attacker with their own embedded key, FAILS — the seal proves authorship
    only against Tex's known key;
  * tamper anywhere (a fact, or a sealed e-value that lies about its
    components) is caught — by the chain, or by composition replay even when
    the chain and signature are intact.
"""

from __future__ import annotations

import base64
import math
from uuid import uuid4

import pytest

from tex.domain.evidence import (
    CombinedEvidence,
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.ml_dsa import active_backend_id
from tex.provenance.bundle import (
    SealedFactBundle,
    export_sealed_fact_bundle,
    verify_sealed_fact_bundle,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import (
    SealedFact,
    SealedFactKind,
    SealEnvelope,
    SealSignature,
)

_HAS_PQ = active_backend_id() is not None
_ECDSA = SignatureAlgorithm.ECDSA_P256.value
_MLDSA = SignatureAlgorithm.ML_DSA_65.value


def _components() -> list[TexEvidence]:
    return [
        TexEvidence(
            stream_id="drift",
            kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=math.log(2.0),
            null_hypothesis_id="drift:no_change",
            filtration_id="drift:s",
            sequentially_predictable=True,
        ),
        TexEvidence(
            stream_id="agent",
            kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=math.log(8.0),
            null_hypothesis_id="agent:on_baseline",
            filtration_id="agent:s",
            sequentially_predictable=True,
        ),
    ]


def _decision_fact(combined: CombinedEvidence) -> SealedFact:
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=str(uuid4()),
        claim="decision resolved with combined e-value",
        evidence=combined,
        maturity=EvidenceMaturity.RESEARCH_EARLY,
    )


def _ledger_with_one_fact() -> tuple[SealedFactLedger, list[TexEvidence]]:
    comps = _components()
    combined = compose_arithmetic_mean(comps)
    led = SealedFactLedger()
    led.append(_decision_fact(combined))
    return led, comps


# --------------------------------------------------------------------------- #
# portability + clean verification
# --------------------------------------------------------------------------- #
def test_bundle_round_trips_through_json() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="exhibit-A", components=tuple(comps))
    raw = bundle.to_json()
    back = SealedFactBundle.from_json(raw)
    assert back.export_name == "exhibit-A"
    assert len(back.records) == 1
    assert len(back.components) == 2


def test_clean_bundle_is_valid_and_fully_replayable() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    # serialize + reload to prove the verifier needs only the artifact + the key
    report = verify_sealed_fact_bundle(
        SealedFactBundle.from_json(bundle.to_json()),
        pinned_public_key_pem=led.public_key_pem,
    )
    assert report.is_valid is True
    assert report.fully_replayable is True
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    assert report.compositions_checked == 1
    assert report.compositions_ok == 1


def test_without_components_valid_but_not_fully_replayable() -> None:
    led, _ = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A")  # no components
    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True
    assert report.fully_replayable is False
    assert report.compositions_checked == 0
    assert report.not_recomputable == (0,)


# --------------------------------------------------------------------------- #
# pinning is load-bearing
# --------------------------------------------------------------------------- #
def test_wrong_pinned_key_fails() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    other_key = SealedFactLedger().public_key_pem  # a different key
    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=other_key)
    assert report.key_matches_pin is False
    assert report.signatures_valid is False
    assert report.is_valid is False


def test_attacker_resigned_bundle_is_caught_by_pin() -> None:
    # Tex's real bundle + the key you pin (Tex's known key).
    real_led, comps = _ledger_with_one_fact()
    pinned = real_led.public_key_pem

    # Attacker re-seals the SAME facts with THEIR OWN key and ships a bundle
    # that embeds their own public key as if it were Tex's.
    attacker_led = SealedFactLedger()
    for rec in real_led.list_all():
        attacker_led.append(rec.fact)
    forged = export_sealed_fact_bundle(
        attacker_led, export_name="forged", components=tuple(comps)
    )

    # Verified against Tex's PINNED key, the forgery fails on both axes.
    report = verify_sealed_fact_bundle(forged, pinned_public_key_pem=pinned)
    assert report.key_matches_pin is False  # embedded key != pinned
    assert report.signatures_valid is False  # signed by attacker, not Tex
    assert report.is_valid is False


# --------------------------------------------------------------------------- #
# tamper detection
# --------------------------------------------------------------------------- #
def test_tampered_fact_breaks_the_chain() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    # swap the wrapped fact for a different claim, keeping the stale hashes
    bad_rec = bundle.records[0].model_copy(
        update={"fact": _decision_fact(compose_arithmetic_mean(comps)).model_copy(
            update={"claim": "decision resolved DIFFERENTLY"}
        )}
    )
    tampered = bundle.model_copy(update={"records": (bad_rec,)})
    report = verify_sealed_fact_bundle(tampered, pinned_public_key_pem=led.public_key_pem)
    assert report.chain_intact is False
    assert report.chain_break_at == 0
    assert report.is_valid is False


def test_sealed_evalue_that_lies_about_components_is_caught() -> None:
    # A CombinedEvidence whose log_e_value does NOT match its components, but is
    # otherwise a self-consistent, properly sealed record (chain + signature
    # valid). Composition replay must catch the lie.
    comps = _components()
    honest = compose_arithmetic_mean(comps)
    lying = CombinedEvidence(
        combiner="arithmetic_mean",
        log_e_value=math.log(999.0),  # the lie (true mean e-value is 5)
        is_true_e_value=True,
        anytime_valid=False,
        joint_null_hypothesis_id=honest.joint_null_hypothesis_id,
        filtration_id="mixed",
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        component_ids=honest.component_ids,
        n_components=2,
    )
    led = SealedFactLedger()
    led.append(_decision_fact(lying))
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))

    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=led.public_key_pem)
    # chain + signature are valid (the lie was sealed honestly as bytes)...
    assert report.chain_intact is True
    assert report.signatures_valid is True
    assert report.key_matches_pin is True
    # ...but recomputing from components exposes it.
    assert report.composition_mismatches == (0,)
    assert report.is_valid is False


def test_multi_record_chain_verifies() -> None:
    led = SealedFactLedger()
    all_comps: list[TexEvidence] = []
    for _ in range(4):
        comps = _components()
        all_comps.extend(comps)
        led.append(_decision_fact(compose_arithmetic_mean(comps)))
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(all_comps))
    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=led.public_key_pem)
    assert report.record_count == 4
    assert report.is_valid is True
    assert report.fully_replayable is True
    assert report.compositions_ok == 4


# --------------------------------------------------------------------------- #
# post-quantum dual-signature bundle verification
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_dual_signed_bundle_is_pq_secured() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    # round-trip through JSON: the verifier needs only the artifact + pinned keys
    report = verify_sealed_fact_bundle(
        SealedFactBundle.from_json(bundle.to_json()),
        pinned_public_key_pem=led.public_key_pem,
        pinned_seal_keys={_MLDSA: led.pq_public_key},
    )
    assert report.is_valid is True
    assert report.dual_signed is True
    assert report.seal_versions == ("2",)
    assert report.seal_algorithms == (_ECDSA, _MLDSA)
    assert report.pq_signatures_valid is True
    assert report.pq_key_matches_pin is True
    assert report.envelope_mismatch_at is None
    assert report.pq_secured is True
    assert report.fully_replayable is True


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_dual_bundle_without_pq_pin_is_valid_but_not_pq_secured() -> None:
    # A PQ-aware verifier that does NOT pin a PQ key must report honestly: the
    # bundle is dual-signed, but post-quantum authorship is unconfirmed.
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    report = verify_sealed_fact_bundle(bundle, pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True            # ECDSA path unchanged
    assert report.dual_signed is True
    assert report.pq_signatures_valid is False  # no PQ key pinned
    assert report.pq_key_matches_pin is False
    assert report.pq_secured is False
    assert report.envelope_mismatch_at is None


def test_legacy_ecdsa_only_bundle_still_verifies() -> None:
    # Requirement 1: an existing ECDSA-only bundle must still verify unchanged.
    led = SealedFactLedger(enable_pq=False)
    led.append(_decision_fact(compose_arithmetic_mean(_components())))
    bundle = export_sealed_fact_bundle(led, export_name="legacy")
    report = verify_sealed_fact_bundle(
        SealedFactBundle.from_json(bundle.to_json()),
        pinned_public_key_pem=led.public_key_pem,
    )
    assert report.is_valid is True
    assert report.dual_signed is False
    assert report.seal_algorithms == ()
    assert report.pq_secured is False


def test_pre_change_bundle_json_without_envelope_fields_verifies() -> None:
    # Requirement 1, the strong form: a JSON artifact produced BEFORE this change
    # has no ``seal_public_keys`` and no per-record ``seal_envelope``. Strip both
    # to simulate it; the new verifier must still validate it on the ECDSA path.
    import json

    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    data = json.loads(bundle.to_json())
    data.pop("seal_public_keys", None)
    for r in data["records"]:
        r.pop("seal_envelope", None)
    back = SealedFactBundle.from_json(json.dumps(data))

    assert back.seal_public_keys == ()
    assert all(r.seal_envelope is None for r in back.records)
    report = verify_sealed_fact_bundle(back, pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True
    assert report.fully_replayable is True  # chain + signatures + composition
    assert report.dual_signed is False
    assert report.pq_secured is False


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_forged_dual_bundle_is_caught_by_both_pins() -> None:
    # Attacker re-seals the SAME facts with THEIR OWN ECDSA + ML-DSA keys and
    # embeds their own public keys. Pinned to Tex's keys, the forgery fails on
    # every axis — including the post-quantum one.
    real_led, comps = _ledger_with_one_fact()
    pinned_ecdsa = real_led.public_key_pem
    pinned_pq = real_led.pq_public_key

    attacker = SealedFactLedger(key_label="attacker")
    for rec in real_led.list_all():
        attacker.append(rec.fact)
    forged = export_sealed_fact_bundle(
        attacker, export_name="forged", components=tuple(comps)
    )

    report = verify_sealed_fact_bundle(
        forged,
        pinned_public_key_pem=pinned_ecdsa,
        pinned_seal_keys={_MLDSA: pinned_pq},
    )
    assert report.key_matches_pin is False       # embedded ECDSA key != pinned
    assert report.signatures_valid is False       # ECDSA signed by attacker
    assert report.pq_key_matches_pin is False     # embedded ML-DSA key != pinned
    assert report.pq_signatures_valid is False    # ML-DSA signed by attacker
    assert report.is_valid is False
    assert report.pq_secured is False


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_algorithm_mismatch_in_bundle_is_caught() -> None:
    # The algorithm-mismatch case: relabel the ML-DSA signature as ECDSA-P256.
    # The verifier dispatches ECDSA against ML-DSA bytes -> fails -> mismatch.
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    rec = bundle.records[0]
    env = rec.seal_envelope
    m_sig = env.signature_for(_MLDSA)
    mislabelled = SealEnvelope(
        seal_version=env.seal_version,
        signatures=(
            env.signature_for(_ECDSA),
            SealSignature(
                algorithm=_ECDSA,  # wrong tag for ML-DSA bytes
                key_id=m_sig.key_id,
                signature_b64=m_sig.signature_b64,
            ),
        ),
    )
    bad_rec = rec.model_copy(update={"seal_envelope": mislabelled})
    tampered = bundle.model_copy(update={"records": (bad_rec,)})
    report = verify_sealed_fact_bundle(
        tampered,
        pinned_public_key_pem=led.public_key_pem,
        pinned_seal_keys={_MLDSA: led.pq_public_key},
    )
    assert report.envelope_mismatch_at == 0
    assert report.pq_signatures_valid is False
    assert report.pq_secured is False
    # the chain + legacy ECDSA signature are intact (the envelope is not in the
    # hash chain) — so a non-PQ verifier still sees a valid bundle, while a
    # PQ-requiring one is correctly denied via pq_secured.
    assert report.chain_intact is True
    assert report.signatures_valid is True


@pytest.mark.skipif(not _HAS_PQ, reason="no ML-DSA backend")
def test_tampered_pq_bytes_in_bundle_are_caught() -> None:
    led, comps = _ledger_with_one_fact()
    bundle = export_sealed_fact_bundle(led, export_name="A", components=tuple(comps))
    rec = bundle.records[0]
    env = rec.seal_envelope
    m_sig = env.signature_for(_MLDSA)
    raw = bytearray(base64.b64decode(m_sig.signature_b64))
    raw[0] ^= 0x01
    bad_env = SealEnvelope(
        seal_version=env.seal_version,
        signatures=(
            env.signature_for(_ECDSA),
            SealSignature(
                algorithm=_MLDSA,
                key_id=m_sig.key_id,
                signature_b64=base64.b64encode(bytes(raw)).decode("ascii"),
            ),
        ),
    )
    bad_rec = rec.model_copy(update={"seal_envelope": bad_env})
    tampered = bundle.model_copy(update={"records": (bad_rec,)})
    report = verify_sealed_fact_bundle(
        tampered,
        pinned_public_key_pem=led.public_key_pem,
        pinned_seal_keys={_MLDSA: led.pq_public_key},
    )
    assert report.pq_signatures_valid is False
    assert report.pq_signature_invalid_at == 0
    assert report.envelope_mismatch_at == 0
    assert report.pq_secured is False
