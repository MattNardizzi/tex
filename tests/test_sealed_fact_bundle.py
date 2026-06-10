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

import math
from uuid import uuid4

from tex.domain.evidence import (
    CombinedEvidence,
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
)
from tex.provenance.bundle import (
    SealedFactBundle,
    export_sealed_fact_bundle,
    verify_sealed_fact_bundle,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind


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
