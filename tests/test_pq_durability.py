"""
PQ-maturity-gated live signer — Wave 2 leap **L10** (``pqcrypto/pq_durability.py``).

The invariants that make this signal safe to wire onto a live verdict, each tested
directly here:

  1. **fail-closed probe** — only allow-listed backend ids earn DURABLE /
     RESEARCH_ONLY; everything else (unknown id, empty, ``None``) is NONE. This is
     the nanozk-trap guard: a non-real backend can never be labelled durable.
  2. **the nanozk trap, pinned** — a real OpenSSL ML-DSA CLI existing on the box
     does NOT raise the *live* maturity (the live signer doesn't dispatch to it).
  3. **monotone-lowering** — the signal only ever demotes a PERMIT to ABSTAIN; it
     never raises or relaxes a verdict and never fires the structural floor.
  4. **fail-closed seal** — sealing the PQ-durable=false fact is observation-only
     and a no-op without a ledger; the chain + signatures verify when wired.
  5. **earn it** — a *real* composite ML-DSA-87 + ECDSA-P384 chain-head sign/verify
     round-trip: a good signature verifies True, a 1-bit flip in either half False.
"""

from __future__ import annotations

import pytest

from tex.domain.verdict import Verdict
from tex.engine.router import RoutingResult
from tex.pqcrypto import ml_dsa
from tex.pqcrypto import pq_durability as pq
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind

from tests.factories import make_request


# ── helpers ──────────────────────────────────────────────────────────────


def _routing(verdict: Verdict, *, score: float = 0.1) -> RoutingResult:
    return RoutingResult(verdict=verdict, confidence=0.9, final_score=score)


def _claim_request():
    return make_request(metadata={pq.PQ_CLAIM_METADATA_KEY: True})


# Severity ordering for the monotone-lowering property: a signal may only move a
# verdict toward caution, never the reverse.
_SEVERITY = {Verdict.PERMIT: 0, Verdict.ABSTAIN: 1, Verdict.FORBID: 2}


# ─────────────────────────────────────────────────────────────────────────
# 1. The fail-closed maturity probe (the heart of L10)
# ─────────────────────────────────────────────────────────────────────────


def test_native_backend_id_is_durable() -> None:
    assert (
        pq.durability_for_backend_id("pyca-cryptography-native")
        is pq.SignerDurability.DURABLE
    )


def test_liboqs_backend_id_is_research_only() -> None:
    assert (
        pq.durability_for_backend_id("liboqs") is pq.SignerDurability.RESEARCH_ONLY
    )


def test_none_backend_id_is_none() -> None:
    assert pq.durability_for_backend_id(None) is pq.SignerDurability.NONE


@pytest.mark.parametrize(
    "bogus",
    ["", "  ", "liboqs ", "LIBOQS", "pyca", "openssl-cli-3.5", "kms", "totally-made-up"],
)
def test_unknown_backend_id_fails_closed_to_none(bogus: str) -> None:
    """THE NANOZK TRAP: any id that is not explicitly allow-listed → NONE.

    Includes near-misses (trailing space, wrong case) and plausible-but-unreviewed
    ids (a CLI shim id, a bare "kms"). None may earn durability by resemblance.
    """
    assert pq.durability_for_backend_id(bogus) is pq.SignerDurability.NONE


def test_live_probe_is_durable_in_this_env() -> None:
    """In-env pyca >= 48 ships the native ML-DSA module (OpenSSL 3.5), so the live
    signer's backend id is the allow-listed durable id and the probe reads DURABLE.

    This pins the L10 runtime goal as a fact about THIS box — ``requirements.txt``
    pins ``cryptography>=48.0.0``. If the native backend ever regresses or is
    uninstalled, ``active_backend_id()`` falls back to ``None`` and this test fails,
    surfacing the loss of the durable signer rather than silently re-lowering every
    PQ-non-repudiation claim. (The non-durable branch is still exercised below, but
    via an explicit monkeypatch so it does not depend on a downgraded box.)
    """
    assert ml_dsa.active_backend_id() == "pyca-cryptography-native"
    assert pq.probe_backend() is pq.SignerDurability.DURABLE


def test_probe_tracks_active_backend_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe_backend is a pure function of the LIVE backend id and nothing else."""
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "pyca-cryptography-native")
    assert pq.probe_backend() is pq.SignerDurability.DURABLE
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "liboqs")
    assert pq.probe_backend() is pq.SignerDurability.RESEARCH_ONLY
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "some-future-backend")
    assert pq.probe_backend() is pq.SignerDurability.NONE


def test_cli_shim_does_not_raise_live_maturity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The nanozk trap, pinned deterministically.

    A real OpenSSL-3.5 ML-DSA CLI IS reachable on this host (it signs the composite
    round-trip below). With the LIVE backend id forced to ``None``, that reachable
    CLI must NOT move the maturity off NONE: the live signer does not dispatch to the
    CLI shim. "Something on the box can sign with ML-DSA" does not make the running
    signer post-quantum — conflating the two is the failure we exist to never repeat.

    We force the live id to ``None`` (rather than read the ambient one) because this
    box now ships a *durable native* backend — see
    ``test_live_probe_is_durable_in_this_env`` — so forcing ``None`` isolates the trap
    from the genuine durable path. ``openssl_mldsa_available()`` stays UNPATCHED: the
    CLI presence is real, only the live signer's backend id is pinned absent.
    """
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    assert pq.openssl_mldsa_available() is True
    assert pq.probe_backend() is pq.SignerDurability.NONE


# ─────────────────────────────────────────────────────────────────────────
# 2. Assessment semantics
# ─────────────────────────────────────────────────────────────────────────


def test_assessment_no_claim_does_not_lower() -> None:
    a = pq.assess(make_request())
    assert a.claim_requested is False
    assert a.lowers_verdict is False
    assert a.claim_honored is False


def test_assessment_claim_without_durable_backend_lowers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force the no-durable-backend branch. This box ships a durable native backend;
    # the lowering branch is the behavior on a box that does NOT (the signal firing).
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    a = pq.assess(_claim_request())
    assert a.claim_requested is True
    assert a.pq_durable is False
    assert a.lowers_verdict is True
    assert a.claim_honored is False
    # The sealed detail keeps the real None backend id (JSON null); the Finding
    # view coerces it to a scalar string.
    assert a.seal_detail()["ml_dsa_backend_id"] is None
    assert a.finding_metadata()["ml_dsa_backend_id"] == "<none>"


def test_assessment_claim_with_durable_backend_is_honored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "pyca-cryptography-native")
    a = pq.assess(_claim_request())
    assert a.pq_durable is True
    assert a.claim_honored is True
    assert a.lowers_verdict is False  # a durable signer honors the claim → no demotion


# ─────────────────────────────────────────────────────────────────────────
# 3. The monotone-lowering hook — verdict-path coverage.
#    These tests MUST fail if the monotonicity / floor invariant breaks.
# ─────────────────────────────────────────────────────────────────────────


def test_permit_with_claim_and_no_backend_demotes_to_abstain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force the no-durable-backend branch so the monotone-lowering demotion is the
    # behavior under test regardless of what backend this box ships.
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    out = pq.apply_pq_durability_hold(base=_routing(Verdict.PERMIT), request=_claim_request())
    assert out.verdict is Verdict.ABSTAIN
    assert pq.PQ_NON_REPUDIATION_FLAG in out.uncertainty_flags
    assert out.scores["pq_durable"] == 0.0
    assert any(
        f.rule_name == "pq_non_repudiation_unavailable" for f in out.findings
    )
    # determinism-preserving fields carried through unchanged
    assert out.final_score == 0.1
    assert out.confidence == 0.9


def test_permit_without_claim_is_a_noop() -> None:
    base = _routing(Verdict.PERMIT)
    out = pq.apply_pq_durability_hold(base=base, request=make_request())
    assert out.verdict is Verdict.PERMIT
    assert out is base  # untouched object, zero-cost


def test_forbid_with_claim_is_untouched_floor_preserved() -> None:
    """A PQ-maturity signal never relaxes a FORBID and never fires/touches the floor."""
    base = _routing(Verdict.FORBID)
    out = pq.apply_pq_durability_hold(base=base, request=_claim_request())
    assert out.verdict is Verdict.FORBID
    assert out is base
    assert pq.PQ_NON_REPUDIATION_FLAG not in out.uncertainty_flags


def test_abstain_with_claim_is_untouched() -> None:
    base = _routing(Verdict.ABSTAIN)
    out = pq.apply_pq_durability_hold(base=base, request=_claim_request())
    assert out.verdict is Verdict.ABSTAIN
    assert out is base


def test_permit_with_claim_but_durable_backend_is_not_demoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable signer honors the claim — the verdict is NOT lowered."""
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "pyca-cryptography-native")
    base = _routing(Verdict.PERMIT)
    out = pq.apply_pq_durability_hold(base=base, request=_claim_request())
    assert out.verdict is Verdict.PERMIT
    assert out is base


@pytest.mark.parametrize("verdict", [Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID])
@pytest.mark.parametrize("claim", [True, False])
def test_signal_only_ever_lowers_never_raises(verdict: Verdict, claim: bool) -> None:
    """The monotone-lowering invariant over the full cross-product.

    Output severity is never below input severity, and the only change ever made
    is PERMIT→ABSTAIN. This test fails if the hook ever raises a verdict or relaxes
    one, or demotes a non-PERMIT.
    """
    req = _claim_request() if claim else make_request()
    out = pq.apply_pq_durability_hold(base=_routing(verdict), request=req)
    assert _SEVERITY[out.verdict] >= _SEVERITY[verdict]
    if verdict is not Verdict.PERMIT:
        assert out.verdict is verdict  # non-PERMIT verdicts are immutable to this signal
    if not (verdict is Verdict.PERMIT and claim):
        assert out.verdict is verdict  # only PERMIT+claim may move


# ─────────────────────────────────────────────────────────────────────────
# 4. The sealed "PQ-durable=false" fact (fail-closed, mirrors decision_seal)
# ─────────────────────────────────────────────────────────────────────────


def test_seal_with_no_ledger_is_a_noop() -> None:
    assert pq.seal_pq_durability(None, pq.assess(_claim_request()), _claim_request()) is None


def test_seal_skips_when_assessment_does_not_lower() -> None:
    """No claim → nothing to seal, even with a ledger wired."""
    ledger = SealedFactLedger()
    assert pq.seal_pq_durability(ledger, pq.assess(make_request()), make_request()) is None
    assert len(ledger) == 0


def test_seal_appends_and_chain_and_signatures_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fact is sealed ONLY when the signal fires (a non-durable signer). Force
    # that branch so the seal/verify path is exercised on any box.
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    ledger = SealedFactLedger()
    req = _claim_request()
    record = pq.seal_pq_durability(ledger, pq.assess(req), req)

    assert record is not None
    assert len(ledger) == 1
    assert record.fact.kind is SealedFactKind.DECISION
    assert record.fact.detail["pq_durable"] is False
    assert record.fact.detail["signer_maturity"] == "none"
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_build_fact_is_honest_and_does_not_overclaim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tex.domain.evidence import EvidenceMaturity

    # Force the no-durable-backend branch: the fact only exists when the signal
    # fires, and it must record "PQ-durable=false" without overclaiming.
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    req = _claim_request()
    fact = pq.build_pq_durability_fact(pq.assess(req), req)
    assert fact.kind is SealedFactKind.DECISION
    assert fact.subject_id == str(req.request_id)
    assert fact.detail["pq_durable"] is False
    # newly-wired signal, not a benchmarked production default
    assert fact.maturity is EvidenceMaturity.RESEARCH_EARLY
    # the claim names the property and refuses to imply a PQ guarantee was made
    assert "PQ-durable=false" in fact.claim
    assert "PQ guarantee NOT made" in fact.claim
    assert fact.evidence is None  # carries no proof-of-correctness e-value


# ─────────────────────────────────────────────────────────────────────────
# 5. EARN IT — real composite ML-DSA-87 + ECDSA-P384 chain-head round-trip.
#    Uses the OpenSSL >= 3.5 CLI (real FIPS 204) for the ML-DSA-87 half and pyca
#    for the ECDSA-P384 half. Skipped (never faked) if no such CLI is present.
# ─────────────────────────────────────────────────────────────────────────

_needs_openssl = pytest.mark.skipif(
    not pq.openssl_mldsa_available(),
    reason="no OpenSSL >= 3.5 CLI exposing ML-DSA-87 on this host",
)

_CHAIN_HEAD = b"tex-evidence-chain-head|genesis|policy=cnsa2.0|seq=0"


@_needs_openssl
def test_composite_chain_head_good_signature_verifies() -> None:
    pub, sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    assert pq.composite_verify_chain_head(_CHAIN_HEAD, pub, sig) is True


@_needs_openssl
def test_composite_ml_dsa_half_is_genuinely_ml_dsa_87() -> None:
    """The ML-DSA half is a real FIPS 204 ML-DSA-87 signature (exact 4627 bytes)."""
    from tex.pqcrypto.composite_ml_dsa import _split_length_prefixed
    from tex.pqcrypto.ml_dsa import expected_signature_size
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

    _pub, sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    ml_dsa_sig, ecdsa_sig = _split_length_prefixed(sig, label="composite signature")
    assert len(ml_dsa_sig) == expected_signature_size(SignatureAlgorithm.ML_DSA_87)
    assert len(ml_dsa_sig) == 4627
    assert len(ecdsa_sig) > 0  # ECDSA-P384 DER signature present


@_needs_openssl
def test_composite_chain_head_one_bit_flip_fails() -> None:
    pub, sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    flipped = bytearray(sig)
    flipped[len(sig) // 2] ^= 0x01
    assert pq.composite_verify_chain_head(_CHAIN_HEAD, pub, bytes(flipped)) is False


@_needs_openssl
def test_composite_chain_head_tampered_message_fails() -> None:
    pub, sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    assert pq.composite_verify_chain_head(_CHAIN_HEAD + b"!", pub, sig) is False


@_needs_openssl
def test_composite_non_separability_either_half_flip_fails() -> None:
    """Both halves are load-bearing: flipping the ML-DSA half OR the ECDSA half fails."""
    from tex.pqcrypto.composite_ml_dsa import (
        _concat_length_prefixed,
        _split_length_prefixed,
    )

    pub, sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    ml_dsa_sig, ecdsa_sig = _split_length_prefixed(sig, label="composite signature")

    # corrupt only the ML-DSA half
    bad_mldsa = bytearray(ml_dsa_sig)
    bad_mldsa[0] ^= 0x01
    sig_bad_mldsa = _concat_length_prefixed(bytes(bad_mldsa), ecdsa_sig)
    assert pq.composite_verify_chain_head(_CHAIN_HEAD, pub, sig_bad_mldsa) is False

    # corrupt only the ECDSA half
    bad_ecdsa = bytearray(ecdsa_sig)
    bad_ecdsa[-1] ^= 0x01
    sig_bad_ecdsa = _concat_length_prefixed(ml_dsa_sig, bytes(bad_ecdsa))
    assert pq.composite_verify_chain_head(_CHAIN_HEAD, pub, sig_bad_ecdsa) is False


@_needs_openssl
def test_composite_verify_rejects_malformed_signature() -> None:
    pub, _sig = pq.composite_sign_chain_head(_CHAIN_HEAD)
    assert pq.composite_verify_chain_head(_CHAIN_HEAD, pub, b"\x00\x00") is False


# ─────────────────────────────────────────────────────────────────────────
# 6. End-to-end PDP integration — clean content that WOULD permit is lowered to
#    ABSTAIN by the PQ-maturity signal, and the PQ-durable=false fact is sealed.
# ─────────────────────────────────────────────────────────────────────────

_CLEAN = "Hi Alice, following up on onboarding next week. Happy to help."


def test_clean_content_permits_without_a_pq_claim(runtime) -> None:
    """Baseline: clean content reaches PERMIT; the hook is a zero-cost no-op."""
    result = runtime.evaluate_action_command.execute(make_request(content=_CLEAN))
    assert result.response.verdict is Verdict.PERMIT


def test_pq_claim_lowers_permit_to_abstain_and_seals_end_to_end(
    runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force the no-durable-backend branch so the lowered end-to-end path (demote +
    # seal) is exercised regardless of the backend this box ships.
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    ledger = SealedFactLedger()
    runtime.pdp._decision_ledger = ledger

    result = runtime.evaluate_action_command.execute(
        make_request(content=_CLEAN, metadata={pq.PQ_CLAIM_METADATA_KEY: True})
    )

    # the verdict that would have been PERMIT is lowered to ABSTAIN
    assert result.response.verdict is Verdict.ABSTAIN
    assert pq.PQ_NON_REPUDIATION_FLAG in result.response.uncertainty_flags

    # the PQ-durable=false fact is sealed, and the whole chain verifies
    decision_facts = ledger.list_by_kind(SealedFactKind.DECISION)
    pq_facts = [r for r in decision_facts if r.fact.detail.get("pq_durable") is False]
    assert len(pq_facts) == 1
    assert pq_facts[0].fact.detail["signer_maturity"] == "none"
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


# This box ships a durable signing backend (cryptography>=48, requirements-pinned).
# The next test proves the HONORED path end-to-end; it skips (never fakes) on a box
# where the backend is absent — the hard "the backend is required" canary is
# ``test_live_probe_is_durable_in_this_env`` above.
_needs_durable_backend = pytest.mark.skipif(
    pq.probe_backend() is not pq.SignerDurability.DURABLE,
    reason="no durable ML-DSA signing backend available on this host",
)


@_needs_durable_backend
def test_pq_claim_is_honored_end_to_end_on_durable_box(runtime) -> None:
    """The L10 runtime goal, proven through the full PDP on THIS box.

    When the maturity probe reports a durable ML-DSA backend is available to the
    signer, a PQ-non-repudiation claim over clean content is HONORED by the signal:
    the verdict stays PERMIT, no uncertainty flag is raised, and NO ``pq_durable``
    fact is sealed (the engine seals only when the signal fires — the durable
    outcome's evidence is the decision itself, not a fail-closed fact). This is the
    behavior the capstone records as ``durable_not_lowered``.

    Honest scope — the capability-vs-use line: "honored" means the maturity SIGNAL
    did not lower the verdict because a durable backend exists; it does NOT mean this
    epoch's evidence chain is post-quantum signed. The live ledger signer is
    ECDSA-P256 (``provenance/ledger.py``). This test asserts the governance signal's
    behavior, never a PQ property of the bytes actually sealed.

    Fails if the durable backend regresses (the claim would lower to ABSTAIN and a
    fail-closed fact would appear).
    """
    assert ml_dsa.active_backend_id() == "pyca-cryptography-native"  # precondition
    ledger = SealedFactLedger()
    runtime.pdp._decision_ledger = ledger

    result = runtime.evaluate_action_command.execute(
        make_request(content=_CLEAN, metadata={pq.PQ_CLAIM_METADATA_KEY: True})
    )

    assert result.response.verdict is Verdict.PERMIT
    assert pq.PQ_NON_REPUDIATION_FLAG not in result.response.uncertainty_flags
    pq_facts = [
        r
        for r in ledger.list_by_kind(SealedFactKind.DECISION)
        if r.fact.detail.get("pq_durable") is False
    ]
    assert pq_facts == []  # no fail-closed fact when the claim is honored
