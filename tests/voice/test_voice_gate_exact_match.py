"""
The faithfulness gate is the load-bearing invariant of the voice surface. These
tests pin the doctrine into code: PERMIT requires an exact reconstruction of an
authored template from sealed slots; an asserted contradiction is a structural
FORBID; anything unprovable is ABSTAIN; and — the trust-critical one — a
probabilistic scorer can only ever make a verdict MORE cautious, never raise it.
"""

from __future__ import annotations

from tex.domain.verdict import Verdict
from tex.voice.voice_gate import (
    ExactMatchScorer,
    NeuralNLIScorer,
    VoiceGate,
)


_TMPL = "{forbidden_total} actions were forbidden in the recent window."


def test_exact_reconstruction_permits() -> None:
    gate = VoiceGate()
    res = gate.evaluate(
        answer="3 actions were forbidden in the recent window.",
        template=_TMPL,
        slots={"forbidden_total": 3},
    )
    assert res.verdict is Verdict.PERMIT
    assert res.reason == "reconstruction-exact"


def test_injected_unsealed_token_abstains() -> None:
    # Answer carries a number (7) that is NOT a sealed slot value. The gate must
    # refuse to call it grounded.
    gate = VoiceGate()
    res = gate.evaluate(
        answer="3 actions were forbidden, and 7 more were blocked.",
        template=_TMPL,
        slots={"forbidden_total": 3},
    )
    assert res.verdict is Verdict.ABSTAIN
    assert any(c.outcome == "unsealed" and c.token == "7" for c in res.claims)


def test_asserted_verdict_contradiction_forbids() -> None:
    # The question asserted PERMIT; the sealed record says FORBID → refuse.
    gate = VoiceGate()
    res = gate.evaluate(
        answer="Decision d resolved to FORBID.",
        template="Decision {decision_id} resolved to {verdict}.",
        slots={"decision_id": "d", "verdict": "FORBID"},
        asserted_verdict="PERMIT",
        sealed_verdict="FORBID",
    )
    assert res.verdict is Verdict.FORBID
    assert "contradicts-sealed" in res.reason


def test_matching_asserted_verdict_is_not_a_contradiction() -> None:
    # Asserted matches sealed (casefold) → no FORBID; the answer reconstructs.
    gate = VoiceGate()
    res = gate.evaluate(
        answer="Decision d resolved to PERMIT.",
        template="Decision {decision_id} resolved to {verdict}.",
        slots={"decision_id": "d", "verdict": "PERMIT"},
        asserted_verdict="permit",
        sealed_verdict="PERMIT",
    )
    assert res.verdict is Verdict.PERMIT


def test_neural_scorer_is_off_and_honest() -> None:
    # The neural seam must not run in this environment and must never fabricate
    # a certainty: load() is False, entails() is None.
    neural = NeuralNLIScorer()
    assert neural.load() is False
    assert neural.entails("premise", "hypothesis") is None


class _YesScorer:
    """A hostile stand-in that claims EVERYTHING entails — used to prove the gate
    is monotone: even a scorer screaming 'grounded!' cannot raise a verdict."""

    name = "yes-scorer(test)"

    def load(self) -> bool:
        return True

    def entails(self, premise: str, hypothesis: str) -> bool:
        return True


def test_high_score_cannot_raise_a_forbid_to_permit() -> None:
    # Structural FORBID (Rule B) is deterministic and not neural-overridable: a
    # scorer that entails everything must NOT flip the refusal.
    gate = VoiceGate(neural=_YesScorer())  # type: ignore[arg-type]
    res = gate.evaluate(
        answer="Decision d resolved to FORBID.",
        template="Decision {decision_id} resolved to {verdict}.",
        slots={"decision_id": "d", "verdict": "FORBID"},
        asserted_verdict="PERMIT",
        sealed_verdict="FORBID",
    )
    assert res.verdict is Verdict.FORBID


def test_high_score_cannot_manufacture_a_permit_from_prose() -> None:
    # PERMIT requires EXACT reconstruction. A non-reconstructible answer whose
    # tokens a hostile scorer all "entails" still tops out at ABSTAIN — the
    # probabilistic path can lower caution toward ABSTAIN but never reach PERMIT.
    gate = VoiceGate(neural=_YesScorer())  # type: ignore[arg-type]
    res = gate.evaluate(
        answer="In my opinion, 3 actions were forbidden and things look fine.",
        template=_TMPL,
        slots={"forbidden_total": 3},
    )
    assert res.verdict is Verdict.ABSTAIN


def test_hash_is_not_casefolded_into_a_false_match() -> None:
    # A wrong hash token in the answer (not equal to any sealed value) is unsealed
    # → ABSTAIN. Hashes are compared with tolerance 0.
    gate = VoiceGate()
    sealed = "a" * 64
    wrong = "b" * 64
    res = gate.evaluate(
        answer=f"The content hash is {wrong}.",
        template="The content hash is {h}.",
        slots={"h": sealed},
    )
    assert res.verdict is Verdict.ABSTAIN


def test_exact_match_scorer_membership() -> None:
    s = ExactMatchScorer()
    assert s.entails("3 forbid FORBID", "3") is True
    assert s.entails("3 forbid FORBID", "forbid") is True  # casefold
    assert s.entails("3 forbid FORBID", "9") is False
