"""
Wave 3 L11 entailment half — the conformal calibration machinery.

What these tests earn: the Mohri–Hashimoto split-conformal quantile is computed
EXACTLY (an order statistic, hand-checked), the ``calibrate`` pipeline runs end
to end over the REAL synthetic NLI corpus with a deterministic, label-blind
scorer (no torch), and the honesty rails hold — an unloaded scorer cannot be
calibrated, a stub's λ̂ self-labels (``model_loaded=False``) and the resulting
commitment is BLOCKED, never green.

The real cross-encoder cannot run here (``import transformers`` raises), so the
stub is what makes the synthetic-corpus validation possible; it is explicitly
NOT a model and never claims to be one.
"""

from __future__ import annotations

import re

import pytest

from tex.bench.wave2_corpus.builders import NLI_LABEL_ENTAILED, build_nli_pairs
from tex.voice.entailment_cert import (
    ENTAILMENT_HALF_BLOCKED,
    commitment_from_calibration,
    entailment_half_status,
    seal_entailment_commitment,
    verify_entailment_commitment,
)
from tex.voice.attestation import VoiceAttestor, _stable_json
from tex.voice.voice_gate import (
    ENTAILMENT_BACKEND_NEURAL,
    ENTAILMENT_BACKEND_STUB,
    NeuralNLIScorer,
    calibrate,
    conformal_lambda_hat,
)

MODEL_A = "MoritzLaurer/DeBERTa-v3-base-mnli"
_HANDLE_RE = re.compile(r"\b[0-9a-fA-F]{4,}\b|\b\d+\b")


class LexicalOverlapStub:
    """A deterministic, model-free entailment scorer, for PIPELINE validation.

    P(entail) ≈ the fraction of the hypothesis's handle tokens (numbers / hex)
    that are present in the premise bag. It is label-BLIND (it never reads the
    NLI label) yet carries real, weak signal: a template-fill hypothesis keeps
    every handle, a value-mutation / unseen-handle hypothesis loses one. It is
    NOT a model — ``backend`` is the stub backend, so a λ̂ it produces is
    recorded ``model_loaded=False`` and can never reach the capstone green."""

    backend = ENTAILMENT_BACKEND_STUB
    name = "lexical-overlap-stub(test)"

    def load(self) -> bool:
        return True

    def score(self, premise: str, hypothesis: str) -> float:
        # The premise is a ``key=value; …`` bag, so pull the handle tokens out
        # of it the same way as the hypothesis (don't naive-split on spaces).
        prem = set(_HANDLE_RE.findall(premise))
        handles = _HANDLE_RE.findall(hypothesis)
        if not handles:
            return 0.5  # genuinely uncertain — a pure-prose hypothesis
        return sum(1 for h in handles if h in prem) / len(handles)


class _NeuralLikeStub(LexicalOverlapStub):
    """Same scores, but ADVERTISES the neural backend — used ONLY to prove the
    ``model_loaded`` wiring marks a neural-backed calibration True without a
    real model. It is never used to build a sealed/green commitment."""

    backend = ENTAILMENT_BACKEND_NEURAL
    name = "neural-like-stub(test)"


# ── 1. the conformal quantile is an exact order statistic ────────────────────


def test_conformal_lambda_hat_is_the_exact_order_statistic() -> None:
    scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]  # n = 10, sorted
    # rank = ceil((n+1)(1-α)); λ̂ = rank-th smallest (1-indexed).
    assert conformal_lambda_hat(scores, 0.2) == 0.9   # ceil(11*0.8)=9 -> 0.9
    assert conformal_lambda_hat(scores, 0.5) == 0.6   # ceil(11*0.5)=6 -> 0.6
    assert conformal_lambda_hat(scores, 0.1) == 1.0   # ceil(11*0.9)=10 -> 1.0
    # rank > n (α so small the finite-sample quantile is undefined) -> 1.0.
    assert conformal_lambda_hat(scores, 0.001) == 1.0
    # order independence: shuffling the inputs changes nothing.
    assert conformal_lambda_hat(list(reversed(scores)), 0.2) == 0.9


def test_conformal_lambda_hat_is_monotone_nonincreasing_in_alpha() -> None:
    scores = [i / 50 for i in range(51)]
    last = 1.0
    for alpha in (0.01, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8):
        lam = conformal_lambda_hat(scores, alpha)
        assert lam <= last  # larger α tolerates more misses → lower (looser) λ̂
        last = lam


def test_conformal_lambda_hat_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        conformal_lambda_hat([], 0.1)            # empty
    with pytest.raises(ValueError):
        conformal_lambda_hat([0.5], 0.0)         # α not in (0,1)
    with pytest.raises(ValueError):
        conformal_lambda_hat([0.5], 1.0)
    with pytest.raises(ValueError):
        conformal_lambda_hat([1.5], 0.1)         # score out of [0,1]


# ── 2. calibrate() end-to-end over the REAL synthetic corpus ─────────────────


def _corpus_triples(n_per_class: int = 25):
    pairs = build_nli_pairs(seed=7, n_per_class=n_per_class)
    return pairs, [
        (p.premise, p.hypothesis, p.label == NLI_LABEL_ENTAILED) for p in pairs
    ]


def test_calibrate_runs_the_full_pipeline_on_synthetic_data() -> None:
    pairs, triples = _corpus_triples()
    scorer = LexicalOverlapStub()
    cal = calibrate(scorer, triples, alpha=0.3, model_id=MODEL_A)

    assert cal.n == len(triples)
    assert 0.0 <= cal.lambda_hat <= 1.0
    assert cal.scorer_backend == ENTAILMENT_BACKEND_STUB
    assert cal.model_loaded is False  # a stub is never a loaded model
    assert cal.model_id == MODEL_A

    # calibrate must wire score→nonconformity→quantile EXACTLY: re-derive the
    # nonconformity (0 for entailed, the score for not-entailed) and recompute.
    nonconf = [
        0.0 if entailed else scorer.score(prem, hyp)
        for prem, hyp, entailed in triples
    ]
    assert cal.lambda_hat == conformal_lambda_hat(nonconf, 0.3)

    # the stub carries real (weak) signal: entailed pairs score higher on avg.
    ent = [scorer.score(p.premise, p.hypothesis) for p in pairs if p.label == NLI_LABEL_ENTAILED]
    neg = [scorer.score(p.premise, p.hypothesis) for p in pairs if p.label != NLI_LABEL_ENTAILED]
    assert sum(ent) / len(ent) > sum(neg) / len(neg)


def test_a_weak_scorer_needs_more_backoff_at_a_stricter_alpha() -> None:
    # Honest instruction, not a bug: a lexical stub cannot catch every
    # not-entailed case (verdict-word mutations, prose-residue keep their
    # handles), so a stricter α forces MORE back-off — a higher λ̂. This is why
    # a real NLI scorer is needed and why the live half stays blocked.
    _, triples = _corpus_triples()
    strict = calibrate(LexicalOverlapStub(), triples, alpha=0.05, model_id=MODEL_A)
    loose = calibrate(LexicalOverlapStub(), triples, alpha=0.5, model_id=MODEL_A)
    assert strict.lambda_hat >= loose.lambda_hat
    assert 0.0 <= loose.lambda_hat <= strict.lambda_hat <= 1.0


def test_calibrate_refuses_an_unloaded_scorer() -> None:
    # The real seam in this env: load() is False, so it cannot be calibrated —
    # a quantile from a scorer that emits no scores would be fabricated.
    real = NeuralNLIScorer()
    assert real.load() is False
    _, triples = _corpus_triples(n_per_class=2)
    with pytest.raises(ValueError, match="not loaded"):
        calibrate(real, triples, alpha=0.1, model_id=MODEL_A)


def test_neural_backend_marks_model_loaded() -> None:
    # The model_loaded wiring: a neural-backed calibration records True. (This
    # stub only advertises the backend to exercise the flag; it is never sealed.)
    _, triples = _corpus_triples(n_per_class=3)
    cal = calibrate(_NeuralLikeStub(), triples, alpha=0.2, model_id=MODEL_A)
    assert cal.scorer_backend == ENTAILMENT_BACKEND_NEURAL
    assert cal.model_loaded is True


# ── 3. the calibrated commitment seals, replays, and stays BLOCKED ───────────


def test_a_synthetic_calibration_seals_replays_and_is_not_green() -> None:
    _, triples = _corpus_triples()
    cal = calibrate(LexicalOverlapStub(), triples, alpha=0.3, model_id=MODEL_A)
    commitment = commitment_from_calibration(
        cal,
        calibration_manifest_sha256="d" * 64,
        calibration_corpus_id="nli-cal-v1",
        calibration_corpus_kind="synthetic",
    )
    # It is a REAL calibrated commitment — but synthetic + stub, so BLOCKED.
    assert commitment.calibrated is True
    assert commitment.lambda_hat == cal.lambda_hat
    assert entailment_half_status(commitment) == ENTAILMENT_HALF_BLOCKED

    at = VoiceAttestor()
    seal_entailment_commitment(at, commitment)
    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.ok is True  # the chain + commitment replay fine…
    assert res.commitments[0].lambda_hat == cal.lambda_hat
    # …and it is STILL not a field guarantee.
    assert entailment_half_status(res.commitments[0]) == ENTAILMENT_HALF_BLOCKED

    # Even a CALIBRATED commitment's sealed payload never over-promises: the
    # calibrated threshold label is vocabulary-clean (no coverage/guarantee/1-alpha).
    sealed = _stable_json(at.records()[0].payload).casefold()
    for word in ("guarantee", "coverage", "1-alpha"):
        assert word not in sealed, f"calibrated payload leaks {word!r}"
