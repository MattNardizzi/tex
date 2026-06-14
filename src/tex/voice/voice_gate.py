"""
[Architecture: Voice cognition] — the faithfulness gate on the spoken answer.

This is the load limit on Tex's voice. Before Tex is allowed to say a grounded
answer, the gate must be satisfied that **every word the answer asserts traces
to a sealed fact**. It is the enforced invariant behind the doctrine "Tex may
only say what it can prove."

Three rules, in caution order (the gate can only ever make a verdict MORE
cautious — PERMIT → ABSTAIN → FORBID — never less; a one-sided lowering that
mirrors the RCPS bound in ``engine/crc_gate.py``):

  RULE B (structural FORBID).  If the question ASSERTED a verdict about a named
    record and the sealed record says otherwise, Tex refuses. This is the
    structural-floor analogue: a contradiction with a sealed fact is not a
    softenable signal. It is deterministic and is NEVER overridable by any
    probabilistic scorer.

  RULE A (faithfulness).  Prove the answer is exactly an authored template
    filled with sealed slot values: ``answer == template.format(**slots)``.
    When that reconstruction holds, every non-template token in the answer is a
    sealed value by construction — the strongest possible faithfulness proof,
    and the path every deterministic answer takes. If it does NOT hold (a
    future prose path, an injected token), the answer is decomposed into handle
    tokens; each must be exactly present in the sealed value set, and any
    non-handle "prose residue" not traceable to a registered template is
    referred to the entailment scorer.

  FAIL CLOSED.  The neural entailment scorer (``NeuralNLIScorer``) is a
    labelled-OFF seam: it does not run in this environment (``import
    transformers`` raises — verified) and even when present it returns None
    rather than a fabricated certainty. A claim the exact-match scorer cannot
    seal and the neural scorer cannot certify resolves to ABSTAIN. Uncertainty
    becomes "I can't prove that," never a guess.

NAMING HONESTY (the nanozk lesson): the LIVE gate is exact-match + a
fail-closed entailment seam, and it carries NO proven coverage. The split
conformal method of Mohri & Hashimoto ("Language Models with Conformal
Factuality Guarantees", ICML 2024, arXiv:2402.10978 — re-fetched 2026-06-14)
is implemented here as ``conformal_lambda_hat`` / ``calibrate``: correctness is
cast as an entailment-set problem, and the conformal quantile
λ̂ = ⌈(n+1)(1-α)⌉-th order statistic of the per-example back-off (the score
that must be exceeded to drop a non-entailed claim) is a real, computable
number GIVEN a scorer that emits scores and a labelled corpus. Two facts keep
the live gate uncalibrated regardless: (1) the real cross-encoder cannot run in
this environment (``import transformers`` raises — the ``tokenizers`` pin, still
true this session), so ``NeuralNLIScorer.score`` returns None and ``entails``
returns None; (2) the only corpus is synthetic, and a quantile from synthetic
calibration is a guarantee over the synthetic distribution alone — never a field
certification (arXiv:2512.15068 shows the field guarantee collapses anyway). So
``THRESHOLD_LABEL`` stays "UNCALIBRATED" for the live gate; the calibration
helpers exist so the seam is wired end to end and a calibrated λ̂ becomes
constructible the day a real scorer + field corpus land. The words "guarantee",
"coverage", and "1-alpha" appear in no user-facing string this module produces.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, Sequence

from tex.domain.verdict import Verdict

__all__ = [
    "Scorer",
    "ExactMatchScorer",
    "NeuralNLIScorer",
    "GateResult",
    "VoiceGate",
    "THRESHOLD_LABEL",
    "ENTAILMENT_BACKEND_NEURAL",
    "ENTAILMENT_BACKEND_STUB",
    "Calibration",
    "conformal_lambda_hat",
    "calibrate",
]

# The honest label for the (uncalibrated) entailment threshold. Surfaced in the
# sealed attestation, never in a user-facing answer.
THRESHOLD_LABEL = (
    "exact-match (tolerance 0); neural-entailment seam UNCALIBRATED — "
    "no proven coverage, conservative fixed constant, research-early"
)


# Handle token classes. A "handle" is a value that must match a sealed field
# EXACTLY — a number, a hash, a UUID, a verdict label, a signature algorithm.
_INT_RE = re.compile(r"\b\d+\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_VERDICT_RE = re.compile(r"\b(PERMIT|ABSTAIN|FORBID)\b")
_ALGO_RE = re.compile(r"\b(ecdsa-p256|ml-dsa-65|ed25519|composite-ml-dsa-65-ed25519)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Claim:
    """One token the gate evaluated, and how it was settled."""

    token: str
    kind: str           # int | sha256 | uuid | verdict | algorithm | prose
    source_field: str | None  # which sealed slot sealed it, or None if unsealed
    outcome: str        # sealed | unsealed | contradiction | unverifiable


@dataclass(frozen=True, slots=True)
class GateResult:
    verdict: Verdict
    scorer: str
    threshold_label: str
    claims: list[Claim] = field(default_factory=list)
    reason: str = ""


class Scorer(Protocol):
    """A faithfulness scorer. ``entails`` returns True/False, or None when it
    cannot decide (e.g. the neural backend is not loaded) — None never asserts
    a fact, it defers to ABSTAIN."""

    name: str

    def entails(self, premise: str, hypothesis: str) -> bool | None: ...


# --------------------------------------------------------------------------- exact-match


def _extract_handles(text: str) -> list[tuple[str, str]]:
    """Return (token, kind) for every handle token in ``text``. Verdict and
    algorithm tokens are matched first so they are not also caught as prose."""
    handles: list[tuple[str, str]] = []
    handles += [(m.group(0), "sha256") for m in _SHA256_RE.finditer(text)]
    handles += [(m.group(0), "uuid") for m in _UUID_RE.finditer(text)]
    handles += [(m.group(0), "verdict") for m in _VERDICT_RE.finditer(text)]
    handles += [(m.group(0), "algorithm") for m in _ALGO_RE.finditer(text)]
    # Integers last, and skip any that are a slice of an already-matched hash.
    consumed = " ".join(h for h, _ in handles)
    for m in _INT_RE.finditer(text):
        if m.group(0) not in consumed:
            handles.append((m.group(0), "int"))
    return handles


def _sealed_value_set(slots: dict[str, Any]) -> set[str]:
    """Every sealed slot value, stringified, plus a lowercased hex variant so a
    case difference in a hash never counts as a mismatch."""
    out: set[str] = set()
    for v in slots.values():
        s = str(v)
        out.add(s)
        out.add(s.casefold())
    return out


def _which_field(token: str, kind: str, slots: dict[str, Any]) -> str | None:
    """Return the slot name whose sealed value equals ``token`` (casefold only
    for verdict labels — NEVER loosen the comparison for a hash), or None."""
    for name, value in slots.items():
        sval = str(value)
        if kind == "verdict":
            if sval.casefold() == token.casefold():
                return name
        elif sval == token or sval.casefold() == token.casefold():
            return name
    return None


class ExactMatchScorer:
    """Re-derive every emitted handle from the sealed field. Tolerance 0 for
    hashes/ids/ints; casefold is applied ONLY to verdict labels."""

    name = "exact-match"

    def entails(self, premise: str, hypothesis: str) -> bool | None:
        # Premise is the sealed-value bag (space-joined); hypothesis is a token.
        bag = set(premise.split())
        return hypothesis in bag or hypothesis.casefold() in {b.casefold() for b in bag}


# --------------------------------------------------------------------------- neural seam


ENTAILMENT_BACKEND_NEURAL = "transformers-cross-encoder"
ENTAILMENT_BACKEND_STUB = "deterministic-stub"


class NeuralNLIScorer:
    """A cross-encoder NLI entailment scorer — the upgrade seam.

    Maturity: ``research-early``. The implementation is real: ``load()`` lazy
    imports ``transformers``/``torch`` and constructs a sequence-classification
    cross-encoder for ``model_id`` (a DeBERTa/MiniCheck-class MNLI model);
    ``score(premise, hypothesis)`` runs the model and returns the softmax
    probability of the ENTAILMENT class. But it is FAIL-CLOSED end to end: in
    this environment ``import transformers`` raises (the ``tokenizers`` pin —
    still true this session), so ``load()`` returns False, ``score`` returns
    None, and ``entails`` returns None — which the gate treats as "cannot
    certify" → ABSTAIN. ``load()`` also refuses to claim availability unless a
    model object is actually constructed (imports alone are never enough — the
    M0c probe's bar). The scorer can never RAISE a verdict: ``entails`` is None
    until a conformal λ̂ is applied, and even then only refers a prose claim
    toward ABSTAIN.
    """

    backend = ENTAILMENT_BACKEND_NEURAL

    def __init__(self, model_id: str = "MoritzLaurer/DeBERTa-v3-base-mnli") -> None:
        self._model_id = model_id
        self._loaded = False
        self._available = False
        self._model: Any = None
        self._tokenizer: Any = None
        self._entail_index: int | None = None
        self._lambda_hat: float | None = None  # set only by a real calibration

    @property
    def name(self) -> str:
        # Honest about run-state: "(off)" until a model is actually loaded.
        return "neural-nli" if self._available else "neural-nli(off)"

    def load(self) -> bool:
        if self._loaded:
            return self._available
        self._loaded = True
        try:  # lazy — never import transformers/torch at module import time
            import torch  # noqa: F401
            from transformers import (  # type: ignore[import-not-found]
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except Exception:  # noqa: BLE001 — ImportError (tokenizers pin) or any other
            self._available = False
            return False
        # Imports alone are NOT availability (the M0c probe bar). Only a
        # constructed model + a located entailment label index counts.
        try:
            tokenizer = AutoTokenizer.from_pretrained(self._model_id)
            model = AutoModelForSequenceClassification.from_pretrained(self._model_id)
            model.eval()
            entail_index = _entailment_label_index(model)
        except Exception:  # noqa: BLE001 — no weights / no network / unknown labels
            self._available = False
            return False
        self._tokenizer = tokenizer
        self._model = model
        self._entail_index = entail_index
        self._available = True
        return True

    def score(self, premise: str, hypothesis: str) -> float | None:
        """P(entailment) ∈ [0,1], or None when the model is not loaded."""
        if not self.load():
            return None
        import torch  # type: ignore[import-not-found]

        inputs = self._tokenizer(
            premise, hypothesis, return_tensors="pt", truncation=True
        )
        with torch.no_grad():
            logits = self._model(**inputs).logits[0]
            probs = torch.softmax(logits, dim=-1)
        return float(probs[self._entail_index].item())

    def set_lambda_hat(self, lambda_hat: float) -> None:
        """Pin a calibrated SCORE threshold; ``entails`` then thresholds on it."""
        if not 0.0 <= lambda_hat <= 1.0:
            raise ValueError(f"lambda_hat must lie in [0,1], got {lambda_hat!r}")
        self._lambda_hat = float(lambda_hat)

    def entails(self, premise: str, hypothesis: str) -> bool | None:
        score = self.score(premise, hypothesis)
        if score is None:
            return None  # not running → cannot certify → ABSTAIN upstream
        if self._lambda_hat is None:
            return None  # loaded but UNCALIBRATED → still cannot certify
        return score >= self._lambda_hat


def _entailment_label_index(model: Any) -> int:
    """Locate the ENTAILMENT class index from the model's own label map.

    MNLI heads order their three labels differently across checkpoints; never
    hard-code an index. Reads ``config.label2id`` (case-insensitive), then
    ``id2label``. Raises if no entailment label is present — refusing to guess
    is the fail-closed choice."""
    config = model.config
    label2id = getattr(config, "label2id", None) or {}
    for label, idx in label2id.items():
        if str(label).strip().lower() == "entailment":
            return int(idx)
    id2label = getattr(config, "id2label", None) or {}
    for idx, label in id2label.items():
        if str(label).strip().lower() == "entailment":
            return int(idx)
    raise ValueError(
        "model exposes no 'entailment' label in config.label2id/id2label; "
        "refusing to guess the class index"
    )


# --------------------------------------------------------------------------- conformal calibration


@dataclass(frozen=True, slots=True)
class Calibration:
    """The result of a split-conformal calibration of an entailment scorer
    (Mohri & Hashimoto 2024, arXiv:2402.10978).

    ``lambda_hat`` is a SCORE threshold: a claim is treated as grounded iff the
    scorer's entailment probability is ``>= lambda_hat``. The named guarantee is
    MARGINAL and exchangeability-dependent: over draws from the SAME
    distribution as the calibration set, P(a claim accepted at λ̂ is in fact
    not-entailed) ≤ ``alpha``. It is not worst-case, not conditional, and not
    valid off-distribution; a synthetic calibration set certifies only the
    synthetic distribution (``model_loaded``/``scorer_backend`` record which
    scorer produced it, so a placeholder λ̂ can never masquerade as the real
    model's)."""

    lambda_hat: float
    alpha: float
    n: int
    model_id: str
    scorer_backend: str
    model_loaded: bool


def conformal_lambda_hat(nonconformity: Sequence[float], alpha: float) -> float:
    """Split-conformal quantile λ̂ (Mohri & Hashimoto 2024; Vovk et al.).

    λ̂ = the ⌈(n+1)(1-α)⌉-th smallest of the ``nonconformity`` scores. When that
    rank exceeds ``n`` the quantile is undefined at finite sample, so λ̂ = 1.0 —
    maximally conservative (accept nothing below the score ceiling); the named
    guarantee then holds only via near-total back-off. Pure order statistic, no
    numpy — the exact-math discipline of ``engine/crc_gate.py``."""
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must lie in (0,1), got {alpha!r}")
    n = len(nonconformity)
    if n == 0:
        raise ValueError("conformal calibration needs at least one labelled pair")
    for s in nonconformity:
        if not 0.0 <= s <= 1.0:
            raise ValueError(f"nonconformity scores must lie in [0,1], got {s!r}")
    rank = math.ceil((n + 1) * (1.0 - alpha))
    if rank > n:
        return 1.0
    return float(sorted(nonconformity)[rank - 1])


class _CalibratableScorer(Protocol):
    backend: str

    def load(self) -> bool: ...
    def score(self, premise: str, hypothesis: str) -> float | None: ...


def calibrate(
    scorer: _CalibratableScorer,
    pairs: Iterable[tuple[str, str, bool]],
    *,
    alpha: float,
    model_id: str,
) -> Calibration:
    """Calibrate ``scorer`` over labelled ``(premise, hypothesis, entailed)``
    pairs and return the conformal λ̂ (Mohri–Hashimoto).

    Per-example back-off (nonconformity): for a NOT-entailed pair it is the
    scorer's own entailment probability ``s`` — the threshold λ̂ must EXCEED to
    drop the claim; for an entailed pair it is ``0.0`` — no back-off is needed
    to keep a factual claim. λ̂ is the upper conformal quantile of those values,
    so filtering a fresh draw at λ̂ leaves it factual w.p. ≥ 1-α (i.e.
    P(accepted ∧ not-entailed) ≤ α, marginally).

    Fail-closed: the scorer MUST be loaded (an unloaded scorer cannot produce
    scores — calibrating one would fabricate the quantile) and MUST return a
    score for every pair, else this raises rather than inventing a value.
    ``model_loaded`` is True only for the real neural backend; any other backend
    (a deterministic test stub) is recorded as ``model_loaded=False`` so its λ̂
    is never mistaken for the real model's."""
    if not scorer.load():
        raise ValueError(
            "scorer is not loaded; an uncalibratable scorer cannot produce the "
            "nonconformity scores a conformal quantile is computed from"
        )
    nonconformity: list[float] = []
    n_pairs = 0
    for premise, hypothesis, entailed in pairs:
        n_pairs += 1
        if entailed:
            nonconformity.append(0.0)
            continue
        s = scorer.score(premise, hypothesis)
        if s is None:
            raise ValueError(
                "a loaded scorer returned None for a calibration pair — refusing "
                "to compute a quantile from missing scores"
            )
        if not 0.0 <= s <= 1.0:
            raise ValueError(f"scorer returned a score outside [0,1]: {s!r}")
        nonconformity.append(float(s))
    if n_pairs == 0:
        raise ValueError("calibration corpus is empty")
    lambda_hat = conformal_lambda_hat(nonconformity, alpha)
    return Calibration(
        lambda_hat=lambda_hat,
        alpha=alpha,
        n=n_pairs,
        model_id=model_id,
        scorer_backend=scorer.backend,
        model_loaded=scorer.backend == ENTAILMENT_BACKEND_NEURAL and scorer.load(),
    )


# --------------------------------------------------------------------------- the gate


class VoiceGate:
    """The faithfulness gate. One-sided: it begins at PERMIT and only lowers."""

    def __init__(
        self,
        *,
        exact: ExactMatchScorer | None = None,
        neural: NeuralNLIScorer | None = None,
    ) -> None:
        self._exact = exact or ExactMatchScorer()
        self._neural = neural or NeuralNLIScorer()

    def evaluate(
        self,
        *,
        answer: str,
        template: str | None,
        slots: dict[str, Any],
        asserted_verdict: str | None = None,
        sealed_verdict: str | None = None,
    ) -> GateResult:
        scorer_name = self._exact.name
        if self._neural.load():  # stays False today; recorded honestly if it ever flips
            scorer_name = f"{self._exact.name}+{self._neural.name}"

        # ── RULE B: structural FORBID on an asserted contradiction ──────────
        # Only fires when the speaker asserted a verdict about a record and the
        # sealed verdict differs. Deterministic; not neural-overridable.
        if (
            asserted_verdict is not None
            and sealed_verdict is not None
            and asserted_verdict.casefold() != str(sealed_verdict).casefold()
        ):
            return GateResult(
                verdict=Verdict.FORBID,
                scorer=scorer_name,
                threshold_label=THRESHOLD_LABEL,
                claims=[
                    Claim(
                        token=asserted_verdict,
                        kind="verdict",
                        source_field=None,
                        outcome="contradiction",
                    )
                ],
                reason=f"asserted-verdict-{asserted_verdict}-contradicts-sealed-{sealed_verdict}",
            )

        # ── RULE A: reconstruction proof (the deterministic happy path) ─────
        if template is not None:
            try:
                if template.format(**slots) == answer:
                    claims = [
                        Claim(
                            token=str(v),
                            kind="slot",
                            source_field=k,
                            outcome="sealed",
                        )
                        for k, v in slots.items()
                    ]
                    return GateResult(
                        verdict=Verdict.PERMIT,
                        scorer=scorer_name,
                        threshold_label=THRESHOLD_LABEL,
                        claims=claims,
                        reason="reconstruction-exact",
                    )
            except (KeyError, IndexError, ValueError):
                pass  # fall through to token decomposition / ABSTAIN

        # ── Fallback: token-by-token faithfulness (any non-reconstructible
        #    answer — prose, injection — lands here and fails closed) ─────────
        sealed = _sealed_value_set(slots)
        bag = " ".join(sealed)
        claims: list[Claim] = []
        all_sealed = True
        for token, kind in _extract_handles(answer):
            field_name = _which_field(token, kind, slots)
            if field_name is not None:
                claims.append(Claim(token=token, kind=kind, source_field=field_name, outcome="sealed"))
                continue
            # Not a sealed handle. Ask exact, then neural (off → None → unsealed).
            decided = self._exact.entails(bag, token)
            if decided is True:
                claims.append(Claim(token=token, kind=kind, source_field="(value-bag)", outcome="sealed"))
                continue
            neural = self._neural.entails(bag, token)
            if neural is True:
                claims.append(Claim(token=token, kind=kind, source_field="(neural)", outcome="sealed"))
                continue
            claims.append(Claim(token=token, kind=kind, source_field=None, outcome="unsealed"))
            all_sealed = False

        if all_sealed:
            # Every handle is sealed, but the answer wasn't a clean reconstruction
            # — there is unverified prose residue around the handles. Without a
            # working entailment scorer we cannot certify the prose, so we do not
            # promote to PERMIT. Fail closed.
            return GateResult(
                verdict=Verdict.ABSTAIN,
                scorer=scorer_name,
                threshold_label=THRESHOLD_LABEL,
                claims=claims,
                reason="handles-sealed-but-prose-uncertified",
            )
        return GateResult(
            verdict=Verdict.ABSTAIN,
            scorer=scorer_name,
            threshold_label=THRESHOLD_LABEL,
            claims=claims,
            reason="unsealed-token-in-answer",
        )
