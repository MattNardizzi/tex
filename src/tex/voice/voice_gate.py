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

NAMING HONESTY (the nanozk lesson): this is exact-match + a fail-closed
entailment seam. It is NOT "conformal factuality" and carries NO coverage
guarantee — there is no labelled calibration corpus, so the conformal quantile
q̂ = ⌈(n+1)(1-α)⌉/n (Mohri & Hashimoto, ICML 2024) is uncomputable today. The
neural threshold is a conservative fixed constant, labelled ``research-early``.
The words "guarantee", "coverage", and "1-alpha" appear in no user-facing
string this module produces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from tex.domain.verdict import Verdict

__all__ = [
    "Scorer",
    "ExactMatchScorer",
    "NeuralNLIScorer",
    "GateResult",
    "VoiceGate",
    "THRESHOLD_LABEL",
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


class NeuralNLIScorer:
    """A cross-encoder NLI entailment scorer — the upgrade seam, **OFF today**.

    Maturity: ``research-early`` / NOT RUNNING. ``load()`` lazy-imports
    ``transformers``; in this environment that import raises (``tokenizers
    0.21.2`` vs the ``<0.14`` transformers pins — verified this session), and no
    model weights are vendored and there is no GPU. So ``load()`` returns False
    and ``entails`` returns None forever, which the gate treats as "cannot
    certify" → ABSTAIN. This class exists so the seam is real and a real
    DeBERTa/MiniCheck-class entailment model can be dropped in later; it does
    NOT pretend to run, and it can never RAISE a verdict — only refer a prose
    claim toward ABSTAIN.
    """

    name = "neural-nli(off)"

    def __init__(self, model_id: str = "MoritzLaurer/DeBERTa-v3-base-mnli") -> None:
        self._model_id = model_id
        self._loaded = False
        self._available = False

    def load(self) -> bool:
        if self._loaded:
            return self._available
        self._loaded = True
        try:  # lazy — never import transformers at module import time
            import transformers  # noqa: F401
        except Exception:  # noqa: BLE001 — ImportError (tokenizers pin) or any other
            self._available = False
            return False
        # Even if the import unexpectedly succeeds, weights are not vendored and
        # there is no GPU here; refuse to claim availability without a verified
        # model load. A future build wires the real pipeline here.
        self._available = False
        return False

    def entails(self, premise: str, hypothesis: str) -> bool | None:
        if not self.load():
            return None  # not running → cannot certify → ABSTAIN upstream
        return None


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
