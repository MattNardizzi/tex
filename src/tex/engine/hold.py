"""
The Hold — Tex's abstention, made first-class.

[Architecture: Layer 4 (Execution Governance)]

PERMIT stands on a bound; FORBID stands on a proof; ABSTAIN, historically,
stood on a hand-tuned middle band — and it is the *only* verdict the operator
ever experiences (a PERMIT keeps the glass clean, a FORBID blocks in silence).
This module turns that residue into a first-class object of the same caliber as
the other two: a **hold** that knows *why* Tex cannot decide and *what one fact*
would let it.

Three properties, each grounded in the research the doctrine cites
(TEX_ABSTAIN_DOCTRINE.md):

  1. CERTIFIED — the two-sided ``CRCCertificate`` (engine/crc_gate.py) already
     carries the hold band [lambda_hat, lambda_forbid]: the region where neither
     a PERMIT nor a FORBID can be certified at its budget. We read it; we do not
     recompute it. ``band_certified`` is the honest line: True only when the gate
     has real calibration AND this score fell inside the certified band.

  2. TYPED — every "cannot decide" splits into epistemic (reducible: a fact
     exists that would resolve it) vs aleatoric (irreducible: the situation is
     genuinely ambiguous; no fetch resolves it). Hüllermeier & Waegeman 2021.
     We emit a *calibrated score*, never a hard label — the dichotomy is
     contested at the margins (ICLR 2025), so the type degrades gracefully and
     the resolution path is chosen by margin, not by a brittle argmax.

  3. RESOLVING — for an epistemic hold we name the single pivotal fact (the
     value-of-information move; decision-targeted, EPIG-style — Bickford Smith
     2023 — not parameter-targeted BALD). Implemented as a deterministic map
     from the *uncertainty flags the pipeline already produced* to a
     human-readable question; when the PDP threads per-stream confidences,
     the L8 credal resolver (engine/credal_hold.py) re-ranks the candidate
     flags by closed-form EPIG over a SYNTHETIC posterior — still short of
     the North-Star: a real EPIG ranking needs a posterior good enough to
     estimate predictive information gain (a Layer-6 dependency, exactly like
     the certificate's live guarantee). The seam is real and wired; the organ
     behind it grows when the data does. The same posture as the vigil v2–v5
     scaffolds.

The Hold is attached to a Decision's metadata whenever the final verdict is
ABSTAIN, and travels to the voice surface (the ``human_decision`` channel) so
the operator hears the type and the pivotal question — never the case file.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict
from tex.engine.credal_hold import rank_pivotal_flags
from tex.engine.crc_gate import CRCCertificate

__all__ = [
    "HoldType",
    "ResolutionMode",
    "Hold",
    "build_hold",
]


class HoldType(StrEnum):
    """Why Tex cannot decide — the load-bearing distinction."""

    EPISTEMIC = "EPISTEMIC"   # reducible: a fact exists that would resolve it
    ALEATORIC = "ALEATORIC"   # irreducible: genuinely ambiguous, a human's call
    MIXED = "MIXED"           # neither side dominates by the margin


class ResolutionMode(StrEnum):
    """What the hold does next."""

    SELF_HEAL = "SELF_HEAL"           # epistemic + fact is fetchable inside the boundary
    HUMAN_FACT = "HUMAN_FACT"         # epistemic, but only a human holds the fact
    HUMAN_JUDGMENT = "HUMAN_JUDGMENT" # aleatoric: the call is the human's


# ── Flag → pivotal-fact map ─────────────────────────────────────────────
# Each uncertainty flag the pipeline can raise maps to (a) whether acquiring
# the missing fact is epistemic, (b) the human-readable question that fact
# answers, and (c) whether Tex could in principle fetch it from inside the
# sealed boundary (self-heal) rather than asking a person. Acquisition must
# ONLY ever consume signals from inside the boundary — never the action's own
# payload — or fact-fetching becomes the attack surface (doctrine §6, the limit).
_FLAG_PIVOTS: dict[str, tuple[bool, str, bool]] = {
    # flag: (is_epistemic, question, self_heal_possible)
    "no_retrieval_context": (
        True,
        "whether the supporting context was actually retrieved for this action",
        True,
    ),
    "crc_permit_region_exceeded": (
        False,
        "whether this action is safe enough to release without review",
        False,
    ),
    "cold_start": (
        True,
        "how this agent has behaved before — there is no history yet",
        True,
    ),
    "pending_lifecycle": (
        True,
        "whether this agent has finished onboarding and been admitted",
        True,
    ),
    "low_evidence_sufficiency": (
        True,
        "whether there is enough sealed evidence to stand behind a call",
        True,
    ),
    "semantic_low_confidence": (
        False,
        "what this action actually intends — the reading is genuinely ambiguous",
        False,
    ),
    "forbid_streak": (
        True,
        "why this agent keeps tripping the gate — something upstream is wrong",
        True,
    ),
}

# Flags that signal genuine ambiguity (aleatoric) rather than a missing fact.
_ALEATORIC_FLAGS = frozenset(
    flag for flag, (is_epi, _q, _sh) in _FLAG_PIVOTS.items() if not is_epi
)


class Hold(BaseModel):
    """A first-class abstention. Attached to a Decision when verdict == ABSTAIN."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # ── certified (read from the two-sided certificate) ──────────────────
    band_certified: bool = Field(
        description=(
            "Whether this hold sits in the gate's certified hold band — i.e. "
            "the gate has real calibration and this score fell strictly between "
            "the permit cutoff and the forbid cutoff. False when the gate is "
            "inert (no calibration yet): the hold is still correct, but its "
            "band carries no live guarantee — the honest posture until Layer 6 "
            "supplies outcome labels."
        )
    )
    band_lower: float = Field(description="Permit cutoff — lower edge of the hold band.")
    band_upper: float = Field(description="Forbid cutoff — upper edge of the hold band.")
    final_score: float = Field(ge=0.0, le=1.0)

    # ── typed (calibrated scores, not a hard label) ──────────────────────
    epistemic_score: float = Field(
        ge=0.0, le=1.0, description="Calibrated weight that the indecision is reducible."
    )
    aleatoric_score: float = Field(
        ge=0.0, le=1.0, description="Calibrated weight that the indecision is irreducible."
    )
    hold_type: HoldType

    # ── resolving (the single pivotal fact) ──────────────────────────────
    resolution_mode: ResolutionMode
    resolving_question: str | None = Field(
        default=None,
        description=(
            "The one fact that would collapse the hold, phrased as the question "
            "it answers. None for a pure aleatoric hold — there is no fact to name."
        ),
    )
    pivotal_flag: str | None = Field(
        default=None,
        description="The uncertainty flag the resolving question derives from.",
    )

    # ── spoken surface (meaning is voiced; the glass stays clean) ─────────
    sentence: str = Field(description="The line Tex speaks when it surfaces this hold.")
    detail: str | None = Field(
        default=None, description="The grounding beneath the sentence, if any."
    )


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def build_hold(
    *,
    verdict: Verdict,
    final_score: float,
    uncertainty_flags: tuple[str, ...] | list[str],
    certificate: CRCCertificate | None,
    confidence: float = 0.5,
    agent_id: str | None = None,
    action_type: str | None = None,
    stream_confidences: dict[str, float] | None = None,
) -> Hold | None:
    """Build the Hold for an ABSTAIN. Returns None for any non-ABSTAIN verdict.

    Pure and deterministic: identical inputs always produce an identical Hold,
    so the PDP determinism fingerprint is preserved. No I/O, no clocks, no
    randomness — the resolution path is a fixed function of the flags and the
    certificate.

    ``stream_confidences`` carries the per-stream confidence components the
    router fused (the ``conf_stream:*`` keys the router surfaces in
    ``RoutingResult.scores``). When present with more than one epistemic
    candidate flag, the L8 credal/EPIG resolver (engine/credal_hold.py)
    re-ranks WHICH resolving question is named first — over a synthetic
    posterior, observation-only, still pure and deterministic. When None
    (every pre-existing caller), behavior is identical to before the
    parameter existed.
    """
    if verdict is not Verdict.ABSTAIN:
        return None

    flags = tuple(f for f in uncertainty_flags)
    flags_cf = tuple(f.casefold() for f in flags)

    # ── typed: epistemic vs aleatoric from the flags the pipeline raised ──
    # Epistemic mass accrues from "a fact exists" flags; aleatoric mass from
    # genuine-ambiguity flags. Low confidence with no informative flag is
    # treated as mildly epistemic (more evidence would help) but never
    # certain — kept honest as a score.
    epi = 0.0
    ale = 0.0
    for f in flags_cf:
        pivot = _FLAG_PIVOTS.get(f)
        if pivot is None:
            continue
        is_epistemic = pivot[0]
        if is_epistemic:
            epi += 1.0
        else:
            ale += 1.0

    # A wide confidence gap with no flag at all → weak epistemic prior:
    # "I might decide with more to go on." Never overrides explicit signals.
    if epi == 0.0 and ale == 0.0:
        epi += (1.0 - _clamp(confidence)) * 0.5
        ale += 0.25  # genuine residual ambiguity floor

    total = epi + ale
    if total <= 0.0:
        epistemic_score = aleatoric_score = 0.5
    else:
        epistemic_score = _clamp(epi / total)
        aleatoric_score = _clamp(ale / total)

    # Margin-based labelling — never a brittle argmax. The dichotomy is
    # contested, so within a margin we say MIXED and lean to the safer path.
    _MARGIN = 0.20
    if epistemic_score - aleatoric_score > _MARGIN:
        hold_type = HoldType.EPISTEMIC
    elif aleatoric_score - epistemic_score > _MARGIN:
        hold_type = HoldType.ALEATORIC
    else:
        hold_type = HoldType.MIXED

    # ── resolving: pick the pivotal fact (decision-targeted VOI seam) ─────
    # Among the epistemic flags present, choose by the fixed pivot order —
    # unless the PDP threaded per-stream confidences, in which case the L8
    # credal/EPIG resolver re-ranks the candidates over its SYNTHETIC
    # posterior (engine/credal_hold.py — not a live Layer-6 posterior).
    # Observation-only: this can only reorder WHICH epistemic fact is named
    # first; with no usable signal the ranking is the identity, and the
    # verdict is never touched. The chosen flag's question is the single
    # thing Tex would need to know.
    epistemic_candidates = tuple(
        f for f in _FLAG_PIVOTS if f in flags_cf and _FLAG_PIVOTS[f][0]
    )
    if stream_confidences and len(epistemic_candidates) > 1:
        band = (
            (certificate.hold_band_lower, certificate.hold_band_upper)
            if certificate is not None
            else None
        )
        epistemic_candidates = rank_pivotal_flags(
            candidate_flags=epistemic_candidates,
            stream_confidences=stream_confidences,
            final_score=final_score,
            band=band,
        )

    pivotal_flag: str | None = None
    resolving_question: str | None = None
    self_heal_possible = False
    if epistemic_candidates:
        pivotal_flag = epistemic_candidates[0]
        _is_epi, resolving_question, self_heal_possible = _FLAG_PIVOTS[pivotal_flag]

    # ── resolution mode ──────────────────────────────────────────────────
    if hold_type is HoldType.ALEATORIC or resolving_question is None:
        resolution_mode = ResolutionMode.HUMAN_JUDGMENT
        resolving_question = resolving_question if hold_type is not HoldType.ALEATORIC else None
    elif self_heal_possible:
        resolution_mode = ResolutionMode.SELF_HEAL
    else:
        resolution_mode = ResolutionMode.HUMAN_FACT

    # ── certified band (read from the certificate; never recomputed) ─────
    if certificate is not None:
        band_certified = bool(certificate.in_hold_band)
        band_lower = certificate.hold_band_lower
        band_upper = certificate.hold_band_upper
    else:
        band_certified = False
        band_lower = 0.0
        band_upper = 1.0

    # ── the spoken surface ───────────────────────────────────────────────
    who = agent_id or "an agent"
    what = action_type or "an action"
    if resolution_mode is ResolutionMode.HUMAN_JUDGMENT:
        sentence = "I'm holding this one. It isn't mine to call — it's yours."
        detail = (
            f"{who} attempted {what}. The signals genuinely conflict; no fact I "
            f"can fetch settles it, so I won't rule alone."
        )
    elif resolution_mode is ResolutionMode.SELF_HEAL:
        sentence = "I'm holding this for a beat while I check one thing."
        detail = (
            f"{who} attempted {what}. I'd clear it if I knew "
            f"{resolving_question}. I'm looking now."
        )
    else:  # HUMAN_FACT
        sentence = "I'm holding this. There's one thing I need to know."
        detail = (
            f"{who} attempted {what}. I'd clear it if I knew "
            f"{resolving_question} — and that's something only you can tell me."
        )

    return Hold(
        band_certified=band_certified,
        band_lower=band_lower,
        band_upper=band_upper,
        final_score=_clamp(final_score),
        epistemic_score=round(epistemic_score, 4),
        aleatoric_score=round(aleatoric_score, 4),
        hold_type=hold_type,
        resolution_mode=resolution_mode,
        resolving_question=resolving_question,
        pivotal_flag=pivotal_flag,
        sentence=sentence,
        detail=detail,
    )
