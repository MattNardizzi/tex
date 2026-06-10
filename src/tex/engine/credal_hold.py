"""
L8 — Credal-conformal hold + EPIG resolver (Wave 2, frontier certificate).

[Architecture: Layer 4 (Execution Governance) — ABSTAIN enrichment only]

What this is
------------
Two deterministic, closed-form primitives over the router's score-fusion
machinery, plus the one narrow wire into ``engine/hold.py``:

1. A **credal interval** for the fused risk. The router reports one number,
   ``sum_k w_k * s_k``, evaluated at the policy's fusion-weight point ``w0``
   (``domain/policy._DEFAULT_FUSION_WEIGHTS`` by default). This module
   computes the exact range ``[risk_low, risk_high]`` that fused risk can
   take as

   * the weight vector ranges over an L1-ball of radius ``weight_epsilon``
     around ``w0``, intersected with the probability simplex (**weight
     ambiguity** — the epistemic part: which fusion weights are "right" is
     a modelling choice, and a fact could in principle settle it), and
   * each stream score ranges over a confidence-derived box
     ``[s_k - (1-c_k)/2, s_k + (1-c_k)/2] ∩ [0, 1]`` (**within-stream
     uncertainty** — the aleatoric part, from the per-stream confidences the
     router now surfaces as ``conf_stream:*`` score keys).

   The extrema of a linear objective over this polytope are attained at
   vertices and computed by a greedy mass transport (sort by coefficient,
   donate from the worst donors to the single best receiver, donor-capped) —
   no solver dependency, pure stdlib, verified against a brute-force grid in
   ``tests/test_credal_hold.py``.

2. An **EPIG resolver**. An ABSTAIN hold names candidate evidence
   acquisitions (the epistemic pivotal flags of ``engine/hold.py``). This
   module ranks them by how much the *expected answer* is predicted to
   shrink — or outright resolve — the credal interval: for each candidate,
   collapse its stream's score-box to each of its two endpoints (a
   moment-matched two-point predictive), recompute the closed-form interval,
   and take the expectation. Rank lexicographically by (expected resolution
   probability, expected width reduction). This is decision-targeted
   expected-information-gain in the EPIG sense (Bickford Smith et al.,
   AISTATS 2023, arXiv:2304.08151 — prediction-oriented, not
   parameter-targeted BALD), with credal width standing in for predictive
   entropy; the epistemic vs aleatoric framing follows Hüllermeier &
   Waegeman 2021 (Mach. Learn. 110:457-506), including their own caveat that
   the dichotomy blurs at the margins. The "credal" vocabulary is the
   standard one for convex sets of probability measures (Levi 1980, where
   the term originates; Walley 1991, the canonical monograph). Combining
   credal sets with conformal machinery has live precedent — Javanmardi,
   Stutz & Hüllermeier, "Conformalized Credal Set Predictors",
   arXiv:2402.10723 (NeurIPS 2024) — but ours is NOT that construction:
   their credal set is conformally calibrated over labels; ours is a
   weight-ambiguity polytope, and the "conformal" half here is the CRC
   gate's certified hold band, read from the certificate and never
   recomputed. (All five citations verified against primary sources,
   2026-06-10.)

The honest scope of THIS wave (read before extending)
-----------------------------------------------------
``research-early``. The North-Star (ROADMAP L8) is EPIG over a *real Layer-6
posterior*. That posterior does not exist yet, so:

* The wired path (``rank_pivotal_flags``, consumed by ``build_hold`` when the
  PDP threads ``stream_confidences``) sees ONLY the fused ``final_score`` and
  the 3–4 per-stream confidences — not per-stream scores, not the live
  policy's weights. Its synthetic posterior therefore centers every stream's
  score-box at ``final_score`` and uses the *default* fusion weights
  (renormalized when no agent stream contributed, mirroring
  ``router._effective_weights``). Under that maximally score-uninformative
  posterior the ranking degrades gracefully toward "stream weight x stream
  uncertainty, band- and clamp-corrected" — information-bearing (it reads
  real confidences the fixed dict order ignores) but far short of the
  North-Star. Say "EPIG over a synthetic posterior", never "decision-optimal
  over the live posterior".
* The benchmark (N=2000 synthetic holds, one true pivot, EPIG ordering beats
  dict-order and random on fraction-resolved-per-question) earns the claim
  that *the machinery recovers a ground-truth pivot from calibrated
  observables*. It is a synthetic artifact, not field validation.
* Wiring is observation-only and monotone-safe: the ONLY live effect is
  which resolving question an ABSTAIN hold asks first. Verdicts are never
  touched (``build_hold`` returns None for non-ABSTAIN), holds are never
  created or suppressed, and with ``stream_confidences=None`` behavior is
  identical to the pre-L8 dict-order pick. Fail-closed: missing or
  unrecognized inputs contribute zero discrimination and fall back to the
  fixed pivot order.

Everything here is pure and deterministic — no I/O, no clocks, no
randomness — so the PDP determinism fingerprint and ``build_hold``'s purity
contract are preserved.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.domain.policy import _DEFAULT_FUSION_WEIGHTS

__all__ = [
    "CredalParams",
    "DEFAULT_CREDAL_PARAMS",
    "CredalInterval",
    "credal_interval",
    "AcquisitionScore",
    "score_acquisition",
    "rank_acquisitions",
    "rank_pivotal_flags",
]


# ── named constants (SelectiveRiskRule pattern — no inline literals) ──────


@dataclass(frozen=True, slots=True)
class CredalParams:
    """The named constants of the credal hold.

    * ``weight_epsilon`` — L1 radius of the fusion-weight credal ball. The
      default 0.10 reads as: the operator stands behind the policy weights up
      to a total reallocation of 10% of the fusion mass. Width scales
      monotonically with it; 0.0 pins the weights (epistemic width 0).
    """

    weight_epsilon: float = 0.10


DEFAULT_CREDAL_PARAMS = CredalParams()


# Streams of the wired synthetic posterior, and how the policy's seven
# fusion-weight keys fold onto the four confidence streams the router
# surfaces (``conf_stream:*``). ``criticality`` carries fusion weight but has
# no confidence stream — it participates with a zero-width box (we have no
# uncertainty signal for it, so we must not invent one).
_WIRED_WEIGHT_FOLD: dict[str, tuple[str, ...]] = {
    "deterministic": ("deterministic",),
    "specialist": ("specialists",),
    "semantic": ("semantic",),
    "criticality": ("criticality",),
    "agent": ("agent_identity", "agent_capability", "agent_behavioral"),
}
_WIRED_CONTENT_STREAMS: tuple[str, ...] = (
    "deterministic",
    "specialist",
    "semantic",
    "criticality",
)

# Which confidence stream each epistemic pivotal flag of hold._FLAG_PIVOTS
# interrogates. Today's epistemic flags reach only the semantic and agent
# streams, so the wired ranking discriminates between exactly those two —
# the deterministic/specialist confidences still shape the interval but no
# current flag can ask about them. Two honest simplifications, named:
# ``no_retrieval_context`` is emitted by the specialist judges
# (specialists/judges.py) as well as the semantic layer; mapping it to
# semantic alone (the larger retrieval consumer, weight .273 vs .195)
# slightly UNDER-ranks it, which is the safe direction. And two census
# entries (``low_evidence_sufficiency``, ``pending_lifecycle``) currently
# have no live emitter in src/ (the router raises ``weak_semantic_evidence``
# instead) — they rank correctly if they ever fire, but cannot appear in a
# production hold today; renaming the census is the abstain track's call,
# not ours. A flag missing from this map (or a stream missing from the
# supplied confidences) scores zero and keeps its fixed-order position —
# fail-closed, never an exception.
_FLAG_STREAMS: dict[str, str] = {
    "no_retrieval_context": "semantic",
    "low_evidence_sufficiency": "semantic",
    "cold_start": "agent",
    "forbid_streak": "agent",
    "pending_lifecycle": "agent",
}

_CONF_KEY_PREFIX = "conf_stream:"


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


# ── the credal interval (closed-form LP extrema) ──────────────────────────


@dataclass(frozen=True, slots=True)
class CredalInterval:
    """The fused-risk credal interval and its uncertainty decomposition.

    ``risk_low <= point <= risk_high`` always. ``epistemic_width`` is the
    interval width with every score-box collapsed to its center (weight
    ambiguity alone); ``aleatoric_width`` is the width with the weights
    pinned at their center (score-boxes alone). The total ``width`` is at
    least each component but is not their sum — the components are named
    slices of one polytope, not independent terms.
    """

    point: float
    risk_low: float
    risk_high: float
    epistemic_width: float
    aleatoric_width: float

    @property
    def width(self) -> float:
        return self.risk_high - self.risk_low

    def resolved(self, band: tuple[float, float]) -> bool:
        """Whether the whole interval clears the hold band ``(lower, upper)``:
        every weight/score in the credal set agrees on PERMIT-side
        (``risk_high <= lower``) or FORBID-side (``risk_low >= upper``)."""
        lower, upper = band
        return self.risk_high <= lower or self.risk_low >= upper


def _linear_extremum(
    *,
    scores: dict[str, float],
    weights: dict[str, float],
    epsilon: float,
    maximize: bool,
) -> float:
    """Closed-form extremum of ``sum_k w_k * scores_k`` over the credal ball.

    Feasible set: ``{w : w_k >= 0, sum_k w_k = sum_k w0_k,
    sum_k |w_k - w0_k| <= epsilon}``. Any feasible point moves total mass
    ``m <= epsilon/2`` from donors to receivers. A linear objective is
    optimized by sending ALL received mass to one best-coefficient receiver
    and drawing donated mass greedily from the worst-coefficient donors,
    donor-capped at ``w0_k`` (the exchange argument for a transportation LP
    on a line; verified against a brute-force grid in the tests).
    """
    keys = sorted(weights)
    value = sum(weights[k] * scores[k] for k in keys)
    budget = epsilon / 2.0
    if budget <= 0.0 or len(keys) < 2:
        return value

    if maximize:
        receiver = max(keys, key=lambda k: scores[k])
        donors = sorted((k for k in keys if k != receiver), key=lambda k: scores[k])
    else:
        receiver = min(keys, key=lambda k: scores[k])
        donors = sorted((k for k in keys if k != receiver), key=lambda k: -scores[k])

    for donor in donors:
        per_unit = scores[receiver] - scores[donor]
        if (maximize and per_unit <= 0.0) or (not maximize and per_unit >= 0.0):
            break  # remaining donors can only hurt (or do nothing)
        take = min(budget, weights[donor])
        value += take * per_unit
        budget -= take
        if budget <= 0.0:
            break
    return value


def _score_boxes(
    *,
    scores: dict[str, float],
    confidences: dict[str, float] | None,
    weights: dict[str, float],
) -> tuple[dict[str, float], dict[str, float]]:
    """Per-stream score boxes ``[lo_k, hi_k]`` from confidences.

    A stream with confidence ``c`` gets a box of width ``1 - c`` centered at
    its score, clamped to ``[0, 1]``. A stream with no confidence entry gets
    a zero-width box — no uncertainty signal means we must not invent one.
    """
    lo: dict[str, float] = {}
    hi: dict[str, float] = {}
    for k in weights:
        s = _clamp(scores[k])
        c = _clamp(confidences.get(k, 1.0)) if confidences is not None else 1.0
        half = (1.0 - c) / 2.0
        lo[k] = max(0.0, s - half)
        hi[k] = min(1.0, s + half)
    return lo, hi


def _normalized_weights(weights: dict[str, float]) -> dict[str, float]:
    total = sum(weights.values())
    if total <= 0.0:
        raise ValueError("weights must have positive total mass")
    if any(w < 0.0 for w in weights.values()):
        raise ValueError("weights must be non-negative")
    return {k: w / total for k, w in weights.items()}


def credal_interval(
    *,
    scores: dict[str, float],
    weights: dict[str, float],
    confidences: dict[str, float] | None = None,
    params: CredalParams = DEFAULT_CREDAL_PARAMS,
) -> CredalInterval:
    """The closed-form credal interval of the fused risk.

    ``scores`` must cover every key of ``weights`` (KeyError otherwise — the
    rich API is strict; the wired path constructs its own complete inputs).
    ``confidences`` may cover any subset; missing streams get zero-width
    boxes. Pure and deterministic.
    """
    w0 = _normalized_weights(dict(weights))
    eps = max(0.0, params.weight_epsilon)
    lo, hi = _score_boxes(scores=scores, confidences=confidences, weights=w0)
    centers = {k: _clamp(scores[k]) for k in w0}

    point = sum(w0[k] * centers[k] for k in sorted(w0))
    risk_high = _linear_extremum(scores=hi, weights=w0, epsilon=eps, maximize=True)
    risk_low = _linear_extremum(scores=lo, weights=w0, epsilon=eps, maximize=False)
    epi_high = _linear_extremum(scores=centers, weights=w0, epsilon=eps, maximize=True)
    epi_low = _linear_extremum(scores=centers, weights=w0, epsilon=eps, maximize=False)
    aleatoric = sum(w0[k] * (hi[k] - lo[k]) for k in sorted(w0))

    return CredalInterval(
        point=_clamp(point),
        risk_low=_clamp(risk_low),
        risk_high=_clamp(risk_high),
        epistemic_width=max(0.0, epi_high - epi_low),
        aleatoric_width=max(0.0, aleatoric),
    )


# ── the EPIG resolver ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AcquisitionScore:
    """EPIG of acquiring one stream's answer, under the synthetic posterior.

    ``resolve_probability`` — predicted probability that the answer resolves
    the hold outright (the post-answer interval clears the band; 0.0 when no
    band is supplied). ``expected_width_drop`` — predicted shrink of the
    credal interval. Ranking is lexicographic on (resolve_probability,
    expected_width_drop), descending.
    """

    stream: str
    resolve_probability: float
    expected_width_drop: float


def score_acquisition(
    *,
    stream: str,
    scores: dict[str, float],
    weights: dict[str, float],
    confidences: dict[str, float],
    band: tuple[float, float] | None = None,
    params: CredalParams = DEFAULT_CREDAL_PARAMS,
) -> AcquisitionScore:
    """Closed-form EPIG of acquiring ``stream``'s answer.

    The synthetic predictive for the answer is the moment-matched two-point
    distribution on the stream's box endpoints (mean equals the current
    center score). For each endpoint, collapse the box (confidence -> 1.0),
    recompute the interval, and take expectations. A stream that is already
    certain — or absent from ``weights`` — scores (0, 0): asking it is
    predicted to change nothing.
    """
    if stream not in weights:
        return AcquisitionScore(stream=stream, resolve_probability=0.0, expected_width_drop=0.0)

    base = credal_interval(
        scores=scores, weights=weights, confidences=confidences, params=params
    )
    w0 = _normalized_weights(dict(weights))
    lo, hi = _score_boxes(scores=scores, confidences=confidences, weights=w0)
    box_width = hi[stream] - lo[stream]
    if box_width <= 0.0:
        return AcquisitionScore(stream=stream, resolve_probability=0.0, expected_width_drop=0.0)

    center = _clamp(scores[stream])
    p_high = (center - lo[stream]) / box_width  # moment-matched: E[answer] == center

    expected_width = 0.0
    resolve_probability = 0.0
    for answer, p_answer in ((hi[stream], p_high), (lo[stream], 1.0 - p_high)):
        if p_answer <= 0.0:
            continue
        post = credal_interval(
            scores={**scores, stream: answer},
            weights=weights,
            confidences={**confidences, stream: 1.0},
            params=params,
        )
        expected_width += p_answer * post.width
        if band is not None and post.resolved(band):
            resolve_probability += p_answer

    return AcquisitionScore(
        stream=stream,
        resolve_probability=resolve_probability,
        expected_width_drop=max(0.0, base.width - expected_width),
    )


def rank_acquisitions(
    *,
    candidates: tuple[str, ...],
    scores: dict[str, float],
    weights: dict[str, float],
    confidences: dict[str, float],
    band: tuple[float, float] | None = None,
    params: CredalParams = DEFAULT_CREDAL_PARAMS,
) -> tuple[AcquisitionScore, ...]:
    """Rank candidate acquisitions by EPIG, descending.

    Lexicographic on (resolve_probability, expected_width_drop); ties keep
    the candidates' input order (the caller's fixed priority), so the
    ranking is total, stable, and deterministic.
    """
    scored = [
        score_acquisition(
            stream=stream,
            scores=scores,
            weights=weights,
            confidences=confidences,
            band=band,
            params=params,
        )
        for stream in candidates
    ]
    indexed = sorted(
        enumerate(scored),
        key=lambda pair: (-pair[1].resolve_probability, -pair[1].expected_width_drop, pair[0]),
    )
    return tuple(score for _idx, score in indexed)


# ── the wired path (consumed by engine/hold.build_hold) ───────────────────


def _wired_weights(*, agent_present: bool) -> dict[str, float]:
    """Default fusion weights folded onto the four confidence streams.

    Mirrors ``router._effective_weights``: when no agent stream contributed,
    the agent mass is redistributed proportionally across the content
    streams so the vector still sums to 1.0. These are the DEFAULT policy
    weights — the live PolicySnapshot is not in ``build_hold``'s scope, and
    pretending otherwise would fabricate precision the wire does not have.
    """
    folded = {
        stream: sum(_DEFAULT_FUSION_WEIGHTS[k] for k in source_keys)
        for stream, source_keys in _WIRED_WEIGHT_FOLD.items()
    }
    if agent_present:
        return folded

    agent_mass = folded.pop("agent")
    content_mass = sum(folded[k] for k in _WIRED_CONTENT_STREAMS)
    scale = (content_mass + agent_mass) / content_mass
    return {k: folded[k] * scale for k in folded}


def _normalize_confidence_keys(stream_confidences: dict[str, float]) -> dict[str, float]:
    """Accept both ``conf_stream:semantic`` (the PDP thread) and bare names."""
    normalized: dict[str, float] = {}
    for key, value in stream_confidences.items():
        name = key[len(_CONF_KEY_PREFIX):] if key.startswith(_CONF_KEY_PREFIX) else key
        normalized[name] = _clamp(value)
    return normalized


def rank_pivotal_flags(
    *,
    candidate_flags: tuple[str, ...],
    stream_confidences: dict[str, float],
    final_score: float,
    band: tuple[float, float] | None = None,
    params: CredalParams = DEFAULT_CREDAL_PARAMS,
) -> tuple[str, ...]:
    """Order an ABSTAIN hold's epistemic pivotal flags information-optimally
    — over the SYNTHETIC posterior (see module docstring), not a live one.

    ``candidate_flags`` must arrive in the caller's fixed priority order
    (``hold._FLAG_PIVOTS`` order); ties — including every fail-closed case:
    empty confidences, unknown flags, streams with no confidence entry —
    preserve that order exactly, so with no usable signal this is the
    identity and ``build_hold`` behaves as it always did. Pure, total,
    deterministic; never raises on missing keys.
    """
    if len(candidate_flags) <= 1:
        return tuple(candidate_flags)

    confidences = _normalize_confidence_keys(stream_confidences)
    weights = _wired_weights(agent_present="agent" in confidences)
    center = _clamp(final_score)
    scores = {k: center for k in weights}

    by_stream: dict[str, AcquisitionScore] = {}
    for stream in sorted(weights):
        by_stream[stream] = score_acquisition(
            stream=stream,
            scores=scores,
            weights=weights,
            confidences=confidences,
            band=band,
            params=params,
        )

    def flag_key(pair: tuple[int, str]) -> tuple[float, float, int]:
        index, flag = pair
        stream = _FLAG_STREAMS.get(flag)
        acquired = by_stream.get(stream) if stream is not None else None
        if acquired is None:
            return (0.0, 0.0, index)
        return (-acquired.resolve_probability, -acquired.expected_width_drop, index)

    ordered = sorted(enumerate(candidate_flags), key=flag_key)
    return tuple(flag for _idx, flag in ordered)
