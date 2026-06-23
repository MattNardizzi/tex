"""
SIEVE ESTIMATE stage — count-based completeness estimator (calibration deferred).

The headline deliverable: a lower-bound unseen FRACTION with a CI plus a named
blind-spot ledger — NEVER a count, NEVER an implied totality (ARCHITECTURE.md §6,
§10, §12; RESEARCH_LOG.md §6).

PROVENANCE / SLICE-VS-ARCHITECTURE (what this estimator actually proves):

  This is the COUNT-BASED slice estimator. It counts capture occasions per
  entity and applies classical two-occasion Lincoln-Petersen / Chao2 /
  Good-Turing. It deliberately does NOT consume ``Incidence.catchability``
  (the slice asserts catchability as a plane constant of 1.0; measured
  catchability is a Phase-5 target). The slice is therefore COUNT-BASED, not
  calibrated, and ``catchability`` is carried-but-unused here.

  Honesty guarantees the SLICE proves (enforced in code + tests):
    - the headline ``lower`` is structurally clamped to <= 0.99 — never totality;
    - the output is an interval ``ci_low <= lower <= ci_high`` in [0,1] with a
      named count-method tag, never a bare count (UnseenEstimate.__post_init__);
    - every deliberately-withheld plane yields a named blind-spot ledger entry,
      and withholding more planes widens ``ci_high`` monotonically;
    - a withheld-plane-only (zero-signal) entity is NAMED, never folded in, and
      never produces a silent zero.

  ARCHITECTURE claims NOT exercised by this slice (do not read them as live):
    - MEASURED catchability (signed-cohort recall / honeytoken bite-rate);
    - the SENECA self-consistent-missing-mass algorithm (the ``seneca_no_overlap``
      method tag names the m==0 regime + a wide count fallback, NOT SENECA);
    - the Valiant-Valiant τ-floor and Orlitsky extrapolation horizon;
    - plane-ablation cross-validation. Until these exist, the ``"calibrated"``
      coverage-health label is RESERVED and this estimator is guarded never to
      emit it.

Two-occasion design for the thin slice: each plane is a capture occasion, each
resolved ``SieveEntity`` is the captured individual, and the cross-plane
incidence frequency-of-frequencies (how many entities were seen on one plane vs
both) feeds:

- Lincoln-Petersen / Chao2 → an absolute unseen-count LOWER bound (carried here
  as a fraction with a wide log-normal CI).
- Good-Turing coverage Ĉ = 1 − f1/N → the headline unseen FRACTION.

The slice deliberately produces a WIDE interval and a fully-populated
``NamedBlindSpot`` for every withheld plane: the honesty layer is proven FIRST.
Withholding MORE planes must widen the interval monotonically (ARCHITECTURE.md
§10 proof (c)). A zero-signal agent that acts only on a withheld plane is NAMED
in the ledger with its exact missing vantage and is NEVER folded into the
estimate (proof (d)).

Math conventions (ARCHITECTURE.md §6; Chao 1987, Lincoln-Petersen, Good 1953):

- ``D`` = number of distinct entities observed (across both occasions).
- ``n1``/``n2`` = entities captured on occasion 1 / occasion 2.
- ``m`` = entities captured on BOTH occasions (the recapture overlap).
- ``f1`` = entities seen on exactly ONE occasion (singletons); ``f2`` = m =
  entities seen on BOTH (doubletons in the two-occasion frequency spectrum).
- Lincoln-Petersen (Chapman bias-corrected):
      N̂ = (n1+1)(n2+1)/(m+1) − 1
  → unseen count D̂_unseen = N̂ − D ; unseen FRACTION = D̂_unseen / N̂.
- Chao2 lower bound on unobserved richness:
      f0̂ = f1·(f1−1) / (2·(f2+1))   (bias-corrected; always finite)
  → richness N̂_chao = D + f0̂.
- Good-Turing coverage:
      Ĉ = 1 − f1 / N_individuals  → unseen mass fraction = 1 − Ĉ = f1 / N.
- Log-normal CI on f0̂ (Chao 1987 §): a symmetric CI on log(f0̂) with variance
  ``var_f0`` maps to an asymmetric multiplicative band on the fraction.

Everything degrades to a deliberately-WIDE interval rather than raising; the
estimate is structurally incapable of asserting a count or an implied 100%
(``UnseenEstimate.__post_init__`` enforces ``0 <= ci_low <= lower <= ci_high <= 1``).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence

from tex.discovery.engine.models import (
    NamedBlindSpot,
    PlaneId,
    SieveEntity,
    UnseenEstimate,
)

# A withheld vantage is, by construction, a plane we cannot estimate the catch
# of. Each withheld plane inflates the upper band of the unseen fraction by this
# much (capped at 1.0 by the post-init invariant). This is the monotone-widening
# primitive: more withheld planes ⇒ strictly wider ci_high (ARCHITECTURE.md §10
# proof (c)). It is a DELIBERATELY conservative penalty, not a measured one — the
# slice withholds, so it must widen rather than pretend to know.
_WITHHELD_BAND_PENALTY = 0.15

# Floor on the half-width of the reported interval. The slice is honest-first:
# even when the recapture math is "clean" we never collapse the band to a point.
_MIN_HALF_WIDTH = 0.05

# z for a nominal ~95% log-normal interval (Chao 1987). We use a wide multiplier
# deliberately — the slice over-covers rather than under-covers.
_Z_95 = 1.96

# Cap on the squared coefficient of variation fed into the log-normal band. The
# Chao f0̂ variance has a fat upper tail in the low-singleton regime that, left
# uncapped, saturates the multiplicative band to the [0,1] ceiling — which would
# hide the deliberate, monotone withheld-plane widening behind a hard clamp. A
# cap of 3.0 still yields a genuinely WIDE band (~5x multiplicative spread) while
# leaving headroom for the withheld penalty to register.
_MAX_CV2 = 3.0


def _frequency_spectrum(
    entities: Iterable[SieveEntity],
    occasions: Sequence[PlaneId],
) -> tuple[int, int, int, int, int]:
    """Reduce entities to the two-occasion capture-recapture sufficient stats.

    Returns ``(D, n1, n2, m, f1)`` where, restricting attention to the supplied
    ``occasions``:

    - ``D``  = distinct entities seen on at least one of ``occasions``.
    - ``n1`` = entities seen on occasion[0].
    - ``n2`` = entities seen on occasion[1] (0 if fewer than two occasions).
    - ``m``  = entities seen on BOTH occasion[0] and occasion[1].
    - ``f1`` = entities seen on exactly ONE of ``occasions`` (singletons).

    Entities that touch NONE of ``occasions`` (e.g. a withheld-plane-only agent)
    are excluded from D — they are NAMED in the blind-spot ledger, never folded
    into the estimate (ARCHITECTURE.md §6 last bullet, §10 proof (d)).
    """
    occ = list(occasions)
    occ_set = set(occ)
    p1 = occ[0] if len(occ) >= 1 else None
    p2 = occ[1] if len(occ) >= 2 else None

    counts: Counter[int] = Counter()  # entity -> how many of `occasions` it hit
    n1 = n2 = m = 0
    distinct = 0
    for ent in entities:
        seen = ent.planes_seen & occ_set
        k = len(seen)
        if k == 0:
            continue  # zero-signal on the run occasions; named, not estimated
        distinct += 1
        counts[k] += 1
        if p1 is not None and p1 in seen:
            n1 += 1
        if p2 is not None and p2 in seen:
            n2 += 1
        if p1 is not None and p2 is not None and p1 in seen and p2 in seen:
            m += 1

    f1 = counts.get(1, 0)
    return distinct, n1, n2, m, f1


def _lognormal_band(point: float, variance: float) -> tuple[float, float]:
    """Chao (1987) log-normal CI multiplier band around a non-negative point.

    Given an estimate ``point`` (here the unseen FRACTION) and an approximate
    variance on the underlying richness, return ``(low, high)`` multiplicative
    bounds. Degenerate inputs (``point<=0`` or non-finite variance) return a
    deliberately-wide symmetric band so the caller never gets a point interval.
    """
    if point <= 0.0 or not math.isfinite(variance) or variance <= 0.0:
        # No usable curvature — widen hard and let the caller clamp to [0,1].
        return max(0.0, point - 0.5), point + 0.5
    cv2 = variance / (point * point)
    if not math.isfinite(cv2) or cv2 <= 0.0:
        return max(0.0, point - 0.5), point + 0.5
    # Cap the coefficient of variation. The Chao f0 variance has a fat upper tail
    # in the low-singleton regime that otherwise saturates the multiplicative
    # band to the [0,1] ceiling, hiding the deliberate withheld-plane widening
    # behind a clamp. We keep the band genuinely WIDE but bounded so that the
    # withheld penalty and estimator-disagreement terms added by the caller stay
    # visible and monotone. (Saturated regimes are still flagged "wide".)
    cv2 = min(cv2, _MAX_CV2)
    c = math.exp(_Z_95 * math.sqrt(math.log1p(cv2)))
    return point / c, point * c


def estimate_unseen(
    entities: Iterable[SieveEntity],
    occasions: Sequence[PlaneId],
    withheld_planes: Sequence[PlaneId] = (),
) -> UnseenEstimate:
    """Two-occasion capture-recapture over resolved entities.

    Args:
        entities: the resolved ``SieveEntity`` set for this scan window.
        occasions: the planes that actually captured (the capture occasions);
            for the slice this is ``[ACTIONS_TRAIL, FS_WRITE]``.
        withheld_planes: planes deliberately NOT run this window (e.g.
            ``[WITHHELD_THIRD]``). Each becomes a ``NamedBlindSpot`` and widens
            the CI.

    Returns:
        An ``UnseenEstimate`` satisfying ``ci_low <= lower <= ci_high`` with a
        ``method`` tag, a ``named_blind_spots`` entry per withheld plane, and a
        ``coverage_health`` word.
    """
    entities = list(entities)
    withheld = list(dict.fromkeys(withheld_planes))  # de-dup, preserve order

    blind_spots = tuple(
        name_withheld_blind_spot(plane) for plane in withheld
    )
    # Each withheld plane inflates the upper band; more withheld → strictly wider.
    withheld_band = _WITHHELD_BAND_PENALTY * len(withheld)

    D, n1, n2, m, f1 = _frequency_spectrum(entities, occasions)
    f2 = m  # doubletons in the two-occasion spectrum == seen-on-both

    # ------------------------------------------------------------------
    # Degenerate regimes → deliberately-wide fallback (never raise).
    # ------------------------------------------------------------------
    # (i) Fewer than two real occasions, or nothing observed: capture-recapture
    #     has no support. We cannot lower-bound the unseen fraction from data, so
    #     the honest answer is a maximally-wide band anchored low.
    if len(occasions) < 2 or D == 0:
        ci_high = min(1.0, 0.5 + withheld_band)
        return UnseenEstimate(
            lower=0.0,
            ci_low=0.0,
            ci_high=ci_high,
            method="degenerate_no_recapture",
            named_blind_spots=blind_spots,
            coverage_health="degenerate",
        )

    # (ii) No overlap (m == 0, the hiding regime): Lincoln-Petersen N̂ explodes
    #      and classical Chao breaks. The full engine routes this to the SENECA
    #      self-consistent-missing-mass estimator (ARCHITECTURE.md §6); that
    #      algorithm is NOT implemented in the slice. Here we emit a deliberately
    #      WIDE count-based fallback and tag it ``seneca_no_overlap`` — the tag
    #      NAMES the regime SENECA would own, it does NOT run SENECA. The wide
    #      band + "degenerate" health flag the elevated uncertainty honestly.
    if m == 0:
        # With zero recapture the unseen fraction is unbounded-above in the
        # classical estimator; we report a conservative non-trivial lower bound
        # (at least the singleton mass is "barely seen") and a very wide band.
        gt_unseen = f1 / float(D) if D > 0 else 0.0
        lower = min(0.95, 0.5 * gt_unseen)  # conservative floor, never totality
        ci_low = max(0.0, lower - _MIN_HALF_WIDTH)
        ci_high = min(1.0, max(lower + 0.45, 0.75) + withheld_band)
        return UnseenEstimate(
            lower=lower,
            ci_low=ci_low,
            ci_high=ci_high,
            method="seneca_no_overlap",
            named_blind_spots=blind_spots,
            coverage_health="degenerate",
        )

    # ------------------------------------------------------------------
    # Non-degenerate two-occasion estimate.
    # ------------------------------------------------------------------
    # Lincoln-Petersen, Chapman bias-corrected (always finite for m>=0):
    #     N̂ = (n1+1)(n2+1)/(m+1) − 1
    n_hat_lp = (n1 + 1.0) * (n2 + 1.0) / (m + 1.0) - 1.0
    n_hat_lp = max(n_hat_lp, float(D))  # richness can't be below what we observed
    lp_unseen_frac = (n_hat_lp - D) / n_hat_lp if n_hat_lp > 0 else 0.0

    # Chao2 bias-corrected unobserved richness:
    #     f0̂ = f1(f1−1) / (2(f2+1))
    f0_chao = (f1 * (f1 - 1.0)) / (2.0 * (f2 + 1.0))
    n_hat_chao = D + f0_chao
    chao_unseen_frac = f0_chao / n_hat_chao if n_hat_chao > 0 else 0.0

    # Good-Turing coverage headline (singleton mass over observed):
    #     Ĉ = 1 − f1/D  → unseen FRACTION = f1/D
    gt_unseen_frac = f1 / float(D)

    # Headline LOWER bound = the most conservative (smallest) point estimate of
    # the unseen-but-detectable fraction. A floor, never totality.
    lower = min(lp_unseen_frac, chao_unseen_frac, gt_unseen_frac)
    lower = max(0.0, min(lower, 0.99))  # structurally never 1.0/totality

    # Estimator disagreement (spread of LP / Chao2 / Good-Turing) is ADDED to the
    # band per ARCHITECTURE.md §6 ("estimator-disagreement is added to the band →
    # interval widens").
    fracs = (lp_unseen_frac, chao_unseen_frac, gt_unseen_frac)
    disagreement = max(fracs) - min(fracs)

    # Chao (1987) approximate variance of f0̂ for the log-normal band, expressed
    # on the fraction via the chao point. Guard division by (f2+1).
    r = f1 / (f2 + 1.0)
    var_f0 = (
        f0_chao
        * (0.25 * (r**4) + r**3 + 0.5 * (r**2))
    )
    # Map richness variance to fraction variance (delta method, coarse): scale by
    # (f0/N̂)² / f0² ≈ 1/N̂². We keep it conservative — wider is safer.
    if n_hat_chao > 0 and f0_chao > 0:
        var_frac = var_f0 / (n_hat_chao * n_hat_chao)
    else:
        var_frac = math.inf

    band_low, band_high = _lognormal_band(
        chao_unseen_frac if chao_unseen_frac > 0 else lower,
        var_frac,
    )

    ci_low = min(band_low, lower)
    ci_high = max(band_high, lower)

    # Widen by estimator disagreement + the withheld-plane penalty + the honesty
    # floor. All of these only ever WIDEN, never tighten.
    ci_high = ci_high + disagreement + withheld_band
    ci_low = max(0.0, ci_low - 0.5 * disagreement)

    # Enforce a non-zero half-width floor so the slice never claims a point.
    if (ci_high - ci_low) < 2.0 * _MIN_HALF_WIDTH:
        ci_low = max(0.0, lower - _MIN_HALF_WIDTH)
        ci_high = lower + _MIN_HALF_WIDTH

    # Clamp into [0,1] and re-establish ci_low <= lower <= ci_high.
    ci_low = max(0.0, min(ci_low, lower))
    ci_high = min(1.0, max(ci_high, lower))
    if ci_high <= lower:  # clamping collapsed the top — nudge open
        ci_high = min(1.0, lower + _MIN_HALF_WIDTH)
        if ci_high <= lower:  # lower was already at the 0.99 ceiling
            ci_low = max(0.0, lower - _MIN_HALF_WIDTH)

    # ------------------------------------------------------------------
    # Coverage health word (ARCHITECTURE.md §9 honest-edge sentence).
    # ------------------------------------------------------------------
    # The slice is COUNT-BASED: it never measures catchability and never runs
    # plane-ablation, so it is NOT entitled to the "calibrated" label. The widest
    # honest word a count-based two-occasion estimate can claim is "narrow" — a
    # tight band given the data IT SAW, with no claim that the planes' recall was
    # measured. "calibrated" is RESERVED for the Phase-5 engine that consumes
    # measured catchability + passes plane-ablation. (Reserving it here, rather
    # than handing it out for a tight band, is the point: a tight band over an
    # un-measured plane can still miss everything that plane is blind to.)
    half_width = (ci_high - ci_low) / 2.0
    if half_width >= 0.25 or disagreement >= 0.25 or withheld:
        coverage_health = "wide"
    else:
        coverage_health = "narrow"

    # f1 degeneracy (no singletons → Chao floor is uninformative) is itself a
    # widening signal we surface in the method tag.
    if f1 <= 1:
        method = "chao2_lincoln_petersen_good_turing_lowsingleton"
        coverage_health = "wide"
    else:
        method = "chao2_lincoln_petersen_good_turing"

    # GUARD: the count-based slice MUST NOT claim "calibrated". This is the
    # backstop for the §9 honest-edge doctrine — it fires if any future edit
    # re-introduces the unbacked label without a measured-catchability +
    # ablation-validated estimator behind it.
    assert coverage_health != "calibrated", (
        "the count-based slice estimator may not emit coverage_health="
        "'calibrated'; that label requires measured catchability + plane-"
        "ablation validation (Phase 5)"
    )

    return UnseenEstimate(
        lower=lower,
        ci_low=ci_low,
        ci_high=ci_high,
        method=method,
        named_blind_spots=blind_spots,
        coverage_health=coverage_health,
    )


def name_withheld_blind_spot(plane: PlaneId, reason: str = "") -> NamedBlindSpot:
    """Build a ``NamedBlindSpot`` for a deliberately-withheld vantage.

    Helper so the pipeline and estimator name the SAME missing vantage with a
    consistent default reason. The reason states the exact missing vantage and
    that its mass is OUTSIDE capture-recapture support — never folded into the
    estimate, never fake-found (ARCHITECTURE.md §6 last bullet; §12; §10 proof
    (d)).
    """
    if not reason:
        reason = (
            f"vantage {plane.value!r} deliberately withheld this window; an "
            f"agent acting only on it has zero catchability and is OUTSIDE "
            f"capture-recapture support — named here, never folded into the "
            f"unseen estimate and never fake-found"
        )
    return NamedBlindSpot(missing_plane=plane, reason=reason, evidence_ref=None)


__all__ = ["estimate_unseen", "name_withheld_blind_spot"]
