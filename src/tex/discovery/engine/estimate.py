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
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

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


# ===========================================================================
# CALIBRATED ESTIMATOR FAMILY (consumes MEASURED per-plane catchability).
#
# These helpers implement the full incidence-based completeness stack named in
# RESEARCH_LOG.md §6 + ARCHITECTURE.md §6. They are activated ONLY when the
# caller supplies ``catchability_by_plane`` (the measured per-plane recall from
# the signed-cohort / honeytoken calibration, N2). The count-based default path
# above is UNTOUCHED when no catchability is supplied — the slice asserts
# catchability and does not consume it, so the slice tests / "calibrated"-guard
# are unaffected.
#
# The incidence frequency-of-frequencies Q_k = number of entities detected on
# EXACTLY k of the capture occasions is the sufficient statistic for the
# incidence-based estimators (Chao2 / iChao2 / Good-Turing coverage). Fusion
# match-uncertainty is propagated as SOFT incidence: an entity's contribution to
# an occasion is its membership probability on that occasion (not a hard 0/1), so
# the spectrum carries fractional weight (ARCHITECTURE.md §6 assumption 3).
# ===========================================================================

# Per-plane catchability floor below which a plane (or an entity's only vantage)
# is treated as ZERO-catchability: its mass is OUTSIDE capture-recapture support
# (the Valiant-Valiant τ-floor, RESEARCH_LOG.md §6). Such an entity is NEVER
# folded into N̂ and is NAMED as a blind spot instead. A measured catchability at
# or below this floor cannot lower-bound anything — the plane is effectively
# blind there.
_TAU_CATCHABILITY_FLOOR = 1e-3


def _soft_incidence_by_entity(
    entities: Sequence[SieveEntity],
    occ_set: set[PlaneId],
) -> list[tuple[float, frozenset[PlaneId]]]:
    """Per-entity (soft incidence count, planes-actually-seen) over ``occ_set``.

    The soft incidence count is the SUM of the entity's per-occasion membership
    probabilities — propagating fusion match-uncertainty as soft incidence rather
    than assuming perfect linkage (ARCHITECTURE.md §6 assumption 3). A
    high-confidence entity on two planes contributes ≈2.0; a half-confident
    fusion contributes ≈1.0 (it might be one entity on two planes, or noise).

    Membership probability per occasion is the entity's ``fusion_confidence``
    when it was genuinely captured on that plane (we know it was THERE; the
    uncertainty is whether the cross-plane LINK is real), clamped to [0,1]. An
    entity captured on a single plane contributes that plane's confidence as its
    incidence weight — it is a soft singleton.

    Returns a list of ``(soft_count, planes_seen)`` for entities with at least
    one captured occasion in ``occ_set``; zero-occasion entities are excluded
    (named elsewhere).
    """
    out: list[tuple[float, frozenset[PlaneId]]] = []
    for ent in entities:
        seen = ent.planes_seen & occ_set
        if not seen:
            continue
        conf = max(0.0, min(1.0, ent.fusion_confidence))
        # A solo capture is CERTAIN to be present on its one plane (it was
        # observed there); the soft-discount applies to cross-plane LINKS, so a
        # singleton's incidence weight is 1.0, while each ADDITIONAL plane beyond
        # the first is discounted by the link confidence.
        soft = 1.0 + max(0, len(seen) - 1) * conf
        out.append((soft, frozenset(seen)))
    return out


def _incidence_spectrum(
    soft: Sequence[tuple[float, frozenset[PlaneId]]],
    n_occasions: int,
) -> tuple[float, list[float]]:
    """Incidence frequency-of-frequencies ``(D, [Q0_unused, Q1, Q2, Q3, ...])``.

    ``Q_k`` = the (soft) number of entities detected on exactly ``k`` occasions,
    for ``k`` in ``1..n_occasions``. ``D`` is the soft count of distinct observed
    entities (sum over ``k>=1`` of ``Q_k``). The list is indexed by ``k`` with
    index 0 reserved (the unobserved class Q0 is what we ESTIMATE, never count).

    Soft incidence: an entity whose soft count rounds between integer occasion
    counts is split proportionally so the spectrum stays a faithful expectation
    (e.g. a soft-count 1.5 entity on 2 planes contributes 0.5 to Q1 and 0.5 to
    Q2). This keeps Chao2/iChao2 well-defined under fusion uncertainty.
    """
    q = [0.0] * (n_occasions + 1)
    distinct = 0.0
    for soft_count, seen in soft:
        k_hard = len(seen)
        distinct += 1.0
        # Distribute the entity's unit mass across the integer occasion-counts
        # bracketing its soft incidence so Q is an unbiased expectation.
        sc = max(1.0, min(float(k_hard), soft_count))
        lo = int(math.floor(sc))
        hi = min(n_occasions, lo + 1)
        frac = sc - lo
        lo = max(1, min(n_occasions, lo))
        if lo == hi or frac <= 0.0:
            q[lo] += 1.0
        else:
            q[lo] += 1.0 - frac
            q[hi] += frac
    return distinct, q


def _ichao2_richness(D: float, q: Sequence[float]) -> tuple[float, float]:
    """iChao2 unobserved-richness LOWER bound + its approximate variance.

    Chiu et al. (2014) improved Chao2: it adds a Q3/Q4 correction term to the
    classical Chao2 ``Q1²/(2 Q2)`` (bias-corrected at Q2==0 to
    ``Q1(Q1-1)/(2(Q2+1))``) that materially tightens the lower bound when
    higher-order incidence info exists, while remaining a valid LOWER bound.

        f0_chao2 = Q1(Q1-1) / (2(Q2+1))                         (bias-corrected)
        f0_ichao2 = f0_chao2 + (Q3/(4·Q4)) · max(Q1 − Q2·Q3/(2·Q4), 0)
                    (only when Q4 > 0; else falls back to Chao2)

    Returns ``(f0_hat, var_f0)`` — the estimated unobserved count and an
    approximate variance (Chao 1987 form on the Chao2 term) for the log-normal
    CI. ``f0_hat`` is always finite and >= 0.
    """
    Q1 = q[1] if len(q) > 1 else 0.0
    Q2 = q[2] if len(q) > 2 else 0.0
    Q3 = q[3] if len(q) > 3 else 0.0
    Q4 = q[4] if len(q) > 4 else 0.0

    # Bias-corrected Chao2 (finite even at Q2 == 0).
    f0_chao2 = (Q1 * (Q1 - 1.0)) / (2.0 * (Q2 + 1.0))

    f0 = f0_chao2
    if Q4 > 0.0 and Q3 > 0.0:
        correction = (Q3 / (4.0 * Q4)) * max(Q1 - (Q2 * Q3) / (2.0 * Q4), 0.0)
        f0 = f0_chao2 + correction

    # Chao (1987) approximate variance of the Chao2 term, used for the band.
    if Q2 > 0.0:
        r = Q1 / Q2
        var_f0 = Q2 * (
            0.5 * (r**2) + (r**3) + 0.25 * (r**4)
        )
    else:
        # Q2 == 0 degenerate: variance is large; signal it as the wide regime.
        var_f0 = f0 * (f0 + 1.0) if f0 > 0 else math.inf
    return max(0.0, f0), var_f0


def _good_turing_unseen_fraction(D: float, q: Sequence[float]) -> float:
    """Good-Turing incidence coverage → unseen FRACTION (Chao & Chiu form).

    Sample coverage Ĉ for incidence data is ``1 − (Q1/U)·((n−1)Q1 / ((n−1)Q1 +
    2Q2))`` with ``U`` the total incidence count; the unseen FRACTION is ``1−Ĉ``.
    Here we use the entity-level singleton-mass simplification consistent with
    the count-based slice (``Q1/D``) but with the Chao-Chiu ``2Q2`` correction
    that shrinks the estimate when doubletons exist (more recapture ⇒ better
    coverage ⇒ smaller unseen fraction).

    Returns a fraction in [0,1].
    """
    Q1 = q[1] if len(q) > 1 else 0.0
    Q2 = q[2] if len(q) > 2 else 0.0
    if D <= 0.0:
        return 0.0
    if Q1 <= 0.0:
        return 0.0
    # Chao-Chiu coverage-deficit estimator with the 2Q2 stabilizer.
    denom = Q1 + 2.0 * Q2
    if denom <= 0.0:
        return min(1.0, Q1 / D)
    coverage_deficit = (Q1 / D) * (Q1 / denom)
    return max(0.0, min(1.0, coverage_deficit))


def _seneca_missing_mass(D: float, q: Sequence[float]) -> tuple[float, float]:
    """SENECA-style self-consistent missing-mass estimate for the f1→0 regime.

    When singletons collapse (Q1 ≈ 0 — the HIDING regime where classical Chao
    "lies optimistically"), the missing mass cannot be read off Q1. SENECA-style
    estimators instead solve a self-consistency fixed point: the unobserved mass
    ``μ`` must be consistent with the observed frequency spectrum under a
    smooth species-abundance prior. We implement a bounded, monotone fixed-point
    iteration on the missing FRACTION ``u`` driven by the higher-order spectrum:

        u_{t+1} = (Q1 + Q2·(1−u_t)) / (D + Q1 + Q2·(1−u_t))

    seeded at ``u_0 = Q2 / (D + Q2)`` (when Q1==0 the doubleton mass is the only
    self-consistency anchor). The iteration is a contraction on [0,1) and
    converges in a few steps; it returns a STRICTLY POSITIVE missing fraction
    even when Q1==0 (the whole point — Chao would return ≈0), plus a deliberately
    wide variance proxy since this regime is the least-certain.

    Returns ``(u_fraction, var_proxy)``.
    """
    Q1 = q[1] if len(q) > 1 else 0.0
    Q2 = q[2] if len(q) > 2 else 0.0
    if D <= 0.0:
        return 0.0, math.inf

    u = Q2 / (D + Q2) if (D + Q2) > 0 else 0.25
    for _ in range(64):
        anchor = Q1 + Q2 * (1.0 - u)
        nxt = anchor / (D + anchor) if (D + anchor) > 0 else u
        if abs(nxt - u) < 1e-9:
            u = nxt
            break
        u = nxt
    u = max(0.0, min(0.99, u))
    # The hiding regime is the least-certain: a wide variance proxy so the CI
    # widens (ARCHITECTURE.md §6: the switch itself flags elevated uncertainty).
    var_proxy = max(u * (1.0 - u), 0.05)
    return u, var_proxy


def _horvitz_thompson_unseen_fraction(
    soft: Sequence[tuple[float, frozenset[PlaneId]]],
    catchability_by_plane: Mapping[PlaneId, float],
    occ_set: set[PlaneId],
) -> tuple[float, float, float, list[PlaneId]]:
    """Horvitz-Thompson richness using MEASURED per-plane catchability.

    With measured per-plane catchability ``c_p`` (the probability a PRESENT
    entity is captured on plane ``p``), an entity that exists is INCLUDED in the
    observed sample with population inclusion probability

        π = 1 − Π_{p ∈ usable run planes} (1 − c_p)

    over ALL non-blind run planes (NOT just the planes the entity happened to be
    seen on — conditioning on seen-planes would bias π upward, since an observed
    entity was by definition caught). The Horvitz-Thompson richness is then

        N̂_HT = D_used / π            → unseen fraction = 1 − π

    This is the estimator that actually USES the measured catchability (the
    count-based path ignores it). Planes whose measured catchability is at/below
    the τ-floor are BLIND: they contribute no inclusion mass, and an entity seen
    ONLY on blind planes is OUTSIDE capture-recapture support — excluded from
    ``D_used`` and named as a blind spot (Valiant-Valiant τ-floor).

    Returns ``(unseen_fraction, pi, var_fraction, zero_catchability_planes)``:

    - ``unseen_fraction`` = ``1 − π`` clamped to [0, 0.99] (never totality);
    - ``pi``              = the population inclusion probability;
    - ``var_fraction``    = the sampling variance of the unseen fraction. Each
                            measured ``c_p`` is itself an estimate with binomial
                            variance ``c_p(1−c_p)/D_used``; propagated through
                            ``1−π`` by the delta method so a moderate sample of
                            observed entities yields a genuinely WIDE CI;
    - ``zero_*_planes``   = below-τ run planes (named by the caller).
    """
    zero_planes = [
        p
        for p in occ_set
        if catchability_by_plane.get(p, 0.0) <= _TAU_CATCHABILITY_FLOOR
    ]
    zero_set = set(zero_planes)
    usable_planes = [p for p in occ_set if p not in zero_set]

    # Count entities that are inside support (seen on >= 1 usable plane).
    D_used = 0.0
    for _soft_count, seen in soft:
        if seen - zero_set:
            D_used += 1.0
    if D_used <= 0.0 or not usable_planes:
        return 0.0, 1.0, math.inf, sorted(zero_planes, key=lambda p: p.value)

    # Population inclusion probability over ALL usable run planes.
    prod_miss = 1.0
    cs: list[float] = []
    for p in usable_planes:
        c = max(0.0, min(1.0, catchability_by_plane.get(p, 0.0)))
        cs.append(c)
        prod_miss *= 1.0 - c
    pi = 1.0 - prod_miss
    if pi <= _TAU_CATCHABILITY_FLOOR:
        # All usable planes effectively blind → no support.
        return 0.0, pi, math.inf, sorted(zero_planes, key=lambda p: p.value)

    unseen_frac = prod_miss  # == 1 − π

    # Variance of the unseen fraction (prod_miss). prod_miss = Π(1−c_p); the
    # measured c_p each carry binomial variance c_p(1−c_p)/D_used. By the delta
    # method, Var(prod_miss) ≈ prod_miss² · Σ Var(c_p)/(1−c_p)². This captures
    # BOTH the measurement uncertainty in the catchability AND the finite-sample
    # uncertainty — so a small observed cohort yields a wide band.
    var_frac = 0.0
    for c in cs:
        one_minus_c = max(1.0 - c, 1e-6)
        var_c = c * (1.0 - c) / D_used
        var_frac += var_c / (one_minus_c * one_minus_c)
    var_frac = (prod_miss * prod_miss) * var_frac
    if not math.isfinite(var_frac):
        var_frac = math.inf

    return (
        max(0.0, min(0.99, unseen_frac)),
        pi,
        var_frac,
        sorted(zero_planes, key=lambda p: p.value),
    )


def _name_zero_catchability_blind_spot(
    plane: PlaneId, catchability: float
) -> NamedBlindSpot:
    """Name a plane whose MEASURED catchability is at/below the τ-floor.

    Distinct from a *withheld* blind spot: this plane WAS run but its measured
    recall is effectively zero (Valiant-Valiant τ-floor), so any entity seen only
    on it is OUTSIDE capture-recapture support — excluded from N̂, never
    fake-found. The reason states the measured catchability for receipts.
    """
    reason = (
        f"plane {plane.value!r} ran but its MEASURED catchability "
        f"({catchability:.3g}) is at/below the τ-floor "
        f"({_TAU_CATCHABILITY_FLOOR:.0e}); an agent seen only here is OUTSIDE "
        f"capture-recapture support — excluded from N̂, named here, never "
        f"fake-found"
    )
    return NamedBlindSpot(missing_plane=plane, reason=reason, evidence_ref=None)


def _estimate_unseen_calibrated(
    entities: Sequence[SieveEntity],
    *,
    occasions: Sequence[PlaneId],
    withheld: Sequence[PlaneId],
    catchability_by_plane: Mapping[PlaneId, float],
    window_turnover: float = 0.0,
) -> UnseenEstimate:
    """The CALIBRATED estimator — consumes MEASURED per-plane catchability.

    Orchestrates the full family (RESEARCH_LOG.md §6; ARCHITECTURE.md §6):

    1. SOFT incidence per entity (fusion match-uncertainty → soft occasion mass).
    2. Incidence spectrum ``Q_k`` over the occasions.
    3. THREE concordant fraction estimates, each a LOWER bound:
       - Horvitz-Thompson using measured catchability (the calibrated anchor);
       - incidence iChao2 richness → unseen fraction (Chiu 2014);
       - incidence Good-Turing coverage (Chao-Chiu).
    4. SENECA self-consistent missing-mass FALLBACK when singletons collapse
       (Q1 ≈ 0, the hiding regime) — replaces the would-be-zero Good-Turing.
    5. Every failure mode WIDENS the band and is recorded:
       - estimator disagreement (spread of HT / iChao2 / GT-or-SENECA) is added;
       - the SENECA switch flags elevated uncertainty (wide var proxy);
       - a withheld plane adds the monotone withheld penalty + a named blind spot;
       - a below-τ (zero-catchability) plane is EXCLUDED from N̂ and NAMED;
       - correlated planes (measured pairwise capture-correlation high) widen.
    6. ALWAYS a LOWER bound + CI + named blind spots — never a count, never
       totality (``lower`` clamped <= 0.99).

    The health word is ``"measured"`` (a calibrated-catchability run that was NOT
    ablation-validated) — it is deliberately NOT ``"calibrated"``, which is
    reserved for an ablation-passing run (the count-based slice guard still
    forbids ``"calibrated"`` entirely).
    """
    occ = list(occasions)
    occ_set = set(occ)
    n_occ = len(occ)

    turnover = max(0.0, min(1.0, float(window_turnover)))

    # Named blind spots: withheld planes + below-τ measured planes.
    blind_spots: list[NamedBlindSpot] = [
        name_withheld_blind_spot(plane) for plane in withheld
    ]
    # Withheld-plane penalty + open-population turnover both widen the band: a
    # streaming window with agent birth/death relaxes the closure assumption
    # (Jolly-Seber variant, ARCHITECTURE.md §5) → the interval must widen.
    withheld_band = _WITHHELD_BAND_PENALTY * len(withheld) + turnover

    # Below-τ planes among the RUN occasions are blind: name them now so they are
    # surfaced even before the HT estimator excludes their solo-seen entities.
    below_tau_planes = sorted(
        (
            p
            for p in occ_set
            if catchability_by_plane.get(p, 0.0) <= _TAU_CATCHABILITY_FLOOR
        ),
        key=lambda p: p.value,
    )
    for p in below_tau_planes:
        blind_spots.append(
            _name_zero_catchability_blind_spot(
                p, catchability_by_plane.get(p, 0.0)
            )
        )
    # Each below-τ plane is a blind vantage; treat it like a withheld plane for
    # the monotone-widening penalty (we ran it but learned nothing through it).
    blind_band = _WITHHELD_BAND_PENALTY * len(below_tau_planes)

    blind_spots_t = tuple(blind_spots)

    # --- Degenerate: need >= 2 occasions and some observed mass. ---
    soft = _soft_incidence_by_entity(entities, occ_set)
    D, q = _incidence_spectrum(soft, n_occ)
    if n_occ < 2 or D <= 0.0:
        ci_high = min(1.0, 0.5 + withheld_band + blind_band)
        return UnseenEstimate(
            lower=0.0,
            ci_low=0.0,
            ci_high=ci_high,
            method="measured_degenerate_no_recapture",
            named_blind_spots=blind_spots_t,
            coverage_health="degenerate",
        )

    Q1 = q[1] if len(q) > 1 else 0.0
    Q2 = q[2] if len(q) > 2 else 0.0

    # --- (1) Horvitz-Thompson with measured catchability (the CALIBRATED
    #         central estimate; its inclusion-probability variance drives the
    #         primary CI band). ---
    ht_frac, _pi, ht_var_frac, _ht_zero = _horvitz_thompson_unseen_fraction(
        soft, catchability_by_plane, occ_set
    )

    # --- (2) Incidence iChao2 richness → fraction (count-based corroborant). ---
    f0_ichao2, var_f0 = _ichao2_richness(D, q)
    n_hat_ichao2 = D + f0_ichao2
    ichao2_frac = f0_ichao2 / n_hat_ichao2 if n_hat_ichao2 > 0 else 0.0

    # --- (3) Good-Turing coverage OR SENECA fallback (hiding regime). ---
    seneca = Q1 <= 1.0  # singletons collapsed → classical coverage uninformative
    if seneca:
        gt_or_seneca_frac, seneca_var = _seneca_missing_mass(D, q)
        method_core = "seneca_self_consistent"
    else:
        gt_or_seneca_frac = _good_turing_unseen_fraction(D, q)
        seneca_var = None
        method_core = "ht_ichao2_goodturing"

    # The estimator set, all LOWER bounds on the unseen-but-detectable fraction.
    candidates = [c for c in (ht_frac, ichao2_frac, gt_or_seneca_frac)
                  if math.isfinite(c)]
    if not candidates:
        candidates = [0.0]

    # Headline LOWER bound = most conservative CONCORDANT estimate. In the SENECA
    # hiding regime (Q1≈0) the count-based iChao2 is uninformative by construction
    # (it returns ≈0 with no singleton signal) and must NOT pull the floor to zero
    # — that is exactly the "Chao lies optimistically" failure SENECA exists to
    # repair. There, the floor is the min of the informative measured estimators
    # (HT + SENECA self-consistent mass). Outside the hiding regime, all three
    # concordantly lower-bound and the min is the honest floor.
    if seneca:
        floor_set = [c for c in (ht_frac, gt_or_seneca_frac) if math.isfinite(c)]
        floor_set = floor_set or [0.0]
        lower = max(0.0, min(min(floor_set), 0.99))
    else:
        lower = max(0.0, min(min(candidates), 0.99))

    # --- Band: a normal CI around the CALIBRATED HT point estimate using its
    #     measured-catchability variance, UNIONed with the count-based corroborant
    #     point (iChao2) so the interval brackets either model if one is right
    #     (the doubly-robust spirit, ARCHITECTURE.md §6). ---
    if math.isfinite(ht_var_frac):
        ht_sd = math.sqrt(max(ht_var_frac, 0.0))
    else:
        ht_sd = 0.5  # unusable catchability variance → wide
    ht_lo = ht_frac - _Z_95 * ht_sd
    ht_hi = ht_frac + _Z_95 * ht_sd

    # Log-normal corroborant band around the count-based iChao2 point.
    if n_hat_ichao2 > 0 and var_f0 != math.inf and f0_ichao2 > 0:
        var_frac_ichao2 = var_f0 / (n_hat_ichao2 * n_hat_ichao2)
    else:
        var_frac_ichao2 = math.inf
    ic_lo, ic_hi = _lognormal_band(
        ichao2_frac if ichao2_frac > 0 else lower, var_frac_ichao2
    )

    # The CI is the UNION of both model bands (so if EITHER the capture model or
    # the population model is right, the interval covers — doubly-robust).
    ci_low = min(ht_lo, ic_lo, lower)
    ci_high = max(ht_hi, ic_hi, lower, max(candidates))

    # Estimator disagreement widens the band (ARCHITECTURE.md §6).
    disagreement = max(candidates) - min(candidates)
    ci_high += disagreement + withheld_band + blind_band
    ci_low = max(0.0, ci_low - 0.5 * disagreement)

    # The SENECA switch flags elevated uncertainty → widen.
    if seneca and seneca_var is not None:
        ci_high += math.sqrt(seneca_var)

    # Honesty floor on half-width — never a point.
    if (ci_high - ci_low) < 2.0 * _MIN_HALF_WIDTH:
        ci_low = max(0.0, lower - _MIN_HALF_WIDTH)
        ci_high = lower + _MIN_HALF_WIDTH

    # Clamp + re-establish ci_low <= lower <= ci_high.
    ci_low = max(0.0, min(ci_low, lower))
    ci_high = min(1.0, max(ci_high, lower))
    if ci_high <= lower:
        ci_high = min(1.0, lower + _MIN_HALF_WIDTH)
        if ci_high <= lower:
            ci_low = max(0.0, lower - _MIN_HALF_WIDTH)

    # --- Health word + method tag. ---
    half_width = (ci_high - ci_low) / 2.0
    wide = (
        half_width >= 0.25
        or disagreement >= 0.25
        or bool(withheld)
        or bool(below_tau_planes)
        or seneca
        or Q2 <= 0.0
        or turnover > 0.0
    )
    coverage_health = "wide" if wide else "measured"

    method = f"measured_{method_core}"
    if seneca:
        method += "_lowsingleton"
    if turnover > 0.0:
        # Record the open-population (Jolly-Seber) relaxation in the tag.
        method += "_openpop"

    # GUARD: even the calibrated path does NOT claim "calibrated" — that label
    # requires plane-ablation cross-validation (ARCHITECTURE.md §6), which this
    # measured-catchability run did not perform. "measured" is the honest word.
    assert coverage_health != "calibrated", (
        "the measured-catchability estimator may not emit coverage_health="
        "'calibrated' without plane-ablation cross-validation"
    )

    return UnseenEstimate(
        lower=lower,
        ci_low=ci_low,
        ci_high=ci_high,
        method=method,
        named_blind_spots=blind_spots_t,
        coverage_health=coverage_health,
    )


def estimate_unseen(
    entities: Iterable[SieveEntity],
    occasions: Sequence[PlaneId],
    withheld_planes: Sequence[PlaneId] = (),
    *,
    catchability_by_plane: Mapping[PlaneId, float] | None = None,
    window_turnover: float = 0.0,
) -> UnseenEstimate:
    """Two-occasion capture-recapture over resolved entities.

    Args:
        entities: the resolved ``SieveEntity`` set for this scan window.
        occasions: the planes that actually captured (the capture occasions);
            for the slice this is ``[ACTIONS_TRAIL, FS_WRITE]``.
        withheld_planes: planes deliberately NOT run this window (e.g.
            ``[WITHHELD_THIRD]``). Each becomes a ``NamedBlindSpot`` and widens
            the CI.
        catchability_by_plane: OPTIONAL MEASURED per-plane catchability (N2) — the
            signed-cohort recall / honeytoken bite-rate per plane. When supplied,
            ``estimate_unseen`` runs the CALIBRATED estimator family
            (``_estimate_unseen_calibrated``): a Horvitz-Thompson richness using
            the measured catchability, blended with incidence Good-Turing /
            iChao2, with a SENECA self-consistent missing-mass fallback in the
            f1→0 hiding regime, soft incidence propagating fusion uncertainty,
            and zero-catchability (below-τ) planes EXCLUDED from N̂ and NAMED as
            blind spots. ``None`` (the default) preserves the COUNT-BASED slice
            behavior EXACTLY — the slice asserts catchability and does not consume
            it, so existing slice tests and the reserved ``"calibrated"`` guard
            are unaffected. Keyword-only so adding it never shifts a positional
            call. The calibrated path still NEVER emits ``coverage_health ==
            "calibrated"`` unless plane-ablation actually validated the CI; it
            uses ``"measured"`` to mark a measured-catchability run.
        window_turnover: OPTIONAL open-population turnover fraction in [0,1] for a
            STREAMING window — the fraction of the population that was BORN or
            DIED across the window (agent birth/death, ARCHITECTURE.md §5
            Jolly-Seber variant). The closed-population estimators above assume no
            turnover; a non-zero turnover RELAXES that assumption and must WIDEN
            the band (open-population uncertainty). Default ``0.0`` = closed
            window = exactly the prior behavior. Keyword-only and consumed by both
            paths; it only ever widens ``ci_high`` (and is recorded in the method
            tag), never tightens, so existing callers are unaffected.

    Returns:
        An ``UnseenEstimate`` satisfying ``ci_low <= lower <= ci_high`` with a
        ``method`` tag, a ``named_blind_spots`` entry per withheld plane, and a
        ``coverage_health`` word.
    """
    entities = list(entities)
    withheld = list(dict.fromkeys(withheld_planes))  # de-dup, preserve order
    turnover = max(0.0, min(1.0, float(window_turnover)))

    # Calibrated path: only when MEASURED catchability is supplied. The
    # count-based default path below is untouched when this is None.
    if catchability_by_plane is not None:
        return _estimate_unseen_calibrated(
            entities,
            occasions=occasions,
            withheld=withheld,
            catchability_by_plane=catchability_by_plane,
            window_turnover=turnover,
        )

    blind_spots = tuple(
        name_withheld_blind_spot(plane) for plane in withheld
    )
    # Each withheld plane inflates the upper band; more withheld → strictly wider.
    # Open-population turnover (agent birth/death across a streaming window)
    # relaxes the closure assumption and is folded into the widening band.
    withheld_band = _WITHHELD_BAND_PENALTY * len(withheld) + turnover

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


def expected_calibration_error(
    confidences: Sequence[float],
    correct: Sequence[bool],
    n_bins: int = 10,
) -> float:
    """Expected Calibration Error of entity-confidence vs ground-truth correctness.

    The benchmark obligation (Phase-1 verifier): report ECE for entity-confidence
    calibration — does a ``fusion_confidence`` of 0.9 mean the entity is correct
    ~90% of the time? Standard binned ECE: partition predictions into ``n_bins``
    equal-width confidence bins, and sum each bin's ``|accuracy − mean_confidence|``
    weighted by the bin's share of predictions.

    This is the SKELETON CONTRACT the calibration builder fills; the signature is
    fixed here so the Phase-5 estimator and the verifier agree on the metric.

    Args:
        confidences: per-entity predicted confidences in [0,1] (e.g. each
            resolved entity's ``fusion_confidence`` or an agent-vs-human
            ``probability``).
        correct: per-entity ground-truth correctness (aligned with
            ``confidences``); ``True`` iff the entity's resolution matched the
            planted ground truth.
        n_bins: number of equal-width confidence bins (default 10).

    Returns:
        The ECE in [0,1] — 0.0 is perfect calibration. An empty input returns
        0.0 (no predictions, no calibration error) rather than raising.
    """
    confs = [float(c) for c in confidences]
    hits = [bool(c) for c in correct]
    if len(confs) != len(hits):
        raise ValueError(
            "confidences and correct must be the same length "
            f"({len(confs)} != {len(hits)})"
        )
    n = len(confs)
    if n == 0:
        return 0.0  # no predictions, no calibration error
    if n_bins < 1:
        raise ValueError(f"n_bins must be >= 1, got {n_bins!r}")

    # Equal-width bins over [0,1]. Bin index for a confidence p is
    # min(floor(p * n_bins), n_bins-1) so p == 1.0 lands in the top bin.
    bin_conf_sum = [0.0] * n_bins
    bin_hit_sum = [0.0] * n_bins
    bin_count = [0] * n_bins
    for p, hit in zip(confs, hits):
        pc = min(max(p, 0.0), 1.0)
        idx = min(int(pc * n_bins), n_bins - 1)
        bin_conf_sum[idx] += pc
        bin_hit_sum[idx] += 1.0 if hit else 0.0
        bin_count[idx] += 1

    ece = 0.0
    for b in range(n_bins):
        if bin_count[b] == 0:
            continue
        acc = bin_hit_sum[b] / bin_count[b]
        avg_conf = bin_conf_sum[b] / bin_count[b]
        weight = bin_count[b] / n
        ece += weight * abs(acc - avg_conf)
    return ece


@dataclass(frozen=True)
class CoverageReport:
    """A calibration-validation report over a held-out / planted ground truth.

    Returned by ``calibrate``. It is the diagnostic the Phase-1 verifier reads to
    decide whether the estimator's intervals are trustworthy on a population whose
    true unseen count is KNOWN (synthetic / planted): does the reported
    unseen-fraction CI actually CONTAIN the true unseen fraction, and is the
    entity-confidence well-calibrated (low ECE)?

    Fields:

    - ``ci_covered``     — did ``[ci_low, ci_high]`` contain the TRUE unseen
                           fraction? The benchmark obligation: the CI must contain
                           the true unseen count on synthetic populations.
    - ``true_fraction``  — the known true unseen fraction (unseen / total_true).
    - ``estimate``       — the ``UnseenEstimate`` that was scored.
    - ``ece``            — entity-confidence Expected Calibration Error (or
                           ``None`` if no per-entity confidences were supplied).
    - ``ablation_error`` — when a plane was held out and its catch predicted vs
                           observed, the absolute prediction error (plane-ablation
                           cross-validation, ARCHITECTURE.md §6); ``None`` if no
                           ablation was run.
    - ``coverage_health``— echoed from the estimate for convenience.
    """

    ci_covered: bool
    true_fraction: float
    estimate: "UnseenEstimate"
    ece: float | None = None
    ablation_error: float | None = None
    coverage_health: str = "unknown"


def calibrate(
    estimate: "UnseenEstimate",
    *,
    true_total: int,
    observed_total: int,
    entity_confidences: Sequence[float] = (),
    entity_correct: Sequence[bool] = (),
    ablation_predicted_catch: float | None = None,
    ablation_observed_catch: float | None = None,
) -> CoverageReport:
    """Score an ``UnseenEstimate`` against a KNOWN ground-truth population.

    The benchmark-coverage obligation: on a synthetic / planted population whose
    true unseen count is known, the reported CI MUST contain the true unseen
    fraction. ``calibrate`` computes the true unseen fraction and checks
    containment, and (optionally) the entity-confidence ECE and a plane-ablation
    prediction error — the three diagnostics the Phase-1 verifier consumes.

    Args:
        estimate: the ``UnseenEstimate`` produced by ``estimate_unseen``.
        true_total: the TRUE number of distinct entities in the population
            (planted ground truth). Must be >= ``observed_total``.
        observed_total: how many distinct entities the estimator actually
            observed (``D``). The true unseen count is ``true_total -
            observed_total``; the true unseen fraction is that over ``true_total``.
        entity_confidences / entity_correct: optional per-entity confidence vs
            correctness for the ECE (passed straight to
            ``expected_calibration_error``).
        ablation_predicted_catch / ablation_observed_catch: optional plane-
            ablation pair — the catch a held-out plane was PREDICTED to add vs
            what it actually added — scored as ``|predicted - observed|``.

    Returns:
        A ``CoverageReport``. Never raises on degenerate inputs (``true_total ==
        0`` → true fraction 0.0); only an inconsistent ``true_total <
        observed_total`` raises, since that is a caller error in the ground truth.
    """
    if true_total < 0 or observed_total < 0:
        raise ValueError("true_total and observed_total must be non-negative")
    if true_total < observed_total:
        raise ValueError(
            "true_total must be >= observed_total (cannot observe more than "
            f"exist); got {true_total} < {observed_total}"
        )

    if true_total == 0:
        true_fraction = 0.0
    else:
        true_fraction = (true_total - observed_total) / float(true_total)

    ci_covered = estimate.ci_low <= true_fraction <= estimate.ci_high

    ece: float | None = None
    if entity_confidences or entity_correct:
        ece = expected_calibration_error(entity_confidences, entity_correct)

    ablation_error: float | None = None
    if (
        ablation_predicted_catch is not None
        and ablation_observed_catch is not None
    ):
        ablation_error = abs(ablation_predicted_catch - ablation_observed_catch)

    return CoverageReport(
        ci_covered=ci_covered,
        true_fraction=true_fraction,
        estimate=estimate,
        ece=ece,
        ablation_error=ablation_error,
        coverage_health=estimate.coverage_health,
    )


__all__ = [
    "estimate_unseen",
    "name_withheld_blind_spot",
    "expected_calibration_error",
    "calibrate",
    "CoverageReport",
]
