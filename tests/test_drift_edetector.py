"""
Anytime-valid risk-stream e-detector (learning/drift.py).

The e-detector turns the heuristic window-delta drift flags into a Ville-bounded
alarm over the false-permit and abstain-rate streams, and — critically — only
ever recommends moving the policy TOWARD caution:

  * a false-permit breach recommends TIGHTEN (autonomous-safe);
  * an abstain-rate breach recommends REVIEW (human-gated);
  * there is no ``loosen`` action at all.

That last property is the trust invariant made structural: a probabilistic
drift signal can never autonomously relax the gate.
"""

from __future__ import annotations

from types import SimpleNamespace

from tex.domain.verdict import Verdict
from tex.learning.drift import (
    DriftAction,
    EDriftSignal,
    RiskStream,
    RiskStreamEDetector,
    _standardise_indicator,
)


def _run(detector: RiskStreamEDetector, stream: RiskStream, events: list[bool]) -> EDriftSignal:
    sig = None
    for e in events:
        sig = detector.observe(stream=stream, event=e)
    assert sig is not None
    return sig


# ── the structural invariant: there is no autonomous loosen ──────────────


def test_no_loosen_action_exists() -> None:
    # The action vocabulary itself excludes loosening — the invariant is not a
    # runtime check that could be bypassed, it is the type.
    assert {a.value for a in DriftAction} == {"none", "tighten", "review"}


def test_breach_never_yields_anything_but_tighten_or_review() -> None:
    det = RiskStreamEDetector(alpha=0.01)
    for stream in (RiskStream.FALSE_PERMIT, RiskStream.ABSTAIN_RATE):
        # a heavily-breaching stream
        sig = _run(det, stream, [True] * 30)
        assert sig.breached is True
        assert sig.action in (DriftAction.TIGHTEN, DriftAction.REVIEW)


# ── false-permit stream → TIGHTEN ────────────────────────────────────────


def test_false_permit_breach_recommends_tighten() -> None:
    det = RiskStreamEDetector(alpha=0.01, baseline_false_permit_rate=0.05)
    # 40% unsafe permits >> 5% baseline.
    events = [(i % 5 < 2) for i in range(40)]  # 40% True
    sig = _run(det, RiskStream.FALSE_PERMIT, events)
    assert sig.breached is True
    assert sig.action is DriftAction.TIGHTEN
    assert sig.p_anytime_valid < 0.01


def test_well_calibrated_stream_does_not_breach() -> None:
    det = RiskStreamEDetector(alpha=0.01, baseline_false_permit_rate=0.20)
    # Exactly at baseline (20% unsafe) — no drift evidence.
    events = [(i % 5 == 0) for i in range(60)]  # 20% True
    sig = _run(det, RiskStream.FALSE_PERMIT, events)
    assert sig.breached is False
    assert sig.action is DriftAction.NONE


# ── abstain-rate stream → REVIEW (human-gated, never auto-loosen) ─────────


def test_abstain_rate_breach_recommends_review_not_tighten() -> None:
    det = RiskStreamEDetector(alpha=0.01, baseline_abstain_rate=0.20)
    events = [True] * 40  # 100% abstain >> 20% baseline
    sig = _run(det, RiskStream.ABSTAIN_RATE, events)
    assert sig.breached is True
    assert sig.action is DriftAction.REVIEW


def test_observe_decision_feeds_the_abstain_stream() -> None:
    det = RiskStreamEDetector(alpha=0.01, baseline_abstain_rate=0.10)
    sig = None
    for _ in range(40):
        sig = det.observe_decision(SimpleNamespace(verdict=Verdict.ABSTAIN))
    assert sig is not None
    assert sig.stream == RiskStream.ABSTAIN_RATE.value
    assert sig.breached is True
    assert sig.action is DriftAction.REVIEW


# ── observation floor, determinism, reset ────────────────────────────────


def test_min_observations_floor_blocks_premature_fire() -> None:
    det = RiskStreamEDetector(alpha=0.01, min_observations=5)
    # Two screaming-unsafe observations must NOT fire (below the floor) even if
    # the raw e-value would already be large.
    s1 = det.observe(stream=RiskStream.FALSE_PERMIT, event=True)
    s2 = det.observe(stream=RiskStream.FALSE_PERMIT, event=True)
    assert s1.breached is False and s2.breached is False


def test_detector_is_deterministic() -> None:
    events = [True, False, True, True, False] * 8
    a = _run(RiskStreamEDetector(alpha=0.01), RiskStream.FALSE_PERMIT, events)
    b = _run(RiskStreamEDetector(alpha=0.01), RiskStream.FALSE_PERMIT, events)
    assert a.as_dict() == b.as_dict()


def test_reset_restarts_the_stream() -> None:
    det = RiskStreamEDetector(alpha=0.01)
    _run(det, RiskStream.FALSE_PERMIT, [True] * 30)
    det.reset(RiskStream.FALSE_PERMIT)
    # After reset, a single fresh observation is back below the floor / boundary.
    sig = det.observe(stream=RiskStream.FALSE_PERMIT, event=False)
    assert sig.sample_size == 1
    assert sig.breached is False


def test_standardise_is_zero_mean_under_null() -> None:
    p0 = 0.05
    x_hit = _standardise_indicator(indicator=True, p0=p0)
    x_miss = _standardise_indicator(indicator=False, p0=p0)
    mean = p0 * x_hit + (1 - p0) * x_miss
    assert abs(mean) < 1e-9
