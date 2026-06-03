"""
v3 — preference / Value-of-Information (PreferenceModel).

The model must:
  * raise the speak threshold when interruptions are revealed costly
    (operator keeps dismissing safe things) and lower it when misses
    dominate (decision-theoretic notification),
  * rank a high-value line above a low-value one via VoI,
  * keep the safety floors inviolable: the threshold is hard-capped, the
    normative-floor lines always retain a positive VoI, and dismissing a
    *real* alarm never raises the threshold (silence is never consent).
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.domain.outcome import OutcomeLabel
from tex.vigil.preference import (
    NORMATIVE_FLOOR,
    _BASE_THRESHOLD,
    _THRESHOLD_CEIL,
    PreferenceModel,
)


@dataclass
class _FakeOutcome:
    label: OutcomeLabel
    was_safe: bool | None = None
    human_override: bool = False
    confidence_score: float = 1.0
    decision_id: object = None


@dataclass
class _Utt:
    dimension: str
    surprise: float


def test_threshold_rises_when_interruptions_dominate() -> None:
    p = PreferenceModel()
    # Operator repeatedly dismisses things that were genuinely safe.
    for _ in range(50):
        p.learn_from_outcome(None, _FakeOutcome(OutcomeLabel.FALSE_FORBID, was_safe=True))
    assert p.speak_threshold() > _BASE_THRESHOLD


def test_threshold_falls_when_misses_dominate() -> None:
    p = PreferenceModel()
    # Real misses: unsafe actions that slipped through.
    for _ in range(50):
        p.learn_from_outcome(None, _FakeOutcome(OutcomeLabel.FALSE_PERMIT, was_safe=False))
    assert p.speak_threshold() < _BASE_THRESHOLD


def test_voi_ranks_high_value_above_low() -> None:
    p = PreferenceModel()
    high = _Utt(dimension="execution", surprise=2.0)
    low = _Utt(dimension="execution", surprise=0.1)
    assert p.value_of_information(high) > p.value_of_information(low)


def test_normative_floor_voi_is_inviolable() -> None:
    p = PreferenceModel()
    # Flood interruption cost as hard as possible.
    for _ in range(1000):
        p.learn_from_outcome(None, _FakeOutcome(OutcomeLabel.FALSE_FORBID, was_safe=True))
    # A near-silent identity line still carries at least the floor VoI.
    tiny = _Utt(dimension="identity", surprise=1e-6)
    assert "identity" in NORMATIVE_FLOOR
    assert p.value_of_information(tiny) >= 0.25


def test_silence_is_not_consent() -> None:
    # Dismissing a REAL (unsafe) alarm must not teach Tex to go quiet: it is
    # accounted as a miss, lowering the threshold, never raising it.
    p = PreferenceModel()
    for _ in range(50):
        p.learn_from_outcome(
            None, _FakeOutcome(OutcomeLabel.FALSE_PERMIT, was_safe=False, human_override=True)
        )
    assert p.speak_threshold() <= _BASE_THRESHOLD
    # And the safety line is still fully spoken-eligible.
    assert p.value_of_information(_Utt("identity", 0.0)) >= 0.25


def test_threshold_is_hard_capped() -> None:
    p = PreferenceModel()
    for _ in range(100000):
        p.learn_from_outcome(None, _FakeOutcome(OutcomeLabel.FALSE_FORBID, was_safe=True))
    assert p.speak_threshold() <= _THRESHOLD_CEIL


def test_learn_from_stores_folds_outcomes() -> None:
    class _OutcomeStore:
        def list_recent(self, limit: int = 500):
            return [
                _FakeOutcome(OutcomeLabel.CORRECT_FORBID, was_safe=False),
                _FakeOutcome(OutcomeLabel.FALSE_FORBID, was_safe=True),
            ]

    class _DecisionStore:
        def get(self, _id):
            return None

    p = PreferenceModel()
    folded = p.learn_from_stores(_DecisionStore(), _OutcomeStore())
    assert folded == 2
    assert p.snapshot()["resolved"] == 2


def test_zero_data_threshold_is_base() -> None:
    assert PreferenceModel().speak_threshold() == _BASE_THRESHOLD


def test_learn_from_stores_is_idempotent() -> None:
    # The per-cycle tick must never double-count an outcome it already folded.
    import uuid as _uuid

    shared = [
        _FakeOutcome(OutcomeLabel.FALSE_FORBID, was_safe=True, decision_id=_uuid.uuid4()),
        _FakeOutcome(OutcomeLabel.CORRECT_FORBID, was_safe=False, decision_id=_uuid.uuid4()),
    ]
    for o in shared:
        o.outcome_id = _uuid.uuid4()

    class _OutcomeStore:
        def list_recent(self, limit: int = 500):
            return list(shared)

    class _DecisionStore:
        def get(self, _id):
            return None

    p = PreferenceModel()
    first = p.learn_from_stores(_DecisionStore(), _OutcomeStore())
    again = p.learn_from_stores(_DecisionStore(), _OutcomeStore())
    assert first == 2          # both folded the first time
    assert again == 0          # nothing new the second time
    assert p.snapshot()["resolved"] == 2  # not 4 — no double counting

    # A newly resolved outcome on the next tick IS folded.
    shared.append(_FakeOutcome(OutcomeLabel.FALSE_PERMIT, was_safe=False, decision_id=_uuid.uuid4()))
    shared[-1].outcome_id = _uuid.uuid4()
    third = p.learn_from_stores(_DecisionStore(), _OutcomeStore())
    assert third == 1
    assert p.snapshot()["resolved"] == 3
