"""
[Architecture: Cross-cutting (Vigil cognition)] — v3 PREFERENCE / VALUE-OF-INFORMATION.

Learn from the operator's decisions. Every time a human resolves the
human-decision gate (and every recorded outcome of a PERMIT / FORBID), that
resolution is a label on two things: what mattered, and the *cost of
speaking versus staying silent*. v3 fits a preference / Value-of-Information
model from those labels (read off the decision + outcome stores) and uses it
to:

  * calibrate the speak / stay-quiet threshold from *revealed cost
    asymmetry* rather than a hand-set constant (decision-theoretic
    notification: speak iff expected decision-gain exceeds expected
    interruption cost), and
  * score the human-decision channel by expected improvement in the
    operator's decision, net of the cost of interrupting them (VoI) — the
    pragmatic term that v4's expected free energy adds to v1's epistemic
    surprise.

THE NORMATIVE FLOOR (load-bearing):

    Descriptive preferences learn freely. FORBID invariants do not.

The cost of over-speaking on routine volume is learned from how the operator
actually behaves. But the safety dimensions (identity, monitoring, a broken
evidence chain, and the human-decision gate itself) are NORMATIVE floors.
Learning may lower Tex's confidence in a floor; it may never erase it:

  * the calibrated threshold is hard-capped so it can never rise high enough
    to suppress a safety line, and
  * a dismissal only teaches "this was noise" when the dismissed thing was
    actually safe (``was_safe is True``). Dismissing a *real* alarm is not
    consent — silence is never encoded as consent.

Iron rule holds: preference changes *what is selected and in what order*. It
never writes words. The authored forms in vigil/utterances.py are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any

from tex.domain.outcome import OutcomeLabel

__all__ = ["PreferenceModel", "NORMATIVE_FLOOR"]


# Dimensions whose lines are normative floors: never threshold-suppressed,
# never driven to zero value by repeated dismissal. (Evidence only speaks
# when the chain is whole or broken; a broken chain is maximal and floored.)
NORMATIVE_FLOOR: frozenset[str] = frozenset(
    {"identity", "monitoring", "evidence", "human_decision"}
)

# Calibration bounds. The threshold is in nats (same units as Bayesian
# surprise, so it can replace SelectorConfig.min_surprise directly).
_BASE_THRESHOLD = 0.05      # equals SelectorConfig.min_surprise default
_THRESHOLD_FLOOR = 0.005    # there is always *some* bar; never fully silent
_THRESHOLD_CEIL = 0.40      # never so high routine surprise is all suppressed
_COST_PRIOR = 1.0           # pseudo-count so zero-data threshold == base
_FLOOR_VOI = 0.25           # minimum VoI a normative-floor line always retains
_DEFAULT_INTERRUPT_PENALTY = 0.02  # baseline cost of interrupting a person


@dataclass(slots=True)
class _CostModel:
    """Revealed costs of the two error directions, accumulated from outcomes.

    ``interrupt_cost`` grows when Tex spoke / gated and it turned out
    unnecessary (a justified dismissal: the action really was safe).
    ``miss_cost`` grows when Tex under-surfaced something that mattered (an
    unsafe action slipped, or a correct FORBID confirmed the value of
    speaking). The asymmetry between them sets how eager Tex should be.
    """

    interrupt_cost: float = 0.0
    miss_cost: float = 0.0
    resolved: int = 0


class PreferenceModel:
    """v3: preference / VoI fitted from resolved human decisions.

        learn_from_outcome(decision, outcome) — fold one resolved decision
            into the cost model.
        value_of_information(utterance, principal) -> float — expected
            decision-quality gain of speaking this line, net of interruption
            cost, in surprise-comparable units.
        speak_threshold() -> float — the calibrated min-surprise cutoff,
            derived from revealed cost asymmetry (error-budget style).
    """

    __slots__ = ("_lock", "_cost", "_default_interrupt_penalty", "_seen")

    def __init__(self, *, default_interrupt_penalty: float = _DEFAULT_INTERRUPT_PENALTY) -> None:
        self._lock = RLock()
        self._cost = _CostModel()
        self._default_interrupt_penalty = float(default_interrupt_penalty)
        # Outcome ids already folded, so the per-cycle tick is idempotent and
        # never double-counts a resolution.
        self._seen: set[str] = set()

    # ------------------------------------------------------------------ learn

    def learn_from_outcome(self, decision: Any, outcome: Any) -> None:
        """Fold one resolved decision + outcome into the cost model.

        The mapping (revealed-cost accounting):
          * over-caution that was actually safe  -> interrupt_cost
          * a real miss / unsafe slip            -> miss_cost
          * correct FORBID (speaking was right)  -> miss_cost (value of voice)
          * correct PERMIT (quiet was right)     -> interrupt_cost economy
        Silence is never consent: a dismissal only counts as interrupt_cost
        when the thing dismissed was genuinely safe.
        """
        label = _outcome_label(outcome)
        was_safe = getattr(outcome, "was_safe", None)
        human_override = bool(getattr(outcome, "human_override", False))
        weight = _outcome_weight(outcome)

        with self._lock:
            self._cost.resolved += 1

            # A real miss: Tex permitted/under-surfaced something unsafe.
            if label is OutcomeLabel.FALSE_PERMIT or was_safe is False:
                self._cost.miss_cost += weight
                return

            # Correct FORBID: speaking/gating had real value — reinforce it.
            if label is OutcomeLabel.CORRECT_FORBID:
                self._cost.miss_cost += weight
                return

            # Justified dismissal: Tex over-cautioned on something truly safe.
            # ONLY here does an override count as interruption cost.
            if label is OutcomeLabel.FALSE_FORBID or (human_override and was_safe is True):
                self._cost.interrupt_cost += weight
                return

            # Correct PERMIT: staying quiet was right — modest economy signal.
            if label is OutcomeLabel.CORRECT_PERMIT or was_safe is True:
                self._cost.interrupt_cost += 0.5 * weight
                return
            # ABSTAIN_REVIEW / UNKNOWN: no confident cost signal; no update.

    def learn_from_stores(self, decision_store: Any, outcome_store: Any, *, limit: int = 500) -> int:
        """Convenience: fold every *not-yet-seen* resolved outcome.

        Idempotent: each outcome is folded at most once (tracked by
        outcome_id), so this is safe to call every vigil cycle as a live
        recalibration tick. Returns the number of NEW outcomes folded.
        Defensive: a missing store or an unresolvable decision is skipped,
        never raised.
        """
        if outcome_store is None:
            return 0
        try:
            outcomes = outcome_store.list_recent(limit=limit)
        except Exception:  # noqa: BLE001
            return 0
        folded = 0
        for outcome in outcomes or ():
            oid = getattr(outcome, "outcome_id", None)
            key = str(oid) if oid is not None else None
            if key is not None:
                with self._lock:
                    if key in self._seen:
                        continue
                    self._seen.add(key)
            decision = None
            if decision_store is not None:
                try:
                    decision = decision_store.get(getattr(outcome, "decision_id", None))
                except Exception:  # noqa: BLE001
                    decision = None
            self.learn_from_outcome(decision, outcome)
            folded += 1
        return folded

    # ------------------------------------------------------------------ calibrate

    def speak_threshold(self) -> float:
        """Calibrated min-surprise cutoff (nats) from revealed cost asymmetry.

        threshold = base * (interrupt + prior) / (miss + prior), clamped.
        Zero data -> base. Operator dismisses freely (interrupt dominates) ->
        threshold rises, Tex speaks less. Misses dominate -> threshold
        falls, Tex speaks more. Hard-capped so it can never silence a floor.
        """
        with self._lock:
            interrupt = self._cost.interrupt_cost + _COST_PRIOR
            miss = self._cost.miss_cost + _COST_PRIOR
        raw = _BASE_THRESHOLD * (interrupt / miss)
        return _clamp(raw, _THRESHOLD_FLOOR, _THRESHOLD_CEIL)

    def value_of_information(self, utterance: Any, principal: Any = None) -> float:
        """Expected decision-gain of speaking this line, net of interruption.

        Returned in surprise-comparable units so v4 can add it to the
        epistemic (surprise) term on one scale. Normative-floor lines always
        keep at least ``_FLOOR_VOI`` — no amount of dismissal suppresses them.
        """
        surprise = _utterance_surprise(utterance)
        dimension = _utterance_dimension(utterance)
        interrupt_penalty = _principal_interrupt_penalty(
            principal, self._default_interrupt_penalty
        )

        # Learned value-of-voice multiplier: >1 when misses dominate, <1 when
        # interruptions dominate. Smoothed by the cost priors.
        with self._lock:
            miss = self._cost.miss_cost + _COST_PRIOR
            interrupt = self._cost.interrupt_cost + _COST_PRIOR
        voice_value = miss / interrupt

        net = surprise * voice_value - interrupt_penalty

        if dimension in NORMATIVE_FLOOR:
            # A floor line is always worth at least _FLOOR_VOI; learning may
            # add to it but can never push it below the floor.
            return max(net, _FLOOR_VOI)
        return net

    # ------------------------------------------------------------------ inspect

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "interrupt_cost": round(self._cost.interrupt_cost, 6),
                "miss_cost": round(self._cost.miss_cost, 6),
                "resolved": self._cost.resolved,
                "speak_threshold": round(self.speak_threshold(), 6),
            }


# --------------------------------------------------------------------------- helpers


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _outcome_label(outcome: Any) -> OutcomeLabel | None:
    label = getattr(outcome, "label", None)
    if isinstance(label, OutcomeLabel):
        return label
    if isinstance(label, str):
        try:
            return OutcomeLabel(label)
        except ValueError:
            return None
    return None


def _outcome_weight(outcome: Any) -> float:
    """Confidence-weighted cost contribution; defaults to 1.0."""
    conf = getattr(outcome, "confidence_score", None)
    if isinstance(conf, (int, float)) and not isinstance(conf, bool):
        return max(0.1, min(1.0, float(conf)))
    return 1.0


def _utterance_surprise(utterance: Any) -> float:
    for attr in ("surprise", "raw_surprise"):
        v = getattr(utterance, attr, None)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
    return 0.0


def _utterance_dimension(utterance: Any) -> str:
    dim = getattr(utterance, "dimension", None)
    if isinstance(dim, str):
        return dim
    reading = getattr(utterance, "reading", None)
    key = getattr(reading, "key", None)
    return key if isinstance(key, str) else ""


def _principal_interrupt_penalty(principal: Any, default: float) -> float:
    if principal is None:
        return default
    v = getattr(principal, "interrupt_penalty", None)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return max(0.0, float(v))
    return default
