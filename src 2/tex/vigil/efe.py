"""
[Architecture: Cross-cutting (Vigil cognition)] — v4 EXPECTED FREE ENERGY.

The mind, not an organ. v1 ranks lines by belief-shift one at a time — a
better axis than severity, but still a ranking. v4 replaces the ranking
with *policy selection*: choose the set of things to say, evaluated together
against their effect on the operator, by minimizing expected free energy.

    EFE(policy) = -[ epistemic value + pragmatic value ]

  * epistemic value  — expected Bayesian surprise (the KL belief-shift the
                       line would induce), from v2's model of normal. This
                       is v1's surprise, now read as the information the line
                       gives the operator.
  * pragmatic value  — expected improvement in the operator's decision, net
                       of interruption cost (v3's Value-of-Information).

Minimizing EFE is maximizing the combined value V = epistemic + pragmatic.
Active inference's risk + ambiguity decomposition is the same object: a line
worth speaking resolves ambiguity (epistemic) and moves the operator toward
a preferred, safe state (pragmatic) for less than the cost of interrupting.

THE SET-LEVEL NON-LINEARITY (the heart of v4):

Lines are not independent. Once a *cause* is named, its *symptoms* carry
almost no additional information — the operator's belief about the symptom is
already explained by the cause. So the joint information of {cause, symptom}
is less than info(cause) + info(symptom): the symptom's marginal epistemic
value collapses toward zero *inside the objective*. This generalizes v1.5's
post-hoc redundancy filter into a real submodular non-linearity, and it is
exactly the structure v5's sealed causal attribution feeds (via each
reading's ``explained_by`` / attributed cause→symptom edges).

Because the only dependency between lines is the cause→symptom relation,
greedy selection with collapse is the exact EFE-optimal policy here, not a
heuristic — there is no other cross-line coupling to miss.

Fallbacks (contract-preserving):
  * no preference model      -> delegate to v1 select() unchanged.
  * uniform/zero-data pref   -> the EFE value is monotonic in surprise, so
                                the policy reduces to v1's surprise ranking.
The output is always a ``VigilSelection`` of the identical shape.

Iron rule / witness law hold: EFE changes *what* is selected and in what
order. It never writes words and never advises.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tex.vigil.dimensions import DimensionReading
from tex.vigil.normal import ModelOfNormal
from tex.vigil.selector import (
    ChosenUtterance,
    SelectorConfig,
    VigilSelection,
    _standing_word,
    _surprise_for,
    select,
)
from tex.vigil.utterances import fill, select_form

__all__ = ["ExpectedFreeEnergySelector"]


@dataclass(slots=True)
class _EFECandidate:
    reading: DimensionReading
    text: str
    epistemic: float          # expected Bayesian surprise (nats)
    pragmatic: float          # value-of-information, surprise-comparable units
    warm: bool
    collapsed: bool = False    # set True when a named cause explains this line

    # Duck-typed surface v3's value_of_information reads from.
    @property
    def surprise(self) -> float:
        return self.epistemic

    @property
    def dimension(self) -> str:
        return self.reading.key

    def value(self) -> float:
        """Combined value V = epistemic + pragmatic. EFE = -V."""
        eff_epistemic = 0.0 if self.collapsed else self.epistemic
        return eff_epistemic + self.pragmatic


class ExpectedFreeEnergySelector:
    """v4: policy selection by expected free energy.

        select(readings, model, preference=None, config=None) -> VigilSelection
    """

    def select(
        self,
        readings: list[DimensionReading],
        model: ModelOfNormal,
        *,
        preference: Any | None = None,
        config: SelectorConfig | None = None,
    ) -> VigilSelection:
        cfg = config or SelectorConfig()

        # Contract fallback: with no preference model there is no pragmatic
        # term, so EFE has nothing to add over v1's surprise ranking. Use the
        # concrete, already-proven v1 path verbatim.
        if preference is None:
            return select(readings, model, cfg)

        standing = _standing_word(readings)
        warm_any = False

        # ---- human-decision gate: pulled out, never ranked --------------
        human: ChosenUtterance | None = None
        ranked_readings: list[DimensionReading] = []
        for r in readings:
            if r.is_human_gate:
                form = select_form(r.key, r.slots)
                if form is not None:
                    human = ChosenUtterance(
                        text=fill(form, r.slots),
                        dimension=r.key,
                        surprise=0.0,
                        proof=r.proof,
                        requires_human=True,
                    )
            else:
                ranked_readings.append(r)

        # ---- build candidates with epistemic + pragmatic value ----------
        candidates: list[_EFECandidate] = []
        for r in ranked_readings:
            form = select_form(r.key, r.slots)
            if form is None:
                continue  # nothing sealed to say this cycle
            epistemic, warm = _surprise_for(r, model)
            warm_any = warm_any or warm
            cand = _EFECandidate(
                reading=r,
                text=fill(form, r.slots),
                epistemic=epistemic,
                pragmatic=0.0,
                warm=warm,
            )
            cand.pragmatic = float(preference.value_of_information(cand, None))
            candidates.append(cand)

        # ---- calibrated speak threshold (v3) replaces the hand-set knob --
        threshold = _resolve_threshold(preference, cfg)

        # ---- greedy EFE-minimizing policy with cause->symptom collapse ---
        spoken: list[ChosenUtterance] = []
        spoken_keys: dict[str, float] = {}  # dimension -> epistemic of spoken line
        suppressed = 0
        remaining = list(candidates)

        while remaining and len(spoken) < cfg.max_spoken:
            # Apply the non-linearity: a candidate explained by an
            # already-spoken, louder cause has its epistemic value collapsed.
            if cfg.enable_redundancy_collapse:
                for c in remaining:
                    if c.collapsed or not c.reading.explained_by:
                        continue
                    explained = any(
                        cause in spoken_keys and spoken_keys[cause] >= c.epistemic
                        for cause in c.reading.explained_by
                    )
                    if explained:
                        c.collapsed = True

            # Pick the highest-value remaining candidate (EFE-minimizing step).
            best = max(remaining, key=lambda c: c.value())
            remaining.remove(best)

            # A collapsed descriptive line falls below threshold on its
            # pragmatic value alone and is suppressed; a normative-floor line
            # keeps a positive VoI and still speaks (you never silence a
            # safety line just because a cause was named).
            if best.value() < threshold:
                if best.collapsed:
                    suppressed += 1
                continue

            spoken.append(
                ChosenUtterance(
                    text=best.text,
                    dimension=best.reading.key,
                    surprise=best.epistemic,
                    proof=best.reading.proof,
                    requires_human=False,
                )
            )
            spoken_keys[best.reading.key] = best.epistemic

        # Any still-collapsed candidates left unspoken count as suppressed.
        suppressed += sum(1 for c in remaining if c.collapsed)

        return VigilSelection(
            standing=standing,
            utterances=spoken,
            human_decision=human,
            warm=warm_any,
            observed_dimensions=len(readings),
            suppressed=suppressed,
            selector_version="v4",
        )


def _resolve_threshold(preference: Any, cfg: SelectorConfig) -> float:
    """Use v3's calibrated threshold when available; else the v1 constant."""
    fn = getattr(preference, "speak_threshold", None)
    if callable(fn):
        try:
            t = float(fn())
            if t >= 0.0:
                return t
        except Exception:  # noqa: BLE001
            pass
    return cfg.min_surprise
