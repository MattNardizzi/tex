"""
[Architecture: Cross-cutting (Vigil cognition)] — the selector.

This is where surprise chooses. Given the cycle's dimension readings and a
model of normal, it:

  1. computes Bayesian surprise per dimension (KL posterior||prior),
  2. forms candidate utterances from authored, sealed-filled forms,
  3. v1.5: collapses redundancy — once a cause is named, its declared
     symptoms have their surprise attenuated, so the vigil stops repeating
     downstream lines (the first taste of "evaluate the set, not the item"
     that full EFE will generalize),
  4. ranks by surprise, keeps the calm few above threshold,
  5. always speaks the human-decision gate when present — it is a gate, not
     a ranked observation; not speaking it is the one unforgivable failure,
  6. emits the standing word: Absolute when the shop is fully governed and
     sealed right now, Open when something is ungoverned or awaits a person.

The selector is intelligent about *which* sealed truths to speak. It never
touches the words — see vigil/utterances.py for the iron rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tex.vigil.conjugate import beta_surprise, gamma_surprise
from tex.vigil.dimensions import DimensionReading, ProofRef
from tex.vigil.normal import ModelOfNormal
from tex.vigil.utterances import fill, select_form

__all__ = [
    "ChosenUtterance",
    "VigilSelection",
    "SelectorConfig",
    "select",
]


@dataclass(frozen=True, slots=True)
class SelectorConfig:
    """Knobs. Defaults chosen to keep the vigil calm, not chatty."""

    min_surprise: float = 0.05      # nats; below this, a line is held
    max_spoken: int = 4             # the calm few
    enable_redundancy_collapse: bool = True  # v1.5


@dataclass(frozen=True, slots=True)
class ChosenUtterance:
    text: str
    dimension: str
    surprise: float
    proof: ProofRef | None
    requires_human: bool = False


@dataclass(slots=True)
class VigilSelection:
    standing: str                              # "Absolute" | "Open"
    utterances: list[ChosenUtterance] = field(default_factory=list)
    human_decision: ChosenUtterance | None = None
    warm: bool = False
    observed_dimensions: int = 0
    suppressed: int = 0
    selector_version: str = "v1.5"


@dataclass(slots=True)
class _Candidate:
    reading: DimensionReading
    text: str
    raw_surprise: float
    warm: bool


def _surprise_for(reading: DimensionReading, model: ModelOfNormal) -> tuple[float, bool]:
    """Compute Bayesian surprise (nats) for one reading, plus warm flag."""
    prior = model.prior_for(reading)
    if reading.kind == "beta" and prior.beta is not None:
        succ, fail = reading.observation
        posterior = prior.beta.update(succ, fail)
        return beta_surprise(prior.beta, posterior), prior.warm
    if reading.kind == "gamma" and prior.gamma is not None:
        count = reading.observation[0]
        exposure = reading.observation[1] if len(reading.observation) > 1 else 1.0
        posterior = prior.gamma.update(count, exposure)
        return gamma_surprise(prior.gamma, posterior), prior.warm
    return 0.0, prior.warm


def _standing_word(readings: list[DimensionReading]) -> str:
    """Absolute when fully governed + sealed + nothing awaiting a person."""
    by_key: dict[str, DimensionReading] = {r.key: r for r in readings}

    if "human_decision" in by_key:
        return "Open"
    ident = by_key.get("identity")
    if ident is not None and float(ident.slots.get("count", 0) or 0) > 0:
        return "Open"
    mon = by_key.get("monitoring")
    if mon is not None and float(mon.slots.get("count", 0) or 0) > 0:
        return "Open"
    ev = by_key.get("evidence")
    if ev is not None and not bool(ev.slots.get("intact", True)):
        return "Open"
    return "Absolute"


def select(
    readings: list[DimensionReading],
    model: ModelOfNormal,
    config: SelectorConfig | None = None,
) -> VigilSelection:
    cfg = config or SelectorConfig()

    standing = _standing_word(readings)
    warm_any = False

    # ---- human-decision gate: pulled out, never ranked ------------------
    human: ChosenUtterance | None = None
    ranked_readings: list[DimensionReading] = []
    for r in readings:
        if r.is_human_gate:
            form = select_form(r.key, r.slots)
            if form is not None:
                human = ChosenUtterance(
                    text=fill(form, r.slots),
                    dimension=r.key,
                    surprise=0.0,  # a gate is not ranked
                    proof=r.proof,
                    requires_human=True,
                )
        else:
            ranked_readings.append(r)

    # ---- build candidates (surprise + sealed-filled text) ---------------
    candidates: list[_Candidate] = []
    for r in ranked_readings:
        form = select_form(r.key, r.slots)
        if form is None:
            continue  # nothing sealed to say this cycle
        surprise, warm = _surprise_for(r, model)
        warm_any = warm_any or warm
        candidates.append(
            _Candidate(reading=r, text=fill(form, r.slots), raw_surprise=surprise, warm=warm)
        )

    # ---- rank by raw surprise, then v1.5 redundancy collapse ------------
    candidates.sort(key=lambda c: c.raw_surprise, reverse=True)

    spoken: list[ChosenUtterance] = []
    spoken_surprise: dict[str, float] = {}  # dimension -> surprise of spoken line
    suppressed = 0

    for c in candidates:
        # v1.5: a declared symptom goes silent when a *louder* cause has
        # already been named — the first taste of "evaluate the set, not
        # the item". If the supposed symptom is bigger than its cause, the
        # explanation is contradicted by magnitude, so it still speaks.
        if cfg.enable_redundancy_collapse and c.reading.explained_by:
            explained = any(
                cause in spoken_surprise
                and spoken_surprise[cause] >= c.raw_surprise
                for cause in c.reading.explained_by
            )
            if explained:
                suppressed += 1
                continue

        if c.raw_surprise < cfg.min_surprise:
            continue
        if len(spoken) >= cfg.max_spoken:
            continue

        spoken.append(
            ChosenUtterance(
                text=c.text,
                dimension=c.reading.key,
                surprise=c.raw_surprise,
                proof=c.reading.proof,
                requires_human=False,
            )
        )
        spoken_surprise[c.reading.key] = c.raw_surprise

    return VigilSelection(
        standing=standing,
        utterances=spoken,
        human_decision=human,
        warm=warm_any,
        observed_dimensions=len(readings),
        suppressed=suppressed,
        selector_version="v1.5" if cfg.enable_redundancy_collapse else "v1",
    )
