"""Tex Presence L3 — "I've noticed…" habit hypotheses.

Tex notices recurring patterns in a tenant's OWN sealed history and OFFERS them as
hypotheses a human confirms before anything changes. The discipline, end to end:

  * the pattern comes from a DETERMINISTIC miner over sealed records — never an LLM
    "noticing" something (:mod:`tex.presence.habits.miner`);
  * each hypothesis carries the EXACT sealed records that support it and a COMPUTED
    confidence (Wilson lower bound, Bonferroni-corrected for multiplicity), so a
    thin/noisy history surfaces NOTHING (:mod:`tex.presence.habits.confidence`);
  * a hypothesis can only ever propose CAUTION (a tightening), never more
    confidence — and it changes nothing until a human confirms it, which writes ONE
    sealed L2 correction (:mod:`tex.presence.habits.confirm`).

L3 owns only this package + a thin tex-systems surface. It consumes L2's
``ProfileMemory`` interface (duck-typed — it imports only the frozen
:mod:`tex.presence.contract`) and exposes a builder + surfacing hook for the
orchestrator; it never edits ``main.py`` / ``voice_ask.py``. See ``HABITS_INTERFACE.md``.
"""

from __future__ import annotations

from tex.presence.habits.confidence import (
    CONSISTENCY_LABEL,
    PatternConfidence,
    bonferroni_alpha,
    score_pattern,
    wilson_lower_bound,
)
from tex.presence.habits.confirm import (
    HabitConfirmation,
    HabitDecline,
    confirm_hypothesis,
    decline_hypothesis,
)
from tex.presence.habits.hooks import HabitSurface, build_habit_surface
from tex.presence.habits.miner import HabitMiner, MinerConfig
from tex.presence.habits.phrasing import Phraser, TemplatePhraser, render_hypothesis
from tex.presence.habits.sources import (
    CompositeHistorySource,
    IterableHistorySource,
    ProfileCorrectionHistorySource,
    S5MemoryHistorySource,
)
from tex.presence.habits.types import (
    HABITS_INTERFACE_VERSION,
    HabitHypothesis,
    HabitKind,
    HistorySource,
    HypothesisAction,
    ObservedOutcome,
    OutcomeDimension,
    norm_subject,
)

__all__ = [
    "HABITS_INTERFACE_VERSION",
    # types
    "ObservedOutcome",
    "HabitHypothesis",
    "HabitKind",
    "HypothesisAction",
    "OutcomeDimension",
    "HistorySource",
    "norm_subject",
    # confidence
    "PatternConfidence",
    "score_pattern",
    "wilson_lower_bound",
    "bonferroni_alpha",
    "CONSISTENCY_LABEL",
    # miner
    "HabitMiner",
    "MinerConfig",
    # sources
    "S5MemoryHistorySource",
    "ProfileCorrectionHistorySource",
    "IterableHistorySource",
    "CompositeHistorySource",
    # phrasing
    "Phraser",
    "TemplatePhraser",
    "render_hypothesis",
    # confirm
    "confirm_hypothesis",
    "decline_hypothesis",
    "HabitConfirmation",
    "HabitDecline",
    # hooks
    "HabitSurface",
    "build_habit_surface",
]
