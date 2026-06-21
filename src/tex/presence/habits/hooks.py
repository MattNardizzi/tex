"""Orchestrator wiring for L3 habit hypotheses — the ONLY surface main.py touches.

L3 does not edit ``main.py`` / ``voice/voice_ask.py``. At integration the
orchestrator builds a :class:`HabitSurface` and hangs it off ``app.state`` (e.g.
``app.state.presence_habits``), then decides WHEN to surface (on operator request,
or at the end of a session) and renders the hypotheses. Surfacing is read-only and
inert; nothing changes until the operator confirms one.

INTEGRATION CONTRACT (for the orchestrator owner)
-------------------------------------------------
  * ``build_habit_surface(memory=app.state.presence_memory,
    profile=app.state.presence_profile)`` → a :class:`HabitSurface`.
      - ``memory`` (S5 ``SealedPresenceMemory``) feeds the governance-verdict habit.
      - ``profile`` (L2 ``ProfileMemory``) is BOTH a mining source (the
        ``correction_tier`` habit) AND the store confirmations are written to.
      - pass ``source=`` to inject a custom :class:`HistorySource` (e.g. an adapter
        over governance ``Decision`` resolutions); it is composed with the above.
  * ``surface(tenant)`` → the tenant's hypotheses, each phrased + carrying its
    supporting EvidenceRefs (read-only).
  * ``confirm(hypothesis=..., operator=<server-side identity>, decision_id=...)`` →
    writes ONE L2 correction and returns a citable receipt. ``decline(...)`` records
    a "no" and writes nothing.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from tex.presence.habits.confirm import (
    HabitConfirmation,
    HabitDecline,
    confirm_hypothesis,
    decline_hypothesis,
)
from tex.presence.habits.miner import HabitMiner, MinerConfig
from tex.presence.habits.phrasing import Phraser, TemplatePhraser
from tex.presence.habits.sources import (
    CompositeHistorySource,
    ProfileCorrectionHistorySource,
    S5MemoryHistorySource,
)
from tex.presence.habits.types import HabitHypothesis, HistorySource

_logger = logging.getLogger(__name__)

__all__ = ["HabitSurface", "build_habit_surface"]


class HabitSurface:
    """The bundled miner + source + phraser + confirm/decline the orchestrator
    drives. Stateless beyond its injected collaborators; safe to build once."""

    def __init__(
        self,
        *,
        source: HistorySource,
        profile: Any | None = None,
        miner: HabitMiner | None = None,
        phraser: Phraser | None = None,
    ) -> None:
        self._source = source
        self._profile = profile
        self._miner = miner or HabitMiner()
        self._phraser = phraser or TemplatePhraser()

    def surface(self, *, tenant: str) -> tuple[HabitHypothesis, ...]:
        """Mine + phrase a tenant's hypotheses. Read-only and inert: nothing here
        changes a verdict, a profile, or a future answer."""
        mined = self._miner.mine_source(tenant=tenant, source=self._source)
        out = []
        for h in mined:
            try:
                text = self._phraser.phrase(h)
            except Exception:  # noqa: BLE001 — a phraser fault falls back to no prose
                _logger.warning("habit surface: phraser failed for %s", h.hypothesis_id, exc_info=True)
                text = ""
            out.append(replace(h, phrasing=text))
        return tuple(out)

    def confirm(
        self,
        *,
        hypothesis: HabitHypothesis,
        operator: str,
        decision_id: str | None = None,
        profile: Any | None = None,
    ) -> HabitConfirmation:
        """Confirm a hypothesis → one sealed L2 correction. ``profile`` defaults to
        the one this surface was built with; pass it explicitly to override."""
        target = profile if profile is not None else self._profile
        return confirm_hypothesis(
            hypothesis=hypothesis,
            profile=target,
            operator=operator,
            decision_id=decision_id,
        )

    def decline(self, *, hypothesis: HabitHypothesis, operator: str) -> HabitDecline:
        """Record a human "no". Writes nothing."""
        return decline_hypothesis(hypothesis=hypothesis, operator=operator)


def build_habit_surface(
    *,
    memory: Any | None = None,
    profile: Any | None = None,
    source: HistorySource | None = None,
    config: MinerConfig | None = None,
    phraser: Phraser | None = None,
) -> HabitSurface:
    """Build the :class:`HabitSurface` the orchestrator wires onto app.state.

    Composes whatever sources are available: the S5 presence-memory source (from
    ``memory``), the L2 correction source (from ``profile``), and any explicit
    ``source``. ``profile`` is also the store confirmations write to. Raises
    ``ValueError`` if no source can be assembled (nothing to mine)."""
    members: list[Any] = []
    if source is not None:
        members.append(source)
    if memory is not None:
        members.append(S5MemoryHistorySource(memory))
    if profile is not None:
        members.append(ProfileCorrectionHistorySource(profile))
    if not members:
        raise ValueError(
            "build_habit_surface needs at least one of: source, memory, profile "
            "(there is nothing to mine otherwise)"
        )
    composite = members[0] if len(members) == 1 else CompositeHistorySource(*members)
    return HabitSurface(
        source=composite,
        profile=profile,
        miner=HabitMiner(config) if config is not None else HabitMiner(),
        phraser=phraser or TemplatePhraser(),
    )
