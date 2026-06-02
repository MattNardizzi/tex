"""
Dormancy controller — the dormant-agent doctrine, in code.

A dormant agent is not nothing (it costs money and holds live
credentials) and it is not an interruption either. The Jobs-2050 move is
to make it a problem the client never has rather than a notification the
client must process: **governance, not notification.** (§2.)

What this controller does, on its own authority and in silence:

  * **Sleeps an idle agent it can prove is safe to sleep.** Idle past a
    threshold, and not load-bearing as far as Tex can see (nothing
    delegates to it in the sealed delegation graph). Credentials are
    suspended by the lifecycle transition to SLEEPING; the behavioural
    signature is frozen; the sleep is sealed. No count, no list, no
    notification. An attempt to act while sleeping already routes to
    ABSTAIN (``AgentLifecycleStatus.SLEEPING.forces_abstain``), so a wake
    is a deliberate, sealed human act — never a silent resurrection.

  * **Refuses to sleep what it cannot defend.** If an agent is idle but
    Tex cannot tell whether it is load-bearing, that is *not* a silent
    sleep — it is a genuine ABSTAIN, held and surfaced once. The bar to
    act in silence is "I can defend this," not "it looks quiet." The
    moment Tex sleeps something load-bearing and burns the client, the
    silence becomes a lie and Tex is finished.

  * **Never performs the day-90 deletion itself.** Sleep is reversible for
    90 days. The transition past 90 days into terminal REVOKED is the one
    irreversible step in the dormant path, so it is a held decision — a
    named human act — surfaced as the rare ABSTAIN that earns the voice.
    This controller flags it; it does not execute it.

The idle threshold is the one open build detail the doctrine leaves
(fixed default vs learned per estate). Default fixed; injectable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from tex.domain.agent import AgentLifecycleStatus
from tex.provenance.engine import BehavioralProvenanceEngine
from tex.provenance.feed import HeldDecision, HeldDecisionSink
from tex.provenance.models import ProvenanceEventKind

_logger = logging.getLogger(__name__)

# Default idle threshold before an agent is a sleep candidate.
DEFAULT_IDLE_THRESHOLD = timedelta(days=30)

# Reversible sleep window. Past this, the only move is the held,
# irreversible deletion.
SLEEP_REVERSIBLE_WINDOW = timedelta(days=90)


@dataclass
class DormancySweepResult:
    """What one sweep did and held — for tests, metrics, and the audit."""

    slept: list[UUID] = field(default_factory=list)
    abstained_uncertain: list[UUID] = field(default_factory=list)
    held_for_deletion: list[UUID] = field(default_factory=list)
    skipped_active: int = 0
    examined: int = 0

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "slept": [str(a) for a in self.slept],
            "abstained_uncertain": [str(a) for a in self.abstained_uncertain],
            "held_for_deletion": [str(a) for a in self.held_for_deletion],
            "skipped_active": self.skipped_active,
            "examined": self.examined,
        }


class DormancyController:
    """
    Drives the SLEEPING lifecycle on Tex's own authority, sealing every
    transition and holding every uncertain or irreversible one.
    """

    def __init__(
        self,
        *,
        registry: Any,
        action_ledger: Any,
        provenance_engine: BehavioralProvenanceEngine,
        held_sink: HeldDecisionSink,
        delegation_graph: Any | None = None,
        idle_threshold: timedelta = DEFAULT_IDLE_THRESHOLD,
        reversible_window: timedelta = SLEEP_REVERSIBLE_WINDOW,
    ) -> None:
        self._registry = registry
        self._ledger = action_ledger
        self._engine = provenance_engine
        self._held = held_sink
        self._delegation = delegation_graph
        self._idle_threshold = idle_threshold
        self._reversible_window = reversible_window

    # ------------------------------------------------------------------ activity
    def _last_activity(self, agent) -> datetime:
        """
        Most recent moment Tex saw this agent act, from the action ledger;
        falls back to when it was registered if it has never acted.
        """
        last = agent.registered_at
        ledger = self._ledger
        if ledger is not None:
            try:
                entries = ledger.list_for_agent(agent.agent_id)
            except Exception:  # noqa: BLE001
                entries = ()
            for e in entries:
                ts = getattr(e, "recorded_at", None)
                if ts is not None and ts > last:
                    last = ts
        return last

    def _is_load_bearing(self, agent_id: UUID) -> bool:
        if self._delegation is None:
            # No delegation evidence at all → we cannot prove it is *not*
            # load-bearing. Conservative: treat unknown as load-bearing so
            # the sweep routes to ABSTAIN rather than sleeping blind.
            return True
        try:
            return self._delegation.is_load_bearing(agent_id)
        except Exception:  # noqa: BLE001
            return True

    # ------------------------------------------------------------------ sweep
    def sweep(self, *, now: datetime | None = None) -> DormancySweepResult:
        """
        Examine the estate once. Sleep what is provably safe, hold what is
        uncertain, and flag day-90 sleepers for the irreversible human
        decision. Idempotent: an already-sleeping agent is only re-checked
        for the day-90 boundary.
        """
        now = now or datetime.now(UTC)
        result = DormancySweepResult()

        try:
            agents = self._registry.list_all()
        except Exception:  # noqa: BLE001
            return result

        for agent in agents:
            status = agent.lifecycle_status

            # --- already sleeping: only the day-90 boundary matters ---
            if status is AgentLifecycleStatus.SLEEPING:
                self._check_day90(agent, now, result)
                continue

            if status is not AgentLifecycleStatus.ACTIVE:
                continue  # PENDING/QUARANTINED/REVOKED are not sleep candidates

            result.examined += 1
            idle_for = now - self._last_activity(agent)
            if idle_for < self._idle_threshold:
                result.skipped_active += 1
                continue

            # Idle past threshold. Can we *defend* sleeping it?
            if self._is_load_bearing(agent.agent_id):
                # Uncertain or known-load-bearing → genuine ABSTAIN. Held,
                # spoken once. Never slept in silence.
                self._held.append(
                    HeldDecision(
                        agent_id=agent.agent_id,
                        kind="dormancy_abstain",
                        confidence=0.0,
                        note=(
                            f"{agent.name} has been idle "
                            f"{idle_for.days} days but may be load-bearing; "
                            "Tex will not sleep it without a human."
                        ),
                        detail={
                            "idle_days": idle_for.days,
                            "reason": "load_bearing_or_uncertain",
                            "owner": agent.owner,
                        },
                    )
                )
                result.abstained_uncertain.append(agent.agent_id)
                continue

            # Provably safe: idle, and nothing depends on it. Sleep it,
            # on Tex's own authority, in silence.
            self._sleep(agent, idle_for)
            result.slept.append(agent.agent_id)

        return result

    def _sleep(self, agent, idle_for) -> None:
        try:
            self._registry.set_lifecycle(agent.agent_id, AgentLifecycleStatus.SLEEPING)
        except Exception:  # noqa: BLE001
            _logger.warning("dormancy: failed to set SLEEPING", exc_info=True)
            return
        self._engine.seal_sleep(
            agent.agent_id,
            detail={
                "idle_days": idle_for.days,
                "reason": "idle_and_not_load_bearing",
                "reversible_until_days": self._reversible_window.days,
            },
        )

    def _check_day90(self, agent, now: datetime, result: DormancySweepResult) -> None:
        slept = self._engine.last_event(agent.agent_id, ProvenanceEventKind.SLEPT)
        if slept is None:
            return
        asleep_for = now - slept.recorded_at
        if asleep_for < self._reversible_window:
            return
        # Past the reversible window. The deletion is irreversible, so it
        # is NOT performed here — it is held as a named human decision.
        self._held.append(
            HeldDecision(
                agent_id=agent.agent_id,
                kind="dormancy_permanent_deletion",
                confidence=1.0,
                note=(
                    f"{agent.name} has slept {asleep_for.days} days "
                    "(past the 90-day reversible window). Permanent "
                    "deletion is irreversible and needs a human."
                ),
                detail={
                    "asleep_days": asleep_for.days,
                    "owner": agent.owner,
                    "irreversible": True,
                },
            )
        )
        result.held_for_deletion.append(agent.agent_id)

    # ------------------------------------------------------------------ human acts
    def wake(self, agent_id: UUID, *, actor: str) -> None:
        """
        The deliberate, sealed human act that reverses a sleep. Routes a
        sleeping agent back to ACTIVE and seals the WOKE event with the
        actor who did it.
        """
        self._registry.set_lifecycle(agent_id, AgentLifecycleStatus.ACTIVE)
        self._engine.seal_wake(agent_id, detail={"actor": actor})

    def revoke(self, agent_id: UUID, *, actor: str) -> None:
        """
        Execute the day-90 irreversible deletion — only ever called after a
        human approves the held decision. Transitions to terminal REVOKED
        and seals the act with the actor.
        """
        self._registry.set_lifecycle(agent_id, AgentLifecycleStatus.REVOKED)
        self._engine.seal_sleep(  # reuse the seal path; detail marks the kill
            agent_id,
            detail={"revoked": True, "actor": actor, "irreversible": True},
        )
