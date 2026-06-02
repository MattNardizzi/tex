"""
In-memory agent registry.

Holds AgentIdentity records keyed by agent_id with monotonic revisioning.
Updates produce a new immutable AgentIdentity with revision incremented;
the previous revision is preserved for audit access.

This store is the source of truth for "who is this agent?" Every
evaluation that carries agent_id resolves through this store.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from threading import RLock
from uuid import UUID

from tex.domain.agent import AgentIdentity, AgentLifecycleStatus


class AgentNotFoundError(LookupError):
    """Raised when an agent_id is not present in the registry."""


class AgentRevoked(LookupError):
    """Raised when an evaluation is requested for a revoked agent."""


class InMemoryAgentRegistry:
    """
    In-memory registry of agent identities.

    Thread-safe under RLock for the same reasons the other in-memory
    stores are: Tex is multi-threaded under uvicorn workers, and the
    registry is read on every evaluation.
    """

    __slots__ = ("_lock", "_by_id", "_history")

    def __init__(self, initial: Iterable[AgentIdentity] | None = None) -> None:
        self._lock = RLock()
        self._by_id: dict[UUID, AgentIdentity] = {}
        # All historical revisions for one agent_id, in revision order.
        self._history: dict[UUID, list[AgentIdentity]] = {}

        if initial:
            for agent in initial:
                self.save(agent)

    # ------------------------------------------------------------------ writes

    def save(self, agent: AgentIdentity) -> AgentIdentity:
        """
        Save a new agent or a new revision of an existing one.

        Behavior:
        - If the agent_id is unknown, save as revision 1.
        - If the agent_id is known, append as revision N+1 with
          updated_at refreshed.

        Returns the AgentIdentity that was actually persisted (the
        revision number on the return value is authoritative).
        """
        with self._lock:
            existing = self._by_id.get(agent.agent_id)

            if existing is None:
                # First registration. Force revision=1 regardless of input.
                stored = (
                    agent
                    if agent.revision == 1
                    else agent.model_copy(update={"revision": 1})
                )
                self._by_id[agent.agent_id] = stored
                self._history[agent.agent_id] = [stored]
                return stored

            # Update path. New revision = existing.revision + 1, refresh
            # updated_at, and preserve registered_at from the original.
            new_revision = existing.revision + 1
            stored = agent.model_copy(
                update={
                    "revision": new_revision,
                    "registered_at": existing.registered_at,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._by_id[agent.agent_id] = stored
            self._history[agent.agent_id].append(stored)
            return stored

    def set_lifecycle(
        self,
        agent_id: UUID,
        status: AgentLifecycleStatus,
    ) -> AgentIdentity:
        """
        Transition an agent's lifecycle status.

        Lifecycle changes are first-class and produce a new revision so
        the audit trail captures when QUARANTINED or REVOKED happened.
        """
        with self._lock:
            existing = self._by_id.get(agent_id)
            if existing is None:
                raise AgentNotFoundError(f"agent not found: {agent_id}")

            if existing.lifecycle_status is status:
                return existing

            updated = existing.model_copy(
                update={
                    "lifecycle_status": status,
                    "revision": existing.revision + 1,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._by_id[agent_id] = updated
            self._history[agent_id].append(updated)
            return updated

    # ------------------------------------------------------------------ reads

    def get(self, agent_id: UUID) -> AgentIdentity | None:
        with self._lock:
            return self._by_id.get(agent_id)

    def require(self, agent_id: UUID) -> AgentIdentity:
        agent = self.get(agent_id)
        if agent is None:
            raise AgentNotFoundError(f"agent not found: {agent_id}")
        return agent

    def require_evaluable(self, agent_id: UUID) -> AgentIdentity:
        """
        Resolve an agent and confirm it can be evaluated against.

        REVOKED agents raise; PENDING / ACTIVE / QUARANTINED resolve
        normally because the streams downstream know how to handle
        those states. Quarantine forces ABSTAIN downstream; revoke is
        terminal at the application boundary.
        """
        agent = self.require(agent_id)
        if agent.lifecycle_status is AgentLifecycleStatus.REVOKED:
            raise AgentRevoked(f"agent has been revoked: {agent_id}")
        return agent

    def history(self, agent_id: UUID) -> tuple[AgentIdentity, ...]:
        with self._lock:
            entries = self._history.get(agent_id)
            return tuple(entries) if entries else tuple()

    def list_all(self) -> tuple[AgentIdentity, ...]:
        with self._lock:
            return tuple(self._by_id.values())

    def list_by_status(
        self,
        status: AgentLifecycleStatus,
    ) -> tuple[AgentIdentity, ...]:
        with self._lock:
            return tuple(
                a for a in self._by_id.values() if a.lifecycle_status is status
            )

    # ------------------------------------------------------------------ misc

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, UUID):
            return False
        with self._lock:
            return item in self._by_id
