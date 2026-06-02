"""
Agent Identity Document registry.

Holds AIDs by ``agent_id`` for the lifetime of a process. The
in-memory implementation is the default, suitable for single-node
deployments and tests. Operators who need cross-node durability can
wire a Postgres mirror by passing a ``mirror`` implementing
``AidRegistryMirror`` — mirrors are best-effort writes that NEVER
block the in-memory operation, mirroring Tex's
``EvidenceRecorder`` design (Thread 5).

Concurrency: a single RLock guards the in-memory dict. Operations are
fast (microseconds) so contention is not a concern at expected agent
counts (~10^3 per tenant). For 10^6+ agent counts the registry should
be backed by Postgres directly; the in-memory store becomes a cache.

Discovery rule: registry lookups return only the AID *envelope*. The
held base proof inside the AID is returned to internal callers
(``/v1/vet/aid/{agent_id}`` does NOT expose it) but is required for
issuing presentations on the agent's behalf.
"""

from __future__ import annotations

import logging
from threading import RLock
from typing import Iterator, Protocol, runtime_checkable

from tex.vet.agent_identity_document import AgentIdentityDocument, AidStatus


__all__ = [
    "AidRegistry",
    "AidRegistryMirror",
    "InMemoryAidRegistry",
]


_logger = logging.getLogger(__name__)


@runtime_checkable
class AidRegistryMirror(Protocol):
    """Optional durable sink for AID writes."""

    def upsert(self, aid: AgentIdentityDocument) -> None:
        ...

    def mark_status(self, agent_id: str, status: AidStatus) -> None:
        ...


@runtime_checkable
class AidRegistry(Protocol):
    """Protocol implemented by every concrete registry."""

    def register(self, aid: AgentIdentityDocument) -> None:
        ...

    def get(self, agent_id: str) -> AgentIdentityDocument | None:
        ...

    def revoke(self, agent_id: str) -> bool:
        ...

    def suspend(self, agent_id: str) -> bool:
        ...

    def list_active(self) -> Iterator[AgentIdentityDocument]:
        ...


class InMemoryAidRegistry:
    """
    Thread-safe in-memory ``AidRegistry`` implementation.

    Backed by a single dict + RLock. When a ``mirror`` is provided,
    every state change is best-effort propagated to it; mirror errors
    are logged but never raised to callers.
    """

    __slots__ = ("_store", "_lock", "_mirror")

    def __init__(self, *, mirror: AidRegistryMirror | None = None) -> None:
        self._store: dict[str, AgentIdentityDocument] = {}
        self._lock = RLock()
        self._mirror = mirror

    def register(self, aid: AgentIdentityDocument) -> None:
        """Upsert an AID. Existing entries for the same agent_id are replaced."""
        with self._lock:
            self._store[aid.agent_id] = aid
        if self._mirror is not None:
            try:
                self._mirror.upsert(aid)
            except Exception as exc:  # noqa: BLE001 - log all mirror errors
                _logger.warning("AID mirror upsert failed: %s", exc)

    def get(self, agent_id: str) -> AgentIdentityDocument | None:
        with self._lock:
            return self._store.get(agent_id)

    def revoke(self, agent_id: str) -> bool:
        return self._set_status(agent_id, AidStatus.REVOKED)

    def suspend(self, agent_id: str) -> bool:
        return self._set_status(agent_id, AidStatus.SUSPENDED)

    def _set_status(self, agent_id: str, status: AidStatus) -> bool:
        with self._lock:
            aid = self._store.get(agent_id)
            if aid is None:
                return False
            updated = aid.model_copy(update={"status": status})
            self._store[agent_id] = updated
        if self._mirror is not None:
            try:
                self._mirror.mark_status(agent_id, status)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("AID mirror mark_status failed: %s", exc)
        return True

    def list_active(self) -> Iterator[AgentIdentityDocument]:
        with self._lock:
            snapshot = list(self._store.values())
        for aid in snapshot:
            if aid.status is AidStatus.ACTIVE:
                yield aid

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level default registry. Most callers should use this; if you
# need a tenant-scoped registry, instantiate a new ``InMemoryAidRegistry``.
_DEFAULT_REGISTRY = InMemoryAidRegistry()


def default_registry() -> InMemoryAidRegistry:
    """Return the process-wide default registry."""
    return _DEFAULT_REGISTRY
