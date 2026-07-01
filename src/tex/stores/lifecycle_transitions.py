"""Lifecycle-transition records — the data "why was agent X revoked?" needs.

Before this store existed, an agent's lifecycle change (ACTIVE → QUARANTINED →
REVOKED) left no record of the change itself — only the new current state — so
every why/when-did-the-state-change question honestly abstained. This store
records each transition as it happens: from-status, to-status, an optional
reason, and the recorded time.

Honesty edges, baked in:

* **In-memory, since boot.** Transitions before this store was installed (or
  before the last restart) were never recorded and can never be answered. The
  read-tool over this store discloses that; the gate abstains on anything the
  records don't hold — this store only ADDS answerable ground, never invents it.
* **Recorded-at-write-time.** ``occurred_at`` is wall-clock at record time,
  outside any tamper-evident hash — answers over it are DERIVED, not SEALED
  (same contract as every other timestamp in the plan algebra).
* **The recorder observes; it never mutates.** ``install_transition_recorder``
  wraps ``registry.save`` read-only: the save proceeds identically whether or
  not recording succeeds.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = ["LifecycleTransition", "LifecycleTransitionStore", "install_transition_recorder"]


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    agent_id: str
    agent_name: str
    tenant_id: str | None
    from_status: str
    to_status: str
    reason: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "tenant_id": self.tenant_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "reason": self.reason,
            "occurred_at": self.occurred_at.isoformat(),
        }


class LifecycleTransitionStore:
    """Thread-safe, append-only, in-memory list of lifecycle transitions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: list[LifecycleTransition] = []

    def append(self, transition: LifecycleTransition) -> None:
        with self._lock:
            self._items.append(transition)

    def list_all(self) -> tuple[LifecycleTransition, ...]:
        with self._lock:
            return tuple(self._items)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# Which registry INSTANCES record into which store. Keyed by id() because the
# registries are slotted (no __weakref__); they live for the process lifetime,
# so the map cannot grow unboundedly in practice.
_RECORDING_STORES: dict[int, LifecycleTransitionStore] = {}


def _record_change(store: LifecycleTransitionStore, prev: Any, agent: Any) -> None:
    old = str(getattr(prev, "lifecycle_status", ""))
    new = str(getattr(agent, "lifecycle_status", ""))
    if old and new and old != new:
        store.append(
            LifecycleTransition(
                agent_id=str(getattr(agent, "agent_id", "")),
                agent_name=str(getattr(agent, "name", "")),
                tenant_id=getattr(agent, "tenant_id", None),
                from_status=old,
                to_status=new,
                reason=getattr(agent, "status_reason", None),
            )
        )


def install_transition_recorder(registry: Any, store: LifecycleTransitionStore) -> bool:
    """Wrap the registry's ``save`` so every lifecycle-status change is recorded.

    The registries are slotted, so the wrap is installed on the CLASS, with a
    per-instance store map — only instances explicitly registered here record
    anything; every other instance's save is byte-identical in behaviour. The
    wrapper is strictly observational: the original save always runs (and its
    result is returned) even if recording fails for any reason.
    """
    if registry is None or store is None or not hasattr(registry, "save"):
        return False
    _RECORDING_STORES[id(registry)] = store

    cls = type(registry)
    if getattr(cls.save, "_records_transitions", False):
        return True  # class already wrapped — the instance map above is the change

    original_save = cls.save

    def save(self: Any, agent: Any) -> Any:
        bound_store = _RECORDING_STORES.get(id(self))
        prev = None
        if bound_store is not None:
            try:
                agent_id = getattr(agent, "agent_id", None)
                if agent_id is not None:
                    prev = self.get(agent_id)
            except Exception:  # noqa: BLE001 — observation must never block the save
                prev = None
        result = original_save(self, agent)
        if bound_store is not None and prev is not None:
            try:
                _record_change(bound_store, prev, agent)
            except Exception:  # noqa: BLE001 — recording is best-effort; the save already succeeded
                pass
        return result

    save._records_transitions = True  # type: ignore[attr-defined]
    try:
        cls.save = save
    except Exception:  # noqa: BLE001 — an unpatchable registry simply doesn't get recording
        _RECORDING_STORES.pop(id(registry), None)
        return False
    return True
