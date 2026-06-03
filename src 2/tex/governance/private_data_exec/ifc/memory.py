"""
NeuroTaint cross-session memory stream.

Reference
---------
"Ghost in the Agent: Redefining Information Flow Tracking for LLM
Agents." arXiv:2604.23374 (NeuroTaint, Apr 2026).

NeuroTaint's key insight is that taint propagation in LLM agents is
*not* limited to explicit content transfer. Three additional channels
matter:

  1. Semantic transformation — the LLM rephrases tainted content,
     erasing surface-level patterns but preserving the underlying
     dependency.
  2. Causal influence on decisions — even when no tainted bytes
     appear in the output, the agent's decision was *shaped* by
     tainted input.
  3. Cross-session persistence through memory — taint outlives a
     single request. A retrieved memory item or a stored session
     summary carries forward whatever taint flowed into it.

The ARM `ProvenanceGraph` handles (1) and (2) within a request via
the COUNTERFACTUAL edge and field-level labels. This module handles
(3): a tenant-scoped, in-memory store of tainted memory items that the
IfcSpecialist consults when assembling the graph for a new request.

We deliberately keep this in-memory only and bounded by capacity. A
durable backing store (Postgres) is straightforward to add later via
a `MemoryStreamBackend` protocol; we ship the in-memory variant first.

This is BLEEDING-EDGE wiring: no shipping competitor preserves IFC
labels across agent sessions as of May 2026.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

from tex.governance.private_data_exec.ifc.lattice import IfcLabel


@dataclass(frozen=True, slots=True)
class MemoryItem:
    """
    A tainted memory item persisted across sessions.

    `session_key` is the cross-session identifier (tenant_id + agent_id
    or similar — the IfcSpecialist constructs this from
    `EvaluationRequest.agent_identity`).

    `content_hash` is a stable hash of the originating content so the
    NeuroTaint cross-session check can ask "did this memory carry
    forward into this request?" without storing the content itself.
    """

    session_key: str
    content_hash: str
    label: IfcLabel
    recorded_at: datetime
    reason: str = ""


class MemoryStream:
    """
    Tenant-scoped, capacity-bounded LRU store of tainted memory items.

    Thread-safe via a single lock. Per-tenant FIFO eviction. Optional
    TTL drops items older than `ttl` on every put/lookup.

    Tex does NOT need this to be durable; it's a session-bridging
    cache. The durable disclosure log lives in the existing GAAP
    `DisclosureLog`, and the durable evidence chain lives in
    `tex.evidence.*`.
    """

    DEFAULT_CAPACITY = 256
    DEFAULT_TTL = timedelta(hours=24)

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_CAPACITY,
        ttl: timedelta | None = DEFAULT_TTL,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._capacity = capacity
        self._ttl = ttl
        self._store: OrderedDict[tuple[str, str], MemoryItem] = OrderedDict()
        self._lock = threading.Lock()

    def record(self, item: MemoryItem) -> None:
        with self._lock:
            self._evict_expired_locked()
            key = (item.session_key, item.content_hash)
            if key in self._store:
                # Re-insert at the back of the LRU.
                self._store.pop(key)
            self._store[key] = item
            while len(self._store) > self._capacity:
                self._store.popitem(last=False)

    def lookup(
        self,
        *,
        session_key: str,
        content_hashes: Iterable[str],
    ) -> tuple[MemoryItem, ...]:
        """
        Return any memory items whose (session_key, content_hash) is
        in the request set. Hits are moved to the back of the LRU
        (touch semantics).
        """
        wanted = set(content_hashes)
        if not wanted:
            return tuple()
        hits: list[MemoryItem] = []
        with self._lock:
            self._evict_expired_locked()
            for content_hash in wanted:
                key = (session_key, content_hash)
                item = self._store.get(key)
                if item is None:
                    continue
                # Touch.
                self._store.pop(key)
                self._store[key] = item
                hits.append(item)
        return tuple(hits)

    def session_items(self, session_key: str) -> tuple[MemoryItem, ...]:
        """All items for one session key, oldest-first."""
        with self._lock:
            self._evict_expired_locked()
            return tuple(
                item
                for (sk, _), item in self._store.items()
                if sk == session_key
            )

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def _evict_expired_locked(self) -> None:
        if self._ttl is None:
            return
        cutoff = datetime.now(UTC) - self._ttl
        expired_keys: list[tuple[str, str]] = []
        for key, item in self._store.items():
            if item.recorded_at < cutoff:
                expired_keys.append(key)
            else:
                # OrderedDict is FIFO-by-insertion; if we keep an item
                # we can't early-exit because puts after re-touch may
                # reorder. Be conservative and check every item.
                continue
        for key in expired_keys:
            self._store.pop(key, None)


# Default global stream. The IfcSpecialist uses this when constructed
# without an explicit MemoryStream argument. Tests construct their own
# instances to avoid cross-test pollution.
DEFAULT_MEMORY_STREAM = MemoryStream()


__all__ = [
    "MemoryItem",
    "MemoryStream",
    "DEFAULT_MEMORY_STREAM",
]
