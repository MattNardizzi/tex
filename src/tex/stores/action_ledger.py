"""
In-memory action ledger.

Records one ActionLedgerEntry per Tex decision tied to an agent. The
behavioral evaluation stream queries this store every evaluation to
build a fresh BehavioralBaseline.

This is the substrate of stateful agent behavior tracking. Every entry
is immutable. The ledger preserves chronological order so the
"forbid_streak" and "novel action" computations are deterministic.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import UTC, datetime
from threading import RLock
from typing import Iterable
from uuid import UUID

from tex.domain.agent import ActionLedgerEntry, BehavioralBaseline


class InMemoryActionLedger:
    """
    Thread-safe per-agent action ledger.

    Storage layout:
    - one bounded deque per agent_id, capped at `per_agent_limit`
    - newest entries at the right end of the deque
    - global insertion order preserved across agents in `_global_order`
      to support drift / fleet analytics

    The bounded per-agent deque keeps memory predictable. When the cap
    is hit, the oldest entries roll out — these are the entries that
    contribute least to the behavioral baseline anyway.
    """

    __slots__ = ("_lock", "_by_agent", "_per_agent_limit", "_global_count", "_global_order")

    def __init__(
        self,
        *,
        per_agent_limit: int = 5_000,
        initial: Iterable[ActionLedgerEntry] | None = None,
    ) -> None:
        if per_agent_limit < 1:
            raise ValueError("per_agent_limit must be >= 1")
        self._lock = RLock()
        self._by_agent: dict[UUID, deque[ActionLedgerEntry]] = {}
        self._per_agent_limit = per_agent_limit
        self._global_count = 0
        self._global_order: list[ActionLedgerEntry] = []

        if initial:
            for entry in initial:
                self.append(entry)

    # ------------------------------------------------------------------ writes

    def append(self, entry: ActionLedgerEntry) -> None:
        """Append an immutable ledger entry for an agent."""
        with self._lock:
            queue = self._by_agent.get(entry.agent_id)
            if queue is None:
                queue = deque(maxlen=self._per_agent_limit)
                self._by_agent[entry.agent_id] = queue
            queue.append(entry)
            self._global_order.append(entry)
            self._global_count += 1

    # ------------------------------------------------------------------ reads

    def list_all(self, *, limit: int | None = None) -> tuple[ActionLedgerEntry, ...]:
        """
        Return all ledger entries in global chronological order.
        Used for fleet/systemic-risk analytics.
        """
        with self._lock:
            if limit is None:
                return tuple(self._global_order)
            if limit <= 0:
                return tuple()
            return tuple(self._global_order[-limit:])

    def list_for_agent(
        self,
        agent_id: UUID,
        *,
        limit: int | None = None,
    ) -> tuple[ActionLedgerEntry, ...]:
        """
        Return ledger entries for an agent in chronological order
        (oldest → newest). When `limit` is set, return the most recent
        `limit` entries.
        """
        with self._lock:
            queue = self._by_agent.get(agent_id)
            if not queue:
                return tuple()
            if limit is None:
                return tuple(queue)
            if limit <= 0:
                return tuple()
            # last `limit` entries
            return tuple(list(queue)[-limit:])

    def count_for_agent(self, agent_id: UUID) -> int:
        with self._lock:
            queue = self._by_agent.get(agent_id)
            return len(queue) if queue else 0

    def total_count(self) -> int:
        with self._lock:
            return self._global_count

    # ------------------------------------------------------------------ baseline

    def compute_baseline(
        self,
        agent_id: UUID,
        *,
        window: int = 200,
    ) -> BehavioralBaseline:
        """
        Compute a behavioral baseline from the most recent `window`
        entries for this agent.

        Pure function over the ledger window. Deterministic. Safe to
        call on every evaluation.
        """
        if window <= 0:
            raise ValueError("window must be positive")

        entries = self.list_for_agent(agent_id, limit=window)
        sample_size = len(entries)

        if sample_size == 0:
            return BehavioralBaseline(
                agent_id=agent_id,
                sample_size=0,
                permit_rate=0.0,
                abstain_rate=0.0,
                forbid_rate=0.0,
                action_type_distribution={},
                channel_distribution={},
                recipient_domain_distribution={},
                mean_final_score=0.0,
                capability_violation_rate=0.0,
                forbid_streak=0,
                computed_at=datetime.now(UTC),
            )

        verdict_counter: Counter[str] = Counter()
        action_counter: Counter[str] = Counter()
        channel_counter: Counter[str] = Counter()
        domain_counter: Counter[str] = Counter()
        score_sum = 0.0
        capability_violation_count = 0

        for entry in entries:
            verdict_counter[entry.verdict.upper()] += 1
            action_counter[entry.action_type] += 1
            channel_counter[entry.channel] += 1
            score_sum += entry.final_score
            if entry.capability_violations:
                capability_violation_count += 1
            domain = _extract_recipient_domain(entry.recipient)
            if domain:
                domain_counter[domain] += 1

        permit_rate = verdict_counter.get("PERMIT", 0) / sample_size
        abstain_rate = verdict_counter.get("ABSTAIN", 0) / sample_size
        forbid_rate = verdict_counter.get("FORBID", 0) / sample_size

        # Forbid streak: count contiguous FORBIDs from the most recent
        # entry backwards until we hit a non-FORBID.
        streak = 0
        for entry in reversed(entries):
            if entry.verdict.upper() == "FORBID":
                streak += 1
            else:
                break

        return BehavioralBaseline(
            agent_id=agent_id,
            sample_size=sample_size,
            permit_rate=round(permit_rate, 4),
            abstain_rate=round(abstain_rate, 4),
            forbid_rate=round(forbid_rate, 4),
            action_type_distribution=_distribution(action_counter, sample_size),
            channel_distribution=_distribution(channel_counter, sample_size),
            recipient_domain_distribution=_distribution(domain_counter, sample_size),
            mean_final_score=round(score_sum / sample_size, 4),
            capability_violation_rate=round(
                capability_violation_count / sample_size, 4
            ),
            forbid_streak=streak,
            computed_at=datetime.now(UTC),
        )


def _distribution(counter: Counter[str], total: int) -> dict[str, float]:
    if total <= 0:
        return {}
    return {key: round(value / total, 4) for key, value in counter.items()}


def _extract_recipient_domain(recipient: str | None) -> str | None:
    """Extract the lowercase domain from a recipient string, or None."""
    if recipient is None:
        return None
    normalized = recipient.strip().casefold()
    if not normalized:
        return None
    if "@" in normalized:
        return normalized.rsplit("@", 1)[-1] or None
    if "://" in normalized:
        after = normalized.split("://", 1)[-1]
        host = after.split("/", 1)[0]
        return host or None
    return normalized
