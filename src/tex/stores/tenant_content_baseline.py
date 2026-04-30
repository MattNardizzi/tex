"""
In-memory tenant content baseline.

Stores recent PERMITted content signatures, scoped by tenant and
action_type. The behavioral evaluator queries this store on every
evaluation and folds the result into its existing signal.

This is the V11 cross-agent feature. It is a peer to the action
ledger (V10). The ledger captures *what each agent has been doing*;
the tenant baseline captures *what content the entire tenant has
been releasing*.

Two design choices worth flagging:

1. We intentionally only record PERMIT decisions. The baseline
   represents "normal authorized output", not "every output the agent
   tried to release." Recording ABSTAIN/FORBID would poison the
   baseline with the very anomalies we are trying to detect.

2. Storage is a per-(tenant, action_type) bounded ring buffer plus a
   per-(tenant, action_type) recipient-domain set. Both are bounded;
   memory is predictable. The buffer keeps the most recent signatures
   because freshness is what makes "novel content for this tenant"
   meaningful — six-month-old signatures from a deprecated workflow
   should not anchor today's evaluation.
"""

from __future__ import annotations

from collections import deque
from threading import RLock
from typing import Iterable, Mapping

from tex.domain.tenant_baseline import (
    ContentSignatureRecord,
    SIGNATURE_BANDS,
    TenantContentBaselineLookup,
    extract_recipient_domain,
    signature_jaccard_similarity,
)


# A tenant baseline with fewer signatures than this for an action_type
# is considered cold-start at tenant scope. We have data, but not
# enough to draw a confident conclusion about "this is novel for the
# tenant". Picked conservatively: buyers will trust this signal more
# if it doesn't fire on day-one deployments.
_MIN_SAMPLE_FOR_FULL_CONFIDENCE = 30


class InMemoryTenantContentBaseline:
    """
    Thread-safe per-tenant content baseline.

    Storage layout:
    - one bounded deque per (tenant_id, action_type) carrying recent
      ContentSignatureRecords; newest at the right end
    - one set per (tenant_id, action_type) of recipient_domains seen
      with PERMIT verdicts (membership only — counts derived from the
      deque when needed)

    The bounded per-key deque keeps memory predictable. When the cap
    is reached, the oldest signatures roll out — those are the ones
    least informative for "is this novel today" anyway.
    """

    __slots__ = (
        "_lock",
        "_signatures",
        "_recipient_domains",
        "_per_key_limit",
        "_global_count",
    )

    def __init__(
        self,
        *,
        per_key_limit: int = 1_000,
        initial: Iterable[ContentSignatureRecord] | None = None,
    ) -> None:
        if per_key_limit < 1:
            raise ValueError("per_key_limit must be >= 1")
        self._lock = RLock()
        self._signatures: dict[
            tuple[str, str], deque[ContentSignatureRecord]
        ] = {}
        self._recipient_domains: dict[tuple[str, str], dict[str, int]] = {}
        self._per_key_limit = per_key_limit
        self._global_count = 0

        if initial:
            for record in initial:
                self.append(record)

    # ------------------------------------------------------------------ writes

    def append(self, record: ContentSignatureRecord) -> None:
        """
        Append a content signature record to the tenant baseline.

        The caller is responsible for only invoking this on PERMIT
        decisions (see EvaluateActionCommand). This store does not
        re-validate verdict because it does not know about the
        Decision domain — keeping it free of upstream couplings.
        """
        key = (record.tenant_id, record.action_type)
        with self._lock:
            queue = self._signatures.get(key)
            if queue is None:
                queue = deque(maxlen=self._per_key_limit)
                self._signatures[key] = queue
                self._recipient_domains[key] = {}
            queue.append(record)
            if record.recipient_domain is not None:
                domain_counts = self._recipient_domains[key]
                domain_counts[record.recipient_domain] = (
                    domain_counts.get(record.recipient_domain, 0) + 1
                )
            self._global_count += 1

    # ------------------------------------------------------------------ reads

    def lookup(
        self,
        *,
        tenant_id: str,
        action_type: str,
        signature: tuple[int, ...],
        recipient: str | None,
    ) -> TenantContentBaselineLookup:
        """
        Compute a tenant-scope novelty signal for a candidate action.

        Returns a structured lookup that the behavioral evaluator folds
        into its existing signal. Pure with respect to its inputs once
        the store is held under lock.
        """
        if len(signature) != SIGNATURE_BANDS:
            raise ValueError(
                f"signature must have exactly {SIGNATURE_BANDS} bands"
            )

        normalized_tenant = tenant_id.strip().casefold()
        normalized_action = action_type.strip().casefold()
        key = (normalized_tenant, normalized_action)

        with self._lock:
            queue = self._signatures.get(key)
            sample_size = len(queue) if queue else 0

            if sample_size == 0:
                domain = extract_recipient_domain(recipient)
                return TenantContentBaselineLookup(
                    tenant_id=normalized_tenant,
                    sample_size=0,
                    max_similarity=0.0,
                    mean_similarity=0.0,
                    novelty_score=0.0,
                    recipient_domain_seen=False,
                    recipient_domain_seen_count=0,
                    cold_start=True,
                )

            assert queue is not None  # for the type checker; guarded above
            similarities: list[float] = []
            max_similarity = 0.0
            for record in queue:
                similarity = signature_jaccard_similarity(
                    signature, record.signature
                )
                similarities.append(similarity)
                if similarity > max_similarity:
                    max_similarity = similarity
            mean_similarity = sum(similarities) / len(similarities)

            domain = extract_recipient_domain(recipient)
            domain_counts = self._recipient_domains.get(key, {})
            recipient_seen_count = (
                domain_counts.get(domain, 0) if domain is not None else 0
            )
            recipient_seen = recipient_seen_count > 0

            cold_start = sample_size < _MIN_SAMPLE_FOR_FULL_CONFIDENCE

            return TenantContentBaselineLookup(
                tenant_id=normalized_tenant,
                sample_size=sample_size,
                max_similarity=round(max_similarity, 4),
                mean_similarity=round(mean_similarity, 4),
                novelty_score=round(1.0 - max_similarity, 4),
                recipient_domain_seen=recipient_seen,
                recipient_domain_seen_count=recipient_seen_count,
                cold_start=cold_start,
            )

    # ------------------------------------------------------------------ introspection

    def count_for(self, *, tenant_id: str, action_type: str) -> int:
        """Number of signatures the baseline has for one (tenant, action_type)."""
        key = (
            tenant_id.strip().casefold(),
            action_type.strip().casefold(),
        )
        with self._lock:
            queue = self._signatures.get(key)
            return len(queue) if queue else 0

    def recipient_domains_for(
        self,
        *,
        tenant_id: str,
        action_type: str,
    ) -> Mapping[str, int]:
        """
        Snapshot of recipient-domain counts for a tenant+action_type.

        Returns a fresh dict so callers cannot mutate internal state.
        """
        key = (
            tenant_id.strip().casefold(),
            action_type.strip().casefold(),
        )
        with self._lock:
            counts = self._recipient_domains.get(key) or {}
            return dict(counts)

    def total_count(self) -> int:
        with self._lock:
            return self._global_count

    def list_for(
        self,
        *,
        tenant_id: str,
        action_type: str,
        limit: int | None = None,
    ) -> tuple[ContentSignatureRecord, ...]:
        """
        Return signatures for a (tenant, action_type) in chronological
        order (oldest -> newest).
        """
        key = (
            tenant_id.strip().casefold(),
            action_type.strip().casefold(),
        )
        with self._lock:
            queue = self._signatures.get(key)
            if not queue:
                return tuple()
            if limit is None:
                return tuple(queue)
            if limit <= 0:
                return tuple()
            return tuple(list(queue)[-limit:])
