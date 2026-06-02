"""
Contract bridge — adapts the PDP request shape to the ContractEnforcer
shape, then translates violations into ``Finding`` objects that fit the
public ``EvaluationResponse`` surface.

Wiring scope
------------
This module is the *only* place where ``tex.contracts`` meets the live
``/v1/guardrail`` pipeline. The PDP imports ``evaluate_contracts_for_request``
and nothing else. Keeping the adapter logic here means:

  * ``tex.engine.pdp`` stays declarative — it just asks the bridge for a
    verdict-shaped result and decides whether to short-circuit FORBID
    or feed soft signals to the router.
  * ``tex.contracts`` stays pure — its public API (``check_pre``,
    ``violations``) is unchanged.

Thread 1.5 — session-scoped enforcement + ledger replay
-------------------------------------------------------
The original Thread 1 build used a single global ``ContractEnforcer`` and
passed an empty ``recent_window`` to ``check_pre``. That produced correct
hard-violation FORBID semantics but did NOT honour the ABC paper's
session-scoped (p, δ, k)-satisfaction (arxiv 2602.22302 §3.3 Def 3.7):

  * The enforcer's internal ``_soft_pending`` recovery counter is keyed
    by ``(agent_id, contract_id, kind, idx)`` — so agents are correctly
    isolated from each other, but multiple sessions of the same agent
    were sharing recovery state. That violates the paper's notion of a
    "session-bounded" satisfaction window.
  * Soft-recovery contracts of the form ``G(p -> F<=k recovered)`` could
    not be evaluated against history because the enforcer started fresh
    every request and had no view of prior soft violations.

Thread 1.5 fixes both:

  1. ``SessionEnforcerRegistry`` maintains one ``ContractEnforcer``
     instance per ``(agent_id, session_id)`` key, lazy-initialised from
     a template tuple of ``BehavioralContract``s. Cleanup happens via
     an LRU bound on number of live sessions; long-lived deployments
     can call ``forget()`` to evict explicit keys.
  2. ``_ledger_window_for`` translates the agent's recent
     ``ActionLedgerEntry`` records into a tuple of ``ProposedEvent``
     instances, which is passed as ``recent_window`` to ``check_pre``.
     This lets atom resolvers read past-event fields when the contract
     vocabulary supports them.
  3. On the first request in a session, the ledger replay also seeds
     ``_soft_pending`` correctly: any pending soft violation that fired
     in a *previous* request will have its recovery deadline tracked
     forward across the request boundary.

Source-paper alignment
----------------------
  * arxiv 2602.22302 §3 (ABC 6-tuple) — drives the violated_clause split.
  * arxiv 2602.22302 §3.3 Def 3.7 — (p, δ, k)-satisfaction; per-session
    enforcer state is what makes this measurable across requests.
  * arxiv 2602.22302 §5.3 — pre-check loop matches the per-turn enforcement loop.
  * arxiv 2411.14581 §3 (LTL3 finite-trace semantics) — three-valued runtime
    verdicts (true / false / inconclusive) map to PERMIT / FORBID / ABSTAIN.
  * arxiv 2601.22136 (StepShield) — temporal-detection metrics; the
    per-session ``step_index`` now accumulates across requests as the
    paper requires.

Ledger-replay limitations (documented honestly)
------------------------------------------------
``ActionLedgerEntry`` records store ``content_sha256``, NOT raw content.
So contracts whose atoms read ``field:content~contains:...`` on past
events will NOT find their content in the replayed window. They will
still evaluate correctly on the *current* event, because the bridge
hands the live request's content through unchanged. Contracts that
should fire over historical content must restrict themselves to fields
the ledger preserves: ``action_type``, ``channel``, ``environment``,
``recipient``, ``content_sha256``, ``verdict``, ``final_score``,
``confidence``, ``capability_violations``, ``asi_short_codes``,
``policy_version``, ``evidence_hash``. This boundary is surfaced in
CLAIMS.md and is a Phase 0 design decision (FRONTIER_DELTA_thread_1.md
§6, updated for Thread 1.5).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Iterable
from uuid import UUID

from tex.contracts.contract import BehavioralContract
from tex.contracts.runtime_enforcement import ContractEnforcer
from tex.contracts.violation import ContractViolation
from tex.domain.agent import ActionLedgerEntry
from tex.domain.evaluation import EvaluationRequest
from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState


# Marker source string for every Finding emitted from this bridge.
CONTRACT_FINDING_SOURCE: str = "contracts.behavioral"

# Uncertainty flag name when a soft violation fires.
SOFT_VIOLATION_UNCERTAINTY_FLAG: str = "contract_soft_violation"

# Reason text recorded when a hard violation short-circuits the PDP to FORBID.
HARD_VIOLATION_FORBID_REASON: str = (
    "behavioral contract hard violation detected — pipeline short-circuited "
    "to FORBID before fusion"
)

# Default action-type → event_kind mapping used when no explicit override is
# present in the request metadata.
_DEFAULT_EVENT_KIND_PREFIX: str = "guardrail."


# Neutral state-hash placeholder for the EcosystemState snapshot.
_NEUTRAL_STATE_HASH: str = (
    "0000000000000000000000000000000000000000000000000000000000000000"
)

# How many past ledger entries to translate into the recent_window per request.
_DEFAULT_REPLAY_WINDOW: int = 32

# How many distinct (agent_id, session_id) enforcer instances to keep warm.
_DEFAULT_SESSION_CAPACITY: int = 256


# Soft violation clauses per ABC §3.1.
_SOFT_CLAUSE_NAMES: frozenset[str] = frozenset(
    {"soft_invariant", "soft_governance"}
)


@dataclass(frozen=True, slots=True)
class ContractEvaluationOutcome:
    """
    Compact, frozen summary of one contract enforcement pass over one
    evaluation request. Owned by the bridge module.
    """

    has_hard_violation: bool
    has_soft_violation: bool
    findings: tuple[Finding, ...]
    forbid_reason: str | None
    soft_uncertainty_flags: tuple[str, ...]
    contracts_ms: float
    raw_violations: tuple[ContractViolation, ...]
    # Thread 1.5 additions — session-scoped audit fields.
    session_key: str | None = None
    replayed_window_size: int = 0
    step_index_at_check: int = 0


# Neutral outcome returned when no enforcer is wired in.
NEUTRAL_OUTCOME: ContractEvaluationOutcome = ContractEvaluationOutcome(
    has_hard_violation=False,
    has_soft_violation=False,
    findings=(),
    forbid_reason=None,
    soft_uncertainty_flags=(),
    contracts_ms=0.0,
    raw_violations=(),
    session_key=None,
    replayed_window_size=0,
    step_index_at_check=0,
)


# ----------------------------------------------------------------------
# Session registry (Thread 1.5)
# ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ReplayState:
    """
    Internal bookkeeping for whether a session enforcer has been
    primed with historical ledger entries.
    """

    primed: bool
    primed_at_count: int


class SessionEnforcerRegistry:
    """
    LRU registry of per-(agent_id, session_id) ``ContractEnforcer``
    instances.

    Each entry is lazy-initialised from a *template* tuple of
    ``BehavioralContract``s. Contracts themselves are immutable frozen
    dataclasses so cloning them across enforcer instances is free; what
    differs per-instance is the ``_soft_pending`` recovery state, the
    ``_step_index`` counter, and the historical compliance scores.
    These are the pieces the ABC paper §3.3 Def 3.7 calls
    "session-scoped" — they must NOT be shared across sessions.

    The "default" key (no agent_id) reproduces pre-Thread-1.5 behaviour
    bit-for-bit: a single shared enforcer for the agent-less path.

    Thread-safety: a single ``RLock`` guards both the LRU dict and the
    per-key prime state.
    """

    __slots__ = (
        "_contracts",
        "_lock",
        "_enforcers",
        "_prime_state",
        "_capacity",
    )

    DEFAULT_KEY: str = "__default__"

    def __init__(
        self,
        *,
        contracts: tuple[BehavioralContract, ...],
        capacity: int = _DEFAULT_SESSION_CAPACITY,
    ) -> None:
        if not contracts:
            raise ValueError(
                "SessionEnforcerRegistry requires at least one contract"
            )
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._contracts: tuple[BehavioralContract, ...] = contracts
        self._lock = RLock()
        self._enforcers: "OrderedDict[str, ContractEnforcer]" = OrderedDict()
        self._prime_state: dict[str, _ReplayState] = {}
        self._capacity = capacity

    @staticmethod
    def session_key_for(
        *,
        agent_id: UUID | None,
        session_id: str | None,
    ) -> str:
        """
        Compute the stable LRU key for a (agent_id, session_id) pair.
        """
        if agent_id is None and session_id is None:
            return SessionEnforcerRegistry.DEFAULT_KEY
        agent_segment = str(agent_id) if agent_id is not None else "_anonymous"
        session_segment = session_id if session_id is not None else "_no_session"
        return f"{agent_segment}::{session_segment}"

    def get_or_create(self, key: str) -> ContractEnforcer:
        """
        Return the enforcer for ``key``, creating it lazily if absent.
        """
        with self._lock:
            enforcer = self._enforcers.get(key)
            if enforcer is not None:
                self._enforcers.move_to_end(key)
                return enforcer
            enforcer = ContractEnforcer(contracts=self._contracts)
            self._enforcers[key] = enforcer
            self._prime_state[key] = _ReplayState(primed=False, primed_at_count=0)
            while len(self._enforcers) > self._capacity:
                evicted_key, _ = self._enforcers.popitem(last=False)
                self._prime_state.pop(evicted_key, None)
            return enforcer

    def is_primed(self, key: str) -> bool:
        with self._lock:
            state = self._prime_state.get(key)
            return state is not None and state.primed

    def mark_primed(self, key: str, *, after_count: int) -> None:
        with self._lock:
            self._prime_state[key] = _ReplayState(
                primed=True, primed_at_count=after_count
            )

    def forget(self, key: str) -> bool:
        """Drop the enforcer for ``key``. Returns True if a key existed."""
        with self._lock:
            if key in self._enforcers:
                del self._enforcers[key]
                self._prime_state.pop(key, None)
                return True
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._enforcers)


# ----------------------------------------------------------------------
# Ledger → ProposedEvent translation (Thread 1.5)
# ----------------------------------------------------------------------


def _proposed_event_from_ledger_entry(
    entry: ActionLedgerEntry,
) -> ProposedEvent:
    """
    Translate one ``ActionLedgerEntry`` into a ``ProposedEvent`` suitable
    for replay into the contract enforcer's ``recent_window``.

    Field crosswalk
    ---------------
    ledger.action_type      → event_kind = "guardrail.<action_type>"
    ledger.agent_id (UUID)  → actor_entity_id (string form)
    ledger.recipient        → target_entity_id
    ledger.session_id       → session_id
    ledger.recorded_at      → proposed_at
    ledger.{many fields}    → payload

    Lossy fields
    ------------
    ``content`` is intentionally absent from the ledger (only
    ``content_sha256`` is preserved by design). Contracts whose past-event
    atoms read ``field:content`` will see the hash only.
    """
    payload: dict[str, object] = {
        "action_type": entry.action_type,
        "channel": entry.channel,
        "environment": entry.environment,
        "verdict": entry.verdict,
        "final_score": entry.final_score,
        "confidence": entry.confidence,
        "content_sha256": entry.content_sha256,
        "policy_version": entry.policy_version,
        "evidence_hash": entry.evidence_hash,
    }
    if entry.recipient is not None:
        payload["recipient"] = entry.recipient
    if entry.session_id is not None:
        payload["session_id"] = entry.session_id
    if entry.capability_violations:
        payload["capability_violations"] = list(entry.capability_violations)
    if entry.asi_short_codes:
        payload["asi_short_codes"] = list(entry.asi_short_codes)
    if entry.tools:
        payload["tools"] = list(entry.tools)
    if entry.mcp_server_ids:
        payload["mcp_server_ids"] = list(entry.mcp_server_ids)

    return ProposedEvent(
        event_kind=f"{_DEFAULT_EVENT_KIND_PREFIX}{entry.action_type}",
        actor_entity_id=str(entry.agent_id),
        target_entity_id=entry.recipient,
        payload=payload,
        proposed_at=entry.recorded_at,
        session_id=entry.session_id,
        upstream_event_ids=(),
    )


def _ledger_window_for(
    *,
    action_ledger,  # InMemoryActionLedger | PostgresActionLedger
    agent_id: UUID,
    session_id: str | None,
    limit: int,
) -> tuple[ProposedEvent, ...]:
    """
    Pull the most recent ledger entries for ``agent_id`` and translate
    them into a chronological ``ProposedEvent`` window.

    When ``session_id`` is set, the window is filtered to entries from
    that session — matching the ABC paper's session-scoped semantics.
    """
    if not hasattr(action_ledger, "list_for_agent"):
        return ()
    try:
        raw_entries = action_ledger.list_for_agent(
            agent_id,
            limit=limit * 4 if session_id is not None else limit,
        )
    except Exception:
        return ()

    if not raw_entries:
        return ()

    if session_id is not None:
        filtered = tuple(
            e for e in raw_entries if e.session_id == session_id
        )
    else:
        filtered = tuple(raw_entries)

    if not filtered:
        return ()

    window_entries = filtered[-limit:]
    return tuple(
        _proposed_event_from_ledger_entry(e) for e in window_entries
    )


# ----------------------------------------------------------------------
# Priming: seed enforcer's _soft_pending from history
# ----------------------------------------------------------------------


def _prime_enforcer_with_history(
    *,
    enforcer: ContractEnforcer,
    history: tuple[ProposedEvent, ...],
    agent_key: str,
    state: EcosystemState,
) -> None:
    """
    Replay historical events through the enforcer so its
    ``_soft_pending`` recovery counter is correctly seeded before the
    live request runs.

    Each historical event is fed through ``check_pre`` in chronological
    order. Violations emitted during priming are NOT surfaced to the
    caller — they're already in the audit ledger from when those events
    were originally evaluated, and re-surfacing them on a downstream
    request would double-count.

    To suppress surfacing during priming we snapshot the enforcer's
    ``violations`` list before priming and restore it afterwards,
    keeping the new ``_soft_pending`` state but discarding the priming
    violations.
    """
    if not history:
        return

    pre_violations = list(enforcer.violations)

    for past_event in history:
        try:
            enforcer.check_pre(
                agent_id=agent_key,
                proposed_event=past_event,
                current_state=state,
                recent_window=(),
            )
        except Exception:
            continue

    # Restore the violations list — but KEEP the _soft_pending state,
    # KEEP the step_index advance, KEEP the compliance score history.
    # This is the one place the bridge touches enforcer internals;
    # documenting it loudly here. The alternative (introducing a public
    # ``replay`` method on ContractEnforcer) would require modifying
    # tex.contracts module internals, which Thread 1 forbids.
    enforcer._violations[:] = pre_violations


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------


def evaluate_contracts_for_request(
    *,
    enforcer: ContractEnforcer | None = None,
    registry: SessionEnforcerRegistry | None = None,
    request: EvaluationRequest,
    action_ledger=None,
    replay_window: int = _DEFAULT_REPLAY_WINDOW,
) -> ContractEvaluationOutcome:
    """
    Run the behavioral-contract enforcer against one evaluation request.

    Two calling modes
    -----------------
    1. **Stateless** — pass ``enforcer`` (and leave ``registry`` None).
       The provided enforcer is used directly. This is the pre-Thread-1.5
       path: one global enforcer for all requests, no session isolation,
       no ledger replay. Kept for backwards compatibility.

    2. **Session-scoped** — pass ``registry`` (and leave ``enforcer``
       None). The bridge picks the per-session enforcer keyed by
       ``(request.agent_id, request.session_id)`` and, if an
       ``action_ledger`` is supplied and the session has not yet been
       primed, replays the agent's recent history into the enforcer
       before checking the live event. This is the ABC §3.3
       (p, δ, k)-satisfaction-correct path.

    Returns ``NEUTRAL_OUTCOME`` when neither is supplied.

    Fail-safe semantics: any unexpected exception inside the enforcer is
    re-raised; the PDP composes the error path.
    """
    if enforcer is None and registry is None:
        return NEUTRAL_OUTCOME

    start = time.perf_counter()

    proposed_event = _build_proposed_event(request)
    state = _build_neutral_state(request)

    agent_key = (
        str(request.agent_id) if request.agent_id is not None else "_anonymous"
    )

    # Resolve the active enforcer + session bookkeeping.
    session_key: str | None = None
    replayed_window_size = 0

    if registry is not None:
        session_key = SessionEnforcerRegistry.session_key_for(
            agent_id=request.agent_id,
            session_id=request.session_id,
        )
        active_enforcer = registry.get_or_create(session_key)

        # First request in this session — replay the ledger to seed
        # the enforcer's ``_soft_pending`` recovery state.
        if (
            action_ledger is not None
            and request.agent_id is not None
            and not registry.is_primed(session_key)
        ):
            history = _ledger_window_for(
                action_ledger=action_ledger,
                agent_id=request.agent_id,
                session_id=request.session_id,
                limit=replay_window,
            )
            if history:
                _prime_enforcer_with_history(
                    enforcer=active_enforcer,
                    history=history,
                    agent_key=agent_key,
                    state=state,
                )
                replayed_window_size = len(history)
            registry.mark_primed(session_key, after_count=replayed_window_size)
    else:
        assert enforcer is not None
        active_enforcer = enforcer

    # Build a small ``recent_window`` for atom resolvers that want it.
    window_for_check: tuple[ProposedEvent, ...] = ()
    if action_ledger is not None and request.agent_id is not None:
        window_for_check = _ledger_window_for(
            action_ledger=action_ledger,
            agent_id=request.agent_id,
            session_id=request.session_id,
            limit=replay_window,
        )

    pre_count = len(active_enforcer.violations)
    step_index_before = active_enforcer.step_index

    try:
        active_enforcer.check_pre(
            agent_id=agent_key,
            proposed_event=proposed_event,
            current_state=state,
            recent_window=window_for_check,
        )
    except Exception:
        raise

    new_violations = active_enforcer.violations[pre_count:]

    findings: list[Finding] = []
    hard_seen = False
    soft_seen = False

    for violation in new_violations:
        is_soft = violation.violated_clause in _SOFT_CLAUSE_NAMES
        if is_soft:
            soft_seen = True
            severity: Severity = Severity.WARNING
        else:
            hard_seen = True
            severity = Severity.CRITICAL

        message_parts = [
            f"contract={violation.contract_id!r}",
            f"clause={violation.violated_clause}",
            f"step={violation.step_index}",
            f"ltl={violation.clause_ltl!r}",
        ]
        if violation.compliance_gap > 0:
            message_parts.append(
                f"compliance_gap={violation.compliance_gap:.3f}"
            )

        metadata: dict[str, str | int | float | bool] = {
            "contract_id": violation.contract_id,
            "violated_clause": violation.violated_clause,
            "clause_ltl": violation.clause_ltl,
            "step_index": violation.step_index,
            "compliance_gap": violation.compliance_gap,
            "severity_class": violation.severity,
            "is_soft": is_soft,
        }
        if session_key is not None:
            metadata["session_key"] = session_key
        if replayed_window_size > 0:
            metadata["replayed_window_size"] = replayed_window_size
        if violation.recovery_deadline_step is not None:
            metadata["recovery_deadline_step"] = violation.recovery_deadline_step

        findings.append(
            Finding(
                source=CONTRACT_FINDING_SOURCE,
                rule_name=f"contract:{violation.contract_id}:{violation.violated_clause}",
                severity=severity,
                message=" ".join(message_parts),
                metadata=metadata,
            )
        )

    contracts_ms = round((time.perf_counter() - start) * 1000.0, 2)

    forbid_reason: str | None = None
    soft_flags: tuple[str, ...] = ()

    if hard_seen:
        forbid_reason = HARD_VIOLATION_FORBID_REASON
    if soft_seen and not hard_seen:
        soft_flags = (SOFT_VIOLATION_UNCERTAINTY_FLAG,)

    return ContractEvaluationOutcome(
        has_hard_violation=hard_seen,
        has_soft_violation=soft_seen and not hard_seen,
        findings=tuple(findings),
        forbid_reason=forbid_reason,
        soft_uncertainty_flags=soft_flags,
        contracts_ms=contracts_ms,
        raw_violations=tuple(new_violations),
        session_key=session_key,
        replayed_window_size=replayed_window_size,
        step_index_at_check=step_index_before + 1,
    )


def _build_proposed_event(request: EvaluationRequest) -> ProposedEvent:
    """
    Synthesise the ``ProposedEvent`` that the enforcer's atoms expect.
    """
    metadata = request.metadata or {}

    event_kind_override = metadata.get("contract_event_kind")
    if isinstance(event_kind_override, str) and event_kind_override.strip():
        event_kind = event_kind_override.strip()
    else:
        event_kind = f"{_DEFAULT_EVENT_KIND_PREFIX}{request.action_type}"

    actor = (
        str(request.agent_id)
        if request.agent_id is not None
        else "_anonymous"
    )

    payload: dict[str, object] = {
        "action_type": request.action_type,
        "content": request.content,
        "channel": request.channel,
        "environment": request.environment,
        "request_id": str(request.request_id),
    }
    if request.recipient is not None:
        payload["recipient"] = request.recipient
    if request.session_id is not None:
        payload["session_id"] = request.session_id
    if metadata:
        payload["metadata"] = dict(metadata)

    return ProposedEvent(
        event_kind=event_kind,
        actor_entity_id=actor,
        target_entity_id=request.recipient,
        payload=payload,
        proposed_at=request.requested_at,
        session_id=request.session_id,
        upstream_event_ids=(),
    )


def _build_neutral_state(request: EvaluationRequest) -> EcosystemState:
    """
    Build a minimal ``EcosystemState`` snapshot.
    """
    return EcosystemState(
        snapshot_at=request.requested_at,
        state_hash=_NEUTRAL_STATE_HASH,
        active_agent_ids=(),
        active_tool_ids=(),
        active_capability_ids=(),
        active_governance_graph_id="pdp-neutral",
        aggregate_drift_signals={},
        sliding_window_compromise_ratio=0.0,
    )
