"""Deterministic read-tools over the sealed ``app.state`` stores (Session 1).

Each tool implements the :class:`~tex.presence.contract.ReadTool` protocol:
``name`` + ``__call__(request, *, tenant, **kwargs) -> (value, tuple[EvidenceRef])``.
The refs are the rows the value is computed from, so the gate (Session 2) can
re-verify by iterating them. There is **no inference** here and **no model** —
just reads, filters, counts, and digests.

Honest edges, baked in so nothing silently overclaims:

* **Fleet-wide aggregates.** ``decision_store``, ``action_ledger`` and the
  evidence chain carry *no tenant column* (see ``Decision`` / ``ActionLedgerEntry``
  / ``EvidenceRecord``). When a ``tenant`` is supplied, those tools cannot honour
  it; every result therefore states ``tenant_scope="fleet"`` and
  ``tenant_filter_applied=False``. Identity, discovery and monitoring *do* carry a
  tenant and are filtered in-code.
* **REVOKED agents are included.** ``agent_registry.list_all()`` returns REVOKED
  identities. ``identity.list_agents`` keeps them by default and reports
  ``status_counts`` + ``includes_revoked`` so the caller sees them rather than a
  silently-pruned roster. A ``status`` filter is offered to exclude them.
* **No per-request chain replay.** ``discovery_ledger.verify_chain()`` is O(n);
  the default discovery reads use ``latest()`` (O(1)) for the head hash. The full
  replay is exposed only as the explicit, opt-in ``discovery.verify_chain`` tool,
  which says ``cost="O(n)"`` in its result.
* **Bounded, row-backed aggregates.** Counts are defined over an explicit
  ``window`` of recent rows (default 200, hard-clamped to 500) and the refs are
  exactly the rows counted — no unbounded "count all of history" that can't be
  re-derived from the returned refs. The window is part of the answer, never a
  silent cap.
* **Missing/optional stores degrade, never crash** — a result with
  ``available=False`` and a reason, refs ``()``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable
from uuid import UUID

from tex.presence.brain.evidence import chained_ref, digest_ref
from tex.presence.contract import EvidenceRef

__all__ = [
    "BrainReadTool",
    "build_read_tools",
    "build_read_tool_registry",
    "DIMENSIONS",
]

DIMENSIONS = (
    "execution",
    "human_decision",
    "evidence",
    "identity",
    "monitoring",
    "discovery",
)

_DEFAULT_RECENT = 20
_DEFAULT_WINDOW = 200
_MAX_ROWS = 500  # hard bound so refs (and the prompt the brain builds) stay finite


# ─────────────────────────────────────────────────────────────────────────────
# Tool wrapper — a self-contained callable bound to one app.state.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class BrainReadTool:
    """One deterministic read-tool. Conforms to ``contract.ReadTool``."""

    name: str
    description: str
    _impl: Callable[..., tuple[Any, tuple[EvidenceRef, ...]]]
    _state: Any

    def __call__(
        self, request: Any = None, *, tenant: str | None = None, **kwargs: Any
    ) -> tuple[Any, tuple[EvidenceRef, ...]]:
        return self._impl(self._state, request, tenant=tenant, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# Small helpers.
# ─────────────────────────────────────────────────────────────────────────────
def _store(state: Any, name: str) -> Any:
    """Resolve a store off app.state (or a plain mapping), ``None`` if absent."""
    if state is None:
        return None
    if isinstance(state, Mapping):
        return state.get(name)
    return getattr(state, name, None)


def _arg(request: Any, kwargs: Mapping[str, Any], name: str, default: Any = None) -> Any:
    val = kwargs.get(name)
    if val is not None:
        return val
    if isinstance(request, Mapping) and request.get(name) is not None:
        return request.get(name)
    return default


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _as_uuid(value: Any) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            return None
    return None


def _verdict_str(verdict: Any) -> str:
    """Normalise a Verdict enum / string to an upper-case token."""
    value = getattr(verdict, "value", verdict)
    return str(value).upper()


def _unavailable(store_name: str) -> tuple[dict[str, Any], tuple[EvidenceRef, ...]]:
    return (
        {"available": False, "reason": f"{store_name} is not configured on app.state"},
        (),
    )


def _resolve_limit(request: Any, kwargs: Mapping[str, Any], default: int) -> tuple[int, bool]:
    requested = _arg(request, kwargs, "limit", default)
    clamped = _clamp_int(requested, 1, _MAX_ROWS, default)
    return clamped, (isinstance(requested, int) and requested > _MAX_ROWS)


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTION — action_ledger (no tenant column → agent-scoped or fleet).
# ─────────────────────────────────────────────────────────────────────────────
def _exec_recent_actions(state, request, *, tenant, **kwargs):
    ledger = _store(state, "action_ledger")
    if ledger is None:
        return _unavailable("action_ledger")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    agent_id = _as_uuid(_arg(request, kwargs, "agent_id"))
    if agent_id is not None:
        rows = ledger.list_for_agent(agent_id, limit=limit)
        scope = f"agent:{agent_id}"
    else:
        rows = ledger.list_all(limit=limit)
        scope = "fleet"
    refs = tuple(
        digest_ref(record_id=r.entry_id, store="action_ledger", payload=r)
        for r in rows
    )
    value = {
        "actions": [r.model_dump(mode="json") for r in rows],
        "returned": len(rows),
        "scope": scope,
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
        "note": "action_ledger has no tenant column; scoped by agent_id only",
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _exec_action_count(state, request, *, tenant, **kwargs):
    ledger = _store(state, "action_ledger")
    if ledger is None:
        return _unavailable("action_ledger")
    agent_id = _as_uuid(_arg(request, kwargs, "agent_id"))
    verdict = _arg(request, kwargs, "verdict")
    window = _clamp_int(_arg(request, kwargs, "window", _DEFAULT_WINDOW), 1, _MAX_ROWS, _DEFAULT_WINDOW)
    if agent_id is not None:
        rows = ledger.list_for_agent(agent_id, limit=window)
        scope = f"agent:{agent_id}"
    else:
        rows = ledger.list_all(limit=window)
        scope = "fleet"
    matched = [r for r in rows if verdict is None or _verdict_str(r.verdict) == _verdict_str(verdict)]
    refs = tuple(
        digest_ref(record_id=r.entry_id, store="action_ledger", payload=r, field="verdict")
        for r in matched
    )
    value = {
        "count": len(matched),
        "verdict": verdict,
        "window": window,
        "considered": len(rows),
        "scope": scope,
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# HUMAN_DECISION — decision_store (no tenant column → fleet-wide).
# ─────────────────────────────────────────────────────────────────────────────
def _decision_get(state, request, *, tenant, **kwargs):
    store = _store(state, "decision_store")
    if store is None:
        return _unavailable("decision_store")
    decision_id = _as_uuid(_arg(request, kwargs, "decision_id"))
    if decision_id is None:
        return ({"found": False, "reason": "decision_id missing or not a UUID"}, ())
    row = store.get(decision_id)
    if row is None:
        return ({"found": False, "decision_id": str(decision_id)}, ())
    ref = digest_ref(record_id=row.decision_id, store="decision_store", payload=row)
    return ({"found": True, "decision": row.model_dump(mode="json")}, (ref,))


def _decision_recent(state, request, *, tenant, **kwargs):
    store = _store(state, "decision_store")
    if store is None:
        return _unavailable("decision_store")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    verdict = _arg(request, kwargs, "verdict")
    rows = store.list_recent(limit=limit)
    if verdict is not None:
        rows = tuple(r for r in rows if _verdict_str(r.verdict) == _verdict_str(verdict))
    refs = tuple(
        digest_ref(record_id=r.decision_id, store="decision_store", payload=r)
        for r in rows
    )
    value = {
        "decisions": [r.model_dump(mode="json") for r in rows],
        "returned": len(rows),
        "verdict": verdict,
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
        "note": "decision_store has no tenant column; result is fleet-wide",
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _decision_verdict_count(state, request, *, tenant, **kwargs):
    store = _store(state, "decision_store")
    if store is None:
        return _unavailable("decision_store")
    verdict = _arg(request, kwargs, "verdict")
    window = _clamp_int(_arg(request, kwargs, "window", _DEFAULT_WINDOW), 1, _MAX_ROWS, _DEFAULT_WINDOW)
    recent = store.list_recent(limit=window)
    matched = [r for r in recent if verdict is None or _verdict_str(r.verdict) == _verdict_str(verdict)]
    refs = tuple(
        digest_ref(record_id=r.decision_id, store="decision_store", payload=r, field="verdict")
        for r in matched
    )
    value = {
        "count": len(matched),
        "verdict": verdict,
        "window": window,
        "considered": len(recent),
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
        "note": "decision_store has no tenant column; count is fleet-wide",
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE — evidence_recorder (append-only hash chain → chain-anchored refs).
# ─────────────────────────────────────────────────────────────────────────────
def _evidence_chain_head(state, request, *, tenant, **kwargs):
    recorder = _store(state, "evidence_recorder")
    if recorder is None:
        return _unavailable("evidence_recorder")
    head = recorder.last_record()
    if head is None:
        return ({"present": False, "reason": "evidence chain is empty"}, ())
    ref = chained_ref(
        record_id=head.evidence_id,
        record_hash=head.record_hash,
        store="evidence_jsonl",
        previous_hash=head.previous_hash,
        fallback_payload=head,
    )
    return ({"present": True, "head": head.model_dump(mode="json")}, (ref,))


def _evidence_recent(state, request, *, tenant, **kwargs):
    recorder = _store(state, "evidence_recorder")
    if recorder is None:
        return _unavailable("evidence_recorder")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    record_type = _arg(request, kwargs, "record_type")
    # read_all() walks the whole JSONL chain — honest O(n) read; we tail it.
    rows = recorder.read_all()
    if record_type is not None:
        rows = tuple(r for r in rows if r.record_type == record_type)
    tail = rows[-limit:]
    refs = tuple(
        chained_ref(
            record_id=r.evidence_id,
            record_hash=r.record_hash,
            store="evidence_jsonl",
            previous_hash=r.previous_hash,
            fallback_payload=r,
        )
        for r in tail
    )
    value = {
        "records": [r.model_dump(mode="json") for r in tail],
        "returned": len(tail),
        "record_type": record_type,
        "read_cost": "O(n) over the evidence JSONL chain",
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# IDENTITY — agent_registry (has tenant_id; list_all INCLUDES REVOKED).
# ─────────────────────────────────────────────────────────────────────────────
def _identity_get_agent(state, request, *, tenant, **kwargs):
    registry = _store(state, "agent_registry")
    if registry is None:
        return _unavailable("agent_registry")
    agent_id = _as_uuid(_arg(request, kwargs, "agent_id"))
    if agent_id is None:
        return ({"found": False, "reason": "agent_id missing or not a UUID"}, ())
    agent = registry.get(agent_id)
    if agent is None:
        return ({"found": False, "agent_id": str(agent_id)}, ())
    if tenant is not None and agent.tenant_id != tenant:
        return (
            {
                "found": False,
                "agent_id": str(agent_id),
                "reason": f"agent belongs to tenant {agent.tenant_id!r}, not {tenant!r}",
            },
            (),
        )
    ref = digest_ref(record_id=agent.agent_id, store="agent_registry", payload=agent)
    return (
        {
            "found": True,
            "agent": agent.model_dump(mode="json"),
            "lifecycle_status": str(agent.lifecycle_status),
            "revoked": str(agent.lifecycle_status) == "REVOKED",
        },
        (ref,),
    )


def _identity_list_agents(state, request, *, tenant, **kwargs):
    registry = _store(state, "agent_registry")
    if registry is None:
        return _unavailable("agent_registry")
    status = _arg(request, kwargs, "status")
    include_revoked = bool(_arg(request, kwargs, "include_revoked", True))
    limit, clamped = _resolve_limit(request, kwargs, _MAX_ROWS)

    rows = list(registry.list_all())  # NB: includes REVOKED identities
    status_counts: dict[str, int] = {}
    for a in rows:
        key = str(a.lifecycle_status)
        status_counts[key] = status_counts.get(key, 0) + 1

    if tenant is not None:
        rows = [a for a in rows if a.tenant_id == tenant]
    if status is not None:
        rows = [a for a in rows if str(a.lifecycle_status) == str(status).upper()]
    elif not include_revoked:
        rows = [a for a in rows if str(a.lifecycle_status) != "REVOKED"]

    rows = rows[:limit]
    refs = tuple(
        digest_ref(record_id=a.agent_id, store="agent_registry", payload=a)
        for a in rows
    )
    value = {
        "agents": [a.model_dump(mode="json") for a in rows],
        "returned": len(rows),
        "status_filter": status,
        "includes_revoked": status is None and include_revoked,
        "status_counts": status_counts,
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": tenant is not None,
        "note": "agent_registry.list_all() includes REVOKED agents",
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _identity_resolve_agent(state, request, *, tenant, **kwargs):
    """Resolve an agent by NAME to its record (case-insensitive exact, then unique
    substring). An ambiguous name (>1 match) returns found=False with match_count so the
    caller abstains rather than guessing — never picks one arbitrarily."""
    registry = _store(state, "agent_registry")
    if registry is None:
        return _unavailable("agent_registry")
    name = _arg(request, kwargs, "name")
    if not isinstance(name, str) or not name.strip():
        return ({"found": False, "match_count": 0, "reason": "name missing or blank"}, ())
    rows = list(registry.list_all())
    if tenant is not None:
        rows = [a for a in rows if a.tenant_id == tenant]
    want = name.strip().casefold()
    matches = [a for a in rows if a.name.casefold() == want]
    if not matches:
        matches = [a for a in rows if want in a.name.casefold()]
    if len(matches) == 1:
        agent = matches[0]
        ref = digest_ref(record_id=agent.agent_id, store="agent_registry", payload=agent)
        return (
            {
                "found": True,
                "match_count": 1,
                "agent": agent.model_dump(mode="json"),
                "tenant_scope": tenant or "all",
                "tenant_filter_applied": tenant is not None,
            },
            (ref,),
        )
    return (
        {
            "found": False,
            "match_count": len(matches),
            "reason": "ambiguous name (more than one match)" if matches else "no agent with that name",
            "tenant_scope": tenant or "all",
            "tenant_filter_applied": tenant is not None,
        },
        (),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY — discovery_ledger (append-only chain; tenant on the candidate).
# verify_chain() is O(n); default reads use latest() (O(1)).
# ─────────────────────────────────────────────────────────────────────────────
def _discovery_chain_head(state, request, *, tenant, **kwargs):
    ledger = _store(state, "discovery_ledger")
    if ledger is None:
        return _unavailable("discovery_ledger")
    head = ledger.latest()  # O(1) — NOT verify_chain()
    if head is None:
        return ({"present": False, "reason": "discovery ledger is empty"}, ())
    ref = chained_ref(
        record_id=head.sequence,
        record_hash=head.record_hash,
        store="discovery_ledger",
        previous_hash=head.previous_hash,
        fallback_payload=head,
    )
    return (
        {
            "present": True,
            "sequence": head.sequence,
            "head": head.model_dump(mode="json"),
            "note": "head read via latest() (O(1)); chain not replayed",
        },
        (ref,),
    )


def _discovery_recent(state, request, *, tenant, **kwargs):
    ledger = _store(state, "discovery_ledger")
    if ledger is None:
        return _unavailable("discovery_ledger")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    rows = list(ledger.list_all())
    if tenant is not None:
        rows = [e for e in rows if e.candidate.tenant_id == tenant]
    tail = rows[-limit:]
    refs = tuple(
        chained_ref(
            record_id=e.sequence,
            record_hash=e.record_hash,
            store="discovery_ledger",
            previous_hash=e.previous_hash,
            fallback_payload=e,
        )
        for e in tail
    )
    value = {
        "entries": [e.model_dump(mode="json") for e in tail],
        "returned": len(tail),
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": tenant is not None,
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _discovery_entry_count(state, request, *, tenant, **kwargs):
    ledger = _store(state, "discovery_ledger")
    if ledger is None:
        return _unavailable("discovery_ledger")
    window = _clamp_int(_arg(request, kwargs, "window", _DEFAULT_WINDOW), 1, _MAX_ROWS, _DEFAULT_WINDOW)
    rows = list(ledger.list_all())[-window:]
    if tenant is not None:
        rows = [e for e in rows if e.candidate.tenant_id == tenant]
    refs = tuple(
        chained_ref(
            record_id=e.sequence,
            record_hash=e.record_hash,
            store="discovery_ledger",
            previous_hash=e.previous_hash,
            fallback_payload=e,
        )
        for e in rows
    )
    value = {
        "count": len(rows),
        "window": window,
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": tenant is not None,
    }
    return value, refs


def _discovery_verify_chain(state, request, *, tenant, **kwargs):
    """EXPLICIT, opt-in integrity audit. O(n) — never call this per request."""
    ledger = _store(state, "discovery_ledger")
    if ledger is None:
        return _unavailable("discovery_ledger")
    intact = bool(ledger.verify_chain())
    head = ledger.latest()
    refs: tuple[EvidenceRef, ...] = ()
    if head is not None:
        refs = (
            chained_ref(
                record_id=head.sequence,
                record_hash=head.record_hash,
                store="discovery_ledger",
                previous_hash=head.previous_hash,
                fallback_payload=head,
            ),
        )
    value = {
        "chain_intact": intact,
        "entries": len(ledger.list_all()),
        "cost": "O(n)",
        "note": "explicit integrity audit — not run on the default read path",
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# MONITORING — drift_events / scan_runs / governance_snapshots (optional stores).
# ─────────────────────────────────────────────────────────────────────────────
def _monitoring_recent_drift(state, request, *, tenant, **kwargs):
    store = _store(state, "drift_event_store")
    if store is None:
        return _unavailable("drift_event_store")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    if tenant is not None:
        events = store.list_for_tenant(tenant, limit=limit)
        applied = True
    else:
        events = store.list_recent(limit=limit)
        applied = False
    dicts = [e.to_dict() for e in events]
    refs = tuple(
        digest_ref(record_id=d.get("event_id"), store="drift_event_store", payload=d)
        for d in dicts
    )
    value = {
        "events": dicts,
        "returned": len(dicts),
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": applied,
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _monitoring_recent_scans(state, request, *, tenant, **kwargs):
    store = _store(state, "scan_run_store")
    if store is None:
        return _unavailable("scan_run_store")
    limit, clamped = _resolve_limit(request, kwargs, _DEFAULT_RECENT)
    runs = store.list_recent(tenant_id=tenant, limit=limit)
    dicts = [r.to_dict() for r in runs]
    refs = tuple(
        digest_ref(
            record_id=d.get("run_id"),
            store="scan_run_store",
            payload=d,
            field="registry_state_hash" if d.get("registry_state_hash") else None,
        )
        for d in dicts
    )
    value = {
        "scans": dicts,
        "returned": len(dicts),
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": tenant is not None,
        "limit_clamped_to": _MAX_ROWS if clamped else None,
    }
    return value, refs


def _monitoring_latest_snapshot(state, request, *, tenant, **kwargs):
    store = _store(state, "governance_snapshot_store")
    if store is None:
        return _unavailable("governance_snapshot_store")
    recent = store.list_recent(limit=1)
    if not recent:
        return ({"present": False, "reason": "no governance snapshots captured"}, ())
    snap = recent[0]
    ref = chained_ref(
        record_id=snap.get("snapshot_id"),
        record_hash=snap.get("snapshot_hash", ""),
        store="governance_snapshot_store",
        previous_hash=snap.get("previous_snapshot_hash"),
        fallback_payload=snap,
    )
    return ({"present": True, "snapshot": snap}, (ref,))


def _monitoring_drift_count(state, request, *, tenant, **kwargs):
    store = _store(state, "drift_event_store")
    if store is None:
        return _unavailable("drift_event_store")
    window = _clamp_int(_arg(request, kwargs, "window", _DEFAULT_WINDOW), 1, _MAX_ROWS, _DEFAULT_WINDOW)
    if tenant is not None:
        events = store.list_for_tenant(tenant, limit=window)
        applied = True
    else:
        events = store.list_recent(limit=window)
        applied = False
    severity = _arg(request, kwargs, "severity")
    dicts = [e.to_dict() for e in events]
    if severity is not None:
        dicts = [d for d in dicts if str(d.get("severity", "")).upper() == str(severity).upper()]
    refs = tuple(
        digest_ref(record_id=d.get("event_id"), store="drift_event_store", payload=d)
        for d in dicts
    )
    value = {
        "count": len(dicts),
        "severity": severity,
        "window": window,
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": applied,
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATES — single-store, windowed, row-backed distributions.
# ─────────────────────────────────────────────────────────────────────────────
def _aggregate_governance_posture(state, request, *, tenant, **kwargs):
    registry = _store(state, "agent_registry")
    if registry is None:
        return _unavailable("agent_registry")
    rows = list(registry.list_all())  # includes REVOKED
    if tenant is not None:
        rows = [a for a in rows if a.tenant_id == tenant]
    rows = rows[:_MAX_ROWS]
    by_status: dict[str, int] = {}
    by_trust: dict[str, int] = {}
    for a in rows:
        by_status[str(a.lifecycle_status)] = by_status.get(str(a.lifecycle_status), 0) + 1
        by_trust[str(a.trust_tier)] = by_trust.get(str(a.trust_tier), 0) + 1
    refs = tuple(
        digest_ref(record_id=a.agent_id, store="agent_registry", payload=a, field="lifecycle_status")
        for a in rows
    )
    value = {
        "total": len(rows),
        "by_lifecycle_status": by_status,
        "by_trust_tier": by_trust,
        "includes_revoked": True,
        "tenant_scope": tenant or "all",
        "tenant_filter_applied": tenant is not None,
        "note": "counts include REVOKED agents (agent_registry.list_all)",
    }
    return value, refs


def _aggregate_recent_verdicts(state, request, *, tenant, **kwargs):
    store = _store(state, "decision_store")
    if store is None:
        return _unavailable("decision_store")
    window = _clamp_int(_arg(request, kwargs, "window", _DEFAULT_WINDOW), 1, _MAX_ROWS, _DEFAULT_WINDOW)
    rows = store.list_recent(limit=window)
    by_verdict: dict[str, int] = {}
    for r in rows:
        by_verdict[_verdict_str(r.verdict)] = by_verdict.get(_verdict_str(r.verdict), 0) + 1
    refs = tuple(
        digest_ref(record_id=r.decision_id, store="decision_store", payload=r, field="verdict")
        for r in rows
    )
    value = {
        "by_verdict": by_verdict,
        "window": window,
        "considered": len(rows),
        "tenant_scope": "fleet",
        "tenant_filter_applied": False,
        "note": "decision_store has no tenant column; distribution is fleet-wide",
    }
    return value, refs


# ─────────────────────────────────────────────────────────────────────────────
# Registry of (name, description, impl).
# ─────────────────────────────────────────────────────────────────────────────
_SPECS: tuple[tuple[str, str, Callable[..., Any]], ...] = (
    # execution
    ("execution.recent_actions", "Recent action-ledger entries (kwargs: agent_id, limit).", _exec_recent_actions),
    ("execution.action_count", "Count actions in a recent window (kwargs: agent_id, verdict, window).", _exec_action_count),
    # human_decision
    ("human_decision.get_decision", "Fetch one decision by id (kwargs: decision_id).", _decision_get),
    ("human_decision.recent_decisions", "Recent decisions (kwargs: verdict, limit). Fleet-wide.", _decision_recent),
    ("human_decision.verdict_count", "Count decisions of a verdict in a recent window. Fleet-wide.", _decision_verdict_count),
    # evidence
    ("evidence.chain_head", "The head of the signed evidence hash-chain.", _evidence_chain_head),
    ("evidence.recent_records", "Recent evidence records (kwargs: record_type, limit). O(n) read.", _evidence_recent),
    # identity
    ("identity.get_agent", "Fetch one agent identity by id (kwargs: agent_id).", _identity_get_agent),
    ("identity.list_agents", "List agents (kwargs: tenant, status, include_revoked). Includes REVOKED by default.", _identity_list_agents),
    ("identity.resolve_agent", "Resolve an agent by NAME to its record (kwargs: name). Use this to look up an agent the user named (e.g. 'billing-bot'); ambiguous names abstain.", _identity_resolve_agent),
    # discovery
    ("discovery.chain_head", "Latest discovery-ledger entry via latest() (O(1)).", _discovery_chain_head),
    ("discovery.recent_entries", "Recent discovery-ledger entries (kwargs: tenant, limit).", _discovery_recent),
    ("discovery.entry_count", "Count discovery entries in a recent window (kwargs: tenant, window).", _discovery_entry_count),
    ("discovery.verify_chain", "OPT-IN O(n) integrity replay of the discovery chain. Never per-request.", _discovery_verify_chain),
    # monitoring
    ("monitoring.recent_drift", "Recent drift events (kwargs: tenant, limit).", _monitoring_recent_drift),
    ("monitoring.recent_scans", "Recent scan runs (kwargs: tenant, limit).", _monitoring_recent_scans),
    ("monitoring.latest_snapshot", "Latest governance snapshot (chain-anchored).", _monitoring_latest_snapshot),
    ("monitoring.drift_count", "Count drift events in a recent window (kwargs: tenant, severity, window).", _monitoring_drift_count),
    # aggregates
    ("aggregates.governance_posture", "Agent lifecycle/trust distribution (kwargs: tenant). Includes REVOKED.", _aggregate_governance_posture),
    ("aggregates.recent_verdicts", "Verdict distribution over a recent decision window. Fleet-wide.", _aggregate_recent_verdicts),
)


def build_read_tools(state: Any) -> tuple[BrainReadTool, ...]:
    """Build every read-tool bound to one ``app.state`` (or mapping)."""
    return tuple(
        BrainReadTool(name=name, description=desc, _impl=impl, _state=state)
        for name, desc, impl in _SPECS
    )


def build_read_tool_registry(state: Any) -> dict[str, BrainReadTool]:
    """Name → tool mapping for direct lookup by the orchestrator / gate."""
    return {t.name: t for t in build_read_tools(state)}
