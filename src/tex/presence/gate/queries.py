"""The presence query registry — the only place a spoken aggregate/entity/event
is RECOMPUTED from sealed rows.

The model never counts. For every credible claim the gate makes, a deterministic
function in this file re-derives the value from the live stores
(``decision_store``, ``agent_registry``, ``action_ledger``, ``discovery_ledger``,
``connector_health_store``, ``scan_run_store``) and binds the rows it read as
:class:`EvidenceRef`s. The gate's verdict ``recomputed_value`` is THIS value —
not the draft's number (see ``gate.py`` and the threat model in the contract).

Each query also authors its OWN canonical spoken phrasing from the recomputed
value. That is what closes the "hostile draft" hole at the speech layer: the
voice speaks the gate's phrasing of the recomputed truth, never the brain's raw
span, so injected words in a draft cannot reach the user (``compose.py``).

DERIVED queries are different in kind: they are forward-looking / computed
estimates, so they carry a conformal ``correctness_floor`` and an honest
``coverage_mode`` (transductive ≈ approximate; calibrated needs
``TEX_CONFORMAL_CALIBRATION_PATH``) instead of byte-for-byte sealed evidence.
See :mod:`tex.presence.gate.conformal`.

Tenant scope — honest, not faked. Where a row carries a tenant
(``AgentIdentity.tenant_id``, ``ConnectorHealth``/``ScanRun`` keyed by tenant)
the recompute is scoped to the named tenant. But ``Decision`` and
``ActionLedgerEntry`` carry NO tenant field in this codebase, so the
``forbid/permit/abstain/action_total`` aggregates are GLOBAL over the store as it
is partitioned upstream. We do not pretend otherwise: making those per-tenant is
an upstream store change (a tenant column + a filtered ``find``), not something
this gate can conjure. Run the voice ``/v1/ask`` path single-tenant, or add the
tenant column, before treating those counts as tenant-isolated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from tex.domain.verdict import Verdict
from tex.presence.contract import ClaimKind, EvidenceRef
from tex.presence.gate import evidence as ev
from tex.presence.gate.conformal import derive_root_cause_region

__all__ = [
    "Recompute",
    "PresenceQuery",
    "QUERIES",
    "EVIDENCE_CAP",
]

# How many EvidenceRefs a count-style aggregate binds before it truncates and
# DISCLOSES the truncation in the reason. The recomputed value is always the
# true full count; the refs are an auditable witness sample when the set is big.
EVIDENCE_CAP = 64


@dataclass(frozen=True, slots=True)
class Recompute:
    """The deterministic result of recomputing one claim from rows."""

    grounded: bool
    """True iff the stores yielded a real basis for the claim. False ⇒ the gate
    abstains (no store, empty basis, missing target, …)."""

    value: Any = None
    """The recomputed value — the single source of truth for the spoken answer."""

    evidence: tuple[EvidenceRef, ...] = ()
    canonical_phrase: str = ""
    """The gate-authored spoken line for this value. Spoken in place of the
    draft's words for a supported claim (threat-model safe)."""

    correctness_floor: float | None = None
    coverage_mode: str | None = None
    governance_verdict: Verdict | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class PresenceQuery:
    """One recomputable quantity. ``key`` is the stable claim_id a brain SHOULD
    use; ``aliases`` are conservative lexical fallbacks for free-form spans.
    ``needs_target`` flags the parametric queries (a named agent)."""

    key: str
    kind: ClaimKind
    aliases: tuple[str, ...]
    recompute: Any  # Callable[[Any, str | None, UUID | None], Recompute]
    needs_target: bool = False

    def matches(self, *, claim_id: str, text_span: str, kind: ClaimKind) -> bool:
        if kind is not self.kind:
            return False
        cid = (claim_id or "").strip().lower()
        if cid == self.key or cid.startswith(self.key + ":"):
            return True
        span = (text_span or "").lower()
        return any(alias in span for alias in self.aliases)


# ───────────────────────────────────────────────────────── store access helper
def _store(state: Any, name: str) -> Any:
    """Fetch a store off the app state (or a test double passed directly).
    Returns None when absent — every recompute then abstains, fail-closed."""
    if state is None:
        return None
    return getattr(state, name, None)


def _plural(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


# ───────────────────────────────────────────────────────── AGGREGATE recomputes
def _count_decisions(verdict: Verdict, label: str):
    def _run(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
        store = _store(state, "decision_store")
        if store is None or not hasattr(store, "find"):
            return Recompute(False, reason="decision_store-unavailable")
        rows = tuple(store.find(verdict=verdict))
        n = len(rows)
        refs = tuple(ev.ref_for_decision(d) for d in rows[:EVIDENCE_CAP])
        truncated = n > EVIDENCE_CAP
        reason = f"sealed:{label}_count={n}" + (";witness-truncated" if truncated else "")
        # Decision rows carry NO tenant field (see module banner), so this count
        # is fleet-wide. Disclose that in the spoken phrasing — never let a global
        # count sound tenant-scoped (mirrors _count_actions' "across all agents").
        phrase = (
            f"There {_plural(n, 'is', 'are')} {n} {label} "
            f"{_plural(n, 'decision', 'decisions')} on record across all tenants."
        )
        return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase, reason=reason)

    return _run


def _count_agents(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    registry = _store(state, "agent_registry")
    if registry is None or not hasattr(registry, "list_all"):
        return Recompute(False, reason="agent_registry-unavailable")
    rows = tuple(registry.list_all())
    # AgentIdentity carries tenant_id, so we CAN honour per-tenant isolation here
    # (unlike the decision/action aggregates, whose rows have no tenant field —
    # see the module banner). When a tenant is named, count only its agents.
    if tenant:
        want = tenant.strip().casefold()
        rows = tuple(r for r in rows if str(getattr(r, "tenant_id", "")).strip().casefold() == want)
    n = len(rows)
    refs = tuple(ev.ref_for_agent(a) for a in rows[:EVIDENCE_CAP])
    phrase = (
        f"There {_plural(n, 'is', 'are')} {n} registered "
        f"{_plural(n, 'agent', 'agents')}."
    )
    reason = f"sealed:agent_count={n}" + (";witness-truncated" if n > EVIDENCE_CAP else "")
    return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase, reason=reason)


def _count_actions(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    ledger = _store(state, "action_ledger")
    if ledger is None or not hasattr(ledger, "total_count"):
        return Recompute(False, reason="action_ledger-unavailable")
    n = int(ledger.total_count())
    # Bind a bounded witness of the most-recent entries; the value is the
    # ledger's maintained total, disclosed as such.
    witness = ()
    if hasattr(ledger, "list_all"):
        try:
            witness = tuple(ledger.list_all(limit=EVIDENCE_CAP))
        except TypeError:
            witness = tuple(ledger.list_all())[:EVIDENCE_CAP]
    refs = tuple(ev.ref_for_action_entry(e) for e in witness)
    phrase = (
        f"{n} {_plural(n, 'action has', 'actions have')} been recorded across all agents."
    )
    reason = f"sealed:action_total={n};witness={len(refs)}-of-{n}"
    return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase, reason=reason)


def _count_offline_connectors(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    store = _store(state, "connector_health_store")
    if store is None:
        return Recompute(False, reason="connector_health_store-unavailable")
    if tenant and hasattr(store, "list_for_tenant"):
        rows = tuple(store.list_for_tenant(tenant))
    elif hasattr(store, "list_all"):
        rows = tuple(store.list_all())
    else:
        return Recompute(False, reason="connector_health_store-no-list")
    offline = tuple(r for r in rows if str(getattr(r, "status", "")).upper() == "OFFLINE")
    n = len(offline)
    refs = tuple(ev.ref_for_connector_health(r) for r in offline[:EVIDENCE_CAP])
    phrase = (
        f"{n} discovery {_plural(n, 'connector is', 'connectors are')} offline."
    )
    return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase,
                     reason=f"sealed:offline_connector_count={n}")


def _count_discovery_events(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    ledger = _store(state, "discovery_ledger")
    if ledger is None or not hasattr(ledger, "list_all"):
        return Recompute(False, reason="discovery_ledger-unavailable")
    rows = tuple(ledger.list_all())
    n = len(rows)
    # The latest entry carries the live chain anchor; bind a bounded recent tail.
    refs = tuple(ev.ref_for_discovery_entry(e) for e in rows[-EVIDENCE_CAP:])
    # discovery_ledger is not tenant-partitioned here, so disclose fleet scope.
    phrase = (
        f"{n} discovery {_plural(n, 'event has', 'events have')} been logged "
        f"across all tenants."
    )
    reason = f"sealed:discovery_event_count={n}" + (
        ";witness-truncated" if n > EVIDENCE_CAP else ""
    )
    return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase, reason=reason)


def _count_failed_scans(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    store = _store(state, "scan_run_store")
    if store is None or not hasattr(store, "list_recent"):
        return Recompute(False, reason="scan_run_store-unavailable")
    try:
        runs = tuple(store.list_recent(tenant_id=tenant, limit=EVIDENCE_CAP))
    except TypeError:
        runs = tuple(store.list_recent(limit=EVIDENCE_CAP))
    failed = tuple(r for r in runs if str(getattr(r, "status", "")).upper().endswith("FAILED"))
    n = len(failed)
    refs = tuple(ev.ref_for_scan_run(r) for r in failed)
    phrase = (
        f"{n} recent discovery {_plural(n, 'scan', 'scans')} "
        f"{_plural(n, 'has', 'have')} failed."
    )
    reason = f"sealed:failed_scan_count={n};window={len(runs)}"
    return Recompute(True, value=n, evidence=refs, canonical_phrase=phrase, reason=reason)


# ───────────────────────────────────────────────────────── ENTITY recompute
def _agent_status(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    if target is None:
        return Recompute(False, reason="agent_status-no-target")
    registry = _store(state, "agent_registry")
    if registry is None or not hasattr(registry, "get"):
        return Recompute(False, reason="agent_registry-unavailable")
    agent = registry.get(target)
    if agent is None:
        return Recompute(False, reason="agent-not-found")
    status = str(getattr(getattr(agent, "lifecycle_status", None), "value",
                         getattr(agent, "lifecycle_status", "UNKNOWN")))
    phrase = f"Agent {target} is {status}."
    return Recompute(
        True, value=status, evidence=(ev.ref_for_agent(agent),),
        canonical_phrase=phrase, reason=f"sealed:agent_status={status}",
    )


# ───────────────────────────────────────────────────────── EVENT recompute
def _discovery_present(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    ledger = _store(state, "discovery_ledger")
    if ledger is None or not hasattr(ledger, "list_all"):
        return Recompute(False, reason="discovery_ledger-unavailable")
    rows = tuple(ledger.list_all())
    if not rows:
        return Recompute(False, reason="no-discovery-event")
    latest = rows[-1]
    seq = getattr(latest, "sequence", len(rows) - 1)
    phrase = f"At least one discovery event is on record (latest sequence {seq})."
    return Recompute(
        True, value=int(seq), evidence=(ev.ref_for_discovery_entry(latest),),
        canonical_phrase=phrase, reason=f"sealed:latest_discovery_sequence={seq}",
    )


# ───────────────────────────────────────────────────────── DERIVED recompute
def _root_cause_region(state: Any, tenant: str | None, target: UUID | None) -> Recompute:
    """Conformal localization of the decisive step in a named agent's action
    trace. Forward-looking inference, so it carries a correctness floor + honest
    coverage mode rather than sealed evidence of a single fact."""
    if target is None:
        return Recompute(False, reason="root_cause-no-target")
    ledger = _store(state, "action_ledger")
    if ledger is None or not hasattr(ledger, "list_for_agent"):
        return Recompute(False, reason="action_ledger-unavailable")
    entries = tuple(ledger.list_for_agent(target, limit=200))
    region = derive_root_cause_region(entries)
    if region is None:
        return Recompute(False, reason="root_cause-insufficient-trace")
    value, refs, floor, mode = region
    n_in = value["set_size"]
    total = value["trace_length"]
    phrase = (
        f"The decisive step is within a region of {n_in} of {total} steps "
        f"(target coverage {floor:.0%}, {mode} coverage)."
    )
    return Recompute(
        True, value=value, evidence=refs, canonical_phrase=phrase,
        correctness_floor=floor, coverage_mode=mode,
        reason=f"derived:root_cause_region size={n_in}/{total} floor={floor:.3f} mode={mode}",
    )


# ───────────────────────────────────────────────────────── the registry
QUERIES: tuple[PresenceQuery, ...] = (
    PresenceQuery("forbid_count", ClaimKind.AGGREGATE,
                  ("forbid", "forbidden", "blocked", "refus"),
                  _count_decisions(Verdict.FORBID, "forbidden")),
    PresenceQuery("permit_count", ClaimKind.AGGREGATE,
                  ("permit", "permitted", "allowed", "approved"),
                  _count_decisions(Verdict.PERMIT, "permitted")),
    PresenceQuery("abstain_count", ClaimKind.AGGREGATE,
                  ("abstain", "abstained", "held", "on hold"),
                  _count_decisions(Verdict.ABSTAIN, "abstained")),
    PresenceQuery("agent_count", ClaimKind.AGGREGATE,
                  ("how many agent", "registered agent", "number of agent", "agents are"),
                  _count_agents),
    PresenceQuery("action_total", ClaimKind.AGGREGATE,
                  ("how many action", "total action", "actions have", "action recorded"),
                  _count_actions),
    PresenceQuery("offline_connector_count", ClaimKind.AGGREGATE,
                  ("connector", "offline connector", "discovery connector"),
                  _count_offline_connectors),
    PresenceQuery("discovery_event_count", ClaimKind.AGGREGATE,
                  ("discovery event", "how many discover", "discoveries"),
                  _count_discovery_events),
    PresenceQuery("failed_scan_count", ClaimKind.AGGREGATE,
                  ("failed scan", "scan failed", "scan failure"),
                  _count_failed_scans),
    PresenceQuery("agent_status", ClaimKind.ENTITY,
                  ("status of agent", "agent status", "is agent", "state of agent"),
                  _agent_status, needs_target=True),
    PresenceQuery("discovery_present", ClaimKind.EVENT,
                  ("any discovery", "recent discovery", "shadow agent", "discovered any"),
                  _discovery_present),
    PresenceQuery("root_cause_region", ClaimKind.DERIVED,
                  ("root cause", "decisive error", "which step", "likely error", "where did it go wrong"),
                  _root_cause_region, needs_target=True),
)
