"""
[Architecture: Cross-cutting (Vigil cognition)] — the six dimensions, read.

The vigil reads across all six dimensions every cycle. This module turns
the live ``app.state`` stores into a normalized list of ``DimensionReading``
objects, each carrying:

  * ``observation`` — what was seen *this cycle* (the posterior evidence),
  * ``history``     — past observations from the sealed ledgers, used to
                      warm the model of normal (see vigil/normal.py),
  * ``slots``       — sealed values that fill an authored utterance form;
                      every slot traces to real data, never improvised,
  * ``proof``       — a pointer to sealed evidence (hash / id / seq) so the
                      proof layer can later resolve the claim.

The six are how Tex is *built*, never how it is *surfaced*. They are
labeled here only so surprise can be attributed to a source; the voice
never names a "layer". Reading is defensive: a missing or half-initialized
store yields no reading for that dimension rather than an error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "ProofRef",
    "DimensionReading",
    "read_dimensions",
]

Kind = Literal["beta", "gamma"]


@dataclass(frozen=True, slots=True)
class ProofRef:
    """A pointer to sealed evidence behind a spoken line."""

    kind: str
    id: str | None = None
    sha256: str | None = None
    seq: int | None = None

    def is_empty(self) -> bool:
        return self.id is None and self.sha256 is None and self.seq is None


@dataclass(frozen=True, slots=True)
class DimensionReading:
    """One dimension's observation this cycle, with history and proof."""

    key: str
    kind: Kind
    # For "gamma": observation = (count, exposure); history = [count, ...].
    # For "beta":  observation = (successes, failures); history = [(s, f), ...].
    observation: tuple[float, ...]
    history: list[Any] = field(default_factory=list)
    slots: dict[str, Any] = field(default_factory=dict)
    proof: ProofRef | None = None
    # A line whose surprise can be partly explained by another dimension
    # naming it first (v1.5 redundancy collapse). Coarse and declared.
    explained_by: tuple[str, ...] = ()
    # True for the human-decision gate: never surprise-ranked, always
    # spoken when present (the renamed third verdict).
    is_human_gate: bool = False
    # v5: a sealed causal attribution attached by CausalAttributionPort. When
    # present, ``explained_by`` has been confirmed-and-sealed (not merely
    # declared) and carries a proof ref to the attribution ledger. Typed Any
    # to avoid a circular import with vigil.causal.
    causal: Any = None
    # v5: a sealed counterfactual claim ("what would have happened"),
    # resolvable as proof. Typed Any for the same reason.
    counterfactual: Any = None


# --------------------------------------------------------------------------- helpers


def _state(request: Any, name: str) -> Any:
    return getattr(request.app.state, name, None)


# --------------------------------------------------------------------------- dimensions


def _discovery(request: Any, tenant: str | None) -> DimensionReading | None:
    """Inventory: how many new agents discovery registered this scan."""
    store = _state(request, "scan_run_store")
    if store is None:
        return None
    try:
        runs = store.list_recent(tenant_id=tenant, limit=25)
    except Exception:  # noqa: BLE001
        return None
    if not runs:
        return None

    def registered(r: Any) -> float:
        s = getattr(r, "summary", None) or {}
        return float(s.get("registered_count") or 0)

    latest = runs[0]
    current = registered(latest)
    history = [registered(r) for r in runs[1:]]

    seq_end = getattr(latest, "ledger_seq_end", None)
    proof = ProofRef(
        kind="scan_run",
        id=str(getattr(latest, "run_id", "") or "") or None,
        seq=int(seq_end) if seq_end is not None else None,
    )
    return DimensionReading(
        key="discovery",
        kind="gamma",
        observation=(current, 1.0),
        history=history,
        slots={"count": int(current)},
        proof=proof,
    )


def _identity(request: Any, tenant: str | None) -> DimensionReading | None:
    """Identity/access: high-risk agents operating ungoverned."""
    try:
        from tex.api.agent_routes import (
            _build_governance,
            _resolve_discovery_ledger,
            _resolve_ledger,
            _resolve_registry,
        )

        gov = _build_governance(
            registry=_resolve_registry(request),
            action_ledger=_resolve_ledger(request),
            discovery_ledger=_resolve_discovery_ledger(request),
        )
    except Exception:  # noqa: BLE001
        return None

    counts = gov.counts
    ungoverned_hr = float(getattr(counts, "high_risk_ungoverned", 0) or 0)
    hr_total = float(getattr(counts, "high_risk_total", 0) or 0)
    # History is not separately retained per cycle in v1; the prior is
    # neutral and the standing posture is what carries identity. We still
    # surface the count so the line can speak when it is genuinely off.
    proof = ProofRef(
        kind="governance_coverage",
        sha256=(getattr(gov, "coverage_root_sha256", "") or None),
    )
    return DimensionReading(
        key="identity",
        kind="gamma",
        observation=(ungoverned_hr, 1.0),
        history=[],
        slots={"count": int(ungoverned_hr), "high_risk_total": int(hr_total)},
        proof=proof,
        # A discovery spike of new agents partly explains a rise in
        # ungoverned high-risk agents — declared for v1.5 collapse.
        explained_by=("discovery",),
    )


def _monitoring(request: Any, tenant: str | None) -> DimensionReading | None:
    """Observability: connectors failing to report."""
    store = _state(request, "connector_health_store")
    if store is None:
        return None
    try:
        records = (
            store.list_for_tenant(tenant) if tenant else store.list_all()
        )
    except Exception:  # noqa: BLE001
        return None
    records = list(records or [])
    if not records:
        return None

    failing = [r for r in records if int(getattr(r, "consecutive_failures", 0) or 0) > 0]
    worst = max(
        records,
        key=lambda r: int(getattr(r, "consecutive_failures", 0) or 0),
        default=None,
    )
    proof = None
    if worst is not None:
        proof = ProofRef(
            kind="connector",
            id=str(getattr(worst, "connector_name", "") or "") or None,
        )
    return DimensionReading(
        key="monitoring",
        kind="gamma",
        observation=(float(len(failing)), 1.0),
        history=[],
        slots={
            "count": len(failing),
            "connector": (getattr(worst, "connector_name", "") if worst else ""),
            "failures": int(getattr(worst, "consecutive_failures", 0) or 0) if worst else 0,
        },
        proof=proof,
    )


def _held_rows(request: Any, tenant: str | None) -> tuple[Any, ...]:
    """
    The live held queue for ``tenant`` — the HeldDecisionSink rows awaiting a
    human seal. This is the single source of truth the resolvable cards,
    GET /v1/surface/discovery/held, and POST /v1/ask all read, so the vigil
    headline speaks the same number the operator can act on. Read defensively:
    a missing sink yields no rows rather than an error.
    """
    sink = _state(request, "held_decision_sink")
    if sink is None:
        return ()
    try:
        return tuple(sink.peek_for_tenant(tenant))
    except Exception:  # noqa: BLE001
        try:
            return tuple(sink.peek())
        except Exception:  # noqa: BLE001
            return ()


def _execution(request: Any, tenant: str | None) -> list[DimensionReading]:
    """
    Execution governance: the verdict mix in the recent window, plus the
    human-decision gate.

    Produces up to two readings:
      * a surprise-ranked line for FORBID volume (the recent decision
        window), and
      * the human-decision *gate* (the renamed third verdict): always
        spoken when actions are truly waiting on a person, never
        surprise-ranked.

    The gate's count is the LIVE held queue — the same HeldDecisionSink the
    resolvable cards, GET /v1/surface/discovery/held, and POST /v1/ask all
    read — tenant-scoped. So the number on the glass is exactly what the
    operator can act on now, never a historical ABSTAIN-ledger tally that
    would overstate the work and never drain as the operator resolves it.
    """
    out: list[DimensionReading] = []

    # FORBID volume — surprise-ranked observation over the recent window.
    store = _state(request, "decision_store")
    if store is not None:
        try:
            from tex.domain.verdict import Verdict

            recent = store.list_recent(limit=200)
        except Exception:  # noqa: BLE001
            recent = []
        if recent:
            forbids = [
                d for d in recent if getattr(d, "verdict", None) == Verdict.FORBID
            ]
            first = forbids[0] if forbids else None
            out.append(
                DimensionReading(
                    key="execution",
                    kind="gamma",
                    observation=(float(len(forbids)), 1.0),
                    history=[],
                    slots={"count": len(forbids)},
                    proof=(
                        ProofRef(
                            kind="decision",
                            id=str(getattr(first, "decision_id", "") or "") or None,
                            sha256=(getattr(first, "evidence_hash", None) or None),
                        )
                        if first is not None
                        else None
                    ),
                )
            )

    # Human-decision gate — count is the live held queue, tenant-scoped, so
    # the headline equals the resolvable cards. Not surprise-ranked.
    held = _held_rows(request, tenant)
    if held:
        first = held[0]
        out.append(
            DimensionReading(
                key="human_decision",
                kind="gamma",
                observation=(float(len(held)), 1.0),
                history=[],
                slots={"count": len(held)},
                proof=ProofRef(
                    kind="decision",
                    id=(getattr(first, "decision_id", None) or None),
                    sha256=(getattr(first, "anchor_sha256", None) or None),
                ),
                is_human_gate=True,
            )
        )

    return out


def _evidence(request: Any, tenant: str | None) -> DimensionReading | None:
    """Evidence: is the sealed chain intact, and how long is it."""
    ledger = _state(request, "discovery_ledger")
    if ledger is None:
        return None
    try:
        length = len(ledger)
        intact = bool(ledger.verify_chain())
    except Exception:  # noqa: BLE001
        length = 0
        intact = False

    # Beta over "intact": observe a break as a failure. A break is a
    # maximal belief-shift against a prior that expects integrity.
    successes = 1.0 if intact else 0.0
    failures = 0.0 if intact else 1.0
    return DimensionReading(
        key="evidence",
        kind="beta",
        observation=(successes, failures),
        # Prior strongly expects integrity (warmed below in normal.py).
        history=[("intact", length)],
        slots={"length": int(length), "intact": intact},
        proof=ProofRef(kind="evidence_chain", seq=int(length)),
    )


def _learning(request: Any, tenant: str | None) -> DimensionReading | None:
    """Learning: calibration proposals awaiting human review."""
    store = _state(request, "proposal_store")
    if store is None:
        return None
    try:
        pending = store.list_pending(tenant_id=tenant) if tenant else store.list_pending()
    except TypeError:
        try:
            pending = store.list_pending()
        except Exception:  # noqa: BLE001
            return None
    except Exception:  # noqa: BLE001
        return None

    pending = list(pending or [])
    if not pending:
        # No proposals is not surprising; emit nothing.
        return None
    first = pending[0]
    return DimensionReading(
        key="learning",
        kind="gamma",
        observation=(float(len(pending)), 1.0),
        history=[],
        slots={"count": len(pending)},
        proof=ProofRef(
            kind="proposal",
            id=str(getattr(first, "proposal_id", "") or "") or None,
        ),
    )


def read_dimensions(request: Any, tenant: str | None) -> list[DimensionReading]:
    """
    Read every available dimension for ``tenant`` this cycle.

    Order is build-order, but the selector ranks by surprise, so the
    returned order carries no precedence.
    """
    readings: list[DimensionReading] = []
    for fn in (_discovery, _identity, _monitoring, _evidence, _learning):
        r = fn(request, tenant)
        if r is not None:
            readings.append(r)
    readings.extend(_execution(request, tenant))
    return readings
