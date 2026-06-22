"""Assemble the recomputable fact sheet the grounded brain drafts from.

The brain must state ONLY numbers the gate can independently recompute from sealed
rows — otherwise the gate (correctly) abstains on a ``draft-value-mismatch``. The
old failure was that the brain saw only the routed *dimension* sheet (which has no
agent total), so it had to GUESS a number, and the gate rejected the guess.

This builder closes that gap by running the gate's OWN aggregate recomputes
(:data:`tex.presence.gate.queries.QUERIES`) up front and handing the brain the
exact values, each under the ``claim_id`` key the gate routes by, plus the gate's
own canonical phrasing (which is what the voice ultimately speaks for a sealed
claim). Brain and gate therefore agree on every number BY CONSTRUCTION — not by
hope. The gate is unchanged and still re-verifies everything from sealed rows; this
only changes what the (non-load-bearing) brain is allowed to read.

Read-only and fail-closed: an unavailable store, a recompute error, or a
true zero-count aggregate (no positive evidence — the gate abstains on those, so
sealing "0" here would be a value the gate would later reject) is simply OMITTED,
never guessed. Scope honesty rides along in each ``phrase`` (the fleet-wide
aggregates already disclose "across all tenants" — see the queries.py banner).
"""

from __future__ import annotations

from typing import Any

from tex.presence.contract import ClaimKind
from tex.presence.gate.queries import QUERIES

__all__ = ["build_grounded_facts"]


def _resolve_state(request: Any) -> Any:
    """Mirror ``gate._state``: prefer ``request.app.state`` (the live server),
    else treat ``request`` itself as the store-bearing object (test doubles)."""
    state = getattr(getattr(request, "app", None), "state", None)
    return state if state is not None else request


def build_grounded_facts(
    request: Any, *, tenant: str | None, dimension_facts: Any = None
) -> dict[str, Any]:
    """Build the brain's fact sheet: every aggregate the gate would SEAL for this
    tenant, keyed by ``claim_id``, plus the routed-dimension context.

    Only non-parametric AGGREGATE queries are pre-run (the parametric ones —
    ``agent_status``, ``root_cause_region`` — need a named target the question
    supplies, so they cannot be enumerated blind). Each entry carries the exact
    recomputed ``value`` and the gate's ``phrase`` so the draft aligns with what
    the voice will actually speak.
    """
    state = _resolve_state(request)
    recomputable: list[dict[str, Any]] = []
    for query in QUERIES:
        if query.needs_target or query.kind is not ClaimKind.AGGREGATE:
            continue
        try:
            rc = query.recompute(state, tenant, None)
        except Exception:  # noqa: BLE001 — a single store hiccup must not break the sheet
            continue
        # Surface ONLY a fact the gate would actually seal: grounded AND backed by
        # at least one EvidenceRef. A true zero-count has no positive rows, so the
        # gate abstains on it (gate.py: "evidence empty iff ABSTAIN") — handing the
        # brain "0" would only earn a later abstain.
        if not getattr(rc, "grounded", False) or not getattr(rc, "evidence", ()):
            continue
        recomputable.append(
            {
                "claim_id": query.key,
                "kind": query.kind.value,
                "value": rc.value,
                "phrase": rc.canonical_phrase,
            }
        )

    sheet: dict[str, Any] = {"recomputable_facts": recomputable}
    if dimension_facts is not None:
        sheet["dimension_context"] = dimension_facts
    return sheet
