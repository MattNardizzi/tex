"""
[Architecture: Cross-cutting (Vigil cognition)] — the held-decision provider.

The vigil endpoint asks one question when it assembles the held card: *is
there a decision waiting on a human right now, and what is it?* The answer
lives in the runtime's ``HeldDecisionSink`` (provenance/feed.py) — the
thread-safe queue the gate and the discovery path append to. This adapter is
the seam between that queue and the ``/v1/vigil`` contract: it reads the
freshest unresolved hold and maps it to the held-card payload the surface
renders, carrying the Layer-4 ``Hold`` (engine/hold.py) when the held
decision originated from a PDP ABSTAIN.

Read-only and defensive: a malformed item or an empty queue yields ``None``
and the vigil falls back to its posture-true line. Nothing here blocks the
cycle. This mirrors the vigil v2–v5 collaborator pattern — a real interface
the runtime injects, not a computation baked into the route.
"""

from __future__ import annotations

from typing import Any

__all__ = ["HeldDecisionVigilProvider"]


# Map a Hold.resolution_mode / type to the dimension the surface attributes
# the hold to. A Layer-4 hold is an execution-governance hold.
_DEFAULT_DIMENSION = "execution"


class HeldDecisionVigilProvider:
    """Adapts a ``HeldDecisionSink`` into the vigil ``current(tenant)`` seam."""

    __slots__ = ("_sink",)

    def __init__(self, sink: Any) -> None:
        self._sink = sink

    def current(self, tenant: str | None) -> dict[str, Any] | None:
        """Return the freshest unresolved held decision as a held-card payload,
        or ``None`` if nothing waits on a human.

        Tenant scoping: held items may carry a ``detail['tenant_id']``; when
        present and a tenant is requested, only matching items are surfaced.
        Items with no tenant tag are treated as visible (keyless dev posture).
        """
        sink = self._sink
        if sink is None:
            return None
        peek = getattr(sink, "peek", None)
        if not callable(peek):
            return None
        try:
            items = peek()
        except Exception:  # noqa: BLE001 — never break the vigil cycle
            return None
        if not items:
            return None

        # Freshest first; respect tenant scoping when the item is tagged.
        for item in reversed(list(items)):
            detail = getattr(item, "detail", {}) or {}
            item_tenant = detail.get("tenant_id")
            if (
                tenant is not None
                and item_tenant is not None
                and str(item_tenant).casefold() != str(tenant).casefold()
            ):
                continue
            return self._to_payload(item)
        return None

    # ----- mapping -------------------------------------------------------

    @staticmethod
    def _to_payload(item: Any) -> dict[str, Any]:
        hold = getattr(item, "hold", None)
        detail = getattr(item, "detail", {}) or {}
        agent = detail.get("agent") or _short_agent(getattr(item, "agent_id", None))

        # Prefer the Hold's own spoken surface when present (Layer-4 origin);
        # otherwise fall back to the held decision's note (provenance origin).
        if isinstance(hold, dict) and hold.get("sentence"):
            sentence = hold.get("sentence")
            hold_detail = hold.get("detail")
        else:
            sentence = getattr(item, "note", None) or (
                "I'm holding this one. It's yours to decide."
            )
            hold_detail = detail.get("detail")

        return {
            "id": getattr(item, "decision_id", None) or detail.get("decision_id"),
            "sentence": sentence,
            "detail": hold_detail or detail.get("note"),
            "dimension": detail.get("dimension", _DEFAULT_DIMENSION),
            "surprise": float(detail.get("surprise", 0.0) or 0.0),
            "agent": agent,
            "proof_ref": detail.get("proof_ref"),
            "anchor_sha256": getattr(item, "anchor_sha256", None)
            or detail.get("anchor_sha256"),
            "hold": hold if isinstance(hold, dict) else None,
        }


def _short_agent(agent_id: Any) -> str | None:
    if agent_id is None:
        return None
    s = str(agent_id)
    return s
