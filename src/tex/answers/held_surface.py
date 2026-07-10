"""Restart-proof held surfaces — the durable floor beneath the live sink.

The live ``HeldDecisionSink`` (``tex.provenance.feed``) is a per-process queue:
it is wiped on every deploy. The durable truth of *what is still waiting on a
human* already lives in the decision store — the ABSTAIN rows the exhibits
layer measures (``count_held_waiting`` / ``list_held_waiting``, minus the ids a
human has already sealed). This module unions the two so the REST surfaces the
UI loads on page-open (``GET /v1/surface/discovery/held`` and the vigil
headline) are true *immediately* after a deploy, not only once the sink refills.

Two invariants hold this together:

  * **One shared query.** The "waiting" definition lives in exactly one place —
    :func:`tex.answers.exhibits.held_waiting_rows`. Both the answer wire and
    these surfaces read it, so a durable row and an answer row can never
    disagree about what is waiting.

  * **One jsonable shape.** A durable row is mapped into the SAME dict a live
    sink item's :meth:`HeldDecision.to_jsonable` produces — WHO in
    ``detail.agent_name``, WHAT in ``detail.content_excerpt`` /
    ``detail.action_type``, and the real sealable ``decision_id`` — so the
    frontend renders and seals a restored row identically to a live one.

The sink stays the live fast-path (it carries the Layer-4 ``Hold`` object and
its spoken sentence): on a dedup collision the sink item wins, and the durable
floor only fills in the rows the sink lost on deploy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.answers import exhibits

__all__ = ["durable_held_items", "merge_held_items", "union_held"]

# Match the exhibits row cap so a restored excerpt is bounded exactly as the
# live one is.
_CONTENT_EXCERPT_MAX = 280


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _durable_item(decision: Any) -> dict[str, Any]:
    """Map one durable waiting ``Decision`` into the sink's ``to_jsonable`` shape.

    WHO rides ``detail.agent_name`` (the readable actor the frontend renders),
    WHAT rides ``detail.content_excerpt`` / ``detail.action_type``, and
    ``decision_id`` is the real sealable id the queue walks through
    ``POST /decisions/{id}/seal``. ``kind`` is stamped from the decision's own
    provenance so a presence-origin REVIEW is marked ``presence_abstain`` — the
    exact tag the vigil surfaces filter on — while a governance hold reads
    ``held_waiting``.
    """
    agent = exhibits._agent_of(decision)  # noqa: SLF001 — reuse the one actor rule
    excerpt = getattr(decision, "content_excerpt", None)
    excerpt = excerpt[:_CONTENT_EXCERPT_MAX] if isinstance(excerpt, str) else None
    action_type = getattr(decision, "action_type", None)
    anchor = exhibits._anchor_for(decision)  # noqa: SLF001
    tenant = (getattr(decision, "tenant_id", "default") or "default")

    metadata = getattr(decision, "metadata", None)
    dimension = metadata.get("dimension") if isinstance(metadata, dict) else None
    kind = (
        "presence_abstain"
        if isinstance(dimension, str) and dimension.strip().casefold() == "presence"
        else "held_waiting"
    )

    detail: dict[str, Any] = {"tenant_id": tenant}
    if isinstance(dimension, str) and dimension.strip():
        detail["dimension"] = dimension.strip()
    if agent:
        detail["agent_name"] = agent
    if excerpt:
        detail["content_excerpt"] = excerpt
    if action_type:
        detail["action_type"] = action_type

    return {
        # No first-class UUID actor on a Decision; the readable WHO lives in
        # detail.agent_name (what the frontend renders). Keep the top-level
        # agent_id honest — the name when known, else empty — never invented.
        "agent_id": agent or "",
        "kind": kind,
        "confidence": 0.0,
        "note": "I'm holding this one. It's yours to decide.",
        "detail": detail,
        "raised_at": _iso(getattr(decision, "decided_at", None)),
        "hold": None,
        "decision_id": str(getattr(decision, "decision_id", "")),
        "anchor_sha256": anchor,
        "tenant_id": tenant,
    }


def durable_held_items(
    store: Any,
    tenant: str | None,
    resolutions: Any = None,
) -> list[dict[str, Any]]:
    """The durable waiting rows for ``tenant``, mapped to the sink jsonable shape.

    Reads the ONE shared query (:func:`exhibits.held_waiting_rows`). Fail-open:
    a missing store or a read fault yields ``[]`` so a durable hiccup can only
    drop the restart-proof floor, never break the surface (the live sink still
    serves).
    """
    if store is None or not (isinstance(tenant, str) and tenant.strip()):
        return []
    try:
        rows = exhibits.held_waiting_rows(store, tenant, resolutions)
    except Exception:  # noqa: BLE001 — the durable floor is an upgrade, never a dependency
        return []
    return [_durable_item(r) for r in rows]


def merge_held_items(
    sink_items: Any,
    durable_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Union live sink items with durable items, deduped by ``decision_id``,
    newest first.

    Sink items win a collision (they carry the live ``Hold`` object and its
    spoken sentence); a sink item with no ``decision_id`` cannot be deduped and
    is always kept. ``sink_items`` are the raw ``HeldDecision`` objects — mapped
    to jsonable here so the returned list is uniformly the frontend shape.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _emit(item: dict[str, Any]) -> None:
        did = str(item.get("decision_id") or "").strip()
        if did:
            if did in seen:
                return
            seen.add(did)
        out.append(item)

    # Sink first so it wins the dedup; then the durable floor fills the rest.
    for raw in sink_items or ():
        to_jsonable = getattr(raw, "to_jsonable", None)
        _emit(to_jsonable() if callable(to_jsonable) else dict(raw))
    for item in durable_items:
        _emit(item)

    # Newest first. Every raised_at is a tz-aware UTC ISO string, so a plain
    # string sort is a correct reverse-chronological order; rows missing a
    # timestamp sink to the bottom.
    out.sort(key=lambda it: it.get("raised_at") or "", reverse=True)
    return out


def union_held(
    store: Any,
    tenant: str | None,
    resolutions: Any,
    sink_items: Any,
) -> list[dict[str, Any]]:
    """The restart-proof held list: durable waiting rows unioned with the live
    sink, deduped by ``decision_id``, newest first, all in the sink jsonable
    shape. This is what ``GET /held`` returns and what the vigil headline
    counts (after its presence-review filter)."""
    return merge_held_items(sink_items, durable_held_items(store, tenant, resolutions))
