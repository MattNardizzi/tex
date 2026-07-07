"""The four query buttons — the exhibits layer of the fluid-truth pipeline.

Every number, list, or record Tex speaks is minted here, by deterministic code
reading real decision rows. The model never counts; it references an exhibit by
handle. Each primitive returns an Exhibit dict (the shape in
:mod:`tex.answers.spans`), carrying both the machine ``value`` and its humanized
``spoken`` rendering — the two must agree by construction, because one function
produces both.

Doctrine sealed into this file:

- A zero count is a sealed truth, not an abstention. ``count_decisions`` over an
  empty match returns ``value=0`` and ``spoken="zero"`` — never an error.
- Tenant is ALWAYS required. A ``None`` tenant raises: there is no fleet-wide
  default here. Visibility follows the same private+shared rule the presence
  gate applies (a named tenant sees its own rows plus the shared "default"
  partition); the exhibit's ``query.tenant`` discloses the exact scope.
- Verdict vocabulary is the store's real one — PERMIT, ABSTAIN, FORBID (see
  :class:`tex.domain.verdict.Verdict`). There is no distinct HELD verdict in the
  store: a held / awaiting-human decision is recorded as ABSTAIN
  (``Verdict.ABSTAIN`` ⇒ ``requires_human_review``). The caller-facing ``"HELD"``
  label is accepted and normalized to ABSTAIN so the spoken world can say "held"
  while the sealed rows stay honest.
- Store timestamps are UTC (``Decision.decided_at`` is tz-aware UTC). Windows
  ("today", "this week") are resolved in the operator's local zone
  (``TEX_ANSWER_TZ``, default America/New_York) and converted to UTC before any
  comparison, so a decision at 03:00 UTC reads as the prior local evening.
- The anchor a ``record`` exhibit carries is the decision's own sealed
  ``content_sha256`` — the same per-row anchor the presence gate binds
  (``ref_for_decision``). An aggregate (count / list) carries no anchor: a
  count is meaning, not a single graspable record.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Reuse Tex's canonical spoken-number helper — "forty-one", not "41", and
# "zero" for an empty count. It handles 0..9999 and falls back to digits beyond.
# Imported read-only from the discovery layer; not reimplemented here.
from tex.discovery.ignition import humanize_count
from tex.domain.verdict import Verdict

__all__ = [
    "count_decisions",
    "list_decisions",
    "get_decision_record",
    "ANSWER_TZ_ENV",
    "DEFAULT_ANSWER_TZ",
]

ANSWER_TZ_ENV = "TEX_ANSWER_TZ"
DEFAULT_ANSWER_TZ = "America/New_York"

# The caller may say "HELD" for an awaiting-human decision; the store seals that
# as ABSTAIN. Everything else maps to itself. ``None`` means "all verdicts".
_VERDICT_ALIASES = {
    "HELD": Verdict.ABSTAIN,
    "ABSTAIN": Verdict.ABSTAIN,
    "PERMIT": Verdict.PERMIT,
    "FORBID": Verdict.FORBID,
}


# ─────────────────────────────────────────────────────────── tenant + windows
def _require_tenant(tenant: str | None) -> str:
    """A tenant is mandatory. Blank or ``None`` is a caller error, not a
    fleet-wide default — an unscoped count would leak across tenants."""
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError("tenant is required — exhibits are never computed fleet-wide")
    return tenant.strip()


def _tenant_visible(row: Any, wanted_fold: str) -> bool:
    """Private + shared visibility — the same rule the presence gate applies.
    A tenant sees its own decisions plus the unstamped / "default" (shared)
    partition. ``Decision.tenant_id`` is "default" when a row carries none."""
    row_tenant = (getattr(row, "tenant_id", "default") or "default").strip().casefold()
    return row_tenant == wanted_fold or row_tenant == "default"


def _answer_tz() -> ZoneInfo:
    """The operator's local zone for resolving window boundaries. Env-driven,
    defaulting to America/New_York; an unknown zone falls back to the default
    rather than raising, so a mis-set env never silences an answer."""
    name = os.environ.get(ANSWER_TZ_ENV, DEFAULT_ANSWER_TZ) or DEFAULT_ANSWER_TZ
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo(DEFAULT_ANSWER_TZ)


def _normalize_verdict(verdict: str | Verdict | None) -> Verdict | None:
    """Map a caller-supplied verdict to the store's real vocabulary. ``None``
    ⇒ all verdicts. ``"HELD"`` ⇒ ABSTAIN (the store has no HELD)."""
    if verdict is None:
        return None
    if isinstance(verdict, Verdict):
        return verdict
    key = str(verdict).strip().upper()
    mapped = _VERDICT_ALIASES.get(key)
    if mapped is None:
        raise ValueError(
            f"unknown verdict {verdict!r}; expected one of "
            "FORBID, PERMIT, HELD, ABSTAIN, or None for all"
        )
    return mapped


def _coerce_utc(value: datetime | str | None) -> datetime | None:
    """Normalize a since/until bound to a tz-aware UTC datetime for comparison
    against ``Decision.decided_at`` (which is always UTC). A naive datetime is
    read as UTC; an ISO string is parsed; ``None`` passes through."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise TypeError("since/until must be a datetime, ISO string, or None")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _resolve_window(
    window_label: str | None,
    since: datetime | str | None,
    until: datetime | str | None,
) -> tuple[datetime | None, datetime | None, str | None]:
    """Turn a window label into concrete UTC ``[since, until)`` bounds.

    Explicit ``since``/``until`` always win — a caller who passes bounds gets
    exactly them, and the label is retained verbatim for provenance. When only a
    label is given, resolve it in the operator's local zone and convert to UTC:

    - "today"      → local midnight today ..now
    - "this week"  → local Monday 00:00 ..now
    - "recent"     → left open (no lower bound); the recent-window semantics are
                     the store's own list-order, applied by the caller of a list.
    """
    since_utc = _coerce_utc(since)
    until_utc = _coerce_utc(until)

    if since_utc is not None or until_utc is not None:
        return since_utc, until_utc, window_label

    if window_label is None:
        return None, None, None

    label = window_label.strip().casefold()
    tz = _answer_tz()
    now_local = datetime.now(tz)

    if label == "today":
        start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        return start_local.astimezone(UTC), None, window_label

    if label in ("this week", "week"):
        midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        monday = midnight - timedelta(days=midnight.weekday())
        return monday.astimezone(UTC), None, window_label

    # "recent" and any other label carry no computed bound here; the label rides
    # into provenance and the store's own recency ordering does the rest.
    return None, None, window_label


def _in_window(
    row: Any,
    since_utc: datetime | None,
    until_utc: datetime | None,
) -> bool:
    """Half-open ``[since, until)`` membership against ``decided_at`` (UTC)."""
    decided = getattr(row, "decided_at", None)
    if decided is None:
        return since_utc is None and until_utc is None
    if decided.tzinfo is None:
        decided = decided.replace(tzinfo=UTC)
    else:
        decided = decided.astimezone(UTC)
    if since_utc is not None and decided < since_utc:
        return False
    if until_utc is not None and decided >= until_utc:
        return False
    return True


def _matching_rows(
    store: Any,
    wanted_fold: str,
    resolved_verdict: Verdict | None,
    since_utc: datetime | None,
    until_utc: datetime | None,
) -> list[Any]:
    """The tenant-visible, verdict-filtered, window-filtered rows, newest first.

    Reads the whole store and filters here rather than through ``store.find``,
    because ``find`` cannot express the tenant-visibility or time-window
    predicates. ``list_all`` returns save order; we reverse for newest-first,
    the same operationally-useful default the store's own ``find`` uses.
    """
    if hasattr(store, "list_all"):
        rows: Iterable[Any] = store.list_all()
    elif hasattr(store, "find"):
        rows = store.find()
    else:
        raise TypeError("store must expose list_all() or find()")

    ordered = list(reversed(list(rows)))
    matched: list[Any] = []
    for row in ordered:
        if not _tenant_visible(row, wanted_fold):
            continue
        if resolved_verdict is not None and getattr(row, "verdict", None) != resolved_verdict:
            continue
        if not _in_window(row, since_utc, until_utc):
            continue
        matched.append(row)
    return matched


def _anchor_for(decision: Any) -> str | None:
    """The decision's own sealed per-row anchor — its ``content_sha256`` (a real
    64-hex SHA-256, always present on a ``Decision``). Mirrors the presence
    gate's ``ref_for_decision``. Returns ``None`` if the field is absent or not
    a 64-hex digest, so a malformed row degrades to an unanchored exhibit rather
    than fabricating one."""
    anchor = getattr(decision, "content_sha256", None)
    if isinstance(anchor, str):
        candidate = anchor.strip().lower()
        if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
            return candidate
    return None


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat()


def _query_dict(
    tool: str,
    tenant: str,
    resolved_verdict: Verdict | None,
    since_utc: datetime | None,
    until_utc: datetime | None,
    window_label: str | None,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "tenant": tenant,
        "verdict": resolved_verdict.value if resolved_verdict is not None else None,
        "since": _iso(since_utc),
        "until": _iso(until_utc),
        "window_label": window_label,
    }


# ───────────────────────────────────────────────────────────── the four buttons
def count_decisions(
    store: Any,
    tenant: str | None,
    verdict: str | Verdict | None = None,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
    window_label: str | None = None,
) -> dict[str, Any]:
    """Count the decisions matching a verdict and window, scoped to a tenant.

    Returns a ``count`` Exhibit dict. A zero match is a sealed truth
    (``value=0``, ``spoken="zero"``), never an error. ``verdict`` may be
    ``FORBID``/``PERMIT``/``HELD``/``ABSTAIN`` or ``None`` for all; ``HELD``
    normalizes to ABSTAIN. The exhibit carries no anchor — a count is meaning,
    not a single graspable record.
    """
    tenant = _require_tenant(tenant)
    resolved_verdict = _normalize_verdict(verdict)
    since_utc, until_utc, resolved_label = _resolve_window(window_label, since, until)
    wanted_fold = tenant.casefold()

    rows = _matching_rows(store, wanted_fold, resolved_verdict, since_utc, until_utc)
    n = len(rows)

    return {
        "handle": "e1",
        "kind": "count",
        "value": n,
        "spoken": humanize_count(n),
        "unit": "decisions",
        "query": {
            **_query_dict(
                "count_decisions", tenant, resolved_verdict, since_utc, until_utc, resolved_label
            ),
            # Zero-ness travels in provenance (not value) so the redacted
            # drafter can choose the calm "No ..." phrasing without ever
            # seeing a quantity.
            "is_zero": n == 0,
        },
        "anchor_sha256": None,
        "computed_at": datetime.now(UTC).isoformat(),
    }


def _spoken_row_names(rows: list[dict[str, Any]], cap: int = 3) -> str:
    """The ear's rendering of a decision list: up to ``cap`` agent names, then
    a humanized remainder. Every fragment is computed here, deterministically —
    this string IS the value the gate seals into spoken text, so a raw
    structure (brackets, timestamps, ids) must never appear in it.
    """
    if not rows:
        return "none"
    names = [str(r.get("agent") or "an unnamed agent") for r in rows[:cap]]
    rest = len(rows) - len(names)
    if rest > 0:
        names.append(f"{humanize_count(rest)} more")
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"


def list_decisions(
    store: Any,
    tenant: str | None,
    verdict: str | Verdict | None = None,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """List the most recent matching decisions, scoped to a tenant.

    Returns a ``list`` Exhibit whose ``value`` is a list of
    ``{decision_id, agent, verdict, at}`` rows, newest first, capped at
    ``limit``. ``spoken`` is the humanized count of listed rows (the ear hears
    "seven", the eye reads the rows). Carries no single anchor — a list binds
    many rows, not one; each row keeps its own id for a follow-up record pull.
    """
    tenant = _require_tenant(tenant)
    resolved_verdict = _normalize_verdict(verdict)
    since_utc, until_utc, _ = _resolve_window(None, since, until)
    wanted_fold = tenant.casefold()

    if limit < 0:
        raise ValueError("limit must be non-negative")

    rows = _matching_rows(store, wanted_fold, resolved_verdict, since_utc, until_utc)
    selected = rows[:limit]

    value = [
        {
            "decision_id": str(getattr(r, "decision_id", "")),
            "agent": _agent_of(r),
            "verdict": _verdict_str(r),
            "at": _iso(getattr(r, "decided_at", None)),
        }
        for r in selected
    ]

    return {
        "handle": "e1",
        "kind": "list",
        "value": value,
        "spoken": _spoken_row_names(value),
        "unit": "decisions",
        "query": _query_dict(
            "list_decisions", tenant, resolved_verdict, since_utc, until_utc, None
        ),
        "anchor_sha256": None,
        "computed_at": datetime.now(UTC).isoformat(),
    }


def get_decision_record(
    store: Any,
    decision_id: str | UUID,
    tenant: str | None,
) -> dict[str, Any]:
    """Pull one decision as a ``record`` Exhibit — the "show me the evidence" ask.

    ``value`` is an ordered list of ``[field, value]`` pairs (the contract types
    an exhibit value as int | str | list, never a bare dict) carrying the
    decision's spoken-relevant fields;
    ``anchor_sha256`` is the decision's own sealed ``content_sha256`` (the same
    per-row anchor the presence gate binds), when the store exposes one.

    Tenant isolation is enforced on read: a record outside the tenant's
    visibility (its own rows plus the shared "default" partition) is treated as
    not found. A missing decision raises ``KeyError`` — there is no exhibit to
    seal, and the pipeline abstains upstream rather than speaking a guess.
    """
    tenant = _require_tenant(tenant)
    wanted_fold = tenant.casefold()

    uid = decision_id if isinstance(decision_id, UUID) else UUID(str(decision_id))
    decision = store.get(uid) if hasattr(store, "get") else None
    if decision is None or not _tenant_visible(decision, wanted_fold):
        raise KeyError(f"decision not found for tenant: {decision_id}")

    anchor = _anchor_for(decision)
    # The Exhibit contract types ``value`` as int | str | list — never a bare
    # dict. A record is carried as an ordered list of ``[field, value]`` pairs:
    # a list satisfies the shape while keeping the record whole and ordered for
    # the ear/eye. Consumers read it as an ordered mapping.
    value = [
        ["decision_id", str(getattr(decision, "decision_id", ""))],
        ["agent", _agent_of(decision)],
        ["verdict", _verdict_str(decision)],
        ["action_type", getattr(decision, "action_type", None)],
        ["at", _iso(getattr(decision, "decided_at", None))],
        ["content_sha256", anchor],
        ["evidence_hash", getattr(decision, "evidence_hash", None)],
    ]

    return {
        "handle": "e1",
        "kind": "record",
        "value": value,
        # The ear's rendering of one record: a clean sentence fragment built
        # from the decision's own fields — never a serialized structure.
        "spoken": (
            f"{_verdict_str(decision) or 'a decision'}"
            f" for {getattr(decision, 'action_type', None) or 'an action'}"
            f" by {_agent_of(decision) or 'an unnamed agent'}"
        ),
        "unit": "decision",
        "query": {
            "tool": "get_decision_record",
            "tenant": tenant,
            "verdict": _verdict_str(decision),
            "since": None,
            "until": None,
            "window_label": None,
        },
        "anchor_sha256": anchor,
        "computed_at": datetime.now(UTC).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────── row shape
def _verdict_str(row: Any) -> str | None:
    """The row's verdict as its canonical string, tolerant of enum or str."""
    verdict = getattr(row, "verdict", None)
    if verdict is None:
        return None
    return getattr(verdict, "value", str(verdict))


def _agent_of(row: Any) -> str | None:
    """The acting agent for a decision, for the spoken list/record.

    A ``Decision`` carries no first-class agent column; the acting identity, when
    known, rides in ``metadata`` (``agent_id`` / ``agent`` / ``actor``). Absent
    ⇒ ``None`` — the list stays honest rather than inventing an actor.
    """
    metadata = getattr(row, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("agent_id", "agent", "actor"):
            candidate = metadata.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None
