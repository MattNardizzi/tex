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
    "count_held_waiting",
    "list_held_waiting",
    "held_waiting_rows",
    "ANSWER_TZ_ENV",
    "DEFAULT_ANSWER_TZ",
]

ANSWER_TZ_ENV = "TEX_ANSWER_TZ"
DEFAULT_ANSWER_TZ = "America/New_York"

# The "still waiting on a human" window and caps. Waiting is a present-tense
# ask ("what needs me right now"), so it is bounded to the same seven local
# days "recent" means elsewhere; the list names a capped set for the ear and
# carries a larger rows payload for the eye.
_HELD_WAITING_SPOKEN_CAP = 10
_HELD_WAITING_ROWS_CAP = 25
_CONTENT_EXCERPT_MAX = 280

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

    if label == "yesterday":
        # The one BOUNDED window: local midnight-to-midnight, half-open.
        midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        start_local = midnight - timedelta(days=1)
        return start_local.astimezone(UTC), midnight.astimezone(UTC), window_label

    if label in ("this month", "month"):
        first = now_local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return first.astimezone(UTC), None, window_label

    if label in ("in total", "total", "all time", "ever"):
        # Everything the store holds — honestly labeled, no bounds.
        return None, None, "in total"

    if label == "recent":
        # "recently" must MEAN recently. Unbounded, this window spoke the
        # store's whole history as "recent" — a true number at a dishonest
        # altitude (the live-probe finding: 86 all-time holds spoken as
        # "held for you recently"). Seven local days is the bound; "in
        # total" remains the honest word for everything.
        start_local = now_local - timedelta(days=7)
        return start_local.astimezone(UTC), None, window_label

    # Any other label carries no computed bound here; the label rides into
    # provenance and the store's own recency ordering does the rest.
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
            "is_one": n == 1,
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
    decision_id: str | UUID | None,
    tenant: str | None,
    verdict: str | Verdict | None = None,
) -> dict[str, Any]:
    """Pull one decision as a ``record`` Exhibit — the "show me the evidence" ask.

    ``decision_id`` of ``None`` means "the latest one": the most recent
    tenant-visible row ("show me the last recorded"). Same exhibit shape, same
    isolation, same honest KeyError when the tenant has no rows at all.

    ``verdict`` (``FORBID``/``PERMIT``/``HELD``/``ABSTAIN`` or ``None`` for any)
    constrains WHICH record answers: a held-qualified "last/latest" ask ("the
    last HELD action") passes ``verdict="HELD"`` so the latest ABSTAIN — never a
    PERMIT — is returned. This is the FLOOR guarantee: the verdict filter lives
    here, so even a router that dropped the held qualifier can never seal a
    PERMIT for a held question. A verdict-qualified id that names a row of a
    different verdict is an honest KeyError, not a mismatched record.

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
    resolved_verdict = _normalize_verdict(verdict)

    if decision_id is None:
        # Newest-first is _matching_rows' contract. "The last recorded" means
        # the last, whatever it was — unless a verdict qualifier narrows it
        # ("the last HELD action" ⇒ the newest ABSTAIN, never a PERMIT).
        rows = _matching_rows(store, wanted_fold, resolved_verdict, None, None)
        decision = rows[0] if rows else None
        if decision is None:
            raise KeyError(f"no decisions recorded for tenant: {tenant}")
    else:
        uid = decision_id if isinstance(decision_id, UUID) else UUID(str(decision_id))
        decision = store.get(uid) if hasattr(store, "get") else None
        if decision is None or not _tenant_visible(decision, wanted_fold):
            raise KeyError(f"decision not found for tenant: {decision_id}")
        # A verdict-qualified id must name a row of that verdict — otherwise it
        # is honestly "not found" rather than a record of the wrong kind.
        if resolved_verdict is not None and getattr(decision, "verdict", None) != resolved_verdict:
            raise KeyError(f"decision {decision_id} does not match requested verdict")

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


# ─────────────────────────────────────────────── the "waiting on a human" tools
def _resolved_ids(resolutions: Any, candidate_ids: list[str]) -> set[str]:
    """The subset of ``candidate_ids`` a human has already resolved.

    ``resolutions`` may be an ``EvidenceRecorder``-like object (its
    ``resolved_decision_ids(candidate_ids)`` batch lookup), a plain callable
    ``(ids) -> iterable``, or a concrete set/collection of resolved ids.
    ``None`` (the keyless dev posture, no recorder wired) means nothing is
    known-resolved.

    Fail-OPEN by design: an unreadable resolution source yields the empty set,
    so a genuinely-waiting hold is never HIDDEN by a transient read fault — it
    can only be over-surfaced (a resolved hold shown once more), which an
    operator double-checks rather than misses.
    """
    if resolutions is None:
        return set()
    method = getattr(resolutions, "resolved_decision_ids", None)
    if callable(method):
        try:
            return {str(x) for x in method(candidate_ids)}
        except Exception:  # noqa: BLE001 — resolution is an upgrade, never a dependency
            return set()
    if callable(resolutions):
        try:
            return {str(x) for x in resolutions(candidate_ids)}
        except Exception:  # noqa: BLE001
            return set()
    try:
        return {str(x) for x in resolutions}
    except TypeError:
        return set()


def _held_waiting(
    store: Any, tenant: str, resolutions: Any
) -> tuple[list[Any], datetime | None]:
    """The holds genuinely waiting on a human right now, newest first.

    "Waiting" = verdict ABSTAIN (the store's held), tenant-visible, decided
    within the last seven local days, AND with NO human-resolution record
    sealed against the decision_id (the batch lookup). Returns the surviving
    rows and the UTC lower bound (for the exhibit's provenance).
    """
    since_utc, _, _ = _resolve_window("recent", None, None)  # seven local days
    wanted_fold = tenant.casefold()
    rows = _matching_rows(store, wanted_fold, Verdict.ABSTAIN, since_utc, None)
    candidate_ids = [str(getattr(r, "decision_id", "")) for r in rows]
    resolved = _resolved_ids(resolutions, candidate_ids)
    waiting = [r for r in rows if str(getattr(r, "decision_id", "")) not in resolved]
    return waiting, since_utc


def _held_waiting_row(decision: Any) -> dict[str, Any]:
    """One hold's eye-payload for the act-able queue: id, actor, action, a
    bounded content excerpt, and the decision time. Never spoken."""
    excerpt = getattr(decision, "content_excerpt", None)
    if isinstance(excerpt, str):
        excerpt = excerpt[:_CONTENT_EXCERPT_MAX]
    else:
        excerpt = None
    return {
        "decision_id": str(getattr(decision, "decision_id", "")),
        "agent": _agent_of(decision),
        "action_type": getattr(decision, "action_type", None),
        "content_excerpt": excerpt,
        "at": _iso(getattr(decision, "decided_at", None)),
    }


def held_waiting_rows(
    store: Any,
    tenant: str | None,
    resolutions: Any = None,
) -> list[Any]:
    """The raw Decision rows STILL waiting on a human right now, newest first.

    This is the SINGLE shared query behind every "waiting on a human" surface:
    ``count_held_waiting`` / ``list_held_waiting`` (the answer wire) measure it,
    and the restart-proof REST surfaces (``GET /held``, the vigil headline) map
    it — so the three hold wires can never disagree about what is waiting.
    Definition (see :func:`_held_waiting`): verdict ABSTAIN, tenant-visible,
    decided within the last seven local days, minus any human-sealed ids.
    """
    tenant = _require_tenant(tenant)
    waiting, _ = _held_waiting(store, tenant, resolutions)
    return waiting


def count_held_waiting(
    store: Any,
    tenant: str | None,
    resolutions: Any = None,
) -> dict[str, Any]:
    """How many held decisions are STILL waiting on a human right now.

    Distinct from ``count_decisions(verdict="HELD")``, which is the HISTORICAL
    tally of everything held in a window — resolved or not, presence
    self-abstains included. This is the "need my attention" count: only the
    unresolved ABSTAINs of the last seven local days (see :func:`_held_waiting`).
    A zero is a sealed truth — an empty waiting queue — never an error.

    ``resolutions`` is the resolved-id source (an ``EvidenceRecorder``, a
    callable, or a set of ids); ``None`` treats nothing as resolved.
    """
    tenant = _require_tenant(tenant)
    waiting, since_utc = _held_waiting(store, tenant, resolutions)
    n = len(waiting)

    return {
        "handle": "e1",
        "kind": "count",
        "value": n,
        "spoken": humanize_count(n),
        "unit": "decisions",
        "query": {
            # The tool name is the drafter's cue to speak the present, unresolved
            # register ("waiting for your attention") rather than the historical
            # "held ... recently" prose a windowed held count uses.
            "tool": "count_held_waiting",
            "tenant": tenant,
            # The honest sealed verdict these rows carry.
            "verdict": Verdict.ABSTAIN.value,
            "since": _iso(since_utc),
            "until": None,
            "window_label": None,
            "is_zero": n == 0,
            "is_one": n == 1,
        },
        "anchor_sha256": None,
        "computed_at": datetime.now(UTC).isoformat(),
    }


def list_held_waiting(
    store: Any,
    tenant: str | None,
    resolutions: Any = None,
    limit: int = _HELD_WAITING_SPOKEN_CAP,
) -> dict[str, Any]:
    """Name the held decisions STILL waiting on a human right now.

    Same "waiting" definition as :func:`count_held_waiting`. The exhibit's
    ``spoken`` names up to three agents plus a humanized remainder over the FULL
    waiting set (so the ear is never misled about how many need attention);
    ``value`` caps the spoken tier at ``limit`` (ten). The exhibit ADDITIONALLY
    carries ``rows`` — up to twenty-five ``{decision_id, agent, action_type,
    content_excerpt, at}`` payloads, newest first — the exact act-able queue the
    UI walks beside the voice.
    """
    tenant = _require_tenant(tenant)
    if limit < 0:
        raise ValueError("limit must be non-negative")
    waiting, since_utc = _held_waiting(store, tenant, resolutions)
    total = len(waiting)

    spoken_selection = waiting[:limit]
    value = [
        {
            "decision_id": str(getattr(r, "decision_id", "")),
            "agent": _agent_of(r),
            "verdict": _verdict_str(r),
            "at": _iso(getattr(r, "decided_at", None)),
        }
        for r in spoken_selection
    ]
    # The ear hears the true remainder — names computed over EVERY waiting hold,
    # not just the capped spoken tier, so "and N more" can never undercount how
    # many still need a human.
    spoken = _spoken_row_names([{"agent": _agent_of(r)} for r in waiting])
    rows = [_held_waiting_row(r) for r in waiting[:_HELD_WAITING_ROWS_CAP]]

    return {
        "handle": "e1",
        "kind": "list",
        "value": value,
        "spoken": spoken,
        "rows": rows,
        "unit": "decisions",
        "query": {
            "tool": "list_held_waiting",
            "tenant": tenant,
            "verdict": Verdict.ABSTAIN.value,
            "since": _iso(since_utc),
            "until": None,
            "window_label": None,
            "is_zero": total == 0,
            "is_one": total == 1,
        },
        "anchor_sha256": None,
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


# --------------------------------------------------------------------------- #
# The AGENTS roster buttons — who Tex governs, not what it decided.
#
# Semantics mirror the spoken Begin count (discovery_surface_routes'
# _estate_count) EXACTLY: registry.list_all(), exact-case tenant match,
# excluding SLEEPING/REVOKED — so "how many agents" and the count Tex spoke
# at ignition can never disagree. Kept in lockstep by the shared test
# below rather than an api-layer import (stores must not import routes).
# --------------------------------------------------------------------------- #

_AGENT_NOT_RUNNING = frozenset({"SLEEPING", "REVOKED"})


def _running_agents(registry: Any, tenant: str) -> list[Any]:
    rows = []
    for a in registry.list_all():
        if getattr(a, "tenant_id", None) != tenant:
            continue
        status = getattr(a, "lifecycle_status", None)
        name = getattr(status, "name", None) or str(status or "")
        if name.upper() in _AGENT_NOT_RUNNING:
            continue
        rows.append(a)
    return rows


def count_agents(registry: Any, tenant: str | None) -> dict[str, Any]:
    """How many agents Tex is governing right now — the estate headcount.

    A zero is a sealed truth (an honestly empty estate), never an error.
    """
    tenant = _require_tenant(tenant)
    n = len(_running_agents(registry, tenant))
    return {
        "handle": "e1",
        "kind": "count",
        "value": n,
        "spoken": humanize_count(n),
        "unit": "agents",
        "query": {
            "tool": "count_agents",
            "tenant": tenant,
            "verdict": None,
            "since": None,
            "until": None,
            "window_label": None,
            "is_zero": n == 0,
            "is_one": n == 1,
        },
        "anchor_sha256": None,
        "computed_at": datetime.now(UTC).isoformat(),
    }


def list_agents(registry: Any, tenant: str | None, limit: int = 10) -> dict[str, Any]:
    """Name the governed agents — the roster, spoken as names.

    ``value`` rows carry {agent, status}; ``spoken`` reuses the deterministic
    names summary (up to three named, humanized remainder) so a roster of any
    size stays speech, never a serialized structure.
    """
    tenant = _require_tenant(tenant)
    if limit < 0:
        raise ValueError("limit must be non-negative")
    running = _running_agents(registry, tenant)[:limit]
    value = [
        {
            "agent": str(getattr(a, "name", "") or "") or None,
            "status": (
                getattr(getattr(a, "lifecycle_status", None), "name", None)
                or str(getattr(a, "lifecycle_status", "") or "")
            ),
        }
        for a in running
    ]
    return {
        "handle": "e1",
        "kind": "list",
        "value": value,
        "spoken": _spoken_row_names(value),
        "unit": "agents",
        "query": {
            "tool": "list_agents",
            "tenant": tenant,
            "verdict": None,
            "since": None,
            "until": None,
            "window_label": None,
        },
        "anchor_sha256": None,
        "computed_at": datetime.now(UTC).isoformat(),
    }
