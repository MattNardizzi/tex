"""Deterministic operator semantics over read-tool outputs.

Each operator is a PURE function of the rows it is handed — its value is always
re-derivable from the ``evidence_refs`` it binds. That purity is the load-bearing
honesty property (a future operator that computes something NOT re-derivable from
its bound rows — a TREND/extrapolate — would silently re-import confident-wrongness;
``executor`` enforces the invariant, this module never violates it).

Two currencies flow through a plan:

* :class:`RowSet` — an intermediate: the rows a leaf read (or a ``FILTER`` kept),
  with their aligned evidence refs and the read-tool's honesty metadata
  (tenant scope, fleet-only disclosure, clamp). Never spoken.
* :class:`~tex.presence.gate.queries.Recompute` — a terminal, speakable clause: a
  recomputed value + the exact refs it was computed from + the GATE-authored
  canonical phrasing. Reused verbatim from the gate so the existing compose/verdict
  machinery consumes a plan's output unchanged.

Phrasing discipline (the "gate authors the words" guarantee, preserved): the spoken
noun/qualifier is DERIVED from the plan's structure (its source tool + applied
filters) and the literal values come from the REAL rows — never from model prose.
The brain chose which operators to compose; the gate words the result.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from tex.presence.contract import EvidenceRef
from tex.presence.gate.queries import EVIDENCE_CAP, Recompute
from tex.presence.plan.ir import CompareOp

__all__ = ["RowSet", "rowset_from_leaf", "op_filter", "op_count", "op_exists", "op_list",
           "op_get", "op_absence", "op_time_window", "op_group_by", "op_latest", "op_duration",
           "op_compare", "op_diff_over_window", "op_ratio", "op_top_n", "op_aggregate"]


# ─────────────────────────────────────────────────────────────────────────────
# The intermediate row carrier.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class RowSet:
    """Rows a leaf read (or a FILTER kept), with aligned refs + honesty metadata."""

    rows: tuple[Mapping[str, Any], ...]
    refs: tuple[EvidenceRef, ...]
    source: str
    tenant_scope: str = "all"
    tenant_filter_applied: bool = False
    total: int | None = None          # authoritative full count if the leaf gave one
    fleet_only: bool = False          # rows carry no tenant column → must disclose
    clamped: bool = False             # row list hit the read-tool's MAX_ROWS cap
    complete: bool = False            # rows are a COMPLETE current-state snapshot (provable absence)
    qualifiers: tuple[str, ...] = ()  # human qualifiers from applied filters (phrasing)
    time_basis: bool = False          # rows selected by a recorded timestamp → DERIVED, not SEALED
    window_label: str = ""            # gate-authored description of the resolved time window
    source_refs: tuple[EvidenceRef, ...] = ()  # complete scanned set — witness for a windowed zero
    available: bool = True
    reason: str = ""


# Per-tool projection: where the row list lives, the entity key, the noun.
_LEAF_ROWS: dict[str, str] = {
    "identity.list_agents": "agents",
    "human_decision.recent_decisions": "decisions",
    "discovery.recent_entries": "entries",
    "execution.recent_actions": "actions",
    "evidence.recent_records": "records",
    "monitoring.recent_drift": "events",
    "monitoring.recent_scans": "scans",
}
_LEAF_ENTITY: dict[str, tuple[str, str]] = {
    "identity.get_agent": ("agent", "found"),
    "identity.resolve_agent": ("agent", "found"),
    "human_decision.get_decision": ("decision", "found"),
    "evidence.chain_head": ("head", "present"),
    "discovery.chain_head": ("head", "present"),
    "monitoring.latest_snapshot": ("snapshot", "present"),
}
_LEAF_COUNT: frozenset[str] = frozenset(
    {"execution.action_count", "execution.action_total", "discovery.entry_count",
     "monitoring.drift_count", "human_decision.verdict_count", "human_decision.total",
     "evidence.record_total"}
)
# Tools whose rows are a COMPLETE current-state snapshot (the registry's full list),
# so 'no match' over an UNCLAMPED read is a PROVABLE absence — unlike the append-only
# tails (recent_*) which are windowed and can never prove a 'no' on their own.
_COMPLETE_SNAPSHOT_TOOLS: frozenset[str] = frozenset({"identity.list_agents"})
# Tools whose read is NOT per-tenant filtered (decision/action/evidence-chain carry no
# tenant column; chain_head / latest_snapshot return the GLOBAL latest). A leaf over one
# of these is fleet-wide and MUST disclose 'across all tenants'. The read-tool list/count
# variants already report tenant_scope='fleet', but the entity variants (get_decision,
# chain_head, latest_snapshot) don't — so we force fleet scope here for ALL of them.
_FLEET_SOURCE_TOOLS: frozenset[str] = frozenset({
    "human_decision.get_decision", "human_decision.recent_decisions", "human_decision.verdict_count",
    "human_decision.total", "execution.recent_actions", "execution.action_count",
    "execution.action_total", "evidence.chain_head", "evidence.recent_records",
    "evidence.record_total", "discovery.chain_head", "monitoring.latest_snapshot",
})
_NOUN: dict[str, tuple[str, str]] = {
    "identity.list_agents": ("agent", "agents"),
    "identity.get_agent": ("agent", "agents"),
    "identity.resolve_agent": ("agent", "agents"),
    "human_decision.recent_decisions": ("decision", "decisions"),
    "human_decision.verdict_count": ("decision", "decisions"),
    "human_decision.total": ("decision", "decisions"),
    "evidence.record_total": ("evidence record", "evidence records"),
    "execution.action_total": ("action", "actions"),
    "discovery.recent_entries": ("discovery event", "discovery events"),
    "discovery.entry_count": ("discovery event", "discovery events"),
    "execution.recent_actions": ("action", "actions"),
    "execution.action_count": ("action", "actions"),
    "evidence.recent_records": ("evidence record", "evidence records"),
    "monitoring.recent_drift": ("drift event", "drift events"),
    "monitoring.drift_count": ("drift event", "drift events"),
}


def _noun(source: str, n: int) -> str:
    sing, plur = _NOUN.get(source, ("record", "records"))
    return sing if n == 1 else plur


def _disclose_fleet(phrase: str, fleet_only: bool) -> str:
    """Append the honest fleet-scope qualifier so a fleet-wide count never sounds
    tenant-scoped (the same disclosure the hand-written queries hardcode)."""
    if not fleet_only:
        return phrase
    return (phrase[:-1] if phrase.endswith(".") else phrase) + " across all tenants."


# A brain-supplied lookup literal may be ECHOED in the spoken criterion ("matching X"),
# but it must never become a vector for arbitrary prose or a sentence that reads as Tex's
# own assertion. So a literal is rendered ONLY as a short, single-line, bounded token;
# anything else collapses to a generic phrase. The factual value (count / yes / no) is
# always the gate's recompute regardless — this only bounds the spoken *criterion echo*.
_SAFE_CRITERION_RE = re.compile(r"\A[\w][\w .,:@/+\-]{0,39}\Z")
_SAFE_QUALIFIER_RE = re.compile(r"\A[\w][\w \-]{0,30}\Z")


def _safe_criterion(value: Any) -> str:
    """A bounded, quoted rendering of a brain literal, or a generic phrase when it is not
    a short simple token — so the model can never speak prose through the criterion."""
    token = str(value).strip()
    return f"{token!r}" if _SAFE_CRITERION_RE.match(token) else "your criteria"


def _safe_qualifier(value: Any) -> str | None:
    """A sanitized inline qualifier (e.g. 'revoked') for phrasing, or None to drop it — an
    unsafe/long value is simply not spoken rather than injected into the count phrase.
    None in → None out (str(None) would otherwise speak the literal word 'none')."""
    if value is None:
        return None
    token = str(value).strip().casefold()
    return token if _SAFE_QUALIFIER_RE.match(token) else None


# ─────────────────────────────────────────────────────────────────────────────
# Leaf normalisation — read-tool output → RowSet.
# ─────────────────────────────────────────────────────────────────────────────
def rowset_from_leaf(tool_name: str, value: Any, refs: tuple[EvidenceRef, ...]) -> RowSet:
    """Normalise a read-tool's ``(value, refs)`` into a :class:`RowSet`.

    An unrecognised tool shape, or an ``available=False`` value, degrades to an
    unavailable RowSet so the downstream operator abstains — never guesses."""
    if not isinstance(value, Mapping):
        return RowSet((), (), tool_name, available=False, reason="non-mapping-tool-value")
    if value.get("available") is False:
        return RowSet((), (), tool_name, available=False, reason=str(value.get("reason", "unavailable")))

    tenant_scope = str(value.get("tenant_scope", "all"))
    applied = bool(value.get("tenant_filter_applied", False))
    # Force fleet scope for sources the read-tool doesn't tenant-filter (some entity tools
    # omit tenant_scope and would otherwise default to 'all' → a fleet fact sounding
    # tenant-scoped). This is the plan-layer defence for read_tools' entity-get omission.
    fleet_only = tenant_scope == "fleet" or tool_name in _FLEET_SOURCE_TOOLS

    # Count-style leaf: authoritative scalar count + a witness sample of refs.
    if tool_name in _LEAF_COUNT and "count" in value:
        return RowSet((), tuple(refs), tool_name, tenant_scope, applied,
                      total=int(value["count"]), fleet_only=fleet_only)

    # Single-entity leaf: present → one row; absent → zero rows (NOT an error).
    if tool_name in _LEAF_ENTITY:
        key, present_flag = _LEAF_ENTITY[tool_name]
        if value.get(present_flag):
            obj = value.get(key)
            rows = (obj,) if isinstance(obj, Mapping) else ()
            return RowSet(rows, tuple(refs)[: len(rows)], tool_name, tenant_scope, applied,
                          total=len(rows), fleet_only=fleet_only)
        return RowSet((), (), tool_name, tenant_scope, applied, total=0, fleet_only=fleet_only,
                      reason=str(value.get("reason", "not-found")))

    # Row-list leaf.
    rows_key = _LEAF_ROWS.get(tool_name)
    rows_val = value.get(rows_key) if rows_key else None
    if isinstance(rows_val, Sequence) and not isinstance(rows_val, (str, bytes)):
        rows = tuple(r for r in rows_val if isinstance(r, Mapping))
        cap = value.get("limit_clamped_to")
        # A big requested limit over a SMALL store truncates NOTHING. Only treat the read as
        # clamped/incomplete if it actually returned a full cap-sized page (so a count over it
        # would be a lower bound). Previously a brain asking for limit:1000 over a 3-row store
        # wrong-abstained 'how many decisions in total'.
        truncated = cap is not None and len(rows) >= int(cap)
        complete = tool_name in _COMPLETE_SNAPSHOT_TOOLS and not truncated
        return RowSet(rows, tuple(refs), tool_name, tenant_scope, applied,
                      total=(None if truncated else len(rows)), fleet_only=fleet_only,
                      clamped=truncated, complete=complete)

    return RowSet((), tuple(refs), tool_name, tenant_scope, applied, available=False,
                  reason="unrecognized-tool-shape")


# ─────────────────────────────────────────────────────────────────────────────
# Predicate evaluation for FILTER / EXISTS.
# ─────────────────────────────────────────────────────────────────────────────
def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _predicate(row_val: Any, op: CompareOp, target: Any) -> bool:
    if op is CompareOp.EQ:
        return str(row_val).casefold() == str(target).casefold()
    if op is CompareOp.NE:
        return str(row_val).casefold() != str(target).casefold()
    if op is CompareOp.CONTAINS:
        return str(target).casefold() in str(row_val).casefold()
    if op is CompareOp.IN:
        if not isinstance(target, (list, tuple)):
            return False
        return str(row_val).casefold() in {str(x).casefold() for x in target}
    a, b = _as_float(row_val), _as_float(target)
    if a is None or b is None:
        return False
    if op is CompareOp.GT:
        return a > b
    if op is CompareOp.GTE:
        return a >= b
    if op is CompareOp.LT:
        return a < b
    if op is CompareOp.LTE:
        return a <= b
    return False


def _bad(source: str, reason: str) -> Recompute:
    return Recompute(False, reason=reason)


# ─────────────────────────────────────────────────────────────────────────────
# Operators.
# ─────────────────────────────────────────────────────────────────────────────
def op_filter(rs: RowSet, args: Mapping[str, Any]) -> RowSet:
    """Keep rows where (field, op, value) holds; refs stay aligned to kept rows.

    Appends a human qualifier for the phrasing layer when the filter is an equality
    on a recognisable field (so "FILTER status=REVOKED → COUNT" speaks "revoked
    agents", gate-authored, not model prose)."""
    if not rs.available:
        return rs
    field_name = args.get("field")
    op_raw = args.get("op")
    target = args.get("value")
    if not isinstance(field_name, str) or not isinstance(op_raw, str):
        return RowSet((), (), rs.source, rs.tenant_scope, rs.tenant_filter_applied,
                      available=False, reason="filter-bad-args")
    try:
        cop = CompareOp(op_raw)
    except ValueError:
        return RowSet((), (), rs.source, rs.tenant_scope, rs.tenant_filter_applied,
                      available=False, reason=f"filter-bad-op:{op_raw}")

    aligned = len(rs.refs) == len(rs.rows)
    kept_rows: list[Mapping[str, Any]] = []
    kept_refs: list[EvidenceRef] = []
    for i, row in enumerate(rs.rows):
        if _predicate(row.get(field_name), cop, target):
            kept_rows.append(row)
            if aligned:
                kept_refs.append(rs.refs[i])

    qualifier = _safe_qualifier(target) if cop is CompareOp.EQ and target is not None else None
    qualifiers = rs.qualifiers + ((qualifier,) if qualifier else ())
    return RowSet(
        tuple(kept_rows), tuple(kept_refs), rs.source, rs.tenant_scope,
        rs.tenant_filter_applied, total=len(kept_rows), fleet_only=rs.fleet_only,
        clamped=rs.clamped, complete=rs.complete, qualifiers=qualifiers,
    )


def op_count(rs: RowSet) -> Recompute:
    """Count rows. Seals a POSITIVE count with its witness refs; a zero count
    abstains (proving absence needs the completeness proof of ABSENCE_SCAN, not an
    empty query — the contract's "evidence empty iff ABSTAIN" rule)."""
    if not rs.available:
        return _bad(rs.source, f"count-source-unavailable:{rs.reason}")
    n = rs.total if rs.total is not None else len(rs.rows)
    if n == 0:
        # A windowed zero over a COMPLETE snapshot IS provable ('none registered yesterday'),
        # witnessed by the full scanned set — say so instead of an unhelpful abstain.
        if rs.time_basis and rs.source_refs:
            phrase = _disclose_fleet(f"None {rs.window_label} (by recorded time).", rs.fleet_only)
            return Recompute(True, value=0, evidence=rs.source_refs, canonical_phrase=phrase,
                             correctness_floor=1.0, coverage_mode="recorded-timestamp",
                             reason="derived:time_count=0")
        return _bad(rs.source, "zero-count-needs-absence-proof")
    if rs.clamped:
        return _bad(rs.source, "count-clamped-incomplete")  # value is a lower bound — don't seal
    if not rs.refs:
        return _bad(rs.source, "count-no-evidence-witness")
    noun = _noun(rs.source, n)
    if rs.time_basis:  # a windowed count is real but DERIVED — disclose the recorded-time basis
        was = "was" if n == 1 else "were"
        phrase = _disclose_fleet(f"{n} {noun} {was} {rs.window_label} (by recorded time).", rs.fleet_only)
        return Recompute(True, value=n, evidence=rs.refs, canonical_phrase=phrase,
                         correctness_floor=1.0, coverage_mode="recorded-timestamp",
                         reason=f"derived:time_count={n};{rs.window_label}")
    qual = (" ".join(q for q in rs.qualifiers if q) + " ") if any(rs.qualifiers) else ""
    phrase = f"There {'is' if n == 1 else 'are'} {n} {qual}{noun}."
    phrase = _disclose_fleet(phrase, rs.fleet_only)
    return Recompute(True, value=n, evidence=rs.refs, canonical_phrase=phrase,
                     reason=f"sealed:plan_count={n}")


def op_exists(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    """Is there ≥1 matching row? A positive EXISTS seals; a negative EXISTS abstains
    (a sealed "no" requires the completeness proof of ABSENCE_SCAN — deferred)."""
    if not rs.available:
        return _bad(rs.source, f"exists-source-unavailable:{rs.reason}")
    n = rs.total if rs.total is not None else len(rs.rows)
    if n <= 0:
        return _bad(rs.source, "exists-false-needs-absence-proof")
    if not rs.refs:
        return _bad(rs.source, "exists-no-evidence-witness")
    qual = (" ".join(q for q in rs.qualifiers if q) + " ") if any(rs.qualifiers) else ""
    phrase = f"Yes — there {'is' if n == 1 else 'are'} {n} {qual}{_noun(rs.source, n)}."
    phrase = _disclose_fleet(phrase, rs.fleet_only)
    return Recompute(True, value=True, evidence=rs.refs[:1], canonical_phrase=phrase,
                     reason=f"sealed:exists={n}")


def op_list(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    """The first N rows, projected to a named field, each value read from the REAL
    row and bound to its ref. ("list three agents" → the actual agent names.)"""
    if not rs.available:
        return _bad(rs.source, f"list-source-unavailable:{rs.reason}")
    if len(rs.refs) != len(rs.rows):
        return _bad(rs.source, "list-refs-misaligned")
    field_name = args.get("field")
    limit_raw = args.get("limit")
    try:
        k = int(limit_raw) if limit_raw is not None else len(rs.rows)
    except (TypeError, ValueError):
        k = len(rs.rows)
    k = max(0, min(k, len(rs.rows)))
    if k == 0:
        return _bad(rs.source, "list-empty-needs-absence-proof")

    labels: list[str] = []
    for row in rs.rows[:k]:
        if isinstance(field_name, str) and field_name in row:
            labels.append(str(row.get(field_name)))
        else:
            ident = row.get("name") or row.get("agent_id") or row.get("id")
            if ident is None:  # no row-derived label → abstain, never speak a placeholder
                return _bad(rs.source, "list-row-without-identifier")
            labels.append(str(ident))
    refs = rs.refs[:k]
    noun = _noun(rs.source, k)
    joined = ", ".join(labels)
    phrase = (f"{k} {noun} (across all tenants): {joined}." if rs.fleet_only
              else f"{k} {noun}: {joined}.")
    return Recompute(True, value=labels, evidence=refs, canonical_phrase=phrase,
                     reason=f"sealed:plan_list={k}")


def op_get(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    """One entity → a named field's value, read from the real row."""
    if not rs.available:
        return _bad(rs.source, f"get-source-unavailable:{rs.reason}")
    # A count-style leaf has no rows but a scalar total; GET of its count/total → the count
    # (tolerates the brain doing record_total → GET(total) instead of → COUNT).
    if not rs.rows and rs.total is not None:
        field_name = args.get("field")
        if not isinstance(field_name, str) or field_name.strip().lower() in ("total", "count", "value", "number"):
            return op_count(rs)
        return _bad(rs.source, "get-on-count-leaf-without-rows")
    if not rs.rows or not rs.refs:
        return _bad(rs.source, "get-not-found")
    row, ref = rs.rows[0], rs.refs[0]
    field_name = args.get("field")
    if not isinstance(field_name, str) or field_name not in row:
        return _bad(rs.source, "get-field-missing")
    val = row.get(field_name)
    ident = str(row.get("name") or row.get("agent_id") or row.get("id") or "").strip()
    noun = _NOUN.get(rs.source, ("record", "records"))[0]
    subject = f"{noun.capitalize()} {ident}" if ident else f"The {noun}"
    phrase = f"{subject} {field_name.replace('_', ' ')} is {val}."
    phrase = _disclose_fleet(phrase, rs.fleet_only)  # fleet sources must not sound tenant-scoped
    if rs.time_basis:  # e.g. the value of a LATEST-selected row's timestamp → DERIVED
        return Recompute(True, value=val, evidence=(ref,),
                         canonical_phrase=phrase[:-1] + " (by recorded time).",
                         correctness_floor=1.0, coverage_mode="recorded-timestamp",
                         reason=f"derived:plan_get_{field_name}={val}")
    return Recompute(True, value=val, evidence=(ref,), canonical_phrase=phrase,
                     reason=f"sealed:plan_get_{field_name}={val}")


def op_absence(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    """Membership over a COMPLETE current-state list — the provable-absence operator.

    Seals BOTH directions over a fully-scanned set: 'yes' binds the matching rows;
    'no' binds the FULL scanned set as the completeness witness (the proof that none
    of the N known rows matches). Abstains when the source is not provably complete —
    a windowed/clamped read can never prove a 'no' (you can't see what you didn't read).
    This is what lets Tex answer "do I have an Okta agent?" with a sealed "No", not a
    guess. (Time-window absence over the append-only ledgers is a different, harder
    case — see the signed-time-anchor track.)"""
    if not rs.available:
        return _bad(rs.source, f"absence-source-unavailable:{rs.reason}")
    if not rs.complete:
        return _bad(rs.source, "absence-source-not-complete")  # can't prove a 'no' → abstain

    field_name = args.get("field")
    op_raw = args.get("op")
    target = args.get("value")
    if not isinstance(field_name, str) or not isinstance(op_raw, str):
        return _bad(rs.source, "absence-bad-args")
    try:
        cop = CompareOp(op_raw)
    except ValueError:
        return _bad(rs.source, f"absence-bad-op:{op_raw}")

    aligned = len(rs.refs) == len(rs.rows)
    match_rows: list[Mapping[str, Any]] = []
    match_refs: list[EvidenceRef] = []
    for i, row in enumerate(rs.rows):
        if _predicate(row.get(field_name), cop, target):
            match_rows.append(row)
            if aligned:
                match_refs.append(rs.refs[i])

    sing, plur = _NOUN.get(rs.source, ("record", "records"))
    criterion = _safe_criterion(target)  # bounded echo — never the model's prose
    if match_rows:  # present → SEALED yes, binding the matching rows
        if not match_refs:
            return _bad(rs.source, "absence-match-no-witness")
        n = len(match_rows)
        # names are read from the REAL matched rows; drop any row that has no identifier
        # rather than speak a placeholder.
        names = ", ".join(
            s for s in (str(r.get("name") or r.get("id") or "").strip() for r in match_rows[:5]) if s
        )
        suffix = f": {names}" if names else ""
        phrase = f"Yes — you have {n} {sing if n == 1 else plur} matching {criterion}{suffix}."
        if rs.fleet_only:
            phrase = phrase[:-1] + " (across all tenants)."
        return Recompute(True, value=True, evidence=tuple(match_refs[:EVIDENCE_CAP]),
                         canonical_phrase=phrase, reason=f"sealed:membership_present={n}")

    # absent → SEALED 'no', but ONLY over a complete, non-empty scanned set (the witness).
    if not rs.rows or not rs.refs:
        return _bad(rs.source, "absence-no-completeness-witness")  # empty set → no witness
    total = len(rs.rows)
    phrase = f"No — none of your {total} {plur} matches {criterion}."
    if rs.fleet_only:
        phrase = phrase[:-1] + " (across all tenants)."
    return Recompute(True, value=False, evidence=rs.refs[:EVIDENCE_CAP],
                     canonical_phrase=phrase, reason=f"sealed:membership_absent;scanned={total}")


# ─────────────────────────────────────────────────────────────────────────────
# TIME_WINDOW — select rows whose recorded timestamp falls in a resolved window.
# The EXECUTOR resolves relative tokens (today/yesterday/N_days_ago/past_N_days/ISO)
# against a single injected reference_now; the brain supplies tokens/ISO only as lookup
# keys, never an asserted absolute date. Time answers are DERIVED ('by recorded
# timestamp') — the timestamps are real but OUTSIDE the tamper-evident hash, so they can
# never be SEALED until the signed-time-anchor track lands.
# ─────────────────────────────────────────────────────────────────────────────
_TIMESTAMP_FIELDS = frozenset({
    "registered_at", "recorded_at", "decided_at", "appended_at", "discovered_at", "updated_at",
})
_FIELD_VERB = {
    "registered_at": "registered", "recorded_at": "recorded", "decided_at": "decided",
    "appended_at": "appended", "discovered_at": "discovered", "updated_at": "updated",
}
_DAYS_AGO_RE = re.compile(r"\A(\d+)[ _]days?[ _]ago\Z", re.I)
_PAST_DAYS_RE = re.compile(r"\A(?:past|last|in[ _]the[ _]past)[ _](\d+)[ _]days?\Z", re.I)


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)


def _day_bounds(dt: datetime) -> tuple[datetime, datetime]:
    start = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


def _resolve_token(token: Any, now: datetime) -> tuple[datetime, datetime] | None:
    """Resolve a relative token / ISO value to the [lo, hi) interval it denotes."""
    if token is None:
        return None
    t = str(token).strip().lower()
    if t == "today":
        return _day_bounds(now)
    if t == "yesterday":
        start, _ = _day_bounds(now)
        return start - timedelta(days=1), start
    m = _DAYS_AGO_RE.match(t)
    if m:
        return _day_bounds(now - timedelta(days=int(m.group(1))))
    m = _PAST_DAYS_RE.match(t)
    if m:
        return now - timedelta(days=int(m.group(1))), now
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", t):  # a bare calendar day
        d = _parse_dt(t)
        return _day_bounds(d) if d else None
    dt = _parse_dt(t)
    return (dt, dt) if dt is not None else None  # an instant → a point boundary


def _resolve_window(args: Mapping[str, Any], now: datetime) -> tuple[datetime | None, datetime | None] | None:
    """Resolve the operator args into [after, before) bounds (None = unbounded that side)."""
    op = str(args.get("op", "")).strip().lower()
    if op == "on":
        return _resolve_token(args.get("on"), now)
    if op == "after":
        r = _resolve_token(args.get("after"), now)
        return (r[0], None) if r else None
    if op == "before":
        r = _resolve_token(args.get("before"), now)
        return (None, r[1]) if r else None
    if op == "between":
        a = _resolve_token(args.get("after"), now)
        b = _resolve_token(args.get("before"), now)
        return (a[0], b[1]) if a and b else None
    return None


def _fmt_day(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def _window_label(field: str, args: Mapping[str, Any], after: datetime | None, before: datetime | None) -> str:
    verb = _FIELD_VERB.get(field, f"with {field.replace('_', ' ')}")
    op = str(args.get("op", "")).strip().lower()
    if op == "on":
        on = str(args.get("on", "")).strip().lower()
        w = on if on in ("today", "yesterday") else (f"on {_fmt_day(after)}" if after else "on that day")
    elif op == "after":
        w = f"since {_fmt_day(after)}" if after else "since then"
    elif op == "before":
        w = f"before {_fmt_day(before)}" if before else "before then"
    elif op == "between" and after and before:
        w = f"between {_fmt_day(after)} and {_fmt_day(before)}"
    else:
        w = "in that window"
    return f"{verb} {w}"


def op_time_window(rs: RowSet, args: Mapping[str, Any], *, reference_now: datetime) -> RowSet:
    """Keep rows whose timestamp ``field`` falls in the resolved window. Pure row-level
    filter (kept rows ⊆ input); stamps a DERIVED 'by recorded timestamp' basis. Rejects a
    count-style leaf (no per-row timestamp) and abstains on an incomplete tail window."""
    if not rs.available:
        return rs
    if not rs.rows and rs.total is not None:  # a count-style leaf has no rows to filter
        return RowSet((), (), rs.source, available=False, reason="time-window-needs-rows")
    field_name = args.get("field")
    if not isinstance(field_name, str) or field_name not in _TIMESTAMP_FIELDS:
        return RowSet((), (), rs.source, available=False, reason="time-window-bad-field")
    win = _resolve_window(args, reference_now)
    if win is None:
        return RowSet((), (), rs.source, available=False, reason="time-window-bad-args")
    after, before = win

    aligned = len(rs.refs) == len(rs.rows)
    kept_rows: list[Mapping[str, Any]] = []
    kept_refs: list[EvidenceRef] = []
    oldest_seen: datetime | None = None
    for i, row in enumerate(rs.rows):
        ts = _parse_dt(row.get(field_name))
        if ts is None:
            continue
        if oldest_seen is None or ts < oldest_seen:
            oldest_seen = ts
        if (after is None or ts >= after) and (before is None or ts < before):
            kept_rows.append(row)
            if aligned:
                kept_refs.append(rs.refs[i])

    # Incomplete-window guard: over a windowed tail (not a complete snapshot) whose lower
    # bound predates the oldest row we could even see, older matches may have been dropped
    # → the count would be a lower bound, not the truth. Abstain rather than under-report.
    if (not rs.complete) and after is not None and oldest_seen is not None and after < oldest_seen:
        return RowSet((), (), rs.source, available=False, reason="time-window-incomplete-tail")

    return RowSet(
        tuple(kept_rows), tuple(kept_refs), rs.source, rs.tenant_scope,
        rs.tenant_filter_applied, total=len(kept_rows), fleet_only=rs.fleet_only,
        clamped=rs.clamped, complete=False, qualifiers=rs.qualifiers,
        time_basis=True, window_label=_window_label(field_name, args, after, before),
        # carry the complete scanned set so a windowed ZERO can still be witnessed
        source_refs=(rs.refs[:EVIDENCE_CAP] if rs.complete else ()),
    )


# ─────────────────────────────────────────────────────────────────────────────
# GROUP_BY — distribution of rows by a key (owner / status / trust_tier / …).
# SEALED over a complete unclamped snapshot; DERIVED if windowed; abstain if clamped.
# Each bucket's value is re-derivable from the rows bound to it — pure recompute.
# ─────────────────────────────────────────────────────────────────────────────
def op_group_by(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    if not rs.available:
        return _bad(rs.source, f"group-source-unavailable:{rs.reason}")
    if not rs.rows and rs.total is not None:  # count-style leaf: nothing to group
        return _bad(rs.source, "group-by-needs-rows")
    if rs.clamped:
        return _bad(rs.source, "group-by-clamped-incomplete")
    field_name = args.get("field")
    if not isinstance(field_name, str):
        return _bad(rs.source, "group-by-bad-field")

    aligned = len(rs.refs) == len(rs.rows)
    buckets: dict[str, list] = {}
    for i, row in enumerate(rs.rows):
        if field_name not in row:
            return _bad(rs.source, "group-by-missing-field")
        bucket = buckets.setdefault(str(row.get(field_name)), [0, []])
        bucket[0] += 1
        if aligned:
            bucket[1].append(rs.refs[i])
    if not buckets:
        return _bad(rs.source, "group-by-empty")

    items = sorted(buckets.items(), key=lambda kv: kv[1][0], reverse=True)
    try:
        limit_groups = int(args["limit_groups"]) if args.get("limit_groups") is not None else None
    except (TypeError, ValueError):
        limit_groups = None
    other = 0
    if limit_groups is not None and limit_groups > 0 and len(items) > limit_groups:
        other = sum(v[0] for _, v in items[limit_groups:])
        items = items[:limit_groups]
    dist = {k: v[0] for k, v in items}
    if other:
        dist["other"] = other  # so the buckets still reconcile to the total
    refs = tuple(ref for _, v in items for ref in v[1])[:EVIDENCE_CAP]
    if not refs:
        return _bad(rs.source, "group-by-no-witness")

    _, plur = _NOUN.get(rs.source, ("record", "records"))
    parts = ", ".join(f"{k}: {c}" for k, c in dist.items())
    phrase = _disclose_fleet(f"{plur.capitalize()} by {field_name.replace('_', ' ')}: {parts}.", rs.fleet_only)
    if rs.time_basis:
        return Recompute(True, value=dist, evidence=refs, canonical_phrase=phrase[:-1] + " (by recorded time).",
                         correctness_floor=1.0, coverage_mode="recorded-timestamp",
                         reason=f"derived:group_by_{field_name}")
    return Recompute(True, value=dist, evidence=refs, canonical_phrase=phrase,
                     reason=f"sealed:group_by_{field_name}")


# ─────────────────────────────────────────────────────────────────────────────
# TOP_N — the largest groups of rows by a RECORDED key ("which owner has the most
# agents", "which agent acted the most"). GROUP_BY's honesty rules apply verbatim
# (clamped → abstain: a ranking over a truncated read can be flat wrong; missing
# field → abstain; time-windowed rows → DERIVED). Ties at the cutoff are ALL spoken —
# announcing a single "most" when two groups tie would be a confident wrong.
# ─────────────────────────────────────────────────────────────────────────────
def op_top_n(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    if not rs.available:
        return _bad(rs.source, f"top-n-source-unavailable:{rs.reason}")
    if not rs.rows and rs.total is not None:  # count-style leaf: nothing to rank
        return _bad(rs.source, "top-n-needs-rows")
    if rs.clamped:
        return _bad(rs.source, "top-n-clamped-incomplete")  # ranking over a truncated read lies
    field_name = args.get("field")
    if not isinstance(field_name, str):
        return _bad(rs.source, "top-n-bad-field")
    try:
        k = int(args["limit"]) if args.get("limit") is not None else 1
    except (TypeError, ValueError):
        k = 1
    if k <= 0:
        return _bad(rs.source, "top-n-bad-limit")

    aligned = len(rs.refs) == len(rs.rows)
    buckets: dict[str, list] = {}
    for i, row in enumerate(rs.rows):
        if field_name not in row:
            return _bad(rs.source, "top-n-missing-field")
        bucket = buckets.setdefault(str(row.get(field_name)), [0, []])
        bucket[0] += 1
        if aligned:
            bucket[1].append(rs.refs[i])
    if not buckets:
        return _bad(rs.source, "top-n-empty")

    # Deterministic ranking: by count desc, then key — so equal runs speak identically.
    items = sorted(buckets.items(), key=lambda kv: (-kv[1][0], kv[0]))
    cutoff = min(k, len(items))
    # Extend through ties at the cutoff: every group with the k-th group's count is included.
    while cutoff < len(items) and items[cutoff][1][0] == items[cutoff - 1][1][0]:
        cutoff += 1
    top = items[:cutoff]
    refs = tuple(ref for _, v in top for ref in v[1])[:EVIDENCE_CAP]
    if not refs:
        return _bad(rs.source, "top-n-no-witness")

    total = len(rs.rows)
    dist = {key: v[0] for key, v in top}
    _, plur = _NOUN.get(rs.source, ("record", "records"))
    label = field_name.replace("_", " ")
    if len(top) == 1:
        key, (count, _) = top[0]
        phrase = f"Most {plur} by {label}: {key} ({count} of {total})."
    else:
        parts = ", ".join(f"{key}: {c}" for key, c in dist.items())
        phrase = f"Top {plur} by {label}: {parts} (of {total})."
    phrase = _disclose_fleet(phrase, rs.fleet_only)
    if rs.time_basis:
        return Recompute(True, value=dist, evidence=refs,
                         canonical_phrase=phrase[:-1] + " (by recorded time).",
                         correctness_floor=1.0, coverage_mode="recorded-timestamp",
                         reason=f"derived:top_n_{field_name}")
    return Recompute(True, value=dist, evidence=refs, canonical_phrase=phrase,
                     reason=f"sealed:top_n_{field_name}")


# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATE — avg/min/max/sum of a RECORDED numeric field over rows. Pure: the value
# is arithmetic over exactly the rows bound as evidence. Strict by design: EVERY row
# must carry a numeric value for the field, or the operator abstains — an average
# that silently skips rows is a confident wrong. Timestamps are not numbers here
# (LATEST/DURATION own time); a clamped read abstains (aggregate over a truncated
# set misstates the population).
# ─────────────────────────────────────────────────────────────────────────────
_AGG_KINDS = frozenset({"avg", "min", "max", "sum"})
_AGG_WORD = {"avg": "average", "min": "lowest", "max": "highest", "sum": "total"}


def op_aggregate(rs: RowSet, args: Mapping[str, Any]) -> Recompute:
    if not rs.available:
        return _bad(rs.source, f"aggregate-source-unavailable:{rs.reason}")
    if not rs.rows and rs.total is not None:
        return _bad(rs.source, "aggregate-needs-rows")
    if rs.clamped:
        return _bad(rs.source, "aggregate-clamped-incomplete")
    if not rs.rows:
        return _bad(rs.source, "aggregate-empty-needs-rows")
    if len(rs.refs) != len(rs.rows):
        return _bad(rs.source, "aggregate-refs-misaligned")
    field_name = args.get("field")
    agg = str(args.get("agg", "")).strip().lower()
    if not isinstance(field_name, str) or field_name in _TIMESTAMP_FIELDS:
        return _bad(rs.source, "aggregate-bad-field")
    if agg not in _AGG_KINDS:
        return _bad(rs.source, f"aggregate-bad-agg:{agg}")

    values: list[float] = []
    for row in rs.rows:
        if field_name not in row:
            return _bad(rs.source, "aggregate-missing-field")
        v = row.get(field_name)
        num = _as_float(v)
        if num is None or isinstance(v, bool):
            return _bad(rs.source, "aggregate-non-numeric-field")
        values.append(num)

    if agg == "avg":
        result = sum(values) / len(values)
    elif agg == "min":
        result = min(values)
    elif agg == "max":
        result = max(values)
    else:
        result = sum(values)
    # Speak ints as ints; trim floats to at most 4 decimals (pure formatting, not rounding
    # the recomputed value away — `value` carries the full-precision result).
    spoken = str(int(result)) if float(result).is_integer() else f"{result:.4f}".rstrip("0").rstrip(".")

    n = len(rs.rows)
    _, plur = _NOUN.get(rs.source, ("record", "records"))
    qual = (" ".join(q for q in rs.qualifiers if q) + " ") if any(rs.qualifiers) else ""
    label = field_name.replace("_", " ")
    phrase = f"The {_AGG_WORD[agg]} {label} across {n} {qual}{plur} is {spoken}."
    phrase = _disclose_fleet(phrase, rs.fleet_only)
    evidence = rs.refs[:EVIDENCE_CAP]
    if rs.time_basis:
        return Recompute(True, value=result, evidence=evidence,
                         canonical_phrase=phrase[:-1] + " (by recorded time).",
                         correctness_floor=1.0, coverage_mode="recorded-timestamp",
                         reason=f"derived:aggregate_{agg}_{field_name}={spoken}")
    return Recompute(True, value=result, evidence=evidence, canonical_phrase=phrase,
                     reason=f"sealed:aggregate_{agg}_{field_name}={spoken}")


# ─────────────────────────────────────────────────────────────────────────────
# LATEST — select the single most-recent row by a timestamp field (a 1-row RowSet,
# for DURATION/GET to read). DERIVED + complete=False: a tail's max is the most-recent
# SEEN row, never a provable 'last ever'.
# ─────────────────────────────────────────────────────────────────────────────
def op_latest(rs: RowSet, args: Mapping[str, Any]) -> RowSet:
    if not rs.available:
        return rs
    if not rs.rows and rs.total is not None:
        return RowSet((), (), rs.source, available=False, reason="latest-needs-rows")
    field_name = args.get("ordering_field")
    if not isinstance(field_name, str) or field_name not in _TIMESTAMP_FIELDS:
        return RowSet((), (), rs.source, available=False, reason="latest-bad-ordering-field")
    aligned = len(rs.refs) == len(rs.rows)
    best_i: int | None = None
    best_dt: datetime | None = None
    for i, row in enumerate(rs.rows):
        ts = _parse_dt(row.get(field_name))
        if ts is None:
            continue
        if best_dt is None or ts > best_dt:
            best_dt, best_i = ts, i
    if best_i is None:
        return RowSet((), (), rs.source, available=False, reason="latest-no-timestamp")
    return RowSet(
        (rs.rows[best_i],), (rs.refs[best_i],) if aligned else (), rs.source,
        rs.tenant_scope, rs.tenant_filter_applied, total=1, fleet_only=rs.fleet_only,
        complete=False, time_basis=True, window_label=f"most recent by {field_name.replace('_', ' ')}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# DURATION — elapsed time from a single row's timestamp to reference_now. Always
# DERIVED (anchored to an unsealed timestamp). A scalar-from-one-row projection,
# never an aggregate or a forecast.
# ─────────────────────────────────────────────────────────────────────────────
def op_duration(rs: RowSet, args: Mapping[str, Any], *, reference_now: datetime) -> Recompute:
    if not rs.available:
        return _bad(rs.source, f"duration-source-unavailable:{rs.reason}")
    if len(rs.rows) != 1 or not rs.refs:
        return _bad(rs.source, "duration-needs-single-timestamped-row")
    field_name = args.get("field")
    if not isinstance(field_name, str) or field_name not in _TIMESTAMP_FIELDS:
        return _bad(rs.source, "duration-bad-field")
    ts = _parse_dt(rs.rows[0].get(field_name))
    if ts is None:
        return _bad(rs.source, "duration-no-timestamp")
    seconds = max(0.0, (reference_now - ts).total_seconds())  # clamp clock skew

    days, hours, minutes = seconds / 86400, seconds / 3600, seconds / 60
    if days >= 1:
        human = f"{int(days)} day{'s' if int(days) != 1 else ''}"
    elif hours >= 1:
        human = f"{int(hours)} hour{'s' if int(hours) != 1 else ''}"
    else:
        human = f"{int(minutes)} minute{'s' if int(minutes) != 1 else ''}"

    noun = _NOUN.get(rs.source, ("record", "records"))[0]
    ident = str(rs.rows[0].get("name") or "").strip()
    subject = f"{noun.capitalize()} {ident}" if ident else f"The {noun}"
    if field_name == "registered_at":  # a state-start → "has been running/registered for X"
        phrase = f"{subject} has been registered for {human} (by recorded time)."
    else:  # a point event (decided/recorded/…) → "was X ago"
        verb = _FIELD_VERB.get(field_name, field_name.replace("_", " "))
        phrase = f"{subject} was {verb} {human} ago (by recorded time)."
    return Recompute(True, value=int(seconds), evidence=(rs.refs[0],), canonical_phrase=phrase,
                     correctness_floor=1.0, coverage_mode="recorded-timestamp",
                     reason=f"derived:duration_{field_name}={int(seconds)}s")


# ─────────────────────────────────────────────────────────────────────────────
# COMPARE / DIFF_OVER_WINDOW — relate two ALREADY-GROUNDED scalar nodes. These never
# read rows; they only join two proven recomputes, so they cannot invent a value. The
# tier is the MIN of the two operands (a DERIVED operand makes the comparison DERIVED).
# ─────────────────────────────────────────────────────────────────────────────
_REL_WORD = {"eq": "equal to", "ne": "different from", "gt": "greater than",
             "lt": "less than", "gte": "at least", "lte": "at most"}


def _both_numeric(a: Recompute, b: Recompute) -> bool:
    return (
        a.grounded and b.grounded
        and isinstance(a.value, (int, float)) and not isinstance(a.value, bool)
        and isinstance(b.value, (int, float)) and not isinstance(b.value, bool)
    )


def _min_tier_floor(a: Recompute, b: Recompute) -> tuple[float | None, str | None]:
    if a.correctness_floor is not None or b.correctness_floor is not None:
        return 1.0, "recorded-timestamp"  # min-tier: any DERIVED operand → DERIVED result
    return None, None


def op_compare(a: Recompute, b: Recompute, args: Mapping[str, Any]) -> Recompute:
    if not _both_numeric(a, b):
        return Recompute(False, reason="compare-needs-two-grounded-numeric-scalars")
    rel = str(args.get("relation", "")).strip().lower()
    table = {
        "eq": a.value == b.value, "ne": a.value != b.value, "gt": a.value > b.value,
        "lt": a.value < b.value, "gte": a.value >= b.value, "lte": a.value <= b.value,
    }
    if rel not in table:
        return Recompute(False, reason=f"compare-bad-relation:{rel}")
    evidence = (a.evidence + b.evidence)[:EVIDENCE_CAP]
    if not evidence:
        return Recompute(False, reason="compare-no-evidence")
    result = bool(table[rel])
    word = _REL_WORD[rel]
    phrase = (f"Yes — {a.value} is {word} {b.value}." if result
              else f"No — {a.value} is not {word} {b.value}.")
    floor, mode = _min_tier_floor(a, b)
    return Recompute(True, value=result, evidence=evidence, canonical_phrase=phrase,
                     correctness_floor=floor, coverage_mode=mode, reason=f"compare:{rel}={result}")


def _fmt_number(value: float) -> str:
    """Trim a float for speech: 33.300000 → '33.3', 50.0 → '50'."""
    text = f"{value:.1f}".rstrip("0").rstrip(".")
    return text or "0"


def op_ratio(a: Recompute, b: Recompute, args: Mapping[str, Any]) -> Recompute:
    """The share of one grounded count within another — the division the old prompt
    banned, admitted as a PURE join of two proven recomputes (like COMPARE/DIFF, it
    never reads rows and cannot invent a value; both operands were already recomputed
    from real rows). Semantics are strictly "n of d": the part must be ≤ the whole and
    the whole must be positive — a plan that violates either is mis-composed and
    abstains rather than speaking a >100% or 0/0 'percentage'."""
    if not (a.grounded and b.grounded and isinstance(a.value, int) and isinstance(b.value, int)
            and not isinstance(a.value, bool) and not isinstance(b.value, bool)):
        return Recompute(False, reason="ratio-needs-two-grounded-integer-counts")
    if a.value < 0 or b.value < 0:
        return Recompute(False, reason="ratio-negative-count")
    if b.value == 0:
        return Recompute(False, reason="ratio-zero-denominator")
    if a.value > b.value:
        return Recompute(False, reason="ratio-part-exceeds-whole")
    evidence = (a.evidence + b.evidence)[:EVIDENCE_CAP]
    if not evidence:
        return Recompute(False, reason="ratio-no-evidence")
    pct = 100.0 * a.value / b.value
    part = _safe_qualifier(args.get("part_label"))
    whole = _safe_qualifier(args.get("whole_label")) or "records"
    subject = f"{a.value} {part}" if part else f"{a.value}"
    phrase = f"{subject} of {b.value} {whole} — {_fmt_number(pct)}%."
    floor, mode = _min_tier_floor(a, b)
    return Recompute(True, value=round(pct, 1), evidence=evidence, canonical_phrase=phrase,
                     correctness_floor=floor, coverage_mode=mode,
                     reason=f"ratio={a.value}/{b.value}")


def op_diff_over_window(a: Recompute, b: Recompute, args: Mapping[str, Any]) -> Recompute:
    if not (a.grounded and b.grounded and isinstance(a.value, int) and isinstance(b.value, int)
            and not isinstance(a.value, bool) and not isinstance(b.value, bool)):
        return Recompute(False, reason="diff-needs-two-grounded-integer-counts")
    evidence = (a.evidence + b.evidence)[:EVIDENCE_CAP]
    if not evidence:
        return Recompute(False, reason="diff-no-evidence")
    delta = a.value - b.value
    left = _safe_qualifier(args.get("left_label")) or "the first"
    right = _safe_qualifier(args.get("right_label")) or "the second"
    if delta > 0:
        phrase = f"{delta} more in {left} than {right} ({a.value} vs {b.value})."
    elif delta < 0:
        phrase = f"{-delta} fewer in {left} than {right} ({a.value} vs {b.value})."
    else:
        phrase = f"The same in {left} and {right} ({a.value} vs {b.value})."
    floor, mode = _min_tier_floor(a, b)
    return Recompute(True, value=delta, evidence=evidence, canonical_phrase=phrase,
                     correctness_floor=floor, coverage_mode=mode, reason=f"diff={delta}")
