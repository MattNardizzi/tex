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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tex.presence.contract import EvidenceRef
from tex.presence.gate.queries import EVIDENCE_CAP, Recompute
from tex.presence.plan.ir import CompareOp

__all__ = ["RowSet", "rowset_from_leaf", "op_filter", "op_count", "op_exists", "op_list",
           "op_get", "op_absence"]


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
    "human_decision.get_decision": ("decision", "found"),
    "evidence.chain_head": ("head", "present"),
    "discovery.chain_head": ("head", "present"),
    "monitoring.latest_snapshot": ("snapshot", "present"),
}
_LEAF_COUNT: frozenset[str] = frozenset(
    {"execution.action_count", "discovery.entry_count", "monitoring.drift_count",
     "human_decision.verdict_count"}
)
# Tools whose rows are a COMPLETE current-state snapshot (the registry's full list),
# so 'no match' over an UNCLAMPED read is a PROVABLE absence — unlike the append-only
# tails (recent_*) which are windowed and can never prove a 'no' on their own.
_COMPLETE_SNAPSHOT_TOOLS: frozenset[str] = frozenset({"identity.list_agents"})
_NOUN: dict[str, tuple[str, str]] = {
    "identity.list_agents": ("agent", "agents"),
    "identity.get_agent": ("agent", "agents"),
    "human_decision.recent_decisions": ("decision", "decisions"),
    "human_decision.verdict_count": ("decision", "decisions"),
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
    fleet_only = tenant_scope == "fleet"
    clamped = value.get("limit_clamped_to") is not None

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
        complete = tool_name in _COMPLETE_SNAPSHOT_TOOLS and not clamped
        return RowSet(rows, tuple(refs), tool_name, tenant_scope, applied,
                      total=(None if clamped else len(rows)), fleet_only=fleet_only,
                      clamped=clamped, complete=complete)

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

    qualifier = str(target).casefold() if cop is CompareOp.EQ and target is not None else None
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
        return _bad(rs.source, "zero-count-needs-absence-proof")
    if rs.clamped:
        return _bad(rs.source, "count-clamped-incomplete")  # value is a lower bound — don't seal
    if not rs.refs:
        return _bad(rs.source, "count-no-evidence-witness")
    qual = (" ".join(q for q in rs.qualifiers if q) + " ") if any(rs.qualifiers) else ""
    phrase = f"There {'is' if n == 1 else 'are'} {n} {qual}{_noun(rs.source, n)}."
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
            labels.append(str(row.get("name") or row.get("agent_id") or row.get("id") or "?"))
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
    if not rs.rows or not rs.refs:
        return _bad(rs.source, "get-not-found")
    row, ref = rs.rows[0], rs.refs[0]
    field_name = args.get("field")
    if not isinstance(field_name, str) or field_name not in row:
        return _bad(rs.source, "get-field-missing")
    val = row.get(field_name)
    ident = str(row.get("name") or row.get("agent_id") or row.get("id") or "")
    noun = _NOUN.get(rs.source, ("record", "records"))[0].capitalize()
    phrase = f"{noun} {ident} {field_name.replace('_', ' ')} is {val}."
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
    key = str(target)
    if match_rows:  # present → SEALED yes, binding the matching rows
        if not match_refs:
            return _bad(rs.source, "absence-match-no-witness")
        n = len(match_rows)
        names = ", ".join(str(r.get("name") or r.get("id") or "?") for r in match_rows[:5])
        phrase = f"Yes — you have {n} {sing if n == 1 else plur} matching {key!r}: {names}."
        if rs.fleet_only:
            phrase = phrase[:-1] + " (across all tenants)."
        return Recompute(True, value=True, evidence=tuple(match_refs[:EVIDENCE_CAP]),
                         canonical_phrase=phrase, reason=f"sealed:membership_present={n}")

    # absent → SEALED 'no', but ONLY over a complete, non-empty scanned set (the witness).
    if not rs.rows or not rs.refs:
        return _bad(rs.source, "absence-no-completeness-witness")  # empty set → no witness
    total = len(rs.rows)
    phrase = f"No — none of your {total} {plur} matches {key!r}."
    if rs.fleet_only:
        phrase = phrase[:-1] + " (across all tenants)."
    return Recompute(True, value=False, evidence=rs.refs[:EVIDENCE_CAP],
                     canonical_phrase=phrase, reason=f"sealed:membership_absent;scanned={total}")
