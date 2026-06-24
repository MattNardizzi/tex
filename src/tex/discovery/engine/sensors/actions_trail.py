"""
Occasion A — the ACTIONS-TRAIL plane (``PlaneId.ACTIONS_TRAIL``).

Parses ``runtime/logs/<agent>.jsonl`` (what each agent LOGGED doing through
``tex_gate``). Each row is a governed action with shape (verified against the
real tex-enterprise fleet)::

    {"ts": 1782242461.21, "agent": "AssayPilot",
     "agent_id": "add23f99-ee57-44a3-888a-85df2127974b",
     "action_type": "file_write",
     "summary": "Write internal report 'preclinical/study-readouts/52.md' (114 bytes)",
     "risk": "routine", "verdict": "PERMIT", "released": true, "executed": true,
     "result": {"wrote": "preclinical/study-readouts/52.md", "bytes": 114}, ...}

This is a HIGH-admissibility OBSERVED plane: an agent that uses the gate appears
here. An agent that BYPASSES the gate (writes a file but logs no action) does
NOT — which is exactly why Occasion B (fs-write-scan) is needed to see it.

The load-bearing field this sensor extracts is the **workspace-relative path**
the action CLAIMS to have touched (``result.wrote`` / ``result.appended_to`` /
``result.saved`` / ``result.summary`` / ``result.log`` / ``result.file``). That
path is the cross-plane fusion JOIN KEY: a trail row claiming ``foo/bar.md`` and
a real file at ``<workspace>/foo/bar.md`` fuse to one entity. A file with NO
matching trail row is the gate-bypass signal seen only on Occasion B.

Catchability here is an ASSERTED plane recall for gate-using agents, NOT a
measured one: the slice stamps a constant (~1.0 by construction — cooperative
agents log every governed action; bypassers are out-of-cohort and surfaced by
the estimator's blind-spot ledger, not faked here). The count-based slice
estimator does not consume this value; measured recall is a Phase-5 target.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Iterator

from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

#: ASSERTED recall of the actions-trail plane over gate-using agents (a slice
#: constant, NOT measured; measurement deferred to Phase 5). Cooperative agents
#: log every governed action, so recall ≈ 1.0 for the cohort this plane CAN see;
#: bypassers are out-of-cohort and are the estimator's job. The count-based slice
#: estimator carries-but-does-not-consume this value.
ACTIONS_TRAIL_CATCHABILITY = 1.0

#: The aggregate fan-in log; the per-agent ``<agent>.jsonl`` files are the
#: authoritative source, so the aggregate is skipped to avoid double-counting.
_AGGREGATE_LOG = "actions.jsonl"

#: Keys inside an action ``result`` dict that carry a workspace-relative path.
#: Ordered by specificity; the first present wins as the row's claimed path.
_RESULT_PATH_KEYS: tuple[str, ...] = (
    "wrote",
    "appended_to",
    "saved",
    "summary",
    "log",
    "file",
)


#: A workspace-relative path token: one-or-more ``segment/`` parts ending in a
#: ``name.ext`` leaf. Deliberately conservative (must contain a ``/`` and a file
#: extension) so it harvests real paths from free-text summaries without matching
#: arbitrary slash-bearing prose. Used to recover the join key from a row's
#: ``summary`` when ``result`` is ``null`` (the held/abstained case).
_PATH_TOKEN = re.compile(r"(?:[\w.\-]+/)+[\w.\-]+\.[A-Za-z0-9]{1,8}")


def _harvest_paths(row: dict) -> set[str]:
    """All workspace-relative path tokens a trail row references.

    Unions (a) the structured ``result`` path (``_claimed_path``) with (b) every
    path-shaped token found in the ``summary`` and in the string values of the
    ``result`` dict. This makes the cross-plane join robust to rows whose
    ``result`` is ``null`` (held/abstained) but whose ``summary`` still names the
    target file. A path that appears in NO row is the genuine bypass residual.
    """
    paths: set[str] = set()
    structured = _claimed_path(row.get("result"))
    if structured:
        paths.add(structured)

    summary = row.get("summary")
    if isinstance(summary, str):
        paths.update(_PATH_TOKEN.findall(summary))

    result = row.get("result")
    if isinstance(result, dict):
        for v in result.values():
            if isinstance(v, str):
                paths.update(_PATH_TOKEN.findall(v))
    return paths


def _coerce_observed_at(ts: object) -> datetime:
    """Best-effort tz-aware timestamp from a row's ``ts`` (epoch seconds).

    Falls back to "now" (UTC) on anything unparseable so a single odd row never
    drops an otherwise-valid observation.
    """
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(UTC)


def _claimed_path(result: object) -> str | None:
    """Extract the workspace-relative path an action result claims to touch.

    Returns the first present, non-empty path-bearing value from the result
    dict, or ``None`` for non-file actions (payments, blocked attempts whose
    ``result`` is ``null``). This is the cross-plane fusion join key.
    """
    if not isinstance(result, dict):
        return None
    for k in _RESULT_PATH_KEYS:
        v = result.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # The "payment" family carries the touched file under ``ledger``.
    ledger = result.get("ledger")
    if isinstance(ledger, str) and ledger.strip():
        return ledger.strip()
    return None


class ActionsTrailSensor:
    """Emits one ``Incidence`` per logged action footprint (Occasion A).

    Construct with no arguments; ``sense`` reads ``context.actions_dir`` so a
    verifier can point it at a planted directory. Degrades to empty when the
    directory is missing/unreadable or contains no parseable rows.
    """

    plane_id: PlaneId = PlaneId.ACTIONS_TRAIL

    def __init__(self, catchability: float = ACTIONS_TRAIL_CATCHABILITY) -> None:
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401
        """Parse ``<agent>.jsonl`` trails into ``Incidence`` records.

        - Iterates ``*.jsonl`` files under ``context.actions_dir`` (skipping the
          aggregate ``actions.jsonl`` to avoid double-counting per-agent files).
        - Parses each line as JSON; malformed rows are skipped silently.
        - Builds a ``FootprintVector`` keyed on
          ``{agent_external_id, agent_id, workspace_path?}`` with attrs
          ``{action_type, verdict, executed, released, risk}``.
        - Emits one ``Incidence`` per row, ``admissibility=OBSERVED``,
          ``raw_evidence_ref=f"{file}:{lineno}"``, ``observed_at`` from ``ts``.
        - Returns an empty iterable on any missing/unreadable input; NEVER raises.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:
        actions_dir = context.actions_dir
        if actions_dir is None:
            return
        try:
            root = Path(actions_dir)
            if not root.is_dir():
                return
            files = sorted(root.glob("*.jsonl"))
        except OSError:
            return

        for path in files:
            if path.name == _AGGREGATE_LOG:
                continue
            yield from self._iter_file(path)

    def _iter_file(self, path: Path) -> Iterator[Incidence]:
        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            return
        with handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                inc = self._row_to_incidence(path, lineno, line)
                if inc is not None:
                    yield inc

    def _row_to_incidence(
        self, path: Path, lineno: int, line: str
    ) -> Incidence | None:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            return None
        if not isinstance(row, dict):
            return None

        agent_external_id = row.get("agent")
        if not isinstance(agent_external_id, str) or not agent_external_id.strip():
            # Without an agent handle the row cannot be attributed; the file
            # stem is the fallback handle so the row is never silently dropped.
            agent_external_id = path.stem
        agent_id = row.get("agent_id")

        keys: dict[str, str] = {"agent_external_id": agent_external_id}
        if isinstance(agent_id, str) and agent_id.strip():
            keys["agent_id"] = agent_id

        claimed = _claimed_path(row.get("result"))
        if claimed is not None:
            keys["workspace_path"] = claimed

        attrs: dict[str, str] = {}
        for name in ("action_type", "verdict", "risk"):
            val = row.get(name)
            if val is not None:
                attrs[name] = str(val)
        for name in ("executed", "released", "held"):
            if name in row:
                attrs[name] = str(bool(row.get(name))).lower()
        if isinstance(row.get("decision_id"), str):
            attrs["decision_id"] = row["decision_id"]

        footprint = FootprintVector.of(
            plane_id=PlaneId.ACTIONS_TRAIL, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.ACTIONS_TRAIL,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.OBSERVED,
                raw_evidence_ref=f"{path}:{lineno}",
                observed_at=_coerce_observed_at(row.get("ts")),
            )
        except ValueError:
            # A defensive guard (e.g. an out-of-range catchability injected by a
            # verifier) degrades to a dropped row, never a raised exception.
            return None


__all__ = ["ActionsTrailSensor", "ACTIONS_TRAIL_CATCHABILITY"]
