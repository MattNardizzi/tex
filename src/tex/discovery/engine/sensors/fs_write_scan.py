"""
Occasion B — the FS-WRITE-SCAN plane (``PlaneId.FS_WRITE``).

Scans the WORKSPACE for files actually written to disk, diffed against what the
actions-trail claims (Occasion A). This is the GROUND-TRUTH plane: a file on
disk is ``Admissibility.PROVEN`` — it cannot be talked away.

The load-bearing case (ARCHITECTURE.md §10, RESEARCH_LOG.md N3): a
gate-bypassing shadow that writes a real file but logs NO action appears on this
plane and NOT on the actions-trail. The diff (files-present minus files-the-
trail-claims) localizes exactly that shadow — the only way to see it.

The cross-plane fusion JOIN KEY is the workspace-relative path: a file at
``<workspace>/foo/bar.md`` carries ``workspace_path="foo/bar.md"``, which the
actions-trail row that wrote it also carries. When ``context.actions_dir`` is
provided this sensor reads the trail's claimed paths (and the agent that claimed
each one) so it can (a) mark whether a file is ``claimed`` or a ``gate_bypass``
and (b) attribute a claimed file to its writing agent. A NON-cooperative shadow
that never calls ``tex_gate`` is found from the filesystem alone, with no
cooperation from the agent.

Catchability here is the fraction of real writes the scan can attribute (~1.0
for files under the scanned root; files written outside the workspace are a
NAMED blind spot reported by the estimator, not a silent zero).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Iterator

from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.actions_trail import (
    _AGGREGATE_LOG,
    _harvest_paths,
)
from tex.discovery.engine.sensors.base import SenseContext

#: ASSERTED recall of the fs-write plane over files under the workspace (a slice
#: constant, NOT measured; measurement deferred to Phase 5). A file on disk is
#: ground truth; writes outside the scanned root are a named blind spot reported
#: by the estimator, not folded into this recall. The count-based slice estimator
#: carries-but-does-not-consume this value.
FS_WRITE_CATCHABILITY = 1.0

#: Subtrees that are NOT executed writes and must be excluded from the scan:
#:  - ``quarantine`` holds blocked-attempt sentinels (the gate refused them; a
#:    file here is proof of a BLOCK, not an executed side-effect).
#: These are skipped so a forbidden-and-blocked action is never miscounted as a
#: real write (which would manufacture a false discovery).
_EXCLUDED_TOP_DIRS: frozenset[str] = frozenset({"quarantine"})


def _safe_relpath(file: Path, root: Path) -> str | None:
    """Workspace-relative POSIX path, or ``None`` if outside the root."""
    try:
        return file.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _coerce_mtime(file: Path) -> datetime:
    """tz-aware mtime, falling back to now(UTC) if stat fails."""
    try:
        return datetime.fromtimestamp(file.stat().st_mtime, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return datetime.now(UTC)


def _build_claim_index(actions_dir: Path | None) -> dict[str, str]:
    """Map each trail-claimed workspace path → the agent that claimed it.

    Reads the per-agent ``<agent>.jsonl`` trails under ``actions_dir`` (skipping
    the aggregate). Used to mark a scanned file CLAIMED (joined to a trail row)
    vs UNCLAIMED (the gate-bypass signal). Degrades to an empty map on any
    missing/unreadable input — an empty map makes every file look unclaimed,
    which is the conservative (over-report) direction, never a silent miss.
    """
    index: dict[str, str] = {}
    if actions_dir is None:
        return index
    try:
        root = Path(actions_dir)
        if not root.is_dir():
            return index
        files = sorted(root.glob("*.jsonl"))
    except OSError:
        return index

    for path in files:
        if path.name == _AGGREGATE_LOG:
            continue
        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(row, dict):
                    continue
                agent = row.get("agent")
                writer = (
                    agent if isinstance(agent, str) and agent.strip() else path.stem
                )
                for claimed in _harvest_paths(row):
                    index.setdefault(claimed, writer)
    return index


class FsWriteScanSensor:
    """Emits one ``Incidence`` per file actually written under the workspace.

    Construct with no arguments; ``sense`` reads ``context.workspace_dir`` (and
    optionally ``context.actions_dir`` to compute the claimed-vs-actual diff) so
    a verifier can point it at a planted workspace. Degrades to empty when the
    workspace is missing/unreadable.
    """

    plane_id: PlaneId = PlaneId.FS_WRITE

    def __init__(self, catchability: float = FS_WRITE_CATCHABILITY) -> None:
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401
        """Scan ``context.workspace_dir`` into ``Incidence`` records.

        - Walks ``context.workspace_dir`` recursively for regular files
          (skipping the ``quarantine/`` subtree — those are blocked attempts,
          not executed writes).
        - For each file builds a ``FootprintVector`` keyed on
          ``{workspace_path}`` (relative to the workspace root) plus attrs
          ``{bytes, mtime, claimed, gate_bypass, claimed_by?}``.
        - When ``context.actions_dir`` is provided, marks whether each file is
          CLAIMED by a trail row (joined, with ``claimed_by`` the writer) or
          UNCLAIMED (``gate_bypass=true`` — the gate-bypassing shadow's only
          footprint).
        - Emits one ``Incidence`` per file with ``admissibility=PROVEN``,
          ``raw_evidence_ref`` = the absolute file path.
        - Returns an empty iterable on any missing/unreadable input; NEVER raises.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:
        workspace_dir = context.workspace_dir
        if workspace_dir is None:
            return
        root = Path(workspace_dir)
        try:
            if not root.is_dir():
                return
        except OSError:
            return

        claim_index = _build_claim_index(context.actions_dir)
        have_trail = context.actions_dir is not None

        try:
            walker = root.rglob("*")
        except OSError:
            return

        for file in self._iter_files(walker, root):
            rel = _safe_relpath(file, root)
            if rel is None:
                continue
            top = rel.split("/", 1)[0]
            if top in _EXCLUDED_TOP_DIRS:
                continue
            inc = self._file_to_incidence(file, rel, claim_index, have_trail)
            if inc is not None:
                yield inc

    @staticmethod
    def _iter_files(walker: Iterator[Path], root: Path) -> Iterator[Path]:
        """Yield regular files from a recursive walk, swallowing per-entry I/O.

        A directory that vanishes mid-walk or a symlink loop degrades to fewer
        files, never an exception.
        """
        while True:
            try:
                entry = next(walker)
            except StopIteration:
                return
            except OSError:
                # The walk itself faulted (e.g. permission on a subtree). We
                # cannot resume a faulted generator, so stop cleanly.
                return
            try:
                if entry.is_file() and not entry.is_symlink():
                    yield entry
            except OSError:
                continue

    def _file_to_incidence(
        self,
        file: Path,
        rel: str,
        claim_index: dict[str, str],
        have_trail: bool,
    ) -> Incidence | None:
        try:
            size = file.stat().st_size
        except OSError:
            size = 0

        keys = {"workspace_path": rel}

        attrs: dict[str, str] = {
            "bytes": str(size),
            "mtime": _coerce_mtime(file).isoformat(),
        }
        # The diff: only meaningful when we actually read a trail. With no trail
        # we leave claim state unknown rather than asserting a false bypass.
        #
        # ``unclaimed_by_path`` is what the sensor literally MEASURES: no trail
        # row's result/summary names this path. ``gate_bypass`` is the
        # conservative interpretation of that measurement (the gate-bypass
        # candidate signal). They are kept distinct because a governed write
        # whose trail row is *path-silent* (e.g. an access-grant whose result is
        # ``{"granted": ..., "to": ...}`` with the file ``iam/grants.jsonl``
        # named nowhere) is unclaimed-by-path WITHOUT being a true bypass; the
        # FUSE/ESTIMATE stages adjudicate that residual rather than this sensor
        # fake-finding it.
        if have_trail:
            claimed_by = claim_index.get(rel)
            is_claimed = claimed_by is not None
            attrs["claimed"] = str(is_claimed).lower()
            attrs["unclaimed_by_path"] = str(not is_claimed).lower()
            attrs["gate_bypass"] = str(not is_claimed).lower()
            if is_claimed:
                # Carry the trail-attributed writer as a (weak, bridging) hint so
                # the resolver can fuse the FS leaf to the right ACTIONS leaf.
                keys["claimed_by"] = claimed_by  # type: ignore[assignment]

        footprint = FootprintVector.of(
            plane_id=PlaneId.FS_WRITE, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.FS_WRITE,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=Admissibility.PROVEN,
                raw_evidence_ref=str(file),
                observed_at=_coerce_mtime(file),
            )
        except ValueError:
            return None


__all__ = ["FsWriteScanSensor", "FS_WRITE_CATCHABILITY"]
