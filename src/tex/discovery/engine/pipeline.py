"""
SIEVE pipeline — the thin-vertical-slice orchestrator (ARCHITECTURE.md §10).

Wires the four stages over two genuinely-independent capture occasions:

    SENSE  (ActionsTrailSensor + FsWriteScanSensor → Incidence stream)
      │
    FUSE   (resolve → one SieveEntity per agent; cross-plane edge; stable id)
      │
    ESTIMATE (estimate_unseen → wide unseen-FRACTION + CI + named blind spots)
      │
    OUTPUT ADAPTER (project → registry.save + ledger.append → governable)

``run_slice`` is the single direct-test entrypoint. It is NOT wired into the
live ``_build_discovery_connectors`` (Phase 8) and only runs when a caller
invokes it — the master flag ``TEX_SIEVE_ENABLED`` gates the LIVE path, not the
direct tests. Inputs are configurable paths so a verifier can point the sensors
at its own planted shadow. Degrades to an empty result on missing inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from tex.discovery.engine import adapter
from tex.discovery.engine.estimate import estimate_unseen
from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Incidence,
    PlaneId,
    SieveEntity,
    UnseenEstimate,
)
from tex.discovery.engine.sensors import (
    ActionsTrailSensor,
    FsWriteScanSensor,
    SenseContext,
)

#: The two real capture occasions the slice runs (ARCHITECTURE.md §10). Order
#: matters: occasion[0] = ACTIONS_TRAIL, occasion[1] = FS_WRITE feed the
#: two-occasion Lincoln-Petersen / Chao2 estimator as n1 / n2.
_SLICE_OCCASIONS: tuple[PlaneId, ...] = (PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE)


@dataclass(frozen=True)
class SliceResult:
    """The headline object handle for one slice run (ARCHITECTURE.md §9).

    - ``entities``      — the resolved ``SieveEntity`` set (object handle, never
                          a forced agent table in the spoken surface).
    - ``unseen``        — the calibrated ``UnseenEstimate`` (lower + CI + named
                          blind spots) — the spoken honest-edge sentence.
    - ``projected``     — count of entities written through the governance
                          boundary (registry + ledger), so a test can assert the
                          adapter ran.
    - ``occasions`` / ``withheld_planes`` — the planes that captured vs were
                          deliberately withheld this run, for receipts.
    """

    entities: tuple[SieveEntity, ...] = ()
    unseen: UnseenEstimate | None = None
    projected: int = 0
    occasions: tuple[PlaneId, ...] = ()
    withheld_planes: tuple[PlaneId, ...] = field(default_factory=tuple)


def _empty_result(
    withheld_planes: tuple[PlaneId, ...],
) -> SliceResult:
    """A degenerate-but-honest result for missing/empty inputs.

    No entities were seen, so the estimator has no support; it returns a
    deliberately-wide ``degenerate`` estimate with a named blind spot per
    withheld plane. NEVER raises, NEVER fabricates an entity.
    """
    unseen = estimate_unseen(
        (),
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld_planes,
    )
    return SliceResult(
        entities=(),
        unseen=unseen,
        projected=0,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld_planes,
    )


def run_slice(
    actions_dir: Path,
    workspace_dir: Path,
    registry,  # noqa: ANN001 - InMemoryAgentRegistry
    ledger,  # noqa: ANN001 - InMemoryDiscoveryLedger
    index=None,  # noqa: ANN001 - ReconciliationIndex (optional; built if None)
    withheld_planes: Sequence[PlaneId] = (PlaneId.WITHHELD_THIRD,),
) -> SliceResult:
    """Run the full thin slice end-to-end and return a ``SliceResult``.

    Stages:

    1. SENSE — build a ``SenseContext`` from the two configurable dirs; run
       ``ActionsTrailSensor`` (Occasion A) and ``FsWriteScanSensor`` (Occasion
       B, given the actions_dir so it can compute the claimed-vs-actual diff);
       collect every ``Incidence``. Missing dirs → empty (the sensors degrade).
    2. FUSE — ``resolve(incidences)`` → entities. A trail row and the file it
       wrote fuse on ``workspace_path`` into one entity; a gate-bypassing file
       with no trail row resolves to its OWN entity from FS_WRITE alone.
    3. ESTIMATE — ``estimate_unseen(entities, occasions=[ACTIONS_TRAIL,
       FS_WRITE], withheld_planes=...)`` → a deliberately-wide ``UnseenEstimate``
       with a named blind spot per withheld plane.
    4. OUTPUT ADAPTER — for each entity call ``adapter.project`` (registry.save
       then ledger.append); count the projections.

    Returns a ``SliceResult`` carrying entities, the estimate, the projected
    count, and the occasion/withheld plane sets. NEVER raises on missing inputs
    — it degrades to an empty ``SliceResult`` with a degenerate estimate.

    ``index`` defaults to a fresh ``ReconciliationIndex`` bootstrapped from the
    registry so a re-run re-links the same entities instead of churning them.
    """
    withheld = tuple(dict.fromkeys(withheld_planes))  # de-dup, preserve order

    if index is None:
        # Local import: the index lives in the service module and we only need
        # it lazily, keeping the engine import graph free of the service.
        from tex.discovery.service import ReconciliationIndex

        index = ReconciliationIndex(registry=registry)

    # ------------------------------------------------------------------
    # 1. SENSE — two genuinely-independent occasions. Sensors degrade to empty.
    # ------------------------------------------------------------------
    context = SenseContext(
        actions_dir=_as_path(actions_dir),
        workspace_dir=_as_path(workspace_dir),
    )

    incidences: list[Incidence] = []
    incidences.extend(ActionsTrailSensor().sense(context))
    incidences.extend(FsWriteScanSensor().sense(context))

    if not incidences:
        return _empty_result(withheld)

    # ------------------------------------------------------------------
    # 2. FUSE — resolve footprints into probabilistic entities.
    # ------------------------------------------------------------------
    entities = tuple(resolve(incidences))

    # ------------------------------------------------------------------
    # 3. ESTIMATE — two-occasion capture-recapture; widen for each withheld.
    # ------------------------------------------------------------------
    unseen = estimate_unseen(
        entities,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld,
    )

    # ------------------------------------------------------------------
    # 4. OUTPUT ADAPTER — land each entity through the governance boundary.
    # ------------------------------------------------------------------
    projected = 0
    for entity in entities:
        adapter.project(entity, registry, ledger, index)
        projected += 1

    return SliceResult(
        entities=entities,
        unseen=unseen,
        projected=projected,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld,
    )


def _as_path(value: Path | str | None) -> Path | None:
    """Coerce a path-or-string-or-None to a ``Path`` without raising.

    The sensors already guard ``None`` / missing dirs, so this only normalizes
    the type; an odd value degrades to ``None`` rather than raising.
    """
    if value is None:
        return None
    try:
        return Path(value)
    except TypeError:
        return None


__all__ = ["SliceResult", "run_slice"]
