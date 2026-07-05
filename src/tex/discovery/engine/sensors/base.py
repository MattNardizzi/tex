"""
SIEVE engine sensors — the SENSE stage contract.

A sensor is the INSTRUMENT for one plane (RESEARCH_LOG.md §1). It turns a raw
vantage (a log file, a workspace directory, a packet capture) into a stream of
``Incidence`` records, each carrying a catchability for that plane.

SLICE STATUS (honest): in the thin slice the catchability a sensor stamps is an
ASSERTED plane constant, NOT a measured recall, and the count-based slice
estimator does not consume it. Measured catchability (signed-cohort recall /
honeytoken bite-rate) is a Phase-5 target — see ARCHITECTURE.md §6 SLICE STATUS.

Two hard rules every sensor MUST honor (ARCHITECTURE.md §8):

1. **Configurable input paths.** A sensor takes its input directory/handle as a
   constructor or context argument so an independent verifier can point it at a
   directory containing its OWN planted shadow. Sensors NEVER hardcode the
   tex-enterprise path.
2. **Degrade to EMPTY, never raise.** A missing file, an unreadable directory, a
   malformed row — all degrade to *fewer incidences*, never an exception. A
   sensor with nothing to see yields an empty iterable, like
   ``ConduitConnectionsConnector`` returning inert when unconnected.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from tex.discovery.engine.models import Incidence, PlaneId


@dataclass(frozen=True)
class SenseContext:
    """Inputs handed to a sensor at sense-time.

    Carries the configurable input roots so the same sensor instance can be
    pointed at the real fleet or at a verifier's planted directory.

    - ``actions_dir``   — directory of ``runtime/logs/<agent>.jsonl`` trails
                          (Occasion A). ``None`` if not applicable to the plane.
    - ``workspace_dir`` — root of the agents' real file side-effects
                          (Occasion B). ``None`` if not applicable.
    - ``tenant``        — the tenant this sweep is scoped to. A plane fed by a
                          SHARED in-process buffer (e.g. the P11 governance
                          stream, which any tenant's gate calls AND the public
                          evidence-push endpoint write into) uses this to emit
                          only footprints attributable to THIS tenant. The
                          scoping is LENIENT by design: an UNSTAMPED row (no
                          tenant on the row) stays in every tenant's cohort, so
                          cross-tenant isolation depends on every writer to the
                          shared buffer stamping the tenant server-side — the
                          sweep filter alone does not enforce it (both writers
                          that touch the public surface, the gate and the
                          evidence endpoint, do stamp). ``None`` means "unscoped"
                          — every row is in cohort (the pre-tenant behavior, kept
                          for planes that read a per-tenant source root and for
                          tests).
    - ``observed_at_floor`` is reserved for streaming windows (Phase 6).
    """

    actions_dir: Path | None = None
    workspace_dir: Path | None = None
    tenant: str | None = None


@runtime_checkable
class EngineSensor(Protocol):
    """One plane's instrument: a stream of ``Incidence`` records.

    Implementations live alongside this module (``actions_trail``,
    ``fs_write_scan``). Each declares its ``plane_id`` and a ``catchability``
    it self-measures.
    """

    plane_id: PlaneId

    def sense(self, context: SenseContext) -> Iterable[Incidence]:
        """Emit zero-or-more incidences for this plane from ``context``.

        MUST degrade to an empty iterable on missing/unreadable inputs and MUST
        NOT raise. The returned incidences all carry ``plane_id == self.plane_id``.
        """
        ...


__all__ = ["SenseContext", "EngineSensor"]
