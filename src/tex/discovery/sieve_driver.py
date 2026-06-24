"""
SIEVE live-wiring driver — the ADDITIVE, default-safe seam into ignite.

This module is the one place the greenfield SIEVE engine
(``tex.discovery.engine``) is bound to the live discovery surface. It exists so
``tex.main`` can ask for an optional SIEVE driver without importing the engine
eagerly or growing more wiring inline.

The two HARD SAFETY RULES (ARCHITECTURE.md §8) are enforced here:

1. **Flag-gated OFF by default.** ``build_sieve_driver(env)`` returns ``None``
   unless ``TEX_SIEVE_ENABLED`` is truthy. With the master flag unset the live
   path is byte-for-byte the legacy path — no driver is attached, ignite never
   touches SIEVE, and boot is identical to today. Even with the master flag on,
   each plane stays inert until its own ``TEX_SIEVE_P*`` flag is set (the
   registry's ``build_active_sensors`` is itself flag-gated per plane).

2. **Never raise on construction or run.** Building the driver and running a
   scan are both wrapped so a missing source / credential / sensor degrades to
   EMPTY rather than crashing ignite or boot. ``build_active_sensors`` already
   ``_safe``-wraps every factory; this module adds a belt-and-braces guard so a
   surprising import error still degrades to a no-op driver.

Production posture: in ``is_production_env()`` the synthetic/demo estate roots
(the slice's planted actions/workspace dirs) are forced OFF, so SIEVE surfaces
only real, flag-enabled planes — exactly mirroring how
``_build_discovery_connectors`` refuses synthetic agents in production.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_logger = logging.getLogger(__name__)


def _truthy(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


@dataclass(frozen=True)
class SieveDriver:
    """A thin, pre-built handle ignite calls to run the SIEVE engine.

    Constructed ONLY when ``TEX_SIEVE_ENABLED`` is on. Holds the env snapshot
    (so per-plane flags + source paths are read consistently) and the
    sense-context roots for the slice planes. ``run(registry, ledger)`` drives
    ``pipeline.run_planes`` over the flag-enabled plane roster, projecting every
    resolved entity through the existing registry/ledger governance boundary.

    The driver NEVER raises: a missing source, an empty roster, or any internal
    error degrades to an empty, honest result so ignite always completes.
    """

    env: Mapping[str, str]
    actions_dir: Path | None
    workspace_dir: Path | None

    def active_plane_flags(self) -> tuple[str, ...]:
        """The per-plane flags enabled in this driver's env (for receipts)."""
        try:
            from tex.discovery.engine.sensors.registry import active_plane_flags

            return active_plane_flags(self.env)
        except Exception:  # noqa: BLE001 — introspection must never raise
            return ()

    def run(self, registry, ledger, *, index=None):  # noqa: ANN001
        """Run the flag-enabled SIEVE planes and project into registry/ledger.

        Returns the ``PlanesResult`` (object handle) or ``None`` if the run
        degraded. NEVER raises — any failure is logged at INFO and swallowed so
        ignite is never broken by SIEVE.
        """
        try:
            from tex.discovery.engine.pipeline import run_planes
            from tex.discovery.engine.sensors import SenseContext

            context = SenseContext(
                actions_dir=self.actions_dir,
                workspace_dir=self.workspace_dir,
            )
            return run_planes(
                self.env,
                context=context,
                registry=registry,
                ledger=ledger,
                index=index,
            )
        except Exception as exc:  # noqa: BLE001 — SIEVE never breaks ignite
            _logger.info("sieve: run degraded (no-op): %s", exc)
            return None


def build_sieve_driver(env: Mapping[str, str] | None = None) -> SieveDriver | None:
    """Build the optional SIEVE driver — or ``None`` when the master flag is off.

    Default-safe contract:

    - ``TEX_SIEVE_ENABLED`` unset/false  → returns ``None``. The caller attaches
      nothing; the live discovery path is identical to today. This is the
      common case a merge-to-main / prod deploy stays on.
    - ``TEX_SIEVE_ENABLED`` truthy        → returns a ``SieveDriver`` whose
      sense-context roots are read from the env (slice planes) and forced OFF in
      production (no synthetic estate). The per-plane ``TEX_SIEVE_P*`` flags
      still gate which planes actually build a sensor, so an enabled master flag
      with no plane flags is a live-but-empty driver (still no-op in effect).

    NEVER raises: any error constructing the driver degrades to ``None`` (legacy
    path only).
    """
    source = env if env is not None else os.environ
    if not _truthy(source.get("TEX_SIEVE_ENABLED")):
        return None

    try:
        from tex.config import is_production_env

        production = is_production_env()

        # The slice planes (ACTIONS_TRAIL / FS_WRITE) read their roots from the
        # SenseContext. These point at a planted/synthetic estate, so they are a
        # dev/demo affordance — forced OFF in production exactly like the demo
        # seed in ``_build_discovery_connectors``. The roster's network/cloud/
        # identity planes read their own real source paths from env inside their
        # factories and are unaffected by this (they have no SenseContext roots).
        actions_dir: Path | None = None
        workspace_dir: Path | None = None
        if not production:
            a = (source.get("TEX_SIEVE_ACTIONS_DIR") or "").strip()
            w = (source.get("TEX_SIEVE_WORKSPACE_DIR") or "").strip()
            actions_dir = Path(a) if a else None
            workspace_dir = Path(w) if w else None

        return SieveDriver(
            env=dict(source),
            actions_dir=actions_dir,
            workspace_dir=workspace_dir,
        )
    except Exception as exc:  # noqa: BLE001 — construction never breaks boot
        _logger.info("sieve: driver construction degraded to no-op: %s", exc)
        return None


__all__ = ["SieveDriver", "build_sieve_driver"]
