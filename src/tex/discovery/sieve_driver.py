"""
SIEVE live-wiring driver — the ADDITIVE, default-safe seam into ignite.

This module is the one place the greenfield SIEVE engine
(``tex.discovery.engine``) is bound to the live discovery surface. It exists so
``tex.main`` can ask for an optional SIEVE driver without importing the engine
eagerly or growing more wiring inline.

The HARD RULES (ARCHITECTURE.md §8) enforced here:

1. **Begin ignites the ENTIRE discovery layer.** ``build_sieve_driver(env)``
   returns a live driver by default, with the full-sweep switch
   (``TEX_SIEVE_ALL``) lit on its env snapshot — every roster plane arms on
   every sweep, and a plane is dark only when its vantage genuinely does not
   exist (no source, no credential), never because a flag was unset. An
   EXPLICIT operator value always wins: ``TEX_SIEVE_ENABLED=0`` removes the
   driver entirely (legacy path, byte-for-byte), an explicit ``TEX_SIEVE_ALL``
   value is honored as-is, and an explicit falsey per-plane flag opts that one
   plane out even under the full sweep. Genuinely-intrusive sub-actions (decoy
   planting, active MCP probing) stay behind their OWN sub-flags, which the
   sweep never sets — full sweep means passive sensing on every plane.

2. **Never raise on construction or run.** Building the driver and running a
   scan are both wrapped so a missing source / credential / sensor degrades to
   EMPTY rather than crashing ignite or boot. ``build_active_sensors`` already
   ``_safe``-wraps every factory; this module adds a belt-and-braces guard so a
   surprising import error still degrades to a no-op driver.

Production posture: in ``is_production_env()`` the synthetic/demo estate roots
(the slice's planted actions/workspace dirs) are forced OFF, so SIEVE surfaces
only real planes — exactly mirroring how ``_build_discovery_connectors``
refuses synthetic agents in production. The full sweep itself runs in
production too: real planes with real vantage light up for any tenant that
presses Begin.
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


def _explicitly_falsey(value: str | None) -> bool:
    """A deliberate operator opt-out — the only thing that turns SIEVE off."""
    return isinstance(value, str) and value.strip().casefold() in {
        "0",
        "false",
        "no",
        "off",
        "disabled",
    }


#: The slice planes' §8 activation flags (roster: engine/sensors/registry.py).
#: ``build_sieve_driver`` injects these onto its env snapshot when the matching
#: dev-only root (``TEX_SIEVE_ACTIONS_DIR`` / ``TEX_SIEVE_WORKSPACE_DIR``)
#: survived the production gate, so pointing SIEVE at an estate actually senses
#: it without a second flag. An operator's explicit value is never overridden.
_ACTIONS_TRAIL_FLAG = "TEX_SIEVE_ACTIONS_TRAIL"
_FS_WRITE_FLAG = "TEX_SIEVE_FS_WRITE"

#: The full-sweep switch (registry.py `_ALL_FLAG`): lit on the driver's env
#: snapshot by default so a single press of Begin arms the whole roster.
_ALL_FLAG = "TEX_SIEVE_ALL"


@dataclass(frozen=True)
class SieveDriver:
    """A thin, pre-built handle ignite calls to run the SIEVE engine.

    Constructed by default (only an explicit ``TEX_SIEVE_ENABLED=0`` opt-out
    removes it). Holds the env snapshot (so the full-sweep switch, per-plane
    opt-outs and source paths are read consistently) and the sense-context
    roots for the slice planes. ``run(registry, ledger)`` drives
    ``pipeline.run_planes`` over the armed plane roster, projecting every
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

    def run(self, registry, ledger, *, index=None, tenant: str = "default"):  # noqa: ANN001
        """Run the flag-enabled SIEVE planes and project into registry/ledger.

        Returns the ``PlanesResult`` (object handle) or ``None`` if the run
        degraded. NEVER raises — any failure is logged at INFO and swallowed so
        ignite is never broken by SIEVE. ``tenant`` is the tenant being watched
        (the ignite tenant): discovered agents are written under it so they land
        in the SAME estate as the rest of the inventory.
        """
        try:
            from tex.discovery.engine.pipeline import run_planes
            from tex.discovery.engine.sensors import SenseContext

            context = SenseContext(
                actions_dir=self.actions_dir,
                workspace_dir=self.workspace_dir,
                tenant=tenant,
            )
            return run_planes(
                self.env,
                context=context,
                registry=registry,
                ledger=ledger,
                index=index,
                tenant_id=tenant,
            )
        except Exception as exc:  # noqa: BLE001 — SIEVE never breaks ignite
            _logger.info("sieve: run degraded (no-op): %s", exc)
            return None


def build_sieve_driver(env: Mapping[str, str] | None = None) -> SieveDriver | None:
    """Build the SIEVE driver — live, full-sweep, by default.

    Contract (Begin ignites the entire discovery layer):

    - Default (``TEX_SIEVE_ENABLED`` unset or any non-falsey value) → returns a
      ``SieveDriver`` with the full-sweep switch (``TEX_SIEVE_ALL``) lit on its
      env snapshot, so EVERY roster plane arms on every sweep. A plane with no
      vantage (missing source/credential) degrades to its inert sensor and is
      spoken as a dark plane — dark means "no vantage here yet", never "a flag
      was unset".
    - ``TEX_SIEVE_ENABLED`` explicitly falsey (``0``/``false``/``no``/``off``/
      ``disabled``) → returns ``None``; the live discovery path is
      byte-for-byte the legacy path. The ONLY way SIEVE stays out of ignite.
    - An explicit ``TEX_SIEVE_ALL`` value is honored as-is (never overridden),
      and an explicitly-falsey per-plane flag opts that single plane out even
      under the full sweep (see ``build_active_sensors``).
    - A present (non-production) slice root implies its plane:
      ``TEX_SIEVE_ACTIONS_DIR`` lights ``TEX_SIEVE_ACTIONS_TRAIL`` and
      ``TEX_SIEVE_WORKSPACE_DIR`` lights ``TEX_SIEVE_FS_WRITE`` on the driver's
      env snapshot, unless the operator set that flag explicitly (any explicit
      value — including a falsey one — wins). In production the roots are
      forced off first, so no flag is ever injected there.

    NEVER raises: any error constructing the driver degrades to ``None`` (legacy
    path only).
    """
    source = env if env is not None else os.environ
    if _explicitly_falsey(source.get("TEX_SIEVE_ENABLED")):
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

        # A root that survived the production gate IS the operator's intent to
        # sense that estate, so it lights the matching slice plane without a
        # second flag: with the roots alone, ignite's roster run previously
        # built NEITHER slice sensor and the coverage object omitted both
        # planes. The registry stays purely flag-gated (§8); this seam just
        # translates "root present" into the plane's own flag on the driver's
        # env snapshot. An EXPLICIT operator value is never overridden — a
        # deliberate ``TEX_SIEVE_ACTIONS_TRAIL=0`` keeps that plane off even
        # with its root set. In production both roots are already forced off
        # above, so nothing is injected there and the default-safe posture is
        # byte-for-byte unchanged.
        snapshot = dict(source)
        if actions_dir is not None and not (snapshot.get(_ACTIONS_TRAIL_FLAG) or "").strip():
            snapshot[_ACTIONS_TRAIL_FLAG] = "1"
        if workspace_dir is not None and not (snapshot.get(_FS_WRITE_FLAG) or "").strip():
            snapshot[_FS_WRITE_FLAG] = "1"

        # Begin ignites the ENTIRE discovery layer: the full-sweep switch is the
        # default, so every roster plane arms and a plane is dark only for lack
        # of vantage. An explicit operator value (on OR off) is never overridden.
        if not (snapshot.get(_ALL_FLAG) or "").strip():
            snapshot[_ALL_FLAG] = "1"

        return SieveDriver(
            env=snapshot,
            actions_dir=actions_dir,
            workspace_dir=workspace_dir,
        )
    except Exception as exc:  # noqa: BLE001 — construction never breaks boot
        _logger.info("sieve: driver construction degraded to no-op: %s", exc)
        return None


__all__ = ["SieveDriver", "build_sieve_driver"]
