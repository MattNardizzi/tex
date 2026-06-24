"""SIEVE engine sensors (the SENSE stage).

Two genuinely-independent capture occasions over the tex-enterprise fleet:

- ``ActionsTrailSensor``  — Occasion A (``PlaneId.ACTIONS_TRAIL``): what each
  agent LOGGED doing (``runtime/logs/<agent>.jsonl``).
- ``FsWriteScanSensor``   — Occasion B (``PlaneId.FS_WRITE``): files actually
  written under the WORKSPACE, diffed against what the trail claims. The only
  plane that can see a gate-bypassing shadow.
"""

from __future__ import annotations

from tex.discovery.engine.sensors.actions_trail import ActionsTrailSensor
from tex.discovery.engine.sensors.base import EngineSensor, SenseContext
from tex.discovery.engine.sensors.fs_write_scan import FsWriteScanSensor
from tex.discovery.engine.sensors.registry import (
    SensorFactory,
    active_plane_flags,
    build_active_sensors,
    register_sensor,
    roster_plane_ids,
)

__all__ = [
    "EngineSensor",
    "SenseContext",
    "ActionsTrailSensor",
    "FsWriteScanSensor",
    # registry — the flag-gated activation seam the plane builders register on
    "SensorFactory",
    "build_active_sensors",
    "register_sensor",
    "active_plane_flags",
    "roster_plane_ids",
]
