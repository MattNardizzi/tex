"""
SIEVE — Sparse-Incidence Entity & Vantage Estimator.

The greenfield discovery engine for Tex's Discover leg. This package holds its
OWN data model (``models``), the SENSE/FUSE/ESTIMATE pipeline stages, and the
one-way OUTPUT ADAPTER into the existing ``agent_registry`` / ``discovery_ledger``
so ``StandingGovernance.decide`` governs every resolved entity.

The master switch is ``TEX_SIEVE_ENABLED`` — **default ON (opt-out)**: SIEVE is
the standing discovery engine unless an operator explicitly sets the flag to a
falsey value (``0/false/no/off``). Activation is still SAFE — the driver is
additive, never raises, and each sense plane stays inert until its own
``TEX_SIEVE_P*`` flag points at a real source, so an enabled master with no
plane flags is a live-but-empty no-op that cannot crash boot. SIEVE is a SIBLING
of the legacy connector path, never a replacement. See ARCHITECTURE.md §8, §10.

The data-model contract (``models``) is always importable regardless of the
flag; the flag only governs whether the engine runs inside the live service.
"""

from __future__ import annotations

import os

from tex.discovery.engine.models import (
    Admissibility,
    AgentHumanLabel,
    AgentHumanVerdict,
    CapabilityEdge,
    CapabilityGraph,
    EdgeGrade,
    FootprintVector,
    Incidence,
    NamedBlindSpot,
    PlaneId,
    PresenceState,
    SharedCredentialVerdict,
    SieveEntity,
    TypedEdge,
    UnseenEstimate,
)

# Truthy / falsey spellings for the master flag, case-insensitive. The flag is
# default-ON (opt-out): only an explicit falsey value disables SIEVE.
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})

#: The master activation flag name (ARCHITECTURE.md §8). Default ON (opt-out).
SIEVE_ENABLED_ENV = "TEX_SIEVE_ENABLED"


def is_sieve_enabled(env: dict[str, str] | None = None) -> bool:
    """Whether the SIEVE engine is activated for the live service.

    Reads ``TEX_SIEVE_ENABLED`` — **default ON (opt-out)**. SIEVE is enabled
    unless the flag is explicitly set to a falsey value (``0/false/no/off/
    disabled``, case-insensitive); an unset or empty value means ON. When
    explicitly disabled, the live service falls back to the legacy path and
    SIEVE never runs in the request/scan path — but the data model and the
    direct-test entrypoints remain fully importable and usable.

    ``env`` is injectable so tests and the verifier can probe the gate without
    mutating the real process environment.
    """
    source = env if env is not None else os.environ
    token = (source.get(SIEVE_ENABLED_ENV) or "").strip().casefold()
    return token not in _FALSEY


__all__ = [
    "is_sieve_enabled",
    "SIEVE_ENABLED_ENV",
    # data-model contract re-exports
    "Admissibility",
    "AgentHumanLabel",
    "AgentHumanVerdict",
    "CapabilityEdge",
    "CapabilityGraph",
    "EdgeGrade",
    "FootprintVector",
    "Incidence",
    "NamedBlindSpot",
    "PlaneId",
    "PresenceState",
    "SharedCredentialVerdict",
    "SieveEntity",
    "TypedEdge",
    "UnseenEstimate",
]
