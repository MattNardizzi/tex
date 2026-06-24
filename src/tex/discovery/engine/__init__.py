"""
SIEVE — Sparse-Incidence Entity & Vantage Estimator.

The greenfield discovery engine for Tex's Discover leg. This package holds its
OWN data model (``models``), the SENSE/FUSE/ESTIMATE pipeline stages, and the
one-way OUTPUT ADAPTER into the existing ``agent_registry`` / ``discovery_ledger``
so ``StandingGovernance.decide`` governs every resolved entity.

Everything is flag-gated behind ``TEX_SIEVE_ENABLED`` (default OFF). The slice
is exercised by direct unit/integration tests and is NOT yet wired into
``_build_discovery_connectors`` — a merge to main must not activate anything or
crash boot. See ARCHITECTURE.md §8, §10.

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

# Truthy spellings accepted for the master flag, matching the repo's other
# env-gated features (1/true/yes/on, case-insensitive).
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: The master activation flag name (ARCHITECTURE.md §8). Default OFF.
SIEVE_ENABLED_ENV = "TEX_SIEVE_ENABLED"


def is_sieve_enabled(env: dict[str, str] | None = None) -> bool:
    """Whether the SIEVE engine is activated for the live service.

    Reads ``TEX_SIEVE_ENABLED`` (default OFF). Accepts ``1/true/yes/on``
    (case-insensitive). When OFF, the live service falls back to key-equality
    reconciliation and SIEVE never runs in the request/scan path — but the data
    model and the direct-test entrypoints remain fully importable and usable.

    ``env`` is injectable so tests and the verifier can probe the gate without
    mutating the real process environment.
    """
    source = env if env is not None else os.environ
    return source.get(SIEVE_ENABLED_ENV, "").strip().casefold() in _TRUTHY


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
