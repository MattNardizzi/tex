"""
Drift Layer — Change-Point Detection + Emergent Norm Tracing
=============================================================

Detects distributional change in streaming traces of the ecosystem. Finds
where the system has begun behaving differently from its committed baseline.

Reference
---------
arxiv 2512.18561 (AAF). Empirical numbers: 71-step median detection delay,
IQR 39-177, 0.97 mean top-ranked attribution accuracy at 10% Byzantine rate.

Distinct from the existing per-tenant content baseline drift in
`tex.discovery.alerts`. The ecosystem drift layer operates on the full
ecosystem graph stream, not just outbound content.

Detector composition
--------------------
The package ships a primary BOCPD detector (Adams & MacKay 2007,
arXiv:0710.3742) plus an alternative adaptive-CUSUM detector (Page 1954)
selectable via ``ChangePointDetector(detector_kind="cusum")``. AAF uses
adaptive CUSUM in its 71-step empirical claim, so deployments that need
to exactly reproduce the paper's numbers can opt into CUSUM. Both
detectors satisfy the same ``update(...) -> bool`` surface and emit
identical ``ChangePointEvent`` records into the events ledger.

Priority
--------
P1.
"""

from tex.drift.change_point import (
    ChangePointDetector,
    ChangePointEvent,
)
from tex.drift.emergent_norm import (
    PATTERN_ACTION_LOCKSTEP,
    PATTERN_SHARED_TARGET_CONVERGENCE,
    EmergentNormTracer,
    EmergentPattern,
)
from tex.drift.signal_registry import (
    DEFAULT_SIGNAL_IDS,
    SIGNAL_AVERAGE_COMPROMISE_SCORE,
    SIGNAL_AVERAGE_PATH_DEPTH,
    SIGNAL_CAPABILITY_GRANT_RATE,
    SIGNAL_CROSS_AGENT_MESSAGE_RATE,
    SIGNAL_DENIAL_RATE_PER_AGENT,
    SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT,
    SIGNAL_TOOL_CALL_RATE_PER_AGENT,
    DriftSignal,
    DriftSignalRegistry,
)

__all__ = [
    # Public classes
    "ChangePointDetector",
    "ChangePointEvent",
    "EmergentNormTracer",
    "EmergentPattern",
    "DriftSignalRegistry",
    "DriftSignal",
    # Pattern kind constants
    "PATTERN_ACTION_LOCKSTEP",
    "PATTERN_SHARED_TARGET_CONVERGENCE",
    # Default signal id constants
    "DEFAULT_SIGNAL_IDS",
    "SIGNAL_TOOL_CALL_RATE_PER_AGENT",
    "SIGNAL_CROSS_AGENT_MESSAGE_RATE",
    "SIGNAL_CAPABILITY_GRANT_RATE",
    "SIGNAL_DENIAL_RATE_PER_AGENT",
    "SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT",
    "SIGNAL_AVERAGE_PATH_DEPTH",
    "SIGNAL_AVERAGE_COMPROMISE_SCORE",
]
