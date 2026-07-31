"""
Integrity lattice for ARM trust propagation.

Total order over five trust levels:

    ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr

The trust level of a data item derived from multiple sources is the
*minimum* of its sources' trust levels (conservative join —
"Minimum Reachable Trust").

Monotonic taint: for any edge ``(u, v) ∈ E``,
``MinTrust(v) ≤ MinTrust(u)``.

Default policy threshold ``θ`` for graph-aware enforcement (ARM Layer 2)
is ``ToolTrusted``: a tool call with any ancestor at or below
``ToolUntrusted`` is denied.
"""

from __future__ import annotations

from enum import IntEnum


class IntegrityLevel(IntEnum):
    """
    Trust levels, totally ordered low → high.

    ``IntEnum`` so callers can compare directly with ``<`` / ``>`` and so
    ``min(...)`` over a set of levels yields the lattice meet without
    extra wrapping. Numeric values are stable but private — callers
    should reference levels by name.
    """

    TOOL_DESC = 0          # MCP tool descriptions; can be poisoned by malicious server
    TOOL_UNTRUSTED = 1     # raw tool output (web scrape, untrusted API)
    TOOL_TRUSTED = 2       # signed/attested tool output
    USER_INPUT = 3         # end-user message
    SYS_INSTR = 4          # operator system prompt; highest trust


# Default threshold for ARM Layer 2 graph-aware enforcement. A tool call
# whose minimum-reachable-trust falls *below* this threshold is denied.
# ToolTrusted is the operational default.
DEFAULT_TRUST_THRESHOLD: IntegrityLevel = IntegrityLevel.TOOL_TRUSTED


def lattice_meet(levels: tuple[IntegrityLevel, ...]) -> IntegrityLevel:
    """
    Lattice meet (min) over a non-empty tuple of integrity levels.

    Minimum Reachable Trust: the effective trust of a node is the
    minimum trust over its data ancestors. Empty input is a
    programmer error rather than a silent SysInstr default — callers
    that need the empty-ancestor case should branch explicitly.
    """
    if not levels:
        raise ValueError("lattice_meet requires at least one level")
    return min(levels)
