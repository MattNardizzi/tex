"""
Integrity lattice for ARM trust propagation.

Per arxiv 2604.04035 Definition 1: total order over five trust levels:

    ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr

The trust level of a data item derived from multiple sources is the
*minimum* of its sources' trust levels (conservative join — Section 5.3,
"Minimum Reachable Trust").

Property 1 (Monotonic Taint): for any edge ``(u, v) ∈ E``,
``MinTrust(v) ≤ MinTrust(u)``.

Default policy threshold ``θ`` for graph-aware enforcement (ARM Layer 2,
Section 4.3.2 / Section 5.4) is ``ToolTrusted``: a tool call with any
ancestor at or below ``ToolUntrusted`` is denied.
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

    Reference: arxiv 2604.04035 Definition 1.
    """

    TOOL_DESC = 0          # MCP tool descriptions; can be poisoned by malicious server
    TOOL_UNTRUSTED = 1     # raw tool output (web scrape, untrusted API)
    TOOL_TRUSTED = 2       # signed/attested tool output
    USER_INPUT = 3         # end-user message
    SYS_INSTR = 4          # operator system prompt; highest trust


# Default threshold for ARM Layer 2 graph-aware enforcement (Section 4.3.2).
# A tool call whose minimum-reachable-trust falls *below* this threshold is
# denied. The paper picks ToolTrusted as the operational default.
DEFAULT_TRUST_THRESHOLD: IntegrityLevel = IntegrityLevel.TOOL_TRUSTED


def lattice_meet(levels: tuple[IntegrityLevel, ...]) -> IntegrityLevel:
    """
    Lattice meet (min) over a non-empty tuple of integrity levels.

    Per Definition 4 (Minimum Reachable Trust), the effective trust of a
    node is the minimum trust over its data ancestors. Empty input is a
    programmer error rather than a silent SysInstr default — callers
    that need the empty-ancestor case should branch explicitly.

    Reference: arxiv 2604.04035 §5.3.
    """
    if not levels:
        raise ValueError("lattice_meet requires at least one level")
    return min(levels)
