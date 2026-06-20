"""Presence brain (Session 1): grounded reasoning + deterministic read-tools.

Two halves, both swappable, neither load-bearing on its own:

* :func:`build_read_tools` / :class:`BrainReadTool` — deterministic, model-free
  reads over the sealed ``app.state`` stores for the six governance dimensions
  (execution, human_decision, evidence, identity, monitoring, discovery) plus
  windowed aggregates. Each returns ``(value, tuple[EvidenceRef])`` so the gate can
  re-verify by iterating rows.
* :class:`GroundedReasoner` — an off-the-shelf, swappable model that *proposes*
  phrasing + candidate :class:`~tex.presence.contract.PresenceClaim` s from the
  sealed facts it is handed. It never sources facts and its output is verified by
  Session 2's gate before anything is spoken.

The default model is Claude via
:class:`~tex.semantic.anthropic.AnthropicStructuredSemanticProvider`, but any
:class:`~tex.semantic.analyzer.StructuredSemanticProvider` may be swapped in, and
``provider=None`` yields a deterministic no-op proposer.
"""

from tex.presence.brain.evidence import (
    canonical_sha256,
    chained_ref,
    digest_ref,
)
from tex.presence.brain.grounded_brain import GroundedReasoner, build_grounded_brain
from tex.presence.brain.read_tools import (
    DIMENSIONS,
    BrainReadTool,
    build_read_tool_registry,
    build_read_tools,
)

__all__ = [
    "BrainReadTool",
    "DIMENSIONS",
    "GroundedReasoner",
    "build_grounded_brain",
    "build_read_tools",
    "build_read_tool_registry",
    "canonical_sha256",
    "chained_ref",
    "digest_ref",
]
