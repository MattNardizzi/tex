"""
MAGE: Memory As Guardrail Enforcement.

Reference: arxiv 2605.03228, Wang et al (Stony Brook + Cisco), May 4 2026.

Inspired by the shadow stack abstraction from systems security. Maintains
a dedicated, safety-focused agentic memory that distills safety-critical
context across the agent's full execution trajectory. Used to proactively
assess the risk of pending actions BEFORE they execute.

Defends against long-horizon threats: multi-turn attacks (sequential tool
attack chaining, persistent indirect prompt injection) that fly under
single-turn detectors. Achieves STAC ASR 100% → 8.3% and PI2 ASR → 0% in
the paper's evaluation.

Two components share the same backbone:
  M (memory manager)  -> ShadowMemory       Eq. 2:  m_t = M(m_{t-1}, s_{t-1})
  J (judge)           -> PreActionRiskAssessor  Eq. 3: d_t, e_t = J(a_t | m_t)

Priority: P1.
"""

from tex.runtime.mage.risk_assessor import (
    JudgeCallable,
    PreActionRiskAssessor,
)
from tex.runtime.mage.shadow_memory import (
    RelevanceScorer,
    ShadowMemory,
    ShadowMemoryEntry,
    keyword_overlap_scorer,
)

__all__ = [
    "JudgeCallable",
    "PreActionRiskAssessor",
    "RelevanceScorer",
    "ShadowMemory",
    "ShadowMemoryEntry",
    "keyword_overlap_scorer",
]
