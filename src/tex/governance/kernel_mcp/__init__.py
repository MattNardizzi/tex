"""
Kernel-Level / Syscall-Style MCP Governance.

Reference: Son. "Governed MCP: Kernel-Level Tool Governance for AI Agents
via Logit-Based Safety Primitives." arXiv:2604.16870 (Apr 2026).

Treats every MCP tool call as a privileged syscall subject to a kernel-style
policy module. Provides:
  - Capability-based access control over MCP tool surface
  - Six-layer pipeline (schema/trust/rate/prefilter/semantic/constitutional)
  - SSRF guard that resists CVE-2026-44232 IPv6 bypass classes
  - Outbound-secret pattern detection
  - SHA-256 hash-chained audit log (Blake3 migration is a TODO per Rule 6)
  - FAIL-CLOSED semantics: any layer failure denies the call

Highly aligned with Tex as an execution gate.

Priority: P1.
"""

from tex.governance.kernel_mcp.capability import (
    CapabilitySet,
    McpCapability,
    TrustTier,
    tier_meets,
    tier_rank,
)
from tex.governance.kernel_mcp.syscall_gate import (
    ConstitutionalPrinciple,
    McpAuditRecord,
    McpGateConfig,
    McpSyscallGate,
    SemanticGateFn,
    SemanticGateResult,
)

__all__ = [
    "CapabilitySet",
    "ConstitutionalPrinciple",
    "McpAuditRecord",
    "McpCapability",
    "McpGateConfig",
    "McpSyscallGate",
    "SemanticGateFn",
    "SemanticGateResult",
    "TrustTier",
    "tier_meets",
    "tier_rank",
]
