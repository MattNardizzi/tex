"""
MCP capability tokens.

Reference: Son. "Governed MCP: Kernel-Level Tool Governance for AI Agents
via Logit-Based Safety Primitives." arXiv:2604.16870 (Apr 2026).

Each capability grants the holder the right to invoke a specific MCP tool
(or tool family) with constrained parameters. Capabilities are unforgeable,
revocable, and subject to least-privilege constraints.

The Governed MCP paper's Section 4.2 specifies four trust tiers and notes
that "each tool declares its minimum required tier; the gateway checks
that the calling agent's tier is at least the required level". Tex
implements that as a capability-augmented model: the trust tier lives on
the agent (CapabilitySet.trust_tier) and the minimum-required tier lives
on the capability (McpCapability.required_trust_tier). The syscall gate
enforces the relation in Layer 2.

Capability signatures
---------------------
The Governed MCP paper does not specify a signature scheme; Tex makes
this pluggable via tex.pqcrypto.algorithm_agility (Rule 6: ECDSA today,
ML-DSA-65 once liboqs lands). The signature_b64 field below stores the
base64-encoded signature; verification is delegated to the capability
issuer. Issuers SHOULD rotate keys regularly and revoke capabilities
through CapabilitySet.revoke().

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


# Trust tiers per Governed MCP paper Section 4.2.
# Ordered most-trusted to least-trusted; comparisons use tier_rank() below.
TrustTier = Literal["System", "AiNative", "AiEnhanced", "Classic"]


_TIER_RANKS: dict[str, int] = {
    "System": 3,
    "AiNative": 2,
    "AiEnhanced": 1,
    "Classic": 0,
}


def tier_rank(tier: TrustTier) -> int:
    """Return the integer rank of a trust tier (higher = more trusted)."""
    if tier not in _TIER_RANKS:
        raise ValueError(f"unknown trust tier: {tier!r}")
    return _TIER_RANKS[tier]


def tier_meets(actual: TrustTier, required: TrustTier) -> bool:
    """True iff ``actual`` is at least as trusted as ``required``."""
    return tier_rank(actual) >= tier_rank(required)


@dataclass(frozen=True, slots=True)
class McpCapability:
    """
    An unforgeable token authorizing a specific MCP tool invocation.

    Attributes
    ----------
    capability_id:
        Stable identifier; used as the rate-limit bucket key.
    tool_name:
        Exact MCP tool name (the value matched against ``call_tool``'s
        ``name`` field). Wildcard patterns are intentionally not
        supported in v1: per least-privilege, every tool family that a
        capability grants must be enumerated separately.
    parameter_constraints:
        Dict of constraints applied to the tool input. Recognized keys:
          allowed_values: <key> -> tuple of permitted values
          allowed_url_schemes: tuple of schemes (e.g. ("https",))
          allowed_url_hosts: tuple of permitted hostnames
          max_payload_bytes: int upper bound on the JSON-serialized input
          deny_keys: tuple of input keys that must NOT be present
          require_keys: tuple of input keys that MUST be present
        Unknown keys are ignored by the gate (forward-compatible).
    issued_to:
        Agent identity that holds this capability. Matched against the
        agent's identity at gate-check time.
    issued_at:
        Issuance timestamp (UTC).
    expires_at:
        Expiration timestamp (UTC). Capabilities past their expiry are
        rejected by the gate.
    issuer_signature_b64:
        Base64-encoded signature over the canonical capability bytes,
        produced via ``tex.pqcrypto.algorithm_agility``. Signature
        verification is the issuer's responsibility; the gate checks
        only that the field is non-empty.
    required_trust_tier:
        Minimum trust tier the calling agent must have to use this
        capability (Governed MCP Layer 2). Defaults to "Classic" so
        that a capability without an explicit trust requirement is
        usable by any agent.
    rate_limit_per_minute:
        Maximum invocations of this capability per 60-second window
        (Governed MCP Layer 3). Default 60 = 1/sec average.
    """

    capability_id: str
    tool_name: str
    parameter_constraints: dict
    issued_to: str  # agent identity
    issued_at: datetime
    expires_at: datetime
    issuer_signature_b64: str  # ML-DSA signed
    required_trust_tier: TrustTier = "Classic"
    rate_limit_per_minute: int = 60


@dataclass(frozen=True, slots=True)
class CapabilitySet:
    """
    A set of capabilities held by an agent for a session.

    Attributes
    ----------
    capabilities:
        The set of capabilities held by the agent. The same agent may
        hold multiple capabilities for the same tool with different
        parameter constraints; the gate uses the *first matching*
        capability (preserving caller order so authorial intent is
        explicit).
    agent_identity:
        Identity of the holding agent. Matched against
        McpCapability.issued_to.
    trust_tier:
        Trust tier of the holding agent (Governed MCP Section 4.2:
        System / AiNative / AiEnhanced / Classic).
    revoked_capability_ids:
        Set of capability IDs that have been revoked. Revoked
        capabilities are present in ``capabilities`` for audit-trail
        continuity but rejected by the gate.
    """

    capabilities: tuple[McpCapability, ...]
    agent_identity: str = "anonymous-agent"
    trust_tier: TrustTier = "Classic"
    revoked_capability_ids: frozenset[str] = field(default_factory=frozenset)

    def revoke(self, capability_id: str) -> "CapabilitySet":
        """Return a new CapabilitySet with ``capability_id`` revoked."""
        return CapabilitySet(
            capabilities=self.capabilities,
            agent_identity=self.agent_identity,
            trust_tier=self.trust_tier,
            revoked_capability_ids=self.revoked_capability_ids | {capability_id},
        )

    def find_for(self, tool_name: str) -> tuple[McpCapability, ...]:
        """Return all non-revoked capabilities for a given tool name."""
        return tuple(
            c for c in self.capabilities
            if c.tool_name == tool_name
            and c.capability_id not in self.revoked_capability_ids
        )
