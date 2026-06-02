"""
Signal trust tier — the admissibility grade of a discovery signal.

This is the dimension the rest of the category does not have, and it is
the one that turns Tex's inventory from "most complete" into "court-
admissible." It answers a different question than ``AgentTrustTier``:

    AgentTrustTier   → how much do we trust this agent to *act*
                       (a governance / privilege axis).
    SignalTrustTier  → how much could this agent have *faked the signal
                       that revealed it* (an evidentiary / tamper-
                       resistance axis).

The two are orthogonal. A privileged, fully trusted agent can still be
known to Tex only through a forgeable self-declaration; an unsanctioned
shadow agent can be known through tamper-proof kernel observation. The
provability of the inventory is therefore graded per agent, not binary.

The hierarchy (the "Signal Source Trust Hierarchy") ranks every
discovery vantage by how much the workload being observed can do to the
signal before it reaches Tex. Signals the workload cannot reach sit at
the top; signals the workload emits about itself sit at the bottom. A
witness must prefer the former and seal which one it actually had.

    KERNEL_ATTESTED   the workload cannot reach this signal at all —
                      kernel-level observation (eBPF), a hardware /TEE
                      attestation of measured code. Highest admissibility.
    AUDIT_LOG         a control-plane audit log that fires outside the
                      workload's reachability surface (cloud audit trail).
                      Tamper-resistant and, usefully, agentless.
    NETWORK_OBSERVED  out-of-process behavioural observation at a choke-
                      point — egress flow, the enforcement gate itself.
                      The workload cannot suppress that it acted.
    CONTROL_PLANE     a platform/IdP API enumeration (OAuth consent,
                      directory listing). Authoritative for what the
                      platform knows, but mediated by that platform.
    SELF_DECLARED     the workload (or its operator) asserting its own
                      existence — an A2A/MCP card, an in-process emit.
                      Lowest admissibility: forgeable by definition.

Nothing here implies a self-declared agent is ignored. It is recorded —
but recorded *as* self-declared, so the seal never overstates what Tex
knows. That honesty is the product.
"""

from __future__ import annotations

from enum import IntEnum


class SignalTrustTier(IntEnum):
    """
    Tamper-resistance grade of the signal that discovered an agent.

    Modelled as an ``IntEnum`` so tiers compare and sort directly: a
    higher value is more admissible. ``max(...)`` over the tiers that
    confirmed an agent yields the strongest grade Tex can defend, which
    is exactly what a birth certificate should carry.
    """

    SELF_DECLARED = 1
    CONTROL_PLANE = 2
    NETWORK_OBSERVED = 3
    AUDIT_LOG = 4
    KERNEL_ATTESTED = 5

    @property
    def label(self) -> str:
        return {
            SignalTrustTier.SELF_DECLARED: "self_declared",
            SignalTrustTier.CONTROL_PLANE: "control_plane",
            SignalTrustTier.NETWORK_OBSERVED: "network_observed",
            SignalTrustTier.AUDIT_LOG: "audit_log",
            SignalTrustTier.KERNEL_ATTESTED: "kernel_attested",
        }[self]

    @property
    def is_tamper_resistant(self) -> bool:
        """
        True when the workload being observed cannot forge or suppress
        the signal. These are the tiers a witness can stand behind
        without qualification.
        """
        return self >= SignalTrustTier.NETWORK_OBSERVED

    @property
    def admissibility(self) -> str:
        """Human-facing phrasing for the spoken / sealed coverage edge."""
        if self >= SignalTrustTier.AUDIT_LOG:
            return "proven"
        if self is SignalTrustTier.NETWORK_OBSERVED:
            return "observed"
        if self is SignalTrustTier.CONTROL_PLANE:
            return "platform_attested"
        return "claimed"


# ---------------------------------------------------------------------------
# Source → tier mapping
# ---------------------------------------------------------------------------
#
# Where a given DiscoverySource sits in the hierarchy. The behavioural
# provenance engine observes at the enforcement gate, which is a
# chokepoint the workload cannot bypass while still acting, so its
# signal is NETWORK_OBSERVED — tamper-resistant. Platform connectors
# (Graph, Salesforce, Bedrock control plane, etc.) are CONTROL_PLANE:
# authoritative for what the platform knows, but mediated by it. A bare
# MCP / A2A card is SELF_DECLARED.
#
# Keyed by the *string value* of DiscoverySource to avoid a hard import
# cycle (domain.discovery imports nothing from here, and this module
# stays importable on its own). Unknown sources default to CONTROL_PLANE,
# the conservative middle: never assume tamper-resistance we can't show.

_SOURCE_TIER: dict[str, SignalTrustTier] = {
    "aws_bedrock": SignalTrustTier.CONTROL_PLANE,
    "microsoft_graph": SignalTrustTier.CONTROL_PLANE,
    "salesforce": SignalTrustTier.CONTROL_PLANE,
    "github": SignalTrustTier.CONTROL_PLANE,
    "openai": SignalTrustTier.CONTROL_PLANE,
    "slack": SignalTrustTier.CONTROL_PLANE,
    "langsmith": SignalTrustTier.CONTROL_PLANE,
    "mcp_server": SignalTrustTier.SELF_DECLARED,
    "generic": SignalTrustTier.SELF_DECLARED,
    # Forward-looking planes (connectors land later; the grade is fixed now).
    "cloud_audit": SignalTrustTier.AUDIT_LOG,
    "network_egress": SignalTrustTier.NETWORK_OBSERVED,
    "enforcement_gate": SignalTrustTier.NETWORK_OBSERVED,
    "kernel_ebpf": SignalTrustTier.KERNEL_ATTESTED,
    "tee_attestation": SignalTrustTier.KERNEL_ATTESTED,
}


def tier_for_source(source: str) -> SignalTrustTier:
    """Resolve the admissibility tier for a discovery source string."""
    return _SOURCE_TIER.get(str(source), SignalTrustTier.CONTROL_PLANE)
