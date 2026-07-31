"""
MCPShield Labeled Transition System.

Reference: arxiv 2604.05969 (Acharya & Gupta), April 2026.

Formal model of an MCP-based agent system:

    Definition 2 (MCP Agent System): An MCP agent system is a tuple
        (A, S, T, D, λ) where
            A  is the set of agents,
            S  is the set of MCP servers,
            T  is the set of tools,
            D  is the set of trust domains,
            λ  is a labeling function mapping data values to security
               labels drawn from a label lattice L.

    Definition 3 (Trust Domain): D_i = (S_i, T_i, π_i) groups a set of
        servers S_i ⊆ S and their tools T_i ⊆ T under a common trust
        policy π_i. Communication within a trust domain is trusted;
        cross-domain communication requires explicit authorization.

    Definition 4 (MCP Transition System): a labeled transition system
        (Q, Σ, →, q_0) where Σ is the alphabet of labeled actions
        (tool_invoke, data_flow, server_register, …) and the transition
        relation may also carry trust-boundary annotations.

We provide:

    SecurityLabel    — element of the label lattice L (Bell-LaPadula style).
    DataValue        — a value carrying its label (ℓ_d ∈ L).
    TrustDomain      — D_i tuple.
    ToolDefinition   — name + capability + cryptographic hash of definition
                       at approval time.
    Transition       — labeled transition (q, action, q') with optional
                       trust-boundary metadata.
    LtsModel         — the full system tuple.

Priority: P1.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ----------------------------------------------------------------------
# Security label lattice L (Bell-LaPadula style).  We co-locate a small
# lattice with MCPShield instead of importing AgentArmor's so the layers
# stay independently auditable.
# ----------------------------------------------------------------------


class SecurityLabel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


_LABEL_ORDER = {
    SecurityLabel.PUBLIC: 0,
    SecurityLabel.INTERNAL: 1,
    SecurityLabel.CONFIDENTIAL: 2,
    SecurityLabel.SECRET: 3,
}


def label_dominates(higher: SecurityLabel, lower: SecurityLabel) -> bool:
    """True iff ``higher`` is at least as restrictive as ``lower``."""
    return _LABEL_ORDER[higher] >= _LABEL_ORDER[lower]


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EXEC = "exec"


# ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrustBoundary:
    """Marks a transition that crosses a trust boundary."""

    from_zone: str  # "user" | "agent" | "mcp_server" | "external_api" | trust-domain id
    to_zone: str
    label: str  # describes the data flowing across


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One tool, with hash captured at approval time per Property 1."""

    name: str
    server: str
    capability: Capability
    declared_perms: frozenset[Capability]
    definition_blob: str  # canonical tool definition (description, schema)
    approval_hash_hex: str  # H(definition_blob) at approval time

    @staticmethod
    def hash_definition(blob: str) -> str:
        """Cryptographic hash H. Per the paper, any collision-resistant H
        works; we use SHA-256 (FIPS 180-4) here to keep the runtime layer
        free of liboqs dependencies for verification.
        """
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustDomain:
    """D_i = (S_i, T_i, π_i)."""

    domain_id: str
    servers: frozenset[str]
    tools: frozenset[str]
    policy: str  # textual or symbolic policy identifier; opaque here

    def covers_server(self, server: str) -> bool:
        return server in self.servers

    def covers_tool(self, tool_name: str) -> bool:
        return tool_name in self.tools


@dataclass(frozen=True, slots=True)
class DataValue:
    """A data value carrying its security label."""

    name: str
    label: SecurityLabel
    origin_domain: str  # the trust-domain id where this value was created


@dataclass(frozen=True, slots=True)
class Transition:
    """One labeled transition (q, action, q').

    ``action`` is one of:
      tool_invoke   payload: {tool, agent_caps, data_in, data_out, target_domain}
      data_flow    payload: {data, dst, dst_label}
      server_register / server_update / server_remove
      cross_domain payload: {from_domain, to_domain, authorized}
    """

    q_from: str
    action: str
    q_to: str
    payload: dict[str, Any] = field(default_factory=dict)
    trust_boundary: TrustBoundary | None = None


@dataclass(frozen=True, slots=True)
class LtsModel:
    """Full MCP transition system.

    ``states`` is the set Q. ``transitions`` is the labeled transition
    relation. ``initial_state`` is q_0. The remaining fields cover the
    Definition-2 tuple (A, S, T, D, λ) with the labeling λ being implicit
    in each ``DataValue.label``.
    """

    states: tuple[str, ...]
    transitions: tuple[Transition, ...]
    trust_boundaries: tuple[TrustBoundary, ...]
    initial_state: str = ""
    agents: tuple[str, ...] = ()
    servers: tuple[str, ...] = ()
    tools: tuple[ToolDefinition, ...] = ()
    domains: tuple[TrustDomain, ...] = ()

    # ------------------------------------------------------------------
    def domain_of_server(self, server: str) -> TrustDomain | None:
        for d in self.domains:
            if d.covers_server(server):
                return d
        return None

    def domain_of_tool(self, tool_name: str) -> TrustDomain | None:
        for d in self.domains:
            if d.covers_tool(tool_name):
                return d
        return None

    def tool(self, name: str) -> ToolDefinition | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None
