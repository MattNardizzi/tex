"""
Consent graph — the IdP estate as a graph, not a list.

"Defenders think in lists. Attackers think in graphs. As long as this is
true, attackers win." The directory companies enumerate agents as a flat
table. The advantage hiding in the same data is the *graph*: an agent is a
node, an OAuth consent grant is a directed edge to the resource it may
touch, and the transitive closure of those edges is the agent's blast
radius — the set of systems a compromise of it could reach. That is the
question a directory cannot answer from a row, and the one a witness should
seal.

This module is a small, pure, deterministic graph over consent edges. It
takes the records the Microsoft Graph (or Okta) APIs already return —
service principals, ``oauth2PermissionGrants``, ``appRoleAssignments`` —
and turns them into nodes and edges, then computes per-agent reach. It does
no I/O; the connector feeds it. Keeping it pure keeps it testable and keeps
the seal reproducible: the same directory state yields the same graph.

Nothing here is content. An edge carries the two principal ids, the scopes
granted, and whether the grant is tenant-wide — structural facts the
platform records, never anything the agent said or did.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Scopes that grant write or control at tenant breadth — the ones that make
# a reachable resource a real blast-radius concern rather than a read.
HIGH_RISK_SCOPE_STEMS: frozenset[str] = frozenset(
    {
        "readwrite", "fullcontrol", "manage", "write", "send",
        "delete", "impersonation", "accessasuser",
    }
)

# Scopes that are tenant-wide control of identity itself — an agent holding
# one of these can grant *other* agents access, so its blast radius is the
# whole tenant. These force an unbounded surface.
CRITICAL_SCOPE_STEMS: frozenset[str] = frozenset(
    {
        "directory.readwrite.all",
        "application.readwrite.all",
        "rolemanagement.readwrite.directory",
        "approleassignment.readwrite.all",
        "privilegedaccess.readwrite.azuread",
    }
)


@dataclass(frozen=True, slots=True)
class ConsentEdge:
    """One directed consent: ``client`` may act on ``resource`` with ``scopes``."""

    client_id: str
    resource_id: str
    resource_name: str
    scopes: tuple[str, ...]
    tenant_wide: bool  # AllPrincipals / application permission


@dataclass
class _Node:
    principal_id: str
    display_name: str = ""
    is_agent: bool = False
    out_edges: list[ConsentEdge] = field(default_factory=list)


class ConsentGraph:
    """
    A directed graph of consent edges with blast-radius reachability.

    Build it by registering principals and their grants, then ask, per
    agent, what it can reach — directly and transitively (a resource that is
    itself an agent extends the path). The reach set is the agent's sealed
    blast radius.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, _Node] = {}

    # ------------------------------------------------------------------ build
    def add_principal(self, principal_id: str, *, display_name: str = "", is_agent: bool = False) -> None:
        node = self._nodes.get(principal_id)
        if node is None:
            self._nodes[principal_id] = _Node(
                principal_id=principal_id, display_name=display_name, is_agent=is_agent
            )
        else:
            if display_name:
                node.display_name = display_name
            node.is_agent = node.is_agent or is_agent

    def add_edge(self, edge: ConsentEdge) -> None:
        if edge.client_id not in self._nodes:
            self.add_principal(edge.client_id)
        if edge.resource_id not in self._nodes:
            self.add_principal(edge.resource_id, display_name=edge.resource_name)
        self._nodes[edge.client_id].out_edges.append(edge)

    # ------------------------------------------------------------------ read
    def direct_edges(self, principal_id: str) -> tuple[ConsentEdge, ...]:
        node = self._nodes.get(principal_id)
        return tuple(node.out_edges) if node else ()

    def reachable_resources(self, principal_id: str) -> frozenset[str]:
        """
        Transitive closure of resources ``principal_id`` can reach by
        following consent edges. Bounded by cycle-guarding the visited set;
        a resource that is itself an agent extends the path.
        """
        seen: set[str] = set()
        stack = [principal_id]
        while stack:
            current = stack.pop()
            node = self._nodes.get(current)
            if node is None:
                continue
            for edge in node.out_edges:
                if edge.resource_id not in seen:
                    seen.add(edge.resource_id)
                    stack.append(edge.resource_id)
        seen.discard(principal_id)
        return frozenset(seen)

    def scope_set(self, principal_id: str) -> frozenset[str]:
        node = self._nodes.get(principal_id)
        if node is None:
            return frozenset()
        scopes: set[str] = set()
        for edge in node.out_edges:
            scopes.update(s.casefold() for s in edge.scopes)
        return frozenset(scopes)

    def blast_radius(self, principal_id: str) -> dict:
        """
        The sealed blast-radius summary for one agent: how many resources it
        can reach, the names of the directly-granted ones, its scope set,
        and whether any scope makes the surface unbounded.
        """
        direct = self.direct_edges(principal_id)
        reachable = self.reachable_resources(principal_id)
        scopes = self.scope_set(principal_id)
        critical = sorted(s for s in scopes if s in CRITICAL_SCOPE_STEMS)
        high = sorted(
            s for s in scopes
            if any(stem in s for stem in HIGH_RISK_SCOPE_STEMS)
        )
        tenant_wide = any(e.tenant_wide for e in direct)
        return {
            "direct_resources": sorted({e.resource_name or e.resource_id for e in direct}),
            "reachable_resource_count": len(reachable),
            "scopes": sorted(scopes),
            "high_risk_scopes": high,
            "critical_scopes": critical,
            "tenant_wide_grant": tenant_wide,
            "surface_unbounded": bool(critical) or (tenant_wide and bool(high)),
        }

    def agents(self) -> tuple[str, ...]:
        """Principal ids flagged as agents (the ones the connector emits)."""
        return tuple(n.principal_id for n in self._nodes.values() if n.is_agent)

    def __len__(self) -> int:
        return len(self._nodes)
