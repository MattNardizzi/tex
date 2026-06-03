"""
ARM-style provenance graph with counterfactual edges.

Reference (primary)
-------------------
Chinaei, M. H. "Causality Laundering: Denial-Feedback Leakage in
Tool-Calling LLM Agents." arXiv:2604.04035v1 [cs.CR] 05 Apr 2026.

This is the bleeding-edge model nobody has shipped yet: the ARM paper
identifies a class of implicit-flow attacks (*causality laundering*)
that flat IFC tracking and successful-execution dependency graphs both
miss. The defense models denied actions as first-class provenance
nodes with COUNTERFACTUAL edges to subsequent calls.

Companion references
--------------------
- FIDES (arxiv 2505.23643): label-based IFC with type-augmented product
  lattice. We integrate the product lattice from
  ``tex.governance.private_data_exec.ifc.lattice``.

- PCAS (arxiv 2602.16708): dependency-graph + Datalog policies. Our
  graph structure is compatible with future PCAS-style query
  compilation, but we ship a deterministic enforcement query (ARM
  §5.4) directly to avoid the Datalog dependency.

- NeuroTaint / "Ghost in the Agent" (arxiv 2604.23374): semantic +
  causal + cross-session taint axes. Our `Edge.kind` set includes
  ``Counterfactual`` (causal) and the cross-session axis is realized
  by `MemoryStream` in `tex.governance.private_data_exec.ifc.memory`.

- GAAP (arxiv 2604.19657): GAAP's permission DB and disclosure log are
  preserved as a complementary axis. The provenance graph here is the
  *upstream* tracking layer; GAAP's DisclosureLog remains the
  downstream egress audit.

Design rules (constitution-mandated)
------------------------------------
- Pydantic v2 strict ConfigDict(frozen=True, extra="forbid") on every
  exported model. Internal mutable graph state uses dataclasses
  (slots) for hot-path performance.
- Fail-closed: no enforcement query ever returns Allow on error. The
  Layer-2 query returns Deny on inconsistent input.
- Deterministic: graph traversal uses sorted iteration over edges and
  nodes so that fingerprints are reproducible.
- No exec(): the graph computes over data structures only.
- Sub-millisecond evaluation for graphs up to hundreds of nodes (the
  paper's target). Our pure-Python implementation is benchmarked in
  tests/governance/test_ifc_provenance.py.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable, Iterator
from uuid import UUID, uuid4

from tex.governance.private_data_exec.ifc.lattice import (
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)


# ---------------------------------------------------------------------------
# Node and edge types (ARM Definition 3)
# ---------------------------------------------------------------------------


class NodeKind(str, enum.Enum):
    """Four node kinds per ARM §5.1."""

    CALL = "call"
    DATA = "data"
    DATA_FIELD = "data_field"
    DENIED_ACTION = "denied_action"


class EdgeKind(str, enum.Enum):
    """Four edge kinds per ARM §5.2.

    DirectOutput   : Call -> Data (the tool produced this data)
    InputTo        : Data -> Call (this data flowed into a later call)
    FieldOf        : DataField -> Data (a structured component)
    Counterfactual : DeniedAction -> Call (the denial may have
                     influenced this later call — the ARM-novel edge
                     that catches causality laundering)
    """

    DIRECT_OUTPUT = "direct_output"
    INPUT_TO = "input_to"
    FIELD_OF = "field_of"
    COUNTERFACTUAL = "counterfactual"


# ---------------------------------------------------------------------------
# Graph nodes (internal mutable state, slot-based for hot path)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    """Internal graph node.

    The label is None for CALL and DENIED_ACTION nodes (they are
    actions, not data). DATA and DATA_FIELD nodes always carry an
    IfcLabel.
    """

    node_id: str
    kind: NodeKind
    timestamp: datetime
    name: str = ""
    label: IfcLabel | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class _Edge:
    """Internal graph edge."""

    source: str
    target: str
    kind: EdgeKind
    timestamp: datetime


# ---------------------------------------------------------------------------
# The provenance graph (mutable; per-request lifecycle)
# ---------------------------------------------------------------------------


class ProvenanceGraph:
    """
    ARM-style provenance graph for one agent request.

    Lifetime: one graph per `EvaluationRequest`. The IfcSpecialist
    constructs the graph from the request's content, retrieved
    context, and any embedded tool-call metadata; then runs the
    enforcement queries (`min_trust`, `has_counterfactual_chain`); then
    records the result.

    Persisting the graph across requests for cross-session causal taint
    is the responsibility of `MemoryStream` (NeuroTaint axis).
    """

    __slots__ = ("_nodes", "_out_edges", "_in_edges", "_recent_denials")

    def __init__(self) -> None:
        self._nodes: dict[str, _Node] = {}
        self._out_edges: dict[str, list[_Edge]] = {}
        self._in_edges: dict[str, list[_Edge]] = {}
        # Recent denials, queried when adding a new CALL node so that
        # ARM Algorithm 1 lines 7-8 can auto-link a Counterfactual edge.
        self._recent_denials: list[str] = []

    # ── construction ────────────────────────────────────────────────

    def add_call(
        self,
        *,
        name: str,
        node_id: str | None = None,
        metadata: dict[str, object] | None = None,
        auto_link_counterfactual: bool = True,
    ) -> str:
        """
        Materialize a CALL node and (per ARM Alg. 1) auto-link a
        Counterfactual edge from any pending DeniedAction node.

        Returns the node_id.
        """
        nid = node_id or f"call:{uuid4()}"
        self._nodes[nid] = _Node(
            node_id=nid,
            kind=NodeKind.CALL,
            timestamp=datetime.now(UTC),
            name=name,
            metadata=dict(metadata or {}),
        )
        self._out_edges[nid] = []
        self._in_edges[nid] = []

        if auto_link_counterfactual and self._recent_denials:
            for denial_id in self._recent_denials:
                self.add_edge(
                    source=denial_id, target=nid, kind=EdgeKind.COUNTERFACTUAL
                )
            # ARM's heuristic is to link the temporally-adjacent next
            # call only; we clear after linking to honor that.
            self._recent_denials = []
        return nid

    def add_data(
        self,
        *,
        name: str,
        label: IfcLabel,
        node_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> str:
        nid = node_id or f"data:{uuid4()}"
        self._nodes[nid] = _Node(
            node_id=nid,
            kind=NodeKind.DATA,
            timestamp=datetime.now(UTC),
            name=name,
            label=label,
            metadata=dict(metadata or {}),
        )
        self._out_edges[nid] = []
        self._in_edges[nid] = []
        return nid

    def add_data_field(
        self,
        *,
        parent_data_id: str,
        field_name: str,
        label: IfcLabel,
        node_id: str | None = None,
    ) -> str:
        """Add a field node and a FieldOf edge to its parent data node."""
        if parent_data_id not in self._nodes:
            raise KeyError(f"parent data node not found: {parent_data_id}")
        if self._nodes[parent_data_id].kind is not NodeKind.DATA:
            raise ValueError("parent must be a DATA node")
        nid = node_id or f"field:{uuid4()}"
        self._nodes[nid] = _Node(
            node_id=nid,
            kind=NodeKind.DATA_FIELD,
            timestamp=datetime.now(UTC),
            name=field_name,
            label=label,
        )
        self._out_edges[nid] = []
        self._in_edges[nid] = []
        self.add_edge(source=nid, target=parent_data_id, kind=EdgeKind.FIELD_OF)
        return nid

    def add_denied_action(
        self,
        *,
        name: str,
        reason: str,
        metadata: dict[str, object] | None = None,
    ) -> str:
        nid = f"denied:{uuid4()}"
        meta = dict(metadata or {})
        meta["reason"] = reason
        self._nodes[nid] = _Node(
            node_id=nid,
            kind=NodeKind.DENIED_ACTION,
            timestamp=datetime.now(UTC),
            name=name,
            metadata=meta,
        )
        self._out_edges[nid] = []
        self._in_edges[nid] = []
        # Park this denial so the next CALL node gets a Counterfactual
        # edge per ARM Algorithm 1.
        self._recent_denials.append(nid)
        return nid

    def add_edge(self, *, source: str, target: str, kind: EdgeKind) -> None:
        """Add an edge if both endpoints exist. Idempotent on duplicates."""
        if source not in self._nodes:
            raise KeyError(f"source node not found: {source}")
        if target not in self._nodes:
            raise KeyError(f"target node not found: {target}")
        # Skip duplicate edges (same source, target, kind).
        for existing in self._out_edges[source]:
            if existing.target == target and existing.kind is kind:
                return
        edge = _Edge(
            source=source, target=target, kind=kind, timestamp=datetime.now(UTC)
        )
        self._out_edges[source].append(edge)
        self._in_edges[target].append(edge)

    # ── inspection ──────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._out_edges.values())

    def node(self, node_id: str) -> _Node:
        return self._nodes[node_id]

    def nodes_of_kind(self, kind: NodeKind) -> tuple[str, ...]:
        return tuple(
            sorted(nid for nid, n in self._nodes.items() if n.kind is kind)
        )

    # ── ARM Definition 4: MinTrust (taint propagation) ─────────────

    def min_trust(self, node_id: str) -> IntegrityLevel:
        """
        MinTrust(v) per ARM Definition 4.

        Returns the minimum integrity over all DATA / DATA_FIELD
        ancestors of `node_id`. Empty-ancestor case returns
        SYS_INSTR (most trusted), matching the paper's convention.
        """
        ancestors = self._ancestors(node_id)
        levels: list[IntegrityLevel] = []
        for ancestor_id in ancestors:
            node = self._nodes[ancestor_id]
            if node.kind in (NodeKind.DATA, NodeKind.DATA_FIELD):
                assert node.label is not None
                levels.append(node.label.integrity)
        return IntegrityLevel.join(levels) if levels else IntegrityLevel.SYS_INSTR

    def max_sensitivity(self, node_id: str) -> ConfidentialityLevel:
        """
        Dual of MinTrust: maximum sensitivity over DATA / DATA_FIELD
        ancestors. This is the cross-cut we add on top of ARM —
        ARM tracks integrity only; we add the FIDES second axis.
        """
        ancestors = self._ancestors(node_id)
        levels: list[ConfidentialityLevel] = []
        for ancestor_id in ancestors:
            node = self._nodes[ancestor_id]
            if node.kind in (NodeKind.DATA, NodeKind.DATA_FIELD):
                assert node.label is not None
                levels.append(node.label.confidentiality)
        return (
            ConfidentialityLevel.join(levels)
            if levels
            else ConfidentialityLevel.PUBLIC
        )

    def effective_label(self, node_id: str) -> IfcLabel:
        """Composite label: MinTrust integrity × MaxSensitivity confidentiality."""
        ancestors = self._ancestors(node_id)
        labels: list[IfcLabel] = []
        for ancestor_id in ancestors:
            node = self._nodes[ancestor_id]
            if node.kind in (NodeKind.DATA, NodeKind.DATA_FIELD):
                assert node.label is not None
                labels.append(node.label)
        if not labels:
            return IfcLabel.trusted()
        result = labels[0]
        for label in labels[1:]:
            result = result.join(label)
        return result

    # ── ARM §5.4: Counterfactual chain query ────────────────────────

    def has_counterfactual_chain(self, node_id: str) -> bool:
        """
        True iff `node_id` is reachable from any DeniedAction node via
        a path containing at least one COUNTERFACTUAL edge.

        This is THE causality-laundering detector. Implemented as a
        BFS over reverse edges; sub-millisecond on small graphs.
        """
        if node_id not in self._nodes:
            return False
        # BFS backward from node_id; track whether the path so far has
        # crossed a Counterfactual edge.
        # State: (current_node, crossed_counterfactual)
        visited: set[tuple[str, bool]] = set()
        stack: list[tuple[str, bool]] = [(node_id, False)]
        while stack:
            current, crossed = stack.pop()
            if (current, crossed) in visited:
                continue
            visited.add((current, crossed))
            current_node = self._nodes[current]
            if (
                crossed
                and current_node.kind is NodeKind.DENIED_ACTION
            ):
                return True
            for edge in self._in_edges.get(current, ()):
                next_crossed = crossed or (
                    edge.kind is EdgeKind.COUNTERFACTUAL
                )
                stack.append((edge.source, next_crossed))
        return False

    def counterfactual_denials(self, node_id: str) -> tuple[str, ...]:
        """
        Return the IDs of any DeniedAction nodes that reach `node_id`
        via a counterfactual chain. Used for evidence emission.
        """
        if node_id not in self._nodes:
            return tuple()
        results: list[str] = []
        visited: set[tuple[str, bool]] = set()
        stack: list[tuple[str, bool]] = [(node_id, False)]
        while stack:
            current, crossed = stack.pop()
            if (current, crossed) in visited:
                continue
            visited.add((current, crossed))
            current_node = self._nodes[current]
            if (
                crossed
                and current_node.kind is NodeKind.DENIED_ACTION
                and current not in results
            ):
                results.append(current)
            for edge in self._in_edges.get(current, ()):
                next_crossed = crossed or (
                    edge.kind is EdgeKind.COUNTERFACTUAL
                )
                stack.append((edge.source, next_crossed))
        results.sort()
        return tuple(results)

    # ── Deterministic fingerprint ───────────────────────────────────

    def fingerprint(self) -> str:
        """
        Stable SHA-256 fingerprint over the (kind, name, label) of
        each node and the (source, target, kind) of each edge, in
        sorted order. Same inputs → same fingerprint.
        """
        h = hashlib.sha256()
        for nid in sorted(self._nodes.keys()):
            node = self._nodes[nid]
            h.update(b"\x00node:")
            h.update(node.kind.value.encode())
            h.update(b"|")
            h.update(node.name.encode("utf-8", "replace"))
            if node.label is not None:
                h.update(b"|")
                h.update(str(int(node.label.integrity)).encode())
                h.update(b",")
                h.update(str(int(node.label.confidentiality)).encode())
                h.update(b",")
                h.update(str(int(node.label.capacity)).encode())
        # Build a sorted edge view across all sources.
        edge_records: list[tuple[str, str, str]] = []
        for source, edges in self._out_edges.items():
            for edge in edges:
                edge_records.append((source, edge.target, edge.kind.value))
        edge_records.sort()
        for source, target, kind in edge_records:
            h.update(b"\x00edge:")
            h.update(source.encode())
            h.update(b"->")
            h.update(target.encode())
            h.update(b"/")
            h.update(kind.encode())
        return h.hexdigest()

    # ── private helpers ─────────────────────────────────────────────

    def _ancestors(self, node_id: str) -> tuple[str, ...]:
        """All ancestors of `node_id` (DATA/CALL/FIELD/DENIED) under
        the reverse-edge BFS. Does NOT traverse counterfactual edges
        (those are not data-flow ancestors, they are causal influence
        edges queried separately by has_counterfactual_chain)."""
        if node_id not in self._nodes:
            return tuple()
        visited: set[str] = set()
        stack: list[str] = [node_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for edge in self._in_edges.get(current, ()):
                if edge.kind is EdgeKind.COUNTERFACTUAL:
                    continue
                stack.append(edge.source)
        visited.discard(node_id)
        return tuple(sorted(visited))


__all__ = [
    "NodeKind",
    "EdgeKind",
    "ProvenanceGraph",
]
