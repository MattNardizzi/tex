"""
ARM provenance graph.

Per arxiv 2604.04035 Definition 3 (§5.1):

    G = (V, E, τ, ℓ)

  V = V_Call ∪ V_Data ∪ V_DataField ∪ V_DeniedAction   (four disjoint sets)
  E ⊆ V × V                                            (labeled edges)
  τ : V_Data ∪ V_DataField → 𝒯                        (trust assignment)
  ℓ                                                    (metadata labels)

Edge labels (§5.2):
  DirectOutput(c, d)  — call c produced data d
  InputTo(d, c)       — data d was input to call c
  FieldOf(f, d)       — field f is a component of structured data d
  Counterfactual(a_d, c) — denied action a_d may have causally influenced
                            subsequent call c (auto-attached temporally)

Trust propagation (§5.3, Definition 4):

    MinTrust(v) = min_{u ∈ Ancestors(v) ∩ (V_Data ∪ V_DataField)} τ(u)

Empty data-ancestor set ⇒ MinTrust(v) = SysInstr (no taint observed).

Property 1 (Monotonic Taint, §5.3): for any edge ``(u, v) ∈ E``,
``MinTrust(v) ≤ MinTrust(u)``. This is enforced *implicitly* by the
computation — any new edge can only narrow the min over ancestors.

Backend
-------
``networkx.DiGraph`` per the project-wide convention (see
``tex.graph.temporal_kg``). The paper's reference implementation uses
``rustworkx``; we keep semantics identical and accept the constant-factor
slowdown — networkx is the approved dependency.

Reference: arxiv 2604.04035 §5.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from tex.causal._integrity import (
    DEFAULT_TRUST_THRESHOLD,
    IntegrityLevel,
    lattice_meet,
)


class ProvenanceNodeKind(str, Enum):
    """Disjoint node tiers per ARM Definition 3."""

    CALL = "call"
    DATA = "data"
    DATA_FIELD = "data_field"
    DENIED_ACTION = "denied_action"


class ProvenanceEdgeLabel(str, Enum):
    """Labeled edges per ARM §5.2."""

    DIRECT_OUTPUT = "direct_output"   # c → d
    INPUT_TO = "input_to"             # d → c
    FIELD_OF = "field_of"             # f → d
    COUNTERFACTUAL = "counterfactual"  # a_d → c


# --- node payloads -----------------------------------------------------


class _NodeBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CallNode(_NodeBase):
    """A tool-call event observed by ARM (allowed path, pre-execution)."""

    node_id: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    arguments_digest: str = Field(min_length=1, max_length=256)


class DataNode(_NodeBase):
    """A returned data item from a successful tool call."""

    node_id: str = Field(min_length=1, max_length=256)
    trust: IntegrityLevel
    digest: str = Field(min_length=1, max_length=256)


class DataFieldNode(_NodeBase):
    """A sub-component of structured data (field-level provenance, §5.6)."""

    node_id: str = Field(min_length=1, max_length=256)
    field_path: str = Field(min_length=1, max_length=512)
    trust: IntegrityLevel
    digest: str = Field(min_length=1, max_length=256)


class DeniedActionNode(_NodeBase):
    """
    A first-class denied action. Per §3.7, this is the abstraction that
    flat-provenance defenses miss; ARM's whole detection mechanism for
    causality laundering hinges on these nodes existing in the graph.
    """

    node_id: str = Field(min_length=1, max_length=256)
    denied_tool_name: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    denial_reason: str = Field(min_length=1, max_length=1_000)
    arguments_digest: str = Field(min_length=1, max_length=256)


ProvenanceNodePayload = CallNode | DataNode | DataFieldNode | DeniedActionNode


def kind_of(payload: ProvenanceNodePayload) -> ProvenanceNodeKind:
    if isinstance(payload, CallNode):
        return ProvenanceNodeKind.CALL
    if isinstance(payload, DataNode):
        return ProvenanceNodeKind.DATA
    if isinstance(payload, DataFieldNode):
        return ProvenanceNodeKind.DATA_FIELD
    if isinstance(payload, DeniedActionNode):
        return ProvenanceNodeKind.DENIED_ACTION
    raise TypeError(f"unknown payload type: {type(payload).__name__}")


# --- graph implementation ---------------------------------------------


class ProvenanceGraph:
    """
    In-memory ARM provenance graph backed by ``networkx.DiGraph``.

    Mutation surface is intentionally narrow — only ARM's enforcement
    pipeline calls ``add_*`` and ``add_edge``. The graph is queried by
    the two enforcement queries from §5.4:

      1. ``MinTrust(c) < θ``        (transitive taint propagation)
      2. ``CounterfactualChains(c) ≠ ∅``  (causality laundering)

    Reference: arxiv 2604.04035 §5.
    """

    __slots__ = ("_g", "_last_denial_id")

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()
        # Tracks the most recently added DeniedAction node, so that the
        # *next* CallNode (the temporally-adjacent one per §3.7) can
        # auto-receive a Counterfactual edge.
        self._last_denial_id: str | None = None

    # ----- mutation -----

    def add_call(self, node: CallNode) -> None:
        self._add_node(node)
        # §3.7: auto-attach a Counterfactual edge from the most recent
        # denial to this call. This is the conservative over-approximation
        # the paper explicitly chooses (the agent's internal reasoning is
        # opaque, so we mark the temporally adjacent call as potentially
        # influenced).
        if self._last_denial_id is not None:
            self._g.add_edge(
                self._last_denial_id,
                node.node_id,
                label=ProvenanceEdgeLabel.COUNTERFACTUAL.value,
            )
            # The denial's influence is consumed by the immediately
            # following call. Subsequent calls do not receive the edge
            # automatically; this matches the paper's "next tool call"
            # rule (Algorithm 1, line 7).
            self._last_denial_id = None

    def add_data(self, node: DataNode) -> None:
        self._add_node(node)

    def add_data_field(self, node: DataFieldNode) -> None:
        self._add_node(node)

    def add_denied_action(self, node: DeniedActionNode) -> None:
        self._add_node(node)
        self._last_denial_id = node.node_id

    def add_edge(
        self,
        *,
        source_id: str,
        target_id: str,
        label: ProvenanceEdgeLabel,
    ) -> None:
        if source_id not in self._g.nodes:
            raise KeyError(f"unknown source node {source_id!r}")
        if target_id not in self._g.nodes:
            raise KeyError(f"unknown target node {target_id!r}")
        self._g.add_edge(source_id, target_id, label=label.value)

    def _add_node(self, payload: ProvenanceNodePayload) -> None:
        if payload.node_id in self._g.nodes:
            raise KeyError(f"duplicate node {payload.node_id!r}")
        self._g.add_node(
            payload.node_id,
            data=payload,
            kind=kind_of(payload).value,
        )

    # ----- read-only access -----

    def has(self, node_id: str) -> bool:
        return node_id in self._g.nodes

    def kind(self, node_id: str) -> ProvenanceNodeKind:
        return ProvenanceNodeKind(self._g.nodes[node_id]["kind"])

    def payload(self, node_id: str) -> ProvenanceNodePayload:
        return self._g.nodes[node_id]["data"]

    def __len__(self) -> int:
        return self._g.number_of_nodes()

    def edges(self) -> tuple[tuple[str, str, ProvenanceEdgeLabel], ...]:
        return tuple(
            (u, v, ProvenanceEdgeLabel(self._g.edges[u, v]["label"]))
            for u, v in self._g.edges
        )

    # ----- enforcement queries -----

    def min_trust(self, node_id: str) -> IntegrityLevel:
        """
        Compute ``MinTrust(node_id)`` per Definition 4 (§5.3).

        Reverse-walks the graph to collect data ancestors, then takes the
        lattice meet (= numeric ``min``) over their trust labels. If no
        data ancestors exist, returns ``SysInstr`` per the definition.
        """
        if node_id not in self._g.nodes:
            raise KeyError(f"unknown node {node_id!r}")

        trust_levels: list[IntegrityLevel] = []
        ancestors = nx.ancestors(self._g, node_id)
        for ancestor_id in ancestors:
            payload = self._g.nodes[ancestor_id]["data"]
            if isinstance(payload, (DataNode, DataFieldNode)):
                trust_levels.append(payload.trust)
        if not trust_levels:
            return IntegrityLevel.SYS_INSTR
        return lattice_meet(tuple(trust_levels))

    def has_counterfactual_chain_to(self, node_id: str) -> bool:
        """
        ``CounterfactualChains(c) ≠ ∅`` per §5.4 query 2.

        Returns True iff any path from a ``DeniedAction`` node reaches
        ``node_id`` and traverses at least one ``Counterfactual``-labeled
        edge. Implementation is BFS over reverse edges, tracking whether
        a counterfactual edge has been crossed on the path so far —
        avoids enumerating all paths via ``nx.all_simple_paths`` which
        is exponential in graph size.
        """
        if node_id not in self._g.nodes:
            raise KeyError(f"unknown node {node_id!r}")

        # Reverse BFS from target. Each frontier element is
        # (current_node_id, has_traversed_counterfactual_yet).
        frontier: list[tuple[str, bool]] = [(node_id, False)]
        # Visited set keyed by (node, flag) so we can revisit a node via
        # a different traversal flag exactly once.
        seen: set[tuple[str, bool]] = set()

        while frontier:
            current, crossed_cf = frontier.pop()
            key = (current, crossed_cf)
            if key in seen:
                continue
            seen.add(key)

            current_payload = self._g.nodes[current]["data"]
            if isinstance(current_payload, DeniedActionNode) and crossed_cf:
                return True

            # Walk predecessors (reverse direction).
            for pred in self._g.predecessors(current):
                edge_label = ProvenanceEdgeLabel(
                    self._g.edges[pred, current]["label"]
                )
                next_crossed = (
                    crossed_cf
                    or edge_label is ProvenanceEdgeLabel.COUNTERFACTUAL
                )
                frontier.append((pred, next_crossed))

        return False

    def evaluate(
        self,
        *,
        call_node_id: str,
        threshold: IntegrityLevel = DEFAULT_TRUST_THRESHOLD,
    ) -> tuple[bool, str | None]:
        """
        Combined Layer-2 enforcement decision per §4.3.2 / §5.4.

        Returns ``(allow, deny_reason)``. A deny verdict carries one of:
          - ``"transitive_taint"`` — MinTrust(c) < θ
          - ``"causality_laundering"`` — CounterfactualChains(c) ≠ ∅

        The two queries are evaluated in order; the first failing one
        wins so the audit log records a single concrete reason.
        """
        if self.min_trust(call_node_id) < threshold:
            return False, "transitive_taint"
        if self.has_counterfactual_chain_to(call_node_id):
            return False, "causality_laundering"
        return True, None


def utc_now() -> datetime:
    """Process-local UTC clock used by ARM nodes; isolated for tests."""
    return datetime.now(UTC)
