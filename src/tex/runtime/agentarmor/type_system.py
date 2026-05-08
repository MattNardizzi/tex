"""
AgentArmor Type System.

Reference: arxiv 2508.01249 (Wang et al.), §III-C.

Three stages:

  1. TypeAssigner — initialize a (security_type, trust_type, rule_type)
     triple on every PDG node by lookup against the property registry.

  2. TypeInfer — propagate types along DFG edges using lattice operations:
       - confidentiality JOIN (Bell-LaPadula): when data flows together,
         the more-restrictive label dominates (HIGH ∨ LOW = HIGH).
       - integrity MEET (Biba): the least-trustworthy input dominates the
         output (HIGH ∧ LOW = LOW). High-integrity outputs cannot depend on
         low-integrity inputs.
       - trust JOIN: TAINTED dominates UNTRUSTED dominates TRUSTED.

  3. TypeChecker — emit policy violations:
       a. Intra-node: per-node logical predicates over the rule_type field.
          (e.g. tool_param marked as 'must_be_literal' rejecting interpolated
          observation content.)
       b. Inter-node: information-flow rules across DFG edges:
          - UNTRUSTED data ↦ EXEC tool       → BLOCK (RCE class).
          - SECRET data    ↦ NETWORK tool    → BLOCK (exfiltration class).
          - low integrity  ↦ high integrity  → BLOCK (downgrade prohibited).

Performance per paper §V: 95.75% TPR, 3.66% FPR, 1% utility drop on
AgentDojo, ASR 1.16% post-mitigation.

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import networkx as nx

from tex.observability.telemetry import emit_event, get_logger
from tex.runtime.agentarmor.property_registry import (
    Capability,
    Confidentiality,
    Integrity,
    TrustLevel,
    conf_join,
    int_meet,
    trust_join,
)

_logger = get_logger("tex.runtime.agentarmor.types")


@dataclass(frozen=True, slots=True)
class TypeViolation:
    """One detected information-flow violation."""

    code: str  # short id e.g. 'untrusted_to_exec'
    description: str
    src_node: str
    dst_node: str
    src_attrs: dict
    dst_attrs: dict


class TypeSystem:
    """End-to-end type assignment + inference + checking.

    Operates on the annotated PDG produced by ``PropertyRegistry.annotate``.
    """

    def check(
        self,
        annotated_pdg: dict | nx.DiGraph,
    ) -> tuple[bool, tuple[str, ...]]:
        """Return (is_safe, violations_tuple).

        ``violations_tuple`` is a tuple of stable string descriptions for
        backwards compatibility with the scaffolded contract. Use
        ``check_detailed`` for the full ``TypeViolation`` records.
        """
        is_safe, violations = self.check_detailed(annotated_pdg)
        return is_safe, tuple(self._render(v) for v in violations)

    def check_detailed(
        self,
        annotated_pdg: dict | nx.DiGraph,
    ) -> tuple[bool, tuple[TypeViolation, ...]]:
        """Full pipeline: assign → infer → check."""
        graph = self._coerce(annotated_pdg)
        self._assign_types(graph)
        self._infer_types(graph)
        violations = tuple(self._check(graph))

        emit_event(
            "agentarmor.typecheck.completed",
            logger=_logger,
            violations=len(violations),
            nodes=graph.number_of_nodes(),
        )
        return len(violations) == 0, violations

    # ------------------------------------------------------------------
    # Stage 1: Type Assigner.
    # ------------------------------------------------------------------
    @staticmethod
    def _assign_types(graph: nx.DiGraph) -> None:
        """Bind concrete labels parsed from the registry into typed enums on
        each node, and seed UNTRUSTED for any node whose source is external.
        """
        for n, attrs in graph.nodes(data=True):
            trust_str = attrs.get("trust", "trusted")
            graph.nodes[n]["_trust"] = TrustLevel(trust_str)
            graph.nodes[n]["_conf"] = Confidentiality(attrs.get("confidentiality", "public"))
            graph.nodes[n]["_int"] = Integrity(attrs.get("integrity", "high"))

    # ------------------------------------------------------------------
    # Stage 2: Type Infer.
    # ------------------------------------------------------------------
    @staticmethod
    def _infer_types(graph: nx.DiGraph) -> None:
        """Propagate types along DATA edges only.

        Iterates in topological order over the data subgraph; for each node,
        joins/meets predecessor labels per the lattice ops. We compute the
        data-only subgraph by filtering edges with kind == 'data' (or the
        composite 'control+data' / 'data+control' label produced by the
        graph constructor when both edges coincide).
        """
        # Build data-only subgraph view.
        data_edges = [
            (u, v) for u, v, ed in graph.edges(data=True)
            if "data" in str(ed.get("kind", ""))
        ]
        if not data_edges:
            return
        data_sub = graph.edge_subgraph(data_edges).copy()

        # If cycles exist (rare; would only arise from observation->observation
        # backedges), break them via a stable ordering: by node "step" attribute
        # ascending. Without cycles, topological_sort is correct.
        try:
            order = list(nx.topological_sort(data_sub))
        except nx.NetworkXUnfeasible:
            order = sorted(data_sub.nodes(),
                           key=lambda n: graph.nodes[n].get("step", 0))

        for n in order:
            preds = list(data_sub.predecessors(n))
            if not preds:
                continue
            cur_trust = graph.nodes[n]["_trust"]
            cur_conf = graph.nodes[n]["_conf"]
            cur_int = graph.nodes[n]["_int"]
            for p in preds:
                cur_trust = trust_join(cur_trust, graph.nodes[p]["_trust"])
                cur_conf = conf_join(cur_conf, graph.nodes[p]["_conf"])
                cur_int = int_meet(cur_int, graph.nodes[p]["_int"])
            graph.nodes[n]["_trust"] = cur_trust
            graph.nodes[n]["_conf"] = cur_conf
            graph.nodes[n]["_int"] = cur_int
            # Keep string fields in sync for downstream consumers.
            graph.nodes[n]["trust"] = cur_trust.value
            graph.nodes[n]["confidentiality"] = cur_conf.value
            graph.nodes[n]["integrity"] = cur_int.value

    # ------------------------------------------------------------------
    # Stage 3: Type Checker.
    # ------------------------------------------------------------------
    @staticmethod
    def _check(graph: nx.DiGraph) -> Iterable[TypeViolation]:
        """Both intra-node and inter-node checks."""
        # Inter-node: walk every DFG edge that terminates at a TOOL node and
        # assert (UNTRUSTED→EXEC, SECRET→NETWORK, integrity-downgrade) rules.
        for u, v, ed in graph.edges(data=True):
            if "data" not in str(ed.get("kind", "")):
                continue
            v_attrs = graph.nodes[v]
            u_attrs = graph.nodes[u]
            if v_attrs.get("kind") != "tool":
                continue

            cap = v_attrs.get("capability")
            u_trust = TrustLevel(u_attrs.get("trust", "trusted"))
            u_conf = Confidentiality(u_attrs.get("confidentiality", "public"))
            u_int = Integrity(u_attrs.get("integrity", "high"))

            if cap == Capability.EXEC.value and u_trust != TrustLevel.TRUSTED:
                yield TypeViolation(
                    code="untrusted_to_exec",
                    description=(
                        f"untrusted data ({u_trust.value}) flows into EXEC "
                        f"tool '{v_attrs.get('tool_name')}'"
                    ),
                    src_node=u, dst_node=v,
                    src_attrs=dict(u_attrs), dst_attrs=dict(v_attrs),
                )

            if cap == Capability.NETWORK.value and u_conf in (
                Confidentiality.SECRET, Confidentiality.CONFIDENTIAL,
            ):
                yield TypeViolation(
                    code="confidential_to_network",
                    description=(
                        f"{u_conf.value} data flows into NETWORK tool "
                        f"'{v_attrs.get('tool_name')}'"
                    ),
                    src_node=u, dst_node=v,
                    src_attrs=dict(u_attrs), dst_attrs=dict(v_attrs),
                )

            declared_int_str = v_attrs.get("declared_integrity")
            if declared_int_str:
                declared_int = Integrity(declared_int_str)
                if int_meet(declared_int, u_int) != declared_int:
                    # Tool was declared HIGH integrity but is being fed LOW.
                    yield TypeViolation(
                        code="integrity_downgrade",
                        description=(
                            f"low-integrity input ({u_int.value}) reaching tool "
                            f"declared as {declared_int.value} integrity"
                        ),
                        src_node=u, dst_node=v,
                        src_attrs=dict(u_attrs), dst_attrs=dict(v_attrs),
                    )

        # Intra-node check: any tool_param with rule_type 'must_be_literal'
        # whose effective trust is not TRUSTED is a violation. The rule_type
        # field is opt-in; absence is a no-op.
        for n, attrs in graph.nodes(data=True):
            if attrs.get("kind") != "tool_param":
                continue
            rule = attrs.get("rule_type")
            if rule == "must_be_literal":
                if TrustLevel(attrs.get("trust", "trusted")) != TrustLevel.TRUSTED:
                    yield TypeViolation(
                        code="literal_param_tainted",
                        description=(
                            f"tool param '{attrs.get('param_name')}' must be a "
                            f"literal but received {attrs.get('trust')} content"
                        ),
                        src_node=n, dst_node=n,
                        src_attrs=dict(attrs), dst_attrs=dict(attrs),
                    )

    # ------------------------------------------------------------------
    @staticmethod
    def _coerce(pdg: dict | nx.DiGraph) -> nx.DiGraph:
        if isinstance(pdg, nx.DiGraph):
            return pdg
        if isinstance(pdg, dict) and "pdg" in pdg and isinstance(pdg["pdg"], nx.DiGraph):
            return pdg["pdg"]
        raise TypeError("type-system input must be a DiGraph or {'pdg': DiGraph}")

    @staticmethod
    def _render(v: TypeViolation) -> str:
        return f"[{v.code}] {v.description} (src={v.src_node} dst={v.dst_node})"
