"""
PCAS dependency-graph adapter.

PCAS evaluates policies over a *dependency graph* whose nodes are
events (messages, tool calls, data) and whose edges capture causal
relationships (PCAS §3, §4.4.2). Tex already maintains two such graphs:

- ``tex.graph.temporal_kg.InMemoryTemporalKG`` — the broad temporal
  knowledge graph (Zep/Graphiti-inspired) that records entities and
  events with bi-temporal attributes.
- ``tex.governance.private_data_exec.ifc.provenance.ProvenanceGraph`` —
  the ARM-style four-edge provenance graph wired in Thread 11 (arxiv
  2604.04035: ``DirectOutput``, ``InputTo``, ``FieldOf``,
  ``Counterfactual`` edges over ``Call``/``Data``/``DataField``/
  ``DeniedAction`` nodes).

The adapter projects either or both into an EDB suitable for the PCAS
evaluator. The projection is the *only* place we couple the policy
runtime to Tex's graph internals; swapping a backend (e.g. rustworkx)
requires only re-implementing this adapter.

Schema (PCAS §4.5.1 subset)
---------------------------
- ``action(action_id, kind, actor, payload_hash)``
- ``message(msg_id, sender, receiver, content_hash)``
- ``tool_call(call_id, tool, caller, args_hash, result_hash)``
- ``data(data_id, source, label, content_hash)``
- ``denied(action_id, reason)``
- ``depends_on(source_id, target_id)``  — direct causal edge
- ``role(actor, role_name)``
- ``approved(subject_id, approver, decision_id)``

``derived_from/2`` is **NOT** part of the EDB. It is derived inside
policies via the transitive-closure pattern:
``derived_from(X, Y) :- depends_on(X, Y).``
``derived_from(X, Z) :- depends_on(X, Y), derived_from(Y, Z).``
This keeps the EDB compact and makes the recursion explicit.

Hashes (not raw content) keep the EDB inside the canonical-JSON value
space (``str | int | bool``). Helpers like ``json_extract`` can pull
out fields when callers stash JSON strings in the payload position.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event
from tex.pcas.runtime.relation import FactValue, Relation


# ---------------------------------------------------------------------------
# Adapter input models — what callers hand us
# ---------------------------------------------------------------------------


class GraphActionView(BaseModel):
    """One action node in the dependency graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=128)
    payload_hash: str = Field(min_length=1, max_length=128)


class GraphMessageView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    msg_id: str = Field(min_length=1, max_length=128)
    sender: str = Field(min_length=1, max_length=128)
    receiver: str = Field(min_length=1, max_length=128)
    content_hash: str = Field(min_length=1, max_length=128)


class GraphToolCallView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    call_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    caller: str = Field(min_length=1, max_length=128)
    args_hash: str = Field(min_length=1, max_length=128)
    result_hash: str = Field(min_length=1, max_length=128)


class GraphDataView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    data_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=64)
    content_hash: str = Field(min_length=1, max_length=128)


class GraphDeniedView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=128)


class GraphDependencyEdge(BaseModel):
    """Direct causal edge ``source -> target``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)


class GraphRoleAssignment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    actor: str = Field(min_length=1, max_length=128)
    role_name: str = Field(min_length=1, max_length=64)


class GraphApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: str = Field(min_length=1, max_length=128)
    approver: str = Field(min_length=1, max_length=128)
    decision_id: str = Field(min_length=1, max_length=128)


class DependencyGraphView(BaseModel):
    """
    The whole projection in one shot. Callers can construct this
    directly, or use the helpers below to build it from Tex's KG / IFC
    provenance graph.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    actions: tuple[GraphActionView, ...] = ()
    messages: tuple[GraphMessageView, ...] = ()
    tool_calls: tuple[GraphToolCallView, ...] = ()
    data: tuple[GraphDataView, ...] = ()
    denied: tuple[GraphDeniedView, ...] = ()
    edges: tuple[GraphDependencyEdge, ...] = ()
    roles: tuple[GraphRoleAssignment, ...] = ()
    approvals: tuple[GraphApproval, ...] = ()


# ---------------------------------------------------------------------------
# Adapter — view -> EDB
# ---------------------------------------------------------------------------


def _values_action(view: GraphActionView) -> tuple[FactValue, ...]:
    return (view.action_id, view.kind, view.actor, view.payload_hash)


def _values_message(view: GraphMessageView) -> tuple[FactValue, ...]:
    return (view.msg_id, view.sender, view.receiver, view.content_hash)


def _values_tool_call(view: GraphToolCallView) -> tuple[FactValue, ...]:
    return (view.call_id, view.tool, view.caller, view.args_hash, view.result_hash)


def _values_data(view: GraphDataView) -> tuple[FactValue, ...]:
    return (view.data_id, view.source, view.label, view.content_hash)


def _values_denied(view: GraphDeniedView) -> tuple[FactValue, ...]:
    return (view.action_id, view.reason)


def _values_edge(view: GraphDependencyEdge) -> tuple[FactValue, ...]:
    return (view.source_id, view.target_id)


def _values_role(view: GraphRoleAssignment) -> tuple[FactValue, ...]:
    return (view.actor, view.role_name)


def _values_approval(view: GraphApproval) -> tuple[FactValue, ...]:
    return (view.subject_id, view.approver, view.decision_id)


class DependencyGraphAdapter:
    """
    Project a ``DependencyGraphView`` into a dict of PCAS relations.

    The adapter is stateless; instantiate once and call ``to_edb()`` on
    each request.
    """

    EDB_ARITIES: dict[str, int] = {
        "action": 4,
        "message": 4,
        "tool_call": 5,
        "data": 4,
        "denied": 2,
        "depends_on": 2,
        "role": 2,
        "approved": 3,
    }

    def to_edb(self, view: DependencyGraphView) -> dict[str, Relation]:
        edb: dict[str, Relation] = {}

        def add(name: str, facts: Iterable[tuple[FactValue, ...]]) -> None:
            arity = self.EDB_ARITIES[name]
            edb[name] = Relation(name=name, arity=arity, facts=tuple(facts))

        add("action", (_values_action(a) for a in view.actions))
        add("message", (_values_message(m) for m in view.messages))
        add("tool_call", (_values_tool_call(t) for t in view.tool_calls))
        add("data", (_values_data(d) for d in view.data))
        add("denied", (_values_denied(d) for d in view.denied))
        add("depends_on", (_values_edge(e) for e in view.edges))
        add("role", (_values_role(r) for r in view.roles))
        add("approved", (_values_approval(a) for a in view.approvals))

        emit_event(
            "pcas.graph.edb_built",
            relations={name: len(rel) for name, rel in edb.items()},
        )
        return edb

    # ----------------------------- bridges to existing Tex graph layers

    @staticmethod
    def from_ifc_provenance(prov: Any) -> DependencyGraphView:
        """
        Build a view from
        ``tex.governance.private_data_exec.ifc.provenance.ProvenanceGraph``.

        Defensive duck-typed import — the IFC layer is optional from
        PCAS's perspective. If the provenance graph isn't present we
        return an empty view.
        """
        actions: list[GraphActionView] = []
        data: list[GraphDataView] = []
        denied: list[GraphDeniedView] = []
        edges: list[GraphDependencyEdge] = []

        # The ProvenanceGraph from Thread 11 stores nodes by kind. We
        # introspect via its public API if available, otherwise no-op.
        nodes = getattr(prov, "nodes", None) or ()
        for node in nodes:
            kind = getattr(node, "kind", None)
            node_id = getattr(node, "id", None) or getattr(node, "node_id", None)
            if node_id is None:
                continue
            if kind == "Call":
                actions.append(
                    GraphActionView(
                        action_id=str(node_id),
                        kind=str(getattr(node, "call_kind", "call") or "call"),
                        actor=str(getattr(node, "actor", "agent") or "agent"),
                        payload_hash=str(
                            getattr(node, "payload_hash", "") or ""
                        )
                        or "0" * 8,
                    )
                )
            elif kind == "Data":
                data.append(
                    GraphDataView(
                        data_id=str(node_id),
                        source=str(getattr(node, "source", "unknown") or "unknown"),
                        label=str(getattr(node, "label", "untrusted") or "untrusted"),
                        content_hash=str(
                            getattr(node, "content_hash", "") or ""
                        )
                        or "0" * 8,
                    )
                )
            elif kind == "DeniedAction":
                denied.append(
                    GraphDeniedView(
                        action_id=str(node_id),
                        reason=str(getattr(node, "reason", "policy") or "policy"),
                    )
                )

        for edge in getattr(prov, "edges", ()) or ():
            src = getattr(edge, "source", None)
            tgt = getattr(edge, "target", None)
            if src is None or tgt is None:
                continue
            edges.append(GraphDependencyEdge(source_id=str(src), target_id=str(tgt)))

        return DependencyGraphView(
            actions=tuple(actions),
            data=tuple(data),
            denied=tuple(denied),
            edges=tuple(edges),
        )


__all__ = [
    "DependencyGraphAdapter",
    "DependencyGraphView",
    "GraphActionView",
    "GraphApproval",
    "GraphDataView",
    "GraphDeniedView",
    "GraphDependencyEdge",
    "GraphMessageView",
    "GraphRoleAssignment",
    "GraphToolCallView",
]
