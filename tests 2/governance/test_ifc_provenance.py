"""Tests for the ARM-style provenance graph (Thread 11)."""

from __future__ import annotations

import time

import pytest

from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)
from tex.governance.private_data_exec.ifc.provenance import (
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
)


@pytest.fixture
def graph() -> ProvenanceGraph:
    return ProvenanceGraph()


def _label(
    integrity: IntegrityLevel,
    confidentiality: ConfidentialityLevel = ConfidentialityLevel.INTERNAL,
) -> IfcLabel:
    return IfcLabel(
        integrity=integrity,
        confidentiality=confidentiality,
        capacity=CapacityType.TEXT,
    )


# ── construction ─────────────────────────────────────────────────────


def test_add_call_creates_node(graph: ProvenanceGraph) -> None:
    nid = graph.add_call(name="send_email")
    assert graph.node(nid).kind is NodeKind.CALL
    assert graph.node_count == 1
    assert graph.edge_count == 0


def test_add_data_with_label(graph: ProvenanceGraph) -> None:
    nid = graph.add_data(
        name="email_body", label=_label(IntegrityLevel.USER_INPUT)
    )
    node = graph.node(nid)
    assert node.kind is NodeKind.DATA
    assert node.label is not None
    assert node.label.integrity is IntegrityLevel.USER_INPUT


def test_add_data_field_requires_data_parent(graph: ProvenanceGraph) -> None:
    parent = graph.add_data(name="d", label=_label(IntegrityLevel.SYS_INSTR))
    field_id = graph.add_data_field(
        parent_data_id=parent,
        field_name="email",
        label=_label(IntegrityLevel.TOOL_UNTRUSTED),
    )
    assert graph.node(field_id).kind is NodeKind.DATA_FIELD
    # FieldOf edge exists.
    assert graph.edge_count == 1


def test_add_data_field_rejects_non_data_parent(graph: ProvenanceGraph) -> None:
    call_id = graph.add_call(name="c")
    with pytest.raises(ValueError):
        graph.add_data_field(
            parent_data_id=call_id,
            field_name="x",
            label=_label(IntegrityLevel.SYS_INSTR),
        )


def test_duplicate_edges_are_idempotent(graph: ProvenanceGraph) -> None:
    a = graph.add_data(name="a", label=_label(IntegrityLevel.USER_INPUT))
    call = graph.add_call(name="c")
    graph.add_edge(source=a, target=call, kind=EdgeKind.INPUT_TO)
    graph.add_edge(source=a, target=call, kind=EdgeKind.INPUT_TO)
    assert graph.edge_count == 1


def test_missing_endpoint_raises(graph: ProvenanceGraph) -> None:
    call = graph.add_call(name="c")
    with pytest.raises(KeyError):
        graph.add_edge(source="missing", target=call, kind=EdgeKind.INPUT_TO)


# ── MinTrust and effective label ─────────────────────────────────────


def test_min_trust_is_minimum_over_ancestors(graph: ProvenanceGraph) -> None:
    trusted = graph.add_data(name="t", label=_label(IntegrityLevel.SYS_INSTR))
    untrusted = graph.add_data(
        name="u", label=_label(IntegrityLevel.TOOL_UNTRUSTED)
    )
    call = graph.add_call(name="c")
    graph.add_edge(source=trusted, target=call, kind=EdgeKind.INPUT_TO)
    graph.add_edge(source=untrusted, target=call, kind=EdgeKind.INPUT_TO)
    assert graph.min_trust(call) is IntegrityLevel.TOOL_UNTRUSTED


def test_min_trust_with_no_ancestors_returns_sysinstr(
    graph: ProvenanceGraph,
) -> None:
    call = graph.add_call(name="c")
    assert graph.min_trust(call) is IntegrityLevel.SYS_INSTR


def test_max_sensitivity_is_maximum_over_ancestors(
    graph: ProvenanceGraph,
) -> None:
    public = graph.add_data(
        name="p", label=_label(IntegrityLevel.SYS_INSTR, ConfidentialityLevel.PUBLIC)
    )
    sensitive = graph.add_data(
        name="s",
        label=_label(IntegrityLevel.SYS_INSTR, ConfidentialityLevel.RESTRICTED),
    )
    call = graph.add_call(name="c")
    graph.add_edge(source=public, target=call, kind=EdgeKind.INPUT_TO)
    graph.add_edge(source=sensitive, target=call, kind=EdgeKind.INPUT_TO)
    assert graph.max_sensitivity(call) is ConfidentialityLevel.RESTRICTED


def test_effective_label_combines_axes(graph: ProvenanceGraph) -> None:
    a = graph.add_data(
        name="a",
        label=_label(IntegrityLevel.TOOL_UNTRUSTED, ConfidentialityLevel.INTERNAL),
    )
    b = graph.add_data(
        name="b",
        label=_label(IntegrityLevel.SYS_INSTR, ConfidentialityLevel.RESTRICTED),
    )
    call = graph.add_call(name="c")
    graph.add_edge(source=a, target=call, kind=EdgeKind.INPUT_TO)
    graph.add_edge(source=b, target=call, kind=EdgeKind.INPUT_TO)
    label = graph.effective_label(call)
    assert label.integrity is IntegrityLevel.TOOL_UNTRUSTED
    assert label.confidentiality is ConfidentialityLevel.RESTRICTED
    assert label.is_flow_violation is True


# ── ARM novelty: counterfactual chain detection ─────────────────────


def test_counterfactual_edge_auto_linked_on_next_call(
    graph: ProvenanceGraph,
) -> None:
    denied = graph.add_denied_action(name="read_file", reason="HB-2")
    next_call = graph.add_call(name="send_email")
    # ARM Algorithm 1: a Counterfactual edge connects the denial to
    # the next call.
    assert graph.has_counterfactual_chain(next_call) is True
    assert denied in graph.counterfactual_denials(next_call)


def test_counterfactual_chain_clears_after_link(graph: ProvenanceGraph) -> None:
    graph.add_denied_action(name="r", reason="HB-2")
    first_call = graph.add_call(name="c1")
    second_call = graph.add_call(name="c2")
    # First call gets the counterfactual edge; the second does not
    # unless a new denial occurs.
    assert graph.has_counterfactual_chain(first_call) is True
    assert graph.has_counterfactual_chain(second_call) is False


def test_counterfactual_chain_not_triggered_without_denial(
    graph: ProvenanceGraph,
) -> None:
    call = graph.add_call(name="c")
    assert graph.has_counterfactual_chain(call) is False
    assert graph.counterfactual_denials(call) == ()


def test_chain_traverses_transitively_with_one_counterfactual(
    graph: ProvenanceGraph,
) -> None:
    """A counterfactual edge upstream still counts even if intermediate
    calls only have InputTo edges between them."""
    denied = graph.add_denied_action(name="probe", reason="HB-2")
    first_call = graph.add_call(name="encode")
    # Inject data and link onward to a second call.
    data = graph.add_data(name="d", label=_label(IntegrityLevel.SYS_INSTR))
    graph.add_edge(source=first_call, target=data, kind=EdgeKind.DIRECT_OUTPUT)
    second_call = graph.add_call(
        name="send", auto_link_counterfactual=False
    )
    graph.add_edge(source=data, target=second_call, kind=EdgeKind.INPUT_TO)
    # Through first_call's counterfactual ancestor.
    assert graph.has_counterfactual_chain(second_call) is True
    assert denied in graph.counterfactual_denials(second_call)


def test_auto_link_can_be_disabled(graph: ProvenanceGraph) -> None:
    graph.add_denied_action(name="r", reason="HB-2")
    call = graph.add_call(name="c", auto_link_counterfactual=False)
    assert graph.has_counterfactual_chain(call) is False


# ── Fingerprint determinism ──────────────────────────────────────────


def test_fingerprint_is_deterministic_for_same_inputs() -> None:
    def build() -> ProvenanceGraph:
        g = ProvenanceGraph()
        d1 = g.add_data(
            name="d", label=_label(IntegrityLevel.USER_INPUT), node_id="d1"
        )
        c1 = g.add_call(name="c", node_id="c1")
        g.add_edge(source=d1, target=c1, kind=EdgeKind.INPUT_TO)
        return g

    g1 = build()
    g2 = build()
    assert g1.fingerprint() == g2.fingerprint()


def test_fingerprint_changes_with_edge_kind() -> None:
    g1 = ProvenanceGraph()
    a = g1.add_data(name="a", label=_label(IntegrityLevel.SYS_INSTR), node_id="a")
    c = g1.add_call(name="c", node_id="c")
    g1.add_edge(source=a, target=c, kind=EdgeKind.INPUT_TO)

    g2 = ProvenanceGraph()
    a2 = g2.add_data(
        name="a", label=_label(IntegrityLevel.SYS_INSTR), node_id="a"
    )
    c2 = g2.add_call(name="c", node_id="c")
    g2.add_edge(source=c2, target=a2, kind=EdgeKind.DIRECT_OUTPUT)

    assert g1.fingerprint() != g2.fingerprint()


# ── Performance budget (ARM claims sub-millisecond) ─────────────────


def test_query_under_5ms_on_small_graph() -> None:
    """ARM paper: sub-millisecond on tens-to-hundreds of nodes. We
    budget a generous 5ms p99 to absorb shared-CI machine variance."""
    g = ProvenanceGraph()
    # Build a graph of ~50 nodes with a counterfactual chain.
    g.add_denied_action(name="probe", reason="HB-2")
    last = g.add_call(name="c0")
    for i in range(48):
        data = g.add_data(
            name=f"d{i}", label=_label(IntegrityLevel.USER_INPUT)
        )
        g.add_edge(source=last, target=data, kind=EdgeKind.DIRECT_OUTPUT)
        nxt = g.add_call(name=f"c{i+1}", auto_link_counterfactual=False)
        g.add_edge(source=data, target=nxt, kind=EdgeKind.INPUT_TO)
        last = nxt

    times: list[float] = []
    for _ in range(50):
        start = time.perf_counter()
        _ = g.has_counterfactual_chain(last)
        _ = g.min_trust(last)
        _ = g.effective_label(last)
        end = time.perf_counter()
        times.append((end - start) * 1000.0)
    times.sort()
    p99 = times[int(len(times) * 0.99) - 1]
    assert p99 < 5.0, f"IFC graph query p99 {p99:.3f}ms exceeds 5ms"


def test_nodes_of_kind_sorted(graph: ProvenanceGraph) -> None:
    graph.add_data(name="d", label=_label(IntegrityLevel.USER_INPUT), node_id="d1")
    graph.add_data(name="d", label=_label(IntegrityLevel.USER_INPUT), node_id="d2")
    graph.add_call(name="c", node_id="c1")
    data_nodes = graph.nodes_of_kind(NodeKind.DATA)
    assert data_nodes == ("d1", "d2")
