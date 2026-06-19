"""Tests for the deterministic SECRET ↛ EGRESS non-interference checker.

Covers three layers:
  * the checker (``check_noninterference``) — HOLDS / FORBID decisions and
    the witness path it emits, including the trusted-secret hole the FIDES
    dual-axis predicate misses;
  * the offline verifier (``verify_flow_proof``) — it must accept genuine
    proofs and reject every tampering (fingerprint, forged edge, swapped
    label, non-leaking source, HOLDS-with-witness); and
  * the engine wiring — ``IfcVerdict.structural_forbid`` / ``flow_proof`` and
    the new ``SECRET_EGRESS_NONINTERFERENCE`` violation, plus a regression
    guard that the pre-existing checks are unaffected.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext, RetrievedEntity
from tex.governance.private_data_exec.ifc.engine import IfcEngine, IfcViolation
from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)
from tex.governance.private_data_exec.ifc.noninterference import (
    DEFAULT_EGRESS_CLEARANCE,
    NonInterferenceVerdict,
    check_noninterference,
    egress_clearance,
    verify_flow_proof,
)
from tex.governance.private_data_exec.ifc.provenance import (
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
)


def _label(
    confidentiality: ConfidentialityLevel,
    *,
    integrity: IntegrityLevel = IntegrityLevel.SYS_INSTR,
    capacity: CapacityType = CapacityType.TEXT,
) -> IfcLabel:
    return IfcLabel(
        integrity=integrity, confidentiality=confidentiality, capacity=capacity
    )


def _secret_to_sink_graph(
    *,
    confidentiality: ConfidentialityLevel = ConfidentialityLevel.RESTRICTED,
    integrity: IntegrityLevel = IntegrityLevel.SYS_INSTR,
    capacity: CapacityType = CapacityType.TEXT,
) -> ProvenanceGraph:
    """One secret DATA node flowing straight into a sink CALL node."""
    g = ProvenanceGraph()
    g.add_data(
        name="ssn",
        label=_label(confidentiality, integrity=integrity, capacity=capacity),
        node_id="d:secret",
    )
    g.add_call(name="send_email", node_id="call:proposed")
    g.add_edge(source="d:secret", target="call:proposed", kind=EdgeKind.INPUT_TO)
    return g


# ── checker: the trusted-secret hole the FIDES dual-axis check misses ──


def test_trusted_secret_to_egress_forbids() -> None:
    """A TRUSTED (SYS_INSTR) secret reaching an egress sink must FORBID.

    This is the empirically-confirmed hole: the FIDES dual-axis
    ``is_flow_violation`` requires *untrusted* integrity, so it returns
    False here. The single-axis non-interference checker fires anyway.
    """
    g = _secret_to_sink_graph(integrity=IntegrityLevel.SYS_INSTR)
    proof = check_noninterference(g, "call:proposed", sink_action="send_email")
    assert proof.verdict is NonInterferenceVerdict.FORBID
    assert proof.is_forbid is True
    assert proof.proof_kind == "witness_path"
    assert proof.witness is not None
    assert proof.witness.source_id == "d:secret"
    assert proof.witness.source_confidentiality is ConfidentialityLevel.RESTRICTED
    assert proof.witness.steps[-1].node_id == "call:proposed"
    assert verify_flow_proof(g, proof) is True
    # And the dual-axis label predicate genuinely does NOT see it:
    assert g.effective_label("call:proposed").is_flow_violation is False


def test_confidential_is_the_secret_floor() -> None:
    """CONFIDENTIAL (the lattice's is_sensitive floor) → egress FORBIDs."""
    g = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.CONFIDENTIAL)
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.FORBID


def test_internal_to_egress_holds() -> None:
    """INTERNAL data is below the secret threshold — egress is permitted."""
    g = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.INTERNAL)
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.HOLDS
    assert proof.proof_kind == "exhaustive_replay"
    assert proof.witness is None
    assert verify_flow_proof(g, proof) is True


def test_no_ancestors_holds() -> None:
    """A bare sink with no inputs trivially satisfies non-interference."""
    g = ProvenanceGraph()
    g.add_call(name="send_email", node_id="call:proposed")
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.HOLDS


# ── checker: FIDES declassification exemption ──────────────────────────


@pytest.mark.parametrize(
    "capacity", [CapacityType.BOOL, CapacityType.ENUM]
)
def test_declassifiable_low_capacity_secret_holds(
    capacity: CapacityType,
) -> None:
    """A RESTRICTED value of low capacity (≤ ENUM) is FIDES-declassifiable:
    it cannot carry the payload, so the flow is permitted."""
    g = _secret_to_sink_graph(
        confidentiality=ConfidentialityLevel.RESTRICTED, capacity=capacity
    )
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.HOLDS


@pytest.mark.parametrize(
    "capacity",
    [CapacityType.NUMBER, CapacityType.SHORT_STRING, CapacityType.TEXT],
)
def test_nondeclassifiable_capacity_secret_forbids(
    capacity: CapacityType,
) -> None:
    """Above the declassification threshold (> ENUM) a secret still leaks."""
    g = _secret_to_sink_graph(
        confidentiality=ConfidentialityLevel.RESTRICTED, capacity=capacity
    )
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.FORBID


# ── checker: multi-hop / field-level witness reconstruction ────────────


def test_field_level_witness_path() -> None:
    """A RESTRICTED field flows FieldOf → parent → InputTo → sink. The
    witness must reconstruct the full multi-hop path in order."""
    g = ProvenanceGraph()
    g.add_data(
        name="record", label=_label(ConfidentialityLevel.INTERNAL), node_id="d:rec"
    )
    g.add_data_field(
        parent_data_id="d:rec",
        field_name="ssn",
        label=_label(ConfidentialityLevel.RESTRICTED),
        node_id="f:ssn",
    )
    g.add_call(name="post_to_social", node_id="call:proposed")
    g.add_edge(source="d:rec", target="call:proposed", kind=EdgeKind.INPUT_TO)
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.FORBID
    assert proof.witness is not None
    ids = [step.node_id for step in proof.witness.steps]
    assert ids == ["f:ssn", "d:rec", "call:proposed"]
    # The FieldOf edge and the InputTo edge are both data-flow edges.
    assert proof.witness.steps[0].edge_kind_to_next is EdgeKind.FIELD_OF
    assert proof.witness.steps[1].edge_kind_to_next is EdgeKind.INPUT_TO
    assert proof.witness.steps[2].edge_kind_to_next is None
    assert verify_flow_proof(g, proof) is True


def test_counterfactual_edge_is_not_a_dataflow_path() -> None:
    """A counterfactual edge (causal influence, not value provenance) must
    NOT count as a flow into the sink. A secret reachable ONLY via a
    counterfactual edge does not trip the confidentiality check."""
    g = ProvenanceGraph()
    # A denied action parks a counterfactual edge onto the next call.
    g.add_denied_action(name="read_secret", reason="HB-2")
    g.add_call(name="send_email", node_id="call:proposed")
    # No DATA node feeds the call at all — only the counterfactual edge.
    assert g.has_counterfactual_chain("call:proposed") is True
    proof = check_noninterference(g, "call:proposed")
    assert proof.verdict is NonInterferenceVerdict.HOLDS


# ── checker: sink clearance parameterization ───────────────────────────


def test_sink_clearance_override_raises_ceiling_holds() -> None:
    """If the sink is explicitly cleared for RESTRICTED, a RESTRICTED datum
    is within its observer ceiling — the flow holds."""
    g = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.RESTRICTED)
    proof = check_noninterference(
        g, "call:proposed", sink_clearance=ConfidentialityLevel.RESTRICTED
    )
    assert proof.verdict is NonInterferenceVerdict.HOLDS


def test_sink_clearance_override_lowers_ceiling_forbids() -> None:
    """A PUBLIC-only sink may not even receive INTERNAL data."""
    g = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.INTERNAL)
    proof = check_noninterference(
        g, "call:proposed", sink_clearance=ConfidentialityLevel.PUBLIC
    )
    assert proof.verdict is NonInterferenceVerdict.FORBID


def test_egress_clearance_metadata_parsing() -> None:
    assert egress_clearance(metadata=None) is DEFAULT_EGRESS_CLEARANCE
    assert (
        egress_clearance(metadata={"sink_clearance": "public"})
        is ConfidentialityLevel.PUBLIC
    )
    assert (
        egress_clearance(metadata={"sink_clearance": "RESTRICTED"})
        is ConfidentialityLevel.RESTRICTED
    )
    # Unrecognized value falls back to the conservative default.
    assert (
        egress_clearance(metadata={"sink_clearance": "nonsense"})
        is DEFAULT_EGRESS_CLEARANCE
    )


# ── checker: determinism + error handling ──────────────────────────────


def test_proof_is_deterministic() -> None:
    p1 = check_noninterference(_secret_to_sink_graph(), "call:proposed")
    p2 = check_noninterference(_secret_to_sink_graph(), "call:proposed")
    assert p1.commitment() == p2.commitment()
    assert p1.graph_fingerprint == p2.graph_fingerprint


def test_absent_sink_raises() -> None:
    g = ProvenanceGraph()
    with pytest.raises(KeyError):
        check_noninterference(g, "call:does_not_exist")


# ── verifier: accepts genuine proofs ───────────────────────────────────


def test_verify_accepts_genuine_holds_proof() -> None:
    g = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.INTERNAL)
    proof = check_noninterference(g, "call:proposed")
    assert verify_flow_proof(g, proof) is True


# ── verifier: rejects every tampering (fail-closed) ────────────────────


def test_verify_rejects_fingerprint_mismatch() -> None:
    """A proof minted on one graph must not verify against another."""
    g_forbid = _secret_to_sink_graph()
    proof = check_noninterference(g_forbid, "call:proposed")
    # A different graph (same node ids, but the secret is now PUBLIC).
    g_other = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.PUBLIC)
    assert g_other.fingerprint() != proof.graph_fingerprint
    assert verify_flow_proof(g_other, proof) is False


def test_verify_rejects_forged_edge() -> None:
    """A witness claiming an edge kind that does not exist is rejected."""
    g = _secret_to_sink_graph()  # real edge is INPUT_TO
    proof = check_noninterference(g, "call:proposed")
    assert proof.witness is not None
    forged_head = proof.witness.steps[0].model_copy(
        update={"edge_kind_to_next": EdgeKind.DIRECT_OUTPUT}
    )
    forged_witness = proof.witness.model_copy(
        update={"steps": (forged_head,) + proof.witness.steps[1:]}
    )
    forged = proof.model_copy(update={"witness": forged_witness})
    # Same fingerprint (we did not touch the graph), but the claimed
    # DIRECT_OUTPUT edge is absent → reject.
    assert verify_flow_proof(g, forged) is False


def test_verify_rejects_tampered_label() -> None:
    """An echoed label that disagrees with the graph is rejected."""
    g = _secret_to_sink_graph()
    proof = check_noninterference(g, "call:proposed")
    assert proof.witness is not None
    lied_head = proof.witness.steps[0].model_copy(
        update={"confidentiality": ConfidentialityLevel.PUBLIC}
    )
    lied_witness = proof.witness.model_copy(
        update={"steps": (lied_head,) + proof.witness.steps[1:]}
    )
    lied = proof.model_copy(update={"witness": lied_witness})
    assert verify_flow_proof(g, lied) is False


def test_verify_rejects_nonleaking_source() -> None:
    """Swapping the witness head to a real-but-non-secret node is rejected
    (the verifier re-checks the leak predicate on the graph's own label)."""
    g = ProvenanceGraph()
    g.add_data(
        name="ssn", label=_label(ConfidentialityLevel.RESTRICTED), node_id="d:secret"
    )
    g.add_data(
        name="prompt",
        label=_label(ConfidentialityLevel.INTERNAL, integrity=IntegrityLevel.USER_INPUT),
        node_id="d:benign",
    )
    g.add_call(name="send_email", node_id="call:proposed")
    g.add_edge(source="d:secret", target="call:proposed", kind=EdgeKind.INPUT_TO)
    g.add_edge(source="d:benign", target="call:proposed", kind=EdgeKind.INPUT_TO)
    proof = check_noninterference(g, "call:proposed")
    assert proof.witness is not None
    # Re-point the witness at the benign INTERNAL node.
    benign_head = proof.witness.steps[0].model_copy(
        update={
            "node_id": "d:benign",
            "confidentiality": ConfidentialityLevel.INTERNAL,
            "edge_kind_to_next": EdgeKind.INPUT_TO,
        }
    )
    benign_witness = proof.witness.model_copy(
        update={
            "source_id": "d:benign",
            "source_confidentiality": ConfidentialityLevel.INTERNAL,
            "steps": (benign_head, proof.witness.steps[-1]),
        }
    )
    forged = proof.model_copy(update={"witness": benign_witness})
    assert verify_flow_proof(g, forged) is False


def test_verify_rejects_holds_proof_carrying_witness() -> None:
    """A HOLDS verdict must carry no witness; a fabricated one is rejected."""
    g_holds = _secret_to_sink_graph(confidentiality=ConfidentialityLevel.INTERNAL)
    holds = check_noninterference(g_holds, "call:proposed")
    g_forbid = _secret_to_sink_graph()
    forbid = check_noninterference(g_forbid, "call:proposed")
    smuggled = holds.model_copy(update={"witness": forbid.witness})
    assert verify_flow_proof(g_holds, smuggled) is False


def test_verify_rejects_holds_proof_that_should_forbid() -> None:
    """A proof asserting HOLDS for a graph that actually leaks is rejected
    by the verifier's independent re-execution."""
    g = _secret_to_sink_graph()  # actually FORBID
    real = check_noninterference(g, "call:proposed")
    lying = real.model_copy(
        update={
            "verdict": NonInterferenceVerdict.HOLDS,
            "witness": None,
            "proof_kind": "exhaustive_replay",
        }
    )
    assert verify_flow_proof(g, lying) is False


def test_commitment_binds_proof_content() -> None:
    proof = check_noninterference(_secret_to_sink_graph(), "call:proposed")
    mutated = proof.model_copy(update={"sink_action": "tampered_action"})
    assert mutated.commitment() != proof.commitment()


# ── seal seam ──────────────────────────────────────────────────────────


def test_to_sealed_fact_is_well_formed() -> None:
    from tex.domain.evidence import EvidenceMaturity
    from tex.provenance.models import SealedFact, SealedFactKind

    proof = check_noninterference(_secret_to_sink_graph(), "call:proposed")
    fact = proof.to_sealed_fact()
    assert isinstance(fact, SealedFact)
    assert fact.kind is SealedFactKind.ENFORCEMENT
    assert fact.subject_id == "call:proposed"
    assert fact.maturity is EvidenceMaturity.RESEARCH_SOLID
    assert "forbid" in fact.claim
    # The proof round-trips inside the sealed detail.
    assert fact.detail["verdict"] == "forbid"
    # SealedFact itself round-trips (JSON-serializable detail).
    assert SealedFact.model_validate(fact.model_dump(mode="json")).claim == fact.claim


# ── engine integration ─────────────────────────────────────────────────


def _req(
    *,
    action_type: str = "send_email",
    content: str = "quarterly summary",
    recipient: str | None = "external@example.com",
    metadata: dict | None = None,
) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        recipient=recipient,
        channel="email",
        environment="production",
        metadata=metadata or {},
        session_id=None,
    )


def _restricted_entity_ctx() -> RetrievalContext:
    entity = RetrievedEntity(
        entity_id="e1",
        entity_type="customer",
        canonical_name="Alice SSN 123-45-6789",
        sensitivity="restricted",
        relevance_score=1.0,
        rank=1,
    )
    return RetrievalContext(
        policy_clauses=tuple(), precedents=tuple(), entities=(entity,)
    )


def test_engine_structural_forbid_on_trusted_secret() -> None:
    """The end-to-end hole: a trusted RESTRICTED entity → external egress.
    The engine now emits a deterministic structural FORBID with a proof."""
    verdict = IfcEngine().evaluate(
        request=_req(metadata={}),  # nothing untrusted
        retrieval_context=_restricted_entity_ctx(),
    )
    assert verdict.structural_forbid is True
    assert IfcViolation.SECRET_EGRESS_NONINTERFERENCE in verdict.violations
    assert verdict.flow_proof is not None
    assert verdict.flow_proof.verdict is NonInterferenceVerdict.FORBID
    assert verdict.flow_proof.witness is not None


def test_engine_secret_egress_fires_when_fides_silent() -> None:
    """Proof the new check is doing the catching: on a trusted secret the
    FIDES dual-axis FLOW_INTEGRITY stays silent, SECRET_EGRESS fires."""
    verdict = IfcEngine().evaluate(
        request=_req(metadata={}),
        retrieval_context=_restricted_entity_ctx(),
    )
    assert IfcViolation.FLOW_INTEGRITY not in verdict.violations
    assert IfcViolation.SECRET_EGRESS_NONINTERFERENCE in verdict.violations


def test_engine_benign_holds_no_forbid() -> None:
    verdict = IfcEngine().evaluate(
        request=_req(content="lunch at noon", recipient="x@y.com"),
        retrieval_context=RetrievalContext.empty(),
    )
    assert verdict.structural_forbid is False
    assert verdict.flow_proof is not None
    assert verdict.flow_proof.verdict is NonInterferenceVerdict.HOLDS
    assert IfcViolation.SECRET_EGRESS_NONINTERFERENCE not in verdict.violations


def test_engine_nonsink_produces_no_proof() -> None:
    verdict = IfcEngine().evaluate(
        request=_req(
            action_type="summarize",
            content="ssn 123-45-6789",
            recipient=None,
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert verdict.flow_proof is None
    assert verdict.structural_forbid is False


def test_engine_existing_checks_unaffected() -> None:
    """Regression guard: the untrusted-secret → egress case still fires the
    pre-existing FLOW_INTEGRITY and RULE_OF_TWO_TRIFECTA violations."""
    verdict = IfcEngine().evaluate(
        request=_req(
            content="Customer SSN 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.FLOW_INTEGRITY in verdict.violations
    assert IfcViolation.RULE_OF_TWO_TRIFECTA in verdict.violations
    # And the new deterministic check also fires (content is RESTRICTED).
    assert IfcViolation.SECRET_EGRESS_NONINTERFERENCE in verdict.violations
    assert verdict.structural_forbid is True


def test_engine_sink_clearance_override_holds() -> None:
    """Operator raising the sink clearance to RESTRICTED suppresses the
    deterministic FORBID for a RESTRICTED datum (explicit declassification
    of the destination)."""
    verdict = IfcEngine().evaluate(
        request=_req(metadata={"sink_clearance": "restricted"}),
        retrieval_context=_restricted_entity_ctx(),
    )
    assert verdict.structural_forbid is False
    assert IfcViolation.SECRET_EGRESS_NONINTERFERENCE not in verdict.violations


def test_engine_proof_node_kind_tail_is_call() -> None:
    """The witness tail is always the sink CALL node."""
    verdict = IfcEngine().evaluate(
        request=_req(metadata={}),
        retrieval_context=_restricted_entity_ctx(),
    )
    assert verdict.flow_proof is not None
    assert verdict.flow_proof.witness is not None
    tail = verdict.flow_proof.witness.steps[-1]
    assert tail.kind is NodeKind.CALL
