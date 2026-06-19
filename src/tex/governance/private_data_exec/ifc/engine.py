"""
IFC engine: orchestrates classification, provenance graph, NeuroTaint
cross-session memory, and CI norm checking into a single verdict.

This module is the wire-up layer between the IfcSpecialist and the
underlying ARM/FIDES/NeuroTaint/CA-CI mechanisms. The specialist
itself stays narrow (`tex.specialists.ifc_specialist`); all the
algorithmic work lives here.

Engine pipeline (per request)
-----------------------------
1. Classify the request fields and retrieved context into labeled
   source nodes.
2. Build a ProvenanceGraph from the classification.
3. If the operator marked any preceding actions as denied in
   `metadata["recent_denials"]`, materialize DeniedAction nodes
   BEFORE the proposed call node so ARM Algorithm 1 auto-links a
   Counterfactual edge.
4. Materialize a CALL node for the proposed sink action.
5. Run the ARM enforcement queries:
   - MinTrust on the CALL node vs the configured trust floor.
   - has_counterfactual_chain on the CALL node.
6. Run the FIDES/MVAR flow-violation check: untrusted-integrity meets
   sensitive-confidentiality → flow violation.
7. Cross-session NeuroTaint check: any memory items in the request's
   session that have residual taint → propagate forward.
8. CI norm check (CA-CI): does the realized flow match a permitted
   norm in the operator registry?
9. Rule of Two corrective check (Towards AI / EchoLeak counterexample):
   if the agent has private-data access AND untrusted-input AND
   external-communication, raise a triple-bucket violation.
10. Compose IfcVerdict and emit telemetry.

All checks are deterministic; the verdict carries a structured payload
the specialist serializes into evidence.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.governance.private_data_exec.ifc.ci_norms import (
    CiNorm,
    CiNormRegistry,
)
from tex.governance.private_data_exec.ifc.classifier import (
    ClassifiedSource,
    classify_request,
    extract_ci_norm,
    extract_proposed_tool_call,
    is_sink_action,
)
from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)
from tex.governance.private_data_exec.ifc.memory import (
    MemoryItem,
    MemoryStream,
)
from tex.governance.private_data_exec.ifc.noninterference import (
    FlowProof,
    NonInterferenceVerdict,
    check_noninterference,
    egress_clearance,
)
from tex.governance.private_data_exec.ifc.provenance import (
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
)
from tex.observability import telemetry


class IfcViolation(str, enum.Enum):
    """Distinct violation classes the engine can detect."""

    FLOW_INTEGRITY = "ifc.flow_integrity"  # FIDES dual-axis violation
    MIN_TRUST_FLOOR = "ifc.min_trust_floor"  # ARM Layer 2 trust check
    CAUSALITY_LAUNDERING = "ifc.causality_laundering"  # ARM novel check
    CI_NORM_VIOLATION = "ifc.ci_norm_violation"  # CA-CI norm mismatch
    NEUROTAINT_CROSS_SESSION = "ifc.neurotaint_cross_session"
    RULE_OF_TWO_TRIFECTA = "ifc.rule_of_two_trifecta"  # all three buckets
    # Deterministic, proof-carrying confidentiality non-interference
    # (SECRET ↛ EGRESS). Distinct from FLOW_INTEGRITY: single-axis
    # (confidentiality only), so it fires even on a *trusted* secret, and
    # it is a deterministic structural FORBID carrying a re-checkable
    # witness — not a probabilistic signal. See ``noninterference.py``.
    SECRET_EGRESS_NONINTERFERENCE = "ifc.secret_egress_noninterference"


@dataclass(frozen=True, slots=True)
class IfcEvidenceItem:
    """One human-readable evidence record from the engine."""

    violation: IfcViolation
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IfcVerdict:
    """Structured engine verdict consumed by the IfcSpecialist."""

    violations: tuple[IfcViolation, ...]
    evidence: tuple[IfcEvidenceItem, ...]
    effective_label: IfcLabel
    proposed_sink: bool
    ci_norm: CiNorm
    fingerprint: str
    graph_node_count: int
    graph_edge_count: int
    # Deterministic confidentiality non-interference (SECRET ↛ EGRESS).
    # ``flow_proof`` is the proof-carrying, offline-re-checkable object
    # (HOLDS or FORBID) for an egress sink; None for non-sink actions
    # where no egress boundary exists. ``structural_forbid`` is True iff
    # that proof is a FORBID. That FORBID is now CONSUMED as a hard PDP
    # DENY: the engine emits the ``SECRET_EGRESS_NONINTERFERENCE`` violation
    # code in lockstep, and ``tex.specialists.structural_floor`` lists it in
    # ``_IFC_HARD_VIOLATION_CODES`` so the PDP short-circuits to FORBID
    # (monotone — the floor only raises severity). ``structural_forbid`` is
    # the in-band carrier of the same fact for any direct consumer.
    # Defaults keep every existing constructor valid.
    flow_proof: FlowProof | None = None
    structural_forbid: bool = False

    @property
    def has_violations(self) -> bool:
        return bool(self.violations)

    @property
    def risk_score(self) -> float:
        """Aggregate risk in [0, 1] across detected violations.

        Per-class weight is calibrated so a single high-severity
        violation (CAUSALITY_LAUNDERING, RULE_OF_TWO_TRIFECTA,
        FLOW_INTEGRITY) hits the FORBID threshold by itself, while
        multiple medium-severity signals accumulate.
        """
        if not self.violations:
            return 0.05  # specialist floor
        weights = {
            # SECRET_EGRESS is the deterministic structural floor; its soft
            # echo here is the strongest weight so the probabilistic score
            # never *understates* a deterministic FORBID. The live authority is
            # the structural-floor promotion of this violation code (see
            # tex.specialists.structural_floor._IFC_HARD_VIOLATION_CODES), not
            # this score — the score is only the voting-tier echo.
            IfcViolation.SECRET_EGRESS_NONINTERFERENCE: 0.97,
            IfcViolation.FLOW_INTEGRITY: 0.95,
            IfcViolation.CAUSALITY_LAUNDERING: 0.90,
            IfcViolation.RULE_OF_TWO_TRIFECTA: 0.85,
            IfcViolation.MIN_TRUST_FLOOR: 0.55,
            IfcViolation.NEUROTAINT_CROSS_SESSION: 0.45,
            IfcViolation.CI_NORM_VIOLATION: 0.40,
        }
        # Aggregate via complement-of-product (independent failure
        # combine), capped at 1.0.
        survival = 1.0
        for v in set(self.violations):
            survival *= 1.0 - weights.get(v, 0.30)
        return round(min(1.0, max(0.05, 1.0 - survival)), 4)


class IfcEngine:
    """
    The deterministic IFC enforcement engine.

    Construct once per process; call `evaluate(...)` per request.
    Thread-safe per call because the per-request ProvenanceGraph is
    local; only the cross-session MemoryStream is shared, and it owns
    its own lock.
    """

    def __init__(
        self,
        *,
        ci_registry: CiNormRegistry | None = None,
        memory_stream: MemoryStream | None = None,
        min_trust_floor: IntegrityLevel = IntegrityLevel.TOOL_TRUSTED,
    ) -> None:
        self._ci_registry = ci_registry or CiNormRegistry()
        self._memory_stream = memory_stream
        self._min_trust_floor = min_trust_floor

    # ── primary entry point ─────────────────────────────────────────

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> IfcVerdict:
        """Run the full IFC pipeline and return a structured verdict."""
        sources = classify_request(
            request=request, retrieval_context=retrieval_context
        )
        graph = ProvenanceGraph()

        # Materialize source DATA nodes and remember their IDs by
        # source_id for later cross-reference.
        source_node_ids: dict[str, str] = {}
        content_hash_to_source: dict[str, ClassifiedSource] = {}
        for source in sources:
            data_id = graph.add_data(
                name=source.name, label=source.label, node_id=source.source_id
            )
            source_node_ids[source.source_id] = data_id
            content_hash_to_source[source.content_hash] = source

        # Cross-session NeuroTaint: look up memory items keyed by
        # session and any source content hash. Materialize hits as
        # additional DATA nodes (so MinTrust includes them as
        # ancestors of the upcoming CALL node).
        neurotaint_hits: tuple[MemoryItem, ...] = tuple()
        session_key = self._session_key(request)
        if self._memory_stream is not None and session_key:
            content_hashes = tuple(content_hash_to_source.keys())
            neurotaint_hits = self._memory_stream.lookup(
                session_key=session_key, content_hashes=content_hashes
            )
            for idx, item in enumerate(neurotaint_hits):
                graph.add_data(
                    name=f"neurotaint:{idx}",
                    label=item.label,
                    node_id=f"neurotaint:{session_key}:{idx}",
                )

        # Pre-register any operator-asserted denied actions so the
        # CALL node about to be materialized can pick up a
        # Counterfactual edge per ARM Algorithm 1.
        recent_denials = self._extract_recent_denials(request)
        for denial in recent_denials:
            graph.add_denied_action(
                name=denial.get("name", "denied_action"),
                reason=str(denial.get("reason", "operator_marked")),
                metadata=denial,
            )

        # Materialize the proposed-action CALL node.
        action_name = request.action_type
        tool_call = extract_proposed_tool_call(request)
        call_metadata: dict[str, object] = {
            "action_type": request.action_type,
            "channel": request.channel,
            "environment": request.environment,
        }
        if request.recipient:
            call_metadata["recipient"] = request.recipient
        if tool_call is not None:
            call_metadata["tool"] = tool_call.name
            call_metadata["tool_arguments"] = dict(tool_call.arguments)
            action_name = f"{request.action_type}:{tool_call.name}"

        call_id = graph.add_call(
            name=action_name,
            node_id="call:proposed",
            metadata=call_metadata,
        )

        # Link every source DATA node as an InputTo of the CALL.
        for source_id in source_node_ids.values():
            graph.add_edge(
                source=source_id, target=call_id, kind=EdgeKind.INPUT_TO
            )
        for idx in range(len(neurotaint_hits)):
            graph.add_edge(
                source=f"neurotaint:{session_key}:{idx}",
                target=call_id,
                kind=EdgeKind.INPUT_TO,
            )

        # ── checks ──────────────────────────────────────────────────
        violations: list[IfcViolation] = []
        evidence: list[IfcEvidenceItem] = []

        # (a) MinTrust floor (ARM §5.4 query 1).
        effective_label = graph.effective_label(call_id)
        min_trust = effective_label.integrity
        sink = is_sink_action(request.action_type)
        if sink and min_trust < self._min_trust_floor:
            violations.append(IfcViolation.MIN_TRUST_FLOOR)
            evidence.append(
                IfcEvidenceItem(
                    violation=IfcViolation.MIN_TRUST_FLOOR,
                    reason=(
                        f"MinTrust({min_trust.label}) is below required "
                        f"floor ({self._min_trust_floor.label}) for sink "
                        f"action {request.action_type!r}."
                    ),
                    detail={
                        "min_trust": min_trust.label,
                        "floor": self._min_trust_floor.label,
                        "sink_action": request.action_type,
                    },
                )
            )

        # (b) Counterfactual chain (ARM §5.4 query 2) — causality
        # laundering detection.
        if graph.has_counterfactual_chain(call_id):
            denied_ids = graph.counterfactual_denials(call_id)
            violations.append(IfcViolation.CAUSALITY_LAUNDERING)
            evidence.append(
                IfcEvidenceItem(
                    violation=IfcViolation.CAUSALITY_LAUNDERING,
                    reason=(
                        "Counterfactual path reaches the proposed action "
                        f"from {len(denied_ids)} denied-action node(s). "
                        "Per ARM (arxiv 2604.04035), this pattern is the "
                        "denial-feedback leakage attack class."
                    ),
                    detail={"denial_node_ids": list(denied_ids)},
                )
            )

        # (c) FIDES dual-axis flow violation.
        if sink and effective_label.is_flow_violation:
            # If capacity is low enough, FIDES allows declassification.
            if effective_label.may_declassify:
                # Note declassification but don't fire — the operator
                # explicitly tagged this output as low-capacity.
                pass
            else:
                violations.append(IfcViolation.FLOW_INTEGRITY)
                evidence.append(
                    IfcEvidenceItem(
                        violation=IfcViolation.FLOW_INTEGRITY,
                        reason=(
                            "Untrusted-integrity content "
                            f"({effective_label.integrity.label}) is flowing "
                            "into a sensitive-confidentiality sink "
                            f"({effective_label.confidentiality.label}). "
                            "Per FIDES (arxiv 2505.23643) this is an "
                            "inadmissible information flow."
                        ),
                        detail={
                            "integrity": effective_label.integrity.label,
                            "confidentiality": (
                                effective_label.confidentiality.label
                            ),
                            "capacity": effective_label.capacity.name,
                        },
                    )
                )

        # (d) CI norm check (CA-CI).
        ci_norm = extract_ci_norm(request)
        if self._ci_registry.norms:
            # Only enforce when the operator has registered at least
            # one norm; empty registry = advisory.
            if not self._ci_registry.is_permitted(ci_norm):
                violations.append(IfcViolation.CI_NORM_VIOLATION)
                evidence.append(
                    IfcEvidenceItem(
                        violation=IfcViolation.CI_NORM_VIOLATION,
                        reason=(
                            "Realized information flow does not match any "
                            "permitted norm in the operator's CA-CI registry."
                        ),
                        detail={
                            "sender": ci_norm.sender,
                            "receiver": ci_norm.receiver,
                            "subject": ci_norm.subject,
                            "information_type": ci_norm.information_type,
                            "transmission_principle": (
                                ci_norm.transmission_principle.value
                            ),
                            "purpose": ci_norm.purpose,
                        },
                    )
                )

        # (e) NeuroTaint cross-session.
        if neurotaint_hits:
            untrusted_carry = [
                item
                for item in neurotaint_hits
                if item.label.integrity.is_untrusted
            ]
            if untrusted_carry:
                violations.append(IfcViolation.NEUROTAINT_CROSS_SESSION)
                evidence.append(
                    IfcEvidenceItem(
                        violation=IfcViolation.NEUROTAINT_CROSS_SESSION,
                        reason=(
                            f"{len(untrusted_carry)} memory item(s) from "
                            "prior sessions carry untrusted-integrity "
                            "taint into this request. Per NeuroTaint "
                            "(arxiv 2604.23374), cross-session "
                            "persistence is a first-class taint axis."
                        ),
                        detail={
                            "carried_item_count": len(untrusted_carry),
                        },
                    )
                )

        # (f) Rule of Two corrective check (Towards AI Nov 2025 / EchoLeak
        # counterexample): if all three buckets are present, raise the
        # triple-bucket violation.
        has_untrusted_input = any(
            s.label.integrity.is_untrusted for s in sources
        )
        has_private_data = any(
            s.label.confidentiality.is_sensitive for s in sources
        )
        has_external_action = sink
        if has_untrusted_input and has_private_data and has_external_action:
            violations.append(IfcViolation.RULE_OF_TWO_TRIFECTA)
            evidence.append(
                IfcEvidenceItem(
                    violation=IfcViolation.RULE_OF_TWO_TRIFECTA,
                    reason=(
                        "Lethal trifecta detected: this request "
                        "simultaneously involves untrusted input, "
                        "sensitive data, and an external-communication "
                        "action. Per Meta's Rule of Two (Oct 2025) and "
                        "the EchoLeak counterexample (Towards AI Nov "
                        "2025), this configuration is exploitable by "
                        "indirect prompt injection."
                    ),
                    detail={
                        "untrusted_input": has_untrusted_input,
                        "private_data": has_private_data,
                        "external_action": has_external_action,
                    },
                )
            )

        # (g) Deterministic confidentiality non-interference (SECRET ↛
        # EGRESS). Unlike the probabilistic checks above, this emits a
        # DECIDABLE verdict carrying a re-checkable witness, and fires
        # even on a *trusted* secret (the FIDES dual-axis check misses
        # that case). It is the structural floor; everything it does not
        # decide stays the PDP's ABSTAIN residue.
        flow_proof: FlowProof | None = None
        structural_forbid = False
        if sink:
            flow_proof = check_noninterference(
                graph,
                call_id,
                sink_clearance=egress_clearance(metadata=request.metadata),
                sink_action=request.action_type,
            )
            if flow_proof.verdict is NonInterferenceVerdict.FORBID:
                structural_forbid = True
                violations.append(IfcViolation.SECRET_EGRESS_NONINTERFERENCE)
                witness = flow_proof.witness
                assert witness is not None  # FORBID always carries a witness
                evidence.append(
                    IfcEvidenceItem(
                        violation=IfcViolation.SECRET_EGRESS_NONINTERFERENCE,
                        reason=(
                            "Deterministic non-interference violation: a "
                            f"{witness.source_confidentiality.label} datum "
                            f"({witness.source_id}) flows to egress sink "
                            f"{request.action_type!r} cleared only for "
                            f"{flow_proof.sink_clearance.label}. A re-checkable "
                            f"witness path of {len(witness.steps)} node(s) "
                            "proves the explicit flow; this is a structural "
                            "FORBID, not a probabilistic signal."
                        ),
                        detail={
                            "source_id": witness.source_id,
                            "source_confidentiality": (
                                witness.source_confidentiality.label
                            ),
                            "sink_clearance": flow_proof.sink_clearance.label,
                            "witness_node_ids": [
                                step.node_id for step in witness.steps
                            ],
                            "proof_commitment": flow_proof.commitment(),
                            "graph_fingerprint": flow_proof.graph_fingerprint,
                        },
                    )
                )

        # Record memory item for this request's tainted content so
        # downstream sessions see the carry.
        if self._memory_stream is not None and session_key:
            for source in sources:
                if source.label.integrity.is_untrusted:
                    self._memory_stream.record(
                        MemoryItem(
                            session_key=session_key,
                            content_hash=source.content_hash,
                            label=source.label,
                            recorded_at=_now(),
                            reason=source.reason,
                        )
                    )

        verdict = IfcVerdict(
            violations=tuple(violations),
            evidence=tuple(evidence),
            effective_label=effective_label,
            proposed_sink=sink,
            ci_norm=ci_norm,
            fingerprint=graph.fingerprint(),
            graph_node_count=graph.node_count,
            graph_edge_count=graph.edge_count,
            flow_proof=flow_proof,
            structural_forbid=structural_forbid,
        )

        telemetry.emit_event(
            "ifc.evaluated",
            request_id=str(request.request_id),
            violations=[v.value for v in verdict.violations],
            min_trust=effective_label.integrity.label,
            max_sensitivity=effective_label.confidentiality.label,
            sink=sink,
            node_count=verdict.graph_node_count,
            edge_count=verdict.graph_edge_count,
            fingerprint=verdict.fingerprint,
            ni_verdict=(
                flow_proof.verdict.value if flow_proof is not None else "n/a"
            ),
            structural_forbid=structural_forbid,
        )
        if verdict.has_violations:
            telemetry.emit_event(
                "ifc.flow_violation",
                level=logging.WARNING,
                request_id=str(request.request_id),
                violations=[v.value for v in verdict.violations],
            )

        return verdict

    # ── helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _session_key(request: EvaluationRequest) -> str:
        """Compose a stable session key for NeuroTaint cross-session lookup."""
        identity = request.agent_identity
        if identity is None:
            if request.session_id:
                return f"session:{request.session_id}"
            return ""
        parts = [identity.tenant_id]
        if identity.agent_id is not None:
            parts.append(str(identity.agent_id))
        elif identity.external_agent_id:
            parts.append(identity.external_agent_id)
        elif identity.agent_name:
            parts.append(identity.agent_name)
        if request.session_id:
            parts.append(request.session_id)
        return "|".join(parts)

    @staticmethod
    def _extract_recent_denials(
        request: EvaluationRequest,
    ) -> tuple[dict[str, Any], ...]:
        raw = request.metadata.get("recent_denials")
        if not isinstance(raw, (list, tuple)):
            return tuple()
        out: list[dict[str, Any]] = []
        for entry in raw:
            if isinstance(entry, dict):
                # Defensive copy + coerce keys to str.
                out.append({str(k): v for k, v in entry.items()})
        return tuple(out)


def _now():  # pragma: no cover - thin wrapper
    from datetime import datetime, UTC

    return datetime.now(UTC)


__all__ = [
    "IfcEngine",
    "IfcVerdict",
    "IfcEvidenceItem",
    "IfcViolation",
]
