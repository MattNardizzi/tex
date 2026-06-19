"""
Deterministic confidentiality non-interference checker (SECRET ↛ EGRESS).

What this module is — and is NOT
--------------------------------
General non-interference (Goguen & Meseguer, "Security Policies and
Security Models," IEEE S&P 1982) is a *2-safety hyperproperty*: it
quantifies over pairs of executions and, for arbitrary programs, is
**undecidable**. This module does NOT claim it. It is a **deterministic
checker for a single, concrete, DECIDABLE sub-property**:

    P(S, c):  no DATA / DATA_FIELD node whose confidentiality is strictly
              above the egress sink S's observer clearance c — and whose
              value is not FIDES-declassifiable — is a data-flow ancestor
              of S.

Because the ARM provenance graph (``ifc.provenance.ProvenanceGraph``) is
finite and fully materialized for one request, and the confidentiality
lattice is finite, P(S, c) reduces to **graph reachability + a lattice
comparison** — which is decidable and answered exactly here. This is the
"explicit secrecy for confidentiality" that taint-tracking can enforce
soundly (FIDES, arXiv:2505.23643 §2.2; cf. the 2026 IFC-for-agents
survey). It is the floor; the residue — semantic/implicit leakage,
"is this content harmful", purpose drift — stays the PDP's ABSTAIN job.

Why this is not already covered by the engine's FIDES check
-----------------------------------------------------------
``IfcLabel.is_flow_violation`` (lattice.py) is the dual-axis predicate
``integrity.is_untrusted AND confidentiality.is_sensitive`` evaluated on
the *join* of all ancestors. It therefore:
  1. misses a **trusted** secret reaching egress (integrity is not
     untrusted ⇒ predicate False), the empirically-confirmed hole;
  2. collapses provenance into one scalar, so it cannot say *which*
     datum leaks nor emit a **re-checkable witness**; and
  3. feeds a *probabilistic* risk score, not a deterministic verdict.

This checker is single-axis (confidentiality only), reachability-based
(emits an explicit witness path), and produces a **deterministic
verdict** (HOLDS / FORBID) carrying a proof a verifier re-checks offline.

The proof object
----------------
- FORBID carries a **succinct witness**: an ordered source→…→sink path.
  ``verify_flow_proof`` re-confirms every claimed edge against the graph
  (``has_edge``), re-reads every label, and re-checks the leak predicate
  — it never trusts the search that found the path.
- HOLDS carries no succinct certificate (proving *absence* of any leaking
  path is not a one-path object). It is certified by **deterministic
  re-execution** of the same decidable check over the fingerprint-bound
  graph. This asymmetry (witness for violation, replay for absence) is
  stated, not hidden.

Both verdicts bind to ``graph.fingerprint()`` so a proof cannot be
replayed against a different graph.

Maturity: ``research_solid`` — the mechanism is real, deterministic, and
sound for the stated sub-property, but newly wired and not yet
CI-benchmarked. It is NOT a general non-interference guarantee.
"""

from __future__ import annotations

import enum
import hashlib
import json
from collections import deque
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

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

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tex.provenance.models import SealedFact


# Default observer clearance for an external-communication (egress) sink.
# INTERNAL means: PUBLIC and INTERNAL data may leave; CONFIDENTIAL and
# RESTRICTED (the lattice's ``is_sensitive`` tier — i.e. "secret") may not.
# This aligns the deterministic floor with the existing ``is_sensitive``
# threshold: only genuinely-secret data trips it, so routine INTERNAL
# business data going out stays the PDP's discretionary ABSTAIN call.
DEFAULT_EGRESS_CLEARANCE: ConfidentialityLevel = ConfidentialityLevel.INTERNAL


class NonInterferenceVerdict(str, enum.Enum):
    """The decidable verdict of the confidentiality non-interference check."""

    HOLDS = "holds"          # no leaking secret→egress flow exists
    FORBID = "forbid"        # a leaking flow exists; witness attached


# ---------------------------------------------------------------------------
# Proof object (frozen, canonically serializable, offline-re-checkable)
# ---------------------------------------------------------------------------


class FlowStep(BaseModel):
    """One node on a witness path, with the edge that carries flow onward.

    ``edge_kind_to_next`` is the edge from THIS node to the next node
    toward the sink (None on the sink itself, which is the path tail).
    Labels are echoed so a reader sees the trace without the graph, but
    the verifier re-reads them from the graph rather than trusting them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Field(min_length=1, max_length=300)
    kind: NodeKind
    integrity: IntegrityLevel | None = None
    confidentiality: ConfidentialityLevel | None = None
    capacity: CapacityType | None = None
    edge_kind_to_next: EdgeKind | None = None


class FlowWitness(BaseModel):
    """A single explicit source→…→sink path proving a leaking flow.

    ``steps[0]`` is the leaking secret source; ``steps[-1]`` is the sink
    CALL node. Consecutive steps are joined by ``edge_kind_to_next``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(min_length=1, max_length=300)
    sink_id: str = Field(min_length=1, max_length=300)
    source_confidentiality: ConfidentialityLevel
    steps: tuple[FlowStep, ...] = Field(min_length=2)


class FlowProof(BaseModel):
    """A checkable proof object for one non-interference decision.

    Frozen + ``extra="forbid"`` like every sealed Tex model. The proof is
    bound to the exact graph by ``graph_fingerprint``; ``verify_flow_proof``
    re-checks it offline.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Machine-readable statement of the property that was checked.
    property_statement: str = Field(min_length=1, max_length=400)
    verdict: NonInterferenceVerdict
    sink_id: str = Field(min_length=1, max_length=300)
    sink_action: str = Field(default="", max_length=200)
    sink_clearance: ConfidentialityLevel
    graph_fingerprint: str = Field(min_length=64, max_length=64)
    checked_node_count: int = Field(ge=0)
    checked_edge_count: int = Field(ge=0)
    # "witness_path" for FORBID; "exhaustive_replay" for HOLDS.
    proof_kind: str = Field(min_length=1, max_length=40)
    witness: FlowWitness | None = None

    @property
    def is_forbid(self) -> bool:
        return self.verdict is NonInterferenceVerdict.FORBID

    def canonical_bytes(self) -> bytes:
        """Deterministic, sorted-key JSON encoding of the proof.

        The basis for ``commitment()`` and for sealing. Stable across
        processes (no insertion-order or float dependence)."""
        payload = self.model_dump(mode="json")
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def commitment(self) -> str:
        """SHA-256 over ``canonical_bytes`` — the proof's content seal.

        Mirrors ``ProvenanceGraph.fingerprint``'s canonical-hash pattern.
        This is a *commitment* (binding hash), not a signature; authorship
        comes from sealing it into the ECDSA-P256 ledger via
        ``to_sealed_fact`` — see that method's note.
        """
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_sealed_fact(self) -> "SealedFact":
        """Map this proof to a ``SealedFact(ENFORCEMENT)`` for the ledger.

        Reuses the existing seal seam (``provenance.models.SealedFact``,
        the same type ``provenance.decision_seal`` appends) so a 1-line
        out-of-lane call from the specialist/PDP can hash-chain + ECDSA
        sign it. Import is lazy so the per-request IFC path never pulls
        the crypto/ledger stack unless a seal is actually requested.

        Honesty: sealing proves AUTHORSHIP + INTEGRITY of the proof
        record (Tex produced this exact flow decision and it was not
        altered), NOT that the FORBID was the morally-correct call — the
        proof's own ``verify_flow_proof`` is what establishes the flow
        actually exists. Maturity rides in the sealed bytes, not prose.
        """
        from tex.domain.evidence import EvidenceMaturity
        from tex.provenance.models import SealedFact, SealedFactKind

        verdict = self.verdict.value
        claim = (
            f"IFC non-interference {verdict} for egress sink "
            f"{self.sink_id!r} (action={self.sink_action!r}, "
            f"clearance={self.sink_clearance.label}); "
            f"property={self.property_statement}; "
            f"proof={self.proof_kind}; commitment={self.commitment()[:16]} "
            f"— authorship+integrity sealed; checked over graph "
            f"{self.graph_fingerprint[:16]}"
        )
        return SealedFact(
            kind=SealedFactKind.ENFORCEMENT,
            subject_id=self.sink_id,
            claim=claim,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            detail=self.model_dump(mode="json"),
        )


# ---------------------------------------------------------------------------
# Sink clearance derivation
# ---------------------------------------------------------------------------


def egress_clearance(
    *,
    metadata: dict[str, object] | None = None,
    default: ConfidentialityLevel = DEFAULT_EGRESS_CLEARANCE,
) -> ConfidentialityLevel:
    """Resolve an egress sink's observer clearance.

    Operators may raise/lower it per request via
    ``metadata["sink_clearance"]`` (a level name, case-insensitive). An
    unrecognized value falls back to ``default`` rather than failing the
    request — the floor stays conservative.
    """
    raw = (metadata or {}).get("sink_clearance")
    if isinstance(raw, str) and raw.strip():
        try:
            return ConfidentialityLevel[raw.strip().upper()]
        except KeyError:
            return default
    if isinstance(raw, ConfidentialityLevel):
        return raw
    return default


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------


def _leaks(label: IfcLabel, clearance: ConfidentialityLevel) -> bool:
    """True iff ``label`` is secret-above-clearance and not declassifiable.

    FIDES (arXiv:2505.23643 §3) permits release of a low-capacity value
    (BOOL/ENUM) because it cannot carry an arbitrary payload; we honor
    that at the producing node's own capacity (``may_declassify``). The
    graph has no mid-path declassify operator, so a path is treated as
    carrying its source's secrecy end-to-end — conservative (fail-closed):
    it may FORBID a flow a richer declassify model would permit, never
    the reverse. To release a genuinely-safe secret, the operator
    declassifies at the source (capacity ≤ ENUM) or raises the sink's
    clearance — both explicit, auditable acts.
    """
    return (
        int(label.confidentiality) > int(clearance)
        and not label.may_declassify
    )


def check_noninterference(
    graph: ProvenanceGraph,
    sink_id: str,
    *,
    sink_clearance: ConfidentialityLevel = DEFAULT_EGRESS_CLEARANCE,
    sink_action: str = "",
) -> FlowProof:
    """Decide P(sink, clearance) over ``graph`` and return a ``FlowProof``.

    Walks the data-flow graph **backward** from ``sink_id`` (BFS over
    non-counterfactual in-edges, deterministic via sorted edges) looking
    for a DATA / DATA_FIELD node that ``_leaks`` above the clearance. The
    first such node found yields the witness — the shortest, deterministic
    source→…→sink path. No leaking node reachable ⇒ HOLDS.

    Deterministic, side-effect free, sub-millisecond on small graphs.
    """
    fingerprint = graph.fingerprint()
    property_stmt = (
        f"no_confidentiality>{sink_clearance.label}"
        f"_nondeclassifiable_datum_reaches[{sink_id}]"
    )

    if not graph.has_node(sink_id):
        # An absent sink is a programming error, not an adversary input:
        # the engine only ever passes a call node it just materialized.
        # We cannot honestly emit HOLDS (nothing was checked) nor a FORBID
        # (no witness exists), so we raise rather than fabricate a verdict.
        raise KeyError(f"sink node not found in graph: {sink_id}")

    # BFS backward; record, for each visited node, the edge that leads
    # FORWARD toward the sink, so a witness path can be reconstructed.
    forward_next: dict[str, tuple[str, EdgeKind]] = {}
    visited: set[str] = {sink_id}
    queue: deque[str] = deque([sink_id])
    leaking_source: str | None = None

    while queue:
        current = queue.popleft()
        node = graph.node(current)
        # A leaking node that is a genuine ancestor (not the sink itself).
        if (
            current != sink_id
            and node.kind in (NodeKind.DATA, NodeKind.DATA_FIELD)
            and node.label is not None
            and _leaks(node.label, sink_clearance)
        ):
            leaking_source = current
            break
        for parent_id, edge_kind in graph.data_flow_in_edges(current):
            if parent_id in visited:
                continue
            visited.add(parent_id)
            # Edge parent_id --edge_kind--> current: forward step from
            # parent toward the sink is (current, edge_kind).
            forward_next[parent_id] = (current, edge_kind)
            queue.append(parent_id)

    if leaking_source is None:
        return FlowProof(
            property_statement=property_stmt,
            verdict=NonInterferenceVerdict.HOLDS,
            sink_id=sink_id,
            sink_action=sink_action,
            sink_clearance=sink_clearance,
            graph_fingerprint=fingerprint,
            checked_node_count=graph.node_count,
            checked_edge_count=graph.edge_count,
            proof_kind="exhaustive_replay",
            witness=None,
        )

    # Reconstruct the witness path source→…→sink from forward_next.
    steps: list[FlowStep] = []
    cursor = leaking_source
    guard = graph.node_count + 1  # cycle backstop (graph is a DAG in practice)
    while True:
        node = graph.node(cursor)
        label = node.label
        nxt = forward_next.get(cursor)
        steps.append(
            FlowStep(
                node_id=cursor,
                kind=node.kind,
                integrity=label.integrity if label is not None else None,
                confidentiality=(
                    label.confidentiality if label is not None else None
                ),
                capacity=label.capacity if label is not None else None,
                edge_kind_to_next=nxt[1] if nxt is not None else None,
            )
        )
        if cursor == sink_id or nxt is None:
            break
        cursor = nxt[0]
        guard -= 1
        if guard < 0:  # pragma: no cover - defensive cycle guard
            break

    source_label = graph.node(leaking_source).label
    assert source_label is not None  # leaking nodes always carry a label
    witness = FlowWitness(
        source_id=leaking_source,
        sink_id=sink_id,
        source_confidentiality=source_label.confidentiality,
        steps=tuple(steps),
    )
    return FlowProof(
        property_statement=property_stmt,
        verdict=NonInterferenceVerdict.FORBID,
        sink_id=sink_id,
        sink_action=sink_action,
        sink_clearance=sink_clearance,
        graph_fingerprint=fingerprint,
        checked_node_count=graph.node_count,
        checked_edge_count=graph.edge_count,
        proof_kind="witness_path",
        witness=witness,
    )


# ---------------------------------------------------------------------------
# The offline verifier
# ---------------------------------------------------------------------------


def verify_flow_proof(graph: ProvenanceGraph, proof: FlowProof) -> bool:
    """Re-check ``proof`` against ``graph`` independently. Fail-closed.

    Returns True iff the proof is sound for this graph:

      * the proof binds to THIS graph (``graph.fingerprint`` matches);
      * FORBID: the claimed witness is a real source→…→sink path — every
        edge is confirmed via ``graph.has_edge`` (not trusted from the
        proof), the source genuinely ``_leaks`` above the stated
        clearance, the tail is the sink CALL node, and echoed labels
        match the graph;
      * HOLDS: an independent re-run of ``check_noninterference`` with the
        same clearance also returns HOLDS (decidable property, finite
        fingerprint-bound graph — replay is sound).

    Any inconsistency returns False; the verifier never raises into a
    caller on a malformed proof.
    """
    try:
        if graph.fingerprint() != proof.graph_fingerprint:
            return False

        if proof.verdict is NonInterferenceVerdict.HOLDS:
            if proof.witness is not None:
                return False  # a HOLDS proof must carry no witness
            recheck = check_noninterference(
                graph,
                proof.sink_id,
                sink_clearance=proof.sink_clearance,
                sink_action=proof.sink_action,
            )
            return recheck.verdict is NonInterferenceVerdict.HOLDS

        # FORBID: re-walk and re-check the witness independently.
        witness = proof.witness
        if witness is None:
            return False
        steps = witness.steps
        if len(steps) < 2:
            return False
        if steps[0].node_id != witness.source_id:
            return False
        if steps[-1].node_id != proof.sink_id:
            return False
        if witness.sink_id != proof.sink_id:
            return False

        # Tail must be the sink CALL node.
        if not graph.has_node(proof.sink_id):
            return False
        if graph.node(proof.sink_id).kind is not NodeKind.CALL:
            return False

        # Head must be a real, leaking secret source.
        if not graph.has_node(witness.source_id):
            return False
        source_node = graph.node(witness.source_id)
        if source_node.kind not in (NodeKind.DATA, NodeKind.DATA_FIELD):
            return False
        source_label = source_node.label
        if source_label is None:
            return False
        if not _leaks(source_label, proof.sink_clearance):
            return False
        if source_label.confidentiality != witness.source_confidentiality:
            return False

        # Every consecutive pair must be a real data-flow edge, and every
        # echoed label must match the graph's own.
        for idx, step in enumerate(steps):
            if not graph.has_node(step.node_id):
                return False
            node = graph.node(step.node_id)
            if node.kind is not step.kind:
                return False
            label = node.label
            if label is None:
                if (
                    step.integrity is not None
                    or step.confidentiality is not None
                    or step.capacity is not None
                ):
                    return False
            else:
                if (
                    step.integrity != label.integrity
                    or step.confidentiality != label.confidentiality
                    or step.capacity != label.capacity
                ):
                    return False
            is_last = idx == len(steps) - 1
            if is_last:
                if step.edge_kind_to_next is not None:
                    return False
            else:
                if step.edge_kind_to_next is None:
                    return False
                if step.edge_kind_to_next is EdgeKind.COUNTERFACTUAL:
                    return False  # counterfactual is not a data-flow edge
                nxt_id = steps[idx + 1].node_id
                if not graph.has_edge(
                    source=step.node_id,
                    target=nxt_id,
                    kind=step.edge_kind_to_next,
                ):
                    return False
        return True
    except Exception:  # pragma: no cover - verifier must never raise
        return False


__all__ = [
    "NonInterferenceVerdict",
    "FlowStep",
    "FlowWitness",
    "FlowProof",
    "DEFAULT_EGRESS_CLEARANCE",
    "egress_clearance",
    "check_noninterference",
    "verify_flow_proof",
]
