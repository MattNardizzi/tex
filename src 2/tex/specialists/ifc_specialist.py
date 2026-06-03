"""
Information-Flow Control Specialist.

Wires ``tex.governance.private_data_exec.ifc.IfcEngine`` into Tex's
six-layer PDP as a deterministic specialist judge.

Reference stack
---------------
- ARM (arxiv 2604.04035, Apr 2026)  — provenance graph + counterfactual
                                       edges; primary anchor.
- FIDES (arxiv 2505.23643)          — dual-axis (integrity × type)
                                       label lattice; declassification
                                       rule.
- GAAP (arxiv 2604.19657, Apr 2026) — permission DB + disclosure log,
                                       the parent module this layer
                                       sits on top of.
- NeuroTaint (arxiv 2604.23374)     — cross-session causal taint.
- CA-CI (IEEE S&P 2026)             — six-tuple contextual integrity
                                       (sender, receiver, subject,
                                       information_type, transmission
                                       principle, purpose).
- Rule of Two (Meta Oct 2025) +     — lethal-trifecta corrective check
  EchoLeak counterexample             (private data is also a source).
  (Towards AI Nov 2025)
- Five Eyes guidance (Apr 30 2026) — cryptographic attestation +
                                       runtime enforcement mandate.

Where this fits in the specialist suite
---------------------------------------
Slots after the existing Thread 4 runtime-defense specialists. The
ClawGuard/MCPShield short-circuit-DENY class fires first on indirect
prompt injection patterns; the IfcSpecialist then runs the structural
IFC check on every request — including ones that survive the lexical
defenses — to catch flows that look benign at the surface but violate
the underlying information-flow algebra.

ASI mapping
-----------
- Causality laundering         → ASI09 (Unintended Information Leakage)
- FIDES flow violation         → ASI09
- MinTrust floor breach        → ASI09
- CI norm violation            → ASI09
- NeuroTaint cross-session     → ASI07 (Memory Poisoning) + ASI09
- Rule of Two trifecta         → ASI09 + ASI01 (Agent Goal Hijack)

Priority: P0 — ships in the live request path for /v1/guardrail.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.governance.private_data_exec.ifc import (
    CiNormRegistry,
    IfcEngine,
    IfcVerdict,
    IfcViolation,
    MemoryStream,
)
from tex.observability import telemetry
from tex.specialists.base import SpecialistEvidence, SpecialistResult


class _IfcLabelsCache:
    """
    Bounded request-keyed cache so the PDP's
    ``_build_decision_metadata`` can attach the per-request IFC
    labels onto the durable Decision under
    ``metadata['ifc_labels']`` per Thread 11 AC2.

    Pattern matches how Tex's other specialists surface structured
    audit data: produce-side writes here, consume-side reads in
    ``tex.engine.pdp``. Bounded LRU + thread-safe.
    """

    DEFAULT_CAPACITY = 1024

    def __init__(self, *, capacity: int = DEFAULT_CAPACITY) -> None:
        self._capacity = capacity
        self._store: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, *, request_id: str, labels: dict[str, str]) -> None:
        with self._lock:
            if request_id in self._store:
                self._store.pop(request_id)
            self._store[request_id] = dict(labels)
            while len(self._store) > self._capacity:
                self._store.popitem(last=False)

    def pop(self, *, request_id: str) -> dict[str, str] | None:
        """Consume-once: caller takes the labels and the cache forgets."""
        with self._lock:
            return self._store.pop(request_id, None)

    def peek(self, *, request_id: str) -> dict[str, str] | None:
        with self._lock:
            entry = self._store.get(request_id)
            return dict(entry) if entry is not None else None

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


_IFC_LABELS_CACHE = _IfcLabelsCache()


def get_ifc_labels_cache() -> _IfcLabelsCache:
    """Return the process-wide IFC labels cache.

    Public accessor so the PDP and audit replay can read the labels
    that the IfcSpecialist produced for a given request_id.
    """
    return _IFC_LABELS_CACHE


# OWASP Agentic Security Initiative 2026 (ASI) short codes Tex uses.
_ASI_GOAL_HIJACK = "ASI01_goal_hijack"
_ASI_MEMORY_POISONING = "ASI07_memory_poisoning"
_ASI_INFO_LEAKAGE = "ASI09_unintended_information_leakage"


_VIOLATION_TO_ASI: dict[IfcViolation, tuple[str, ...]] = {
    IfcViolation.FLOW_INTEGRITY: (_ASI_INFO_LEAKAGE,),
    IfcViolation.CAUSALITY_LAUNDERING: (_ASI_INFO_LEAKAGE,),
    IfcViolation.MIN_TRUST_FLOOR: (_ASI_INFO_LEAKAGE,),
    IfcViolation.CI_NORM_VIOLATION: (_ASI_INFO_LEAKAGE,),
    IfcViolation.NEUROTAINT_CROSS_SESSION: (
        _ASI_MEMORY_POISONING,
        _ASI_INFO_LEAKAGE,
    ),
    IfcViolation.RULE_OF_TWO_TRIFECTA: (
        _ASI_GOAL_HIJACK,
        _ASI_INFO_LEAKAGE,
    ),
}


_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.60
_CONF_CAP = 0.98
_CONF_PER_VIOLATION = 0.10


class IfcSpecialist:
    """
    Deterministic IFC specialist.

    Owns one ``IfcEngine`` and one optional ``MemoryStream`` for
    cross-session taint persistence. Per request, builds the
    provenance graph, runs the ARM/FIDES/NeuroTaint/CA-CI checks, and
    surfaces structured evidence into Tex's specialist bundle.
    """

    name = "ifc"

    def __init__(
        self,
        *,
        engine: IfcEngine | None = None,
        ci_registry: CiNormRegistry | None = None,
        memory_stream: MemoryStream | None = None,
    ) -> None:
        if engine is not None and (
            ci_registry is not None or memory_stream is not None
        ):
            raise ValueError(
                "pass either engine OR ci_registry/memory_stream, not both"
            )
        if engine is None:
            engine = IfcEngine(
                ci_registry=ci_registry,
                memory_stream=memory_stream,
            )
        self._engine = engine

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        verdict = self._engine.evaluate(
            request=request, retrieval_context=retrieval_context
        )
        # Stash the structured labels under a request-id-keyed cache so
        # the PDP's _build_decision_metadata can pick them up and emit
        # the `ifc_labels` field on the durable Decision record per
        # Thread 11 AC2.
        _IFC_LABELS_CACHE.put(
            request_id=str(request.request_id),
            labels=self._serialize_labels(verdict=verdict),
        )
        return self._compose_result(verdict=verdict, request=request)

    @staticmethod
    def _serialize_labels(*, verdict: IfcVerdict) -> dict[str, str]:
        """
        Produce the audit-grade ``ifc_labels: dict[str, str]`` payload.

        Keys are stable; values are human-readable enum labels. This is
        what gets persisted to the durable Decision metadata so audit
        and replay can answer "what label did Tex apply to this flow?"
        """
        label = verdict.effective_label
        out: dict[str, str] = {
            "integrity": label.integrity.label,
            "confidentiality": label.confidentiality.label,
            "capacity": label.capacity.name,
            "proposed_sink": "true" if verdict.proposed_sink else "false",
            "graph_fingerprint": verdict.fingerprint,
            "ci_sender": verdict.ci_norm.sender,
            "ci_receiver": verdict.ci_norm.receiver,
            "ci_subject": verdict.ci_norm.subject,
            "ci_information_type": verdict.ci_norm.information_type,
            "ci_transmission_principle": (
                verdict.ci_norm.transmission_principle.value
            ),
            "ci_purpose": verdict.ci_norm.purpose,
        }
        if verdict.violations:
            out["violations"] = ",".join(v.value for v in verdict.violations)
        else:
            out["violations"] = ""
        return out

    # ── result composition ──────────────────────────────────────────

    def _compose_result(
        self,
        *,
        verdict: IfcVerdict,
        request: EvaluationRequest,
    ) -> SpecialistResult:
        if not verdict.has_violations:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                violations=tuple(),
                fingerprint=verdict.fingerprint,
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary=(
                    "No IFC flow violation detected on the proposed action."
                ),
                rationale=(
                    "Per ARM (arxiv 2604.04035) + FIDES (arxiv 2505.23643) "
                    "+ NeuroTaint (arxiv 2604.23374) + CA-CI (IEEE S&P 2026): "
                    "the provenance graph for this request shows no untrusted-"
                    "to-sensitive flow, no counterfactual chain from any "
                    "denied action, no cross-session taint carry, and no "
                    "permitted-norm mismatch. Implements the GAAP-paper "
                    "evidence layer (arxiv 2604.19657) beyond GAAP's own "
                    "single-axis taint."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_deterministic",),
            )

        # Compose evidence per violation.
        evidence: list[SpecialistEvidence] = []
        codes: list[str] = []
        asi_tags: list[str] = []

        for item in verdict.evidence:
            text = item.violation.value
            # Build a stable, compact, human-readable evidence line.
            evidence.append(
                SpecialistEvidence(
                    text=text,
                    explanation=item.reason,
                )
            )
            codes.append(item.violation.value)
            for tag in _VIOLATION_TO_ASI.get(item.violation, ()):
                if tag not in asi_tags:
                    asi_tags.append(tag)

        risk_score = verdict.risk_score
        confidence = min(
            _CONF_CAP,
            _CONF_FLOOR + _CONF_PER_VIOLATION * len(verdict.violations),
        )

        # Stable order for matched_policy_clause_ids: violation codes
        # first, then ASI tags. dedupe preserves order.
        deduped_codes = _dedupe(codes)
        deduped_asi = _dedupe(asi_tags)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            violations=tuple(v.value for v in verdict.violations),
            fingerprint=verdict.fingerprint,
        )

        summary = (
            f"IFC violations detected: {len(deduped_codes)} signal(s) "
            f"— {', '.join(deduped_codes)}."
        )

        rationale_lines = [
            "Per ARM (arxiv 2604.04035) provenance + FIDES (arxiv "
            "2505.23643) dual-lattice IFC + NeuroTaint (arxiv "
            "2604.23374) cross-session + CA-CI (IEEE S&P 2026) norm "
            "matching, the provenance graph for this request exposes "
            f"{len(verdict.violations)} distinct violation(s):",
        ]
        for item in verdict.evidence:
            rationale_lines.append(f"- {item.violation.value}: {item.reason}")
        rationale_lines.append(
            f"Effective label: integrity={verdict.effective_label.integrity.label}, "
            f"confidentiality={verdict.effective_label.confidentiality.label}, "
            f"capacity={verdict.effective_label.capacity.name}. "
            f"Graph fingerprint: {verdict.fingerprint[:16]}."
        )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale="\n".join(rationale_lines)[:1_990],
            evidence=tuple(evidence),
            matched_policy_clause_ids=tuple([*deduped_codes, *deduped_asi]),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_deterministic",),
        )


# ── helpers ────────────────────────────────────────────────────────


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _emit(
    *,
    request_id: str,
    risk_score: float,
    violations: tuple[str, ...],
    fingerprint: str,
) -> None:
    payload: dict[str, Any] = {
        "specialist_name": "ifc",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "violations": list(violations),
        "graph_fingerprint": fingerprint[:32],
    }
    telemetry.emit_event("specialist.ifc.evaluated", **payload)


__all__ = ["IfcSpecialist", "get_ifc_labels_cache"]
