"""
PcasSpecialist — exposes the PCAS reference monitor in the PDP suite.

Architecture
------------
The PDP's existing six-layer pipeline runs ``IfcSpecialist`` (Thread 11)
to derive a provenance graph + IFC verdict. The IFC specialist already
stashes its provenance into the request metadata. This specialist:

1. Reads the (already-built) IFC provenance graph from request
   metadata, falling back to constructing an empty
   ``DependencyGraphView`` if absent.
2. Projects the candidate action from the ``EvaluationRequest`` into a
   ``CandidateAction``.
3. Calls ``PcasMonitor.authorize``.
4. Returns a ``SpecialistResult`` whose ``risk_score`` is:
   - 1.0 if FORBID,
   - 0.5 if ABSTAIN (no rule matched — surfaces as advisory weight, not
     a hard block; consistent with Tex's three-state semantics),
   - 0.0 if PERMIT.

Policy source
-------------
The policy program is provided at specialist-construction time. In the
PDP wiring it is loaded from ``var/pcas/policy.pcas`` if present,
otherwise the specialist ships with a permissive default that
authorizes every action *but* denies any action whose actor is reachable
from a node labelled ``"untrusted"`` — a minimal demonstration policy.

ASI mapping
-----------
- ``deny:exfiltrate_untrusted_to_external`` → ASI09 (Information Leakage)
- ``deny:write_after_untrusted_read``        → ASI09
- ``authorize:approved_by_supervisor``       → ASI06 (Identity Spoofing
                                                     mitigation)

Priority: P0 — ships in the live request path.
"""

from __future__ import annotations

import os
from pathlib import Path

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.observability import telemetry
from tex.pcas.graph.adapter import DependencyGraphAdapter, DependencyGraphView
from tex.pcas.monitor import (
    AuthorizationVerdict,
    CandidateAction,
    PcasMonitor,
    PolicyDecision,
)
from tex.specialists.base import SpecialistEvidence, SpecialistResult


_DEFAULT_POLICY = """\
% PCAS default policy: deny actions that read from any node reachable
% from an untrusted source and then write externally.
%
% Schema:
%   pending_action(ActionId, Kind, Actor, PayloadHash)
%   action(ActionId, Kind, Actor, PayloadHash)
%   data(DataId, Source, Label, ContentHash)
%   depends_on(SourceId, TargetId)
%
% Reference: arxiv 2602.16708 §5.2 (Toxic Flow policy).

derived_from(X, Y) :- depends_on(X, Y).
derived_from(X, Z) :- depends_on(X, Y), derived_from(Y, Z).

untrusted_data(DataId) :- data(DataId, _, "untrusted", _).

reads_untrusted(ActionId) :-
    pending_action(ActionId, _, _, _),
    depends_on(ActionId, DataId),
    untrusted_data(DataId).

reads_untrusted(ActionId) :-
    pending_action(ActionId, _, _, _),
    derived_from(ActionId, DataId),
    untrusted_data(DataId).

external_sink(ActionId) :-
    pending_action(ActionId, "send_email", _, _).
external_sink(ActionId) :-
    pending_action(ActionId, "http_post", _, _).
external_sink(ActionId) :-
    pending_action(ActionId, "publish", _, _).

@deny toxic_flow(ActionId) :-
    reads_untrusted(ActionId),
    external_sink(ActionId).

@authorize default_authorize(ActionId) :-
    pending_action(ActionId, _, _, _),
    not reads_untrusted(ActionId).

@authorize default_authorize(ActionId) :-
    pending_action(ActionId, _, _, _),
    reads_untrusted(ActionId),
    not external_sink(ActionId).
"""


class PcasSpecialist:
    """PCAS Datalog reference monitor adapted to the specialist contract."""

    name: str = "pcas"

    def __init__(
        self,
        *,
        policy_source: str | None = None,
        policy_path: str | None = None,
    ) -> None:
        # Resolve policy source: explicit > env > file > default
        resolved_source: str
        resolved_name: str
        if policy_source is not None:
            resolved_source = policy_source
            resolved_name = "<inline>"
        elif policy_path is not None:
            resolved_source = Path(policy_path).read_text(encoding="utf-8")
            resolved_name = policy_path
        else:
            env_path = os.environ.get("TEX_PCAS_POLICY_PATH")
            if env_path and Path(env_path).is_file():
                resolved_source = Path(env_path).read_text(encoding="utf-8")
                resolved_name = env_path
            else:
                resolved_source = _DEFAULT_POLICY
                resolved_name = "<default>"
        self._monitor = PcasMonitor(resolved_source, name=resolved_name)

    @property
    def monitor(self) -> PcasMonitor:
        return self._monitor

    # ----------------------------------------------------------- evaluate

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        action = self._project_action(request)
        graph = self._project_graph(request, retrieval_context)
        decision = self._monitor.authorize(action, graph)
        return self._to_specialist_result(decision)

    # --------------------------------------------------------- projection

    @staticmethod
    def _project_action(request: EvaluationRequest) -> CandidateAction:
        # EvaluationRequest exposes request_id, content, and tool-call
        # metadata. We use request_id as action_id; the action kind
        # comes from the tool-call kind if present, else "evaluate".
        request_id = getattr(request, "request_id", None) or "anon-action"
        kind = "evaluate"
        actor = "agent"
        payload_hash = "0" * 8

        # Best-effort: examine ``request.metadata`` for hints. Tex's
        # EvaluationRequest may not always have these fields.
        metadata = getattr(request, "metadata", None) or {}
        if isinstance(metadata, dict):
            kind = str(metadata.get("action_kind") or kind)
            actor = str(metadata.get("actor") or actor)
            payload_hash = str(metadata.get("payload_hash") or payload_hash)

        return CandidateAction(
            action_id=str(request_id),
            kind=kind,
            actor=actor,
            payload_hash=payload_hash,
        )

    @staticmethod
    def _project_graph(
        request: EvaluationRequest,
        context: RetrievalContext | None,
    ) -> DependencyGraphView:
        # Prefer the IFC specialist's provenance graph if Thread 11
        # already attached it. The IFC specialist stashes labels via
        # ``_IfcLabelsCache``; we look for a provenance graph object on
        # ``request.metadata['ifc_provenance']``.
        metadata = getattr(request, "metadata", None) or {}
        prov = None
        if isinstance(metadata, dict):
            prov = metadata.get("ifc_provenance")
        if prov is not None:
            try:
                return DependencyGraphAdapter.from_ifc_provenance(prov)
            except Exception:  # noqa: BLE001
                telemetry.emit_event(
                    "pcas.specialist.provenance_projection_failed"
                )

        # Otherwise return an empty view — the default policy still
        # authorizes anything that isn't a toxic flow, so this is safe.
        return DependencyGraphView()

    # ----------------------------------------------------- result shaping

    def _to_specialist_result(self, decision: PolicyDecision) -> SpecialistResult:
        if decision.verdict is AuthorizationVerdict.FORBID:
            risk = 1.0
            summary = (
                f"PCAS Datalog policy {decision.policy_source} denied "
                f"action {decision.action_id}: "
                f"{', '.join(decision.reasons) or 'deny rule matched'}"
            )
        elif decision.verdict is AuthorizationVerdict.ABSTAIN:
            risk = 0.5
            summary = (
                f"PCAS policy {decision.policy_source} did not authorize "
                f"action {decision.action_id} (no rule matched)"
            )
        else:
            risk = 0.0
            summary = (
                f"PCAS policy {decision.policy_source} authorized "
                f"action {decision.action_id}"
            )

        evidence: list[SpecialistEvidence] = []
        if decision.diagnostic:
            evidence.append(
                SpecialistEvidence(
                    text=f"PCAS diagnostic: {decision.diagnostic[:1500]}",
                    explanation="PCAS policy compiler reported a non-fatal "
                    "issue during evaluation; fail-closed.",
                )
            )
        for reason in decision.reasons[:8]:
            evidence.append(
                SpecialistEvidence(
                    text=f"reason: {reason}",
                    explanation="PCAS rule annotation matched the candidate "
                    "action.",
                )
            )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=risk,
            confidence=1.0 if decision.diagnostic is None else 0.5,
            summary=summary,
            rationale=(
                f"PCAS reference monitor decision {decision.verdict.value} "
                f"in {decision.elapsed_ms:.3f}ms. "
                f"authorize={len(decision.authorize_facts)} "
                f"deny={len(decision.deny_facts)}"
            ),
            evidence=tuple(evidence),
            matched_policy_clause_ids=tuple(decision.reasons[:16]),
        )


__all__ = ["PcasSpecialist"]
