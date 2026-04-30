from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tex.domain.agent import ActionLedgerEntry
from tex.domain.decision import Decision
from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.evidence import EvidenceRecord
from tex.domain.policy import PolicySnapshot
from tex.domain.tenant_baseline import (
    ContentSignatureRecord,
    compute_content_signature,
    extract_recipient_domain,
)
from tex.domain.verdict import Verdict
from tex.engine.pdp import PDPResult, PolicyDecisionPoint
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.policy_store import InMemoryPolicyStore
from tex.stores.precedent_store import InMemoryPrecedentStore
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


@runtime_checkable
class DecisionEvidenceRecorder(Protocol):
    """
    Narrow protocol for recorders capable of appending decision evidence.
    """

    def record_decision(
        self,
        decision: Decision,
        *,
        metadata: dict[str, object] | None = None,
    ) -> EvidenceRecord:
        """
        Persist an evidence envelope for a decision.
        """
        ...


@runtime_checkable
class DecisionPrecedentStore(Protocol):
    """
    Narrow protocol for stores that can retain decisions as precedents.
    """

    def save(self, decision: Decision) -> None:
        """
        Persist a decision so it can be retrieved later as precedent context.
        """
        ...


@dataclass(frozen=True, slots=True)
class EvaluateActionResult:
    """
    Application-layer result for a single Tex evaluation command.

    This wraps the public response with the internal decision, resolved policy,
    raw PDP result, and any evidence record created during execution.
    """

    response: EvaluationResponse
    decision: Decision
    policy: PolicySnapshot
    pdp_result: PDPResult
    evidence_record: EvidenceRecord | None = None


class EvaluateActionCommand:
    """
    Application service for evaluating one action through Tex.

    Responsibilities:
    - resolve the policy snapshot to use
    - run the PDP
    - validate request / policy / output alignment
    - persist the resulting decision
    - persist the decision as precedent context when configured
    - optionally append evidence

    Responsibilities intentionally excluded:
    - HTTP transport
    - policy activation workflows
    - outcome reporting
    - calibration
    """

    __slots__ = (
        "_pdp",
        "_policy_store",
        "_decision_store",
        "_precedent_store",
        "_evidence_recorder",
        "_action_ledger",
        "_agent_registry",
        "_tenant_baseline",
    )

    def __init__(
        self,
        *,
        pdp: PolicyDecisionPoint,
        policy_store: InMemoryPolicyStore,
        decision_store: InMemoryDecisionStore,
        precedent_store: DecisionPrecedentStore | None = None,
        evidence_recorder: DecisionEvidenceRecorder | None = None,
        action_ledger: InMemoryActionLedger | None = None,
        agent_registry: InMemoryAgentRegistry | None = None,
        tenant_baseline: InMemoryTenantContentBaseline | None = None,
    ) -> None:
        self._pdp = pdp
        self._policy_store = policy_store
        self._decision_store = decision_store
        self._precedent_store = precedent_store
        self._evidence_recorder = evidence_recorder
        self._action_ledger = action_ledger
        self._agent_registry = agent_registry
        self._tenant_baseline = tenant_baseline

    def execute(self, request: EvaluationRequest) -> EvaluateActionResult:
        """
        Evaluate a request, persist the decision, update precedent memory,
        write to the agent action ledger when applicable, and optionally
        record evidence.
        """
        policy = self._resolve_policy(request)
        pdp_result = self._pdp.evaluate(
            request=request,
            policy=policy,
        )

        self._validate_pdp_alignment(
            request=request,
            policy=policy,
            pdp_result=pdp_result,
        )

        decision = pdp_result.decision
        self._decision_store.save(decision)
        self._save_precedent(decision)
        self._record_action_ledger_entry(
            request=request,
            decision=decision,
            pdp_result=pdp_result,
        )
        self._update_tenant_baseline(
            request=request,
            decision=decision,
        )

        evidence_record = None
        response = pdp_result.response

        if self._evidence_recorder is not None:
            evidence_record = self._record_decision_evidence(
                decision=decision,
                request=request,
            )
            # Back-propagate the recorded hash onto the response so API
            # callers see a real evidence_hash instead of "". The domain
            # Decision and EvaluationResponse are both frozen, so we build
            # a new response with the hash attached. This is the only
            # mutation we allow at the application layer.
            response = response.model_copy(
                update={"evidence_hash": evidence_record.record_hash}
            )

        return EvaluateActionResult(
            response=response,
            decision=decision,
            policy=policy,
            pdp_result=pdp_result,
            evidence_record=evidence_record,
        )

    def _resolve_policy(self, request: EvaluationRequest) -> PolicySnapshot:
        """
        Resolve the policy snapshot for the request.

        Rules:
        - if request.policy_id is set, treat it as the requested policy version
        - otherwise, use the currently active policy
        """
        if request.policy_id is not None:
            requested_version = request.policy_id.strip()
            if not requested_version:
                raise ValueError("request.policy_id must not be blank when provided")

            try:
                return self._policy_store.require(requested_version)
            except KeyError as exc:
                raise LookupError(
                    f"requested policy version not found: {requested_version}"
                ) from exc

        try:
            return self._policy_store.require_active()
        except LookupError as exc:
            raise LookupError("no active policy is available for evaluation") from exc

    @staticmethod
    def _validate_pdp_alignment(
        *,
        request: EvaluationRequest,
        policy: PolicySnapshot,
        pdp_result: PDPResult,
    ) -> None:
        """
        Enforce basic integrity between the request, selected policy, and PDP output.
        """
        decision = pdp_result.decision
        response = pdp_result.response

        if decision.request_id != request.request_id:
            raise ValueError("pdp decision.request_id does not match evaluation request")

        if decision.policy_version != policy.version:
            raise ValueError("pdp decision.policy_version does not match selected policy")

        if response.decision_id != decision.decision_id:
            raise ValueError(
                "pdp response.decision_id does not match decision.decision_id"
            )

        if response.policy_version != decision.policy_version:
            raise ValueError(
                "pdp response.policy_version does not match decision.policy_version"
            )

        if response.verdict != decision.verdict:
            raise ValueError("pdp response.verdict does not match decision.verdict")

        if response.confidence != decision.confidence:
            raise ValueError("pdp response.confidence does not match decision.confidence")

        if response.final_score != decision.final_score:
            raise ValueError("pdp response.final_score does not match decision.final_score")

    def _save_precedent(self, decision: Decision) -> None:
        """
        Persist the evaluated decision into precedent memory when configured.

        This is the critical bridge that lets retrieval improve from live traffic
        instead of staying permanently empty.
        """
        store = self._precedent_store
        if store is None:
            return

        if not isinstance(store, DecisionPrecedentStore):
            raise TypeError("precedent_store must implement save(decision)")

        store.save(decision)

    def _record_decision_evidence(
        self,
        *,
        decision: Decision,
        request: EvaluationRequest,
    ) -> EvidenceRecord:
        """
        Record decision evidence using a narrow recorder protocol.
        """
        recorder = self._evidence_recorder
        if recorder is None:
            raise RuntimeError("evidence recorder is not configured")

        if not isinstance(recorder, DecisionEvidenceRecorder):
            raise TypeError(
                "evidence_recorder must implement record_decision("
                "decision, *, metadata=None)"
            )

        metadata: dict[str, object] = {
            "request_id": str(request.request_id),
            "request_channel": request.channel,
            "request_environment": request.environment,
            "request_action_type": request.action_type,
        }

        if request.recipient is not None:
            metadata["request_recipient"] = request.recipient
        if request.policy_id is not None:
            metadata["requested_policy_id"] = request.policy_id
        if request.metadata:
            metadata["request_metadata"] = dict(request.metadata)

        return recorder.record_decision(
            decision,
            metadata=metadata,
        )

    def _record_action_ledger_entry(
        self,
        *,
        request: EvaluationRequest,
        decision: Decision,
        pdp_result: PDPResult,
    ) -> None:
        """
        Append an action ledger entry when the request was tied to an agent.

        This is the feedback loop that lets the behavioral evaluation
        stream improve over time: every Tex decision is durable evidence
        of how the agent has been behaving.
        """
        ledger = self._action_ledger
        if ledger is None:
            return
        if request.agent_id is None:
            return

        bundle = pdp_result.agent_bundle
        capability_violations = (
            bundle.capability.violated_dimensions if bundle.agent_present else tuple()
        )
        asi_short_codes = tuple(
            finding.short_code for finding in pdp_result.routing_result.asi_findings
        )

        entry = ActionLedgerEntry(
            agent_id=request.agent_id,
            session_id=request.session_id,
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            verdict=decision.verdict.value,
            action_type=decision.action_type,
            channel=decision.channel,
            environment=decision.environment,
            recipient=decision.recipient,
            final_score=decision.final_score,
            confidence=decision.confidence,
            content_sha256=decision.content_sha256,
            capability_violations=capability_violations,
            asi_short_codes=asi_short_codes,
        )
        ledger.append(entry)

    def _update_tenant_baseline(
        self,
        *,
        request: EvaluationRequest,
        decision: Decision,
    ) -> None:
        """
        Append a tenant content signature record on PERMITted, agent-
        attached decisions.

        Three guards:
        - the tenant baseline must be wired (V11 is opt-in)
        - the request must carry an agent_id (we need the agent's
          tenant scope; agentless requests do not contribute)
        - the verdict must be PERMIT (the baseline represents *normal
          authorized output*; recording ABSTAIN/FORBID would poison
          the very signal we use to detect anomalies)

        We also need to look up the agent's tenant_id from the registry.
        We do that here rather than on the request because tenant scope
        is owned by the agent identity, not the caller — no caller can
        spoof their way into a different tenant baseline.
        """
        baseline = self._tenant_baseline
        if baseline is None:
            return
        if request.agent_id is None:
            return
        if decision.verdict is not Verdict.PERMIT:
            return

        registry = self._agent_registry
        if registry is None:
            # Without a registry we cannot resolve the tenant_id safely.
            # Defensive: this should not happen in production wiring.
            return

        agent = registry.get(request.agent_id)
        if agent is None:
            return

        signature = compute_content_signature(request.content)
        record = ContentSignatureRecord(
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            action_type=decision.action_type,
            channel=decision.channel,
            recipient_domain=extract_recipient_domain(decision.recipient),
            content_sha256=decision.content_sha256,
            signature=signature,
        )
        baseline.append(record)
