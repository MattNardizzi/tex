from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid5

from tex.domain.agent import ActionLedgerEntry, AgentEnvironment, AgentIdentity, AgentLifecycleStatus, AgentTrustTier, CapabilitySurface
from tex.domain.decision import Decision
from tex.domain.evaluation import AgentRuntimeIdentity, EvaluationRequest, EvaluationResponse
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

AGENT_IDENTITY_NAMESPACE = UUID("9d9d47ff-e665-4abc-9316-390ec97f02fb")


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
        "_memory_system",
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
        memory_system: Any | None = None,
    ) -> None:
        """
        Constructor.

        ``memory_system`` (optional): when provided, decision + input +
        policy_snapshot + evidence are all persisted through the unified
        ``MemorySystem`` orchestrator in a single atomic transaction.
        This is the canonical wiring for the production runtime.

        When ``memory_system`` is ``None`` (the legacy path used by many
        unit tests), the command falls back to writing decisions through
        ``decision_store.save()`` and evidence through
        ``evidence_recorder.record_decision()`` exactly as before — so
        every existing test keeps working unchanged.

        Either way, the spec invariants are preserved: the decision,
        the policy that produced it, and the evidence record always
        share matching ids and policy_version. The memory_system path
        adds durable input persistence + atomicity on top.
        """
        self._pdp = pdp
        self._policy_store = policy_store
        self._decision_store = decision_store
        self._precedent_store = precedent_store
        self._evidence_recorder = evidence_recorder
        self._action_ledger = action_ledger
        self._agent_registry = agent_registry
        self._tenant_baseline = tenant_baseline
        self._memory_system = memory_system

    def execute(self, request: EvaluationRequest) -> EvaluateActionResult:
        """
        Evaluate a request, persist the decision, update precedent memory,
        write to the agent action ledger when applicable, and optionally
        record evidence.
        """
        # Resolve the policy first so we can stamp every registry write
        # that follows with policy_version provenance. This is what
        # turns the durable registry from "storage" into a forensic
        # source of truth — every revision row carries the policy
        # version that was active when the write happened.
        policy = self._resolve_policy(request)
        registry = self._agent_registry
        if registry is not None and hasattr(registry, "set_audit_context"):
            try:
                registry.set_audit_context(
                    policy_version=policy.version,
                    write_source="evaluate_action",
                )
            except Exception:  # noqa: BLE001
                # Audit context is best-effort. A registry that
                # doesn't support it (in-memory, tests, future
                # backends) still saves correctly without it.
                pass

        try:
            request = self._ensure_controlled_agent_registered(request)
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

            # ── Durable persistence ─────────────────────────────────────
            # When a MemorySystem is wired, we go through the unified,
            # transactional path: decision + input + policy_snapshot are
            # all written in ONE Postgres transaction, then the JSONL
            # evidence chain is appended, then the Postgres mirror.
            # This is the spec-compliant write path.
            #
            # When MemorySystem is not wired (legacy test paths), we fall
            # back to the historical sequence: decision_store.save() +
            # evidence_recorder.record_decision(). All existing tests
            # still drive this branch and continue to pass.
            evidence_record = None
            response = pdp_result.response

            if self._memory_system is not None:
                full_input = self._build_full_input_payload(request)
                evidence_metadata = self._build_evidence_metadata(
                    request=request, decision=decision
                )
                evidence_record = self._memory_system.record_decision_with_policy(
                    decision=decision,
                    full_input=full_input,
                    policy=policy,
                    evidence_metadata=evidence_metadata,
                )
                # Precedent feeds retrieval; it's a derived index, not
                # part of the durable spec, so we still save it.
                self._save_precedent(decision)
                response = response.model_copy(
                    update={"evidence_hash": evidence_record.record_hash}
                )
            else:
                self._decision_store.save(decision)
                self._save_precedent(decision)

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

            self._record_action_ledger_entry(
                request=request,
                decision=decision,
                pdp_result=pdp_result,
                evidence_hash=(
                    evidence_record.record_hash if evidence_record is not None else None
                ),
            )
            self._update_tenant_baseline(
                request=request,
                decision=decision,
            )

            return EvaluateActionResult(
                response=response,
                decision=decision,
                policy=policy,
                pdp_result=pdp_result,
                evidence_record=evidence_record,
            )
        finally:
            # Always clear the audit context so a subsequent unrelated
            # save (e.g. an admin endpoint, a discovery scan running
            # concurrently on the same registry) doesn't accidentally
            # inherit this evaluation's policy_version.
            if registry is not None and hasattr(registry, "clear_audit_context"):
                try:
                    registry.clear_audit_context()
                except Exception:  # noqa: BLE001
                    pass

    def _ensure_controlled_agent_registered(
        self,
        request: EvaluationRequest,
    ) -> EvaluationRequest:
        """
        Treat every adjudication with agent context as a controlled discovery signal.

        If the caller supplies only an agent_identity block, derive a stable UUID
        from its fingerprint. If the registry does not know the agent yet,
        register it before PDP evaluation so identity/capability/behavior streams
        run on the first controlled action. If the agent already exists, upgrade
        metadata to mark it CONTROLLED and refresh its runtime fingerprint only
        when the fingerprint actually changed.
        """
        registry = self._agent_registry
        identity = request.agent_identity

        if registry is None:
            return request
        if identity is None and request.agent_id is None:
            return request

        resolved_agent_id = request.agent_id
        if resolved_agent_id is None and identity is not None:
            resolved_agent_id = identity.agent_id or uuid5(
                AGENT_IDENTITY_NAMESPACE,
                identity.stable_key,
            )

        if resolved_agent_id is None:
            return request

        request = request.model_copy(update={"agent_id": resolved_agent_id})

        existing = registry.get(resolved_agent_id)
        if existing is None:
            registry.save(self._build_controlled_agent_identity(
                agent_id=resolved_agent_id,
                identity=identity,
                request=request,
            ))
            return request

        if identity is None:
            if existing.metadata.get("visibility_status") != "controlled":
                metadata = dict(existing.metadata)
                metadata["visibility_status"] = "controlled"
                metadata["controlled_first_seen_at"] = datetime.now(UTC).isoformat()
                registry.save(existing.model_copy(update={"metadata": metadata}))
            return request

        fingerprint_hash = identity.fingerprint_hash
        current_fingerprint = existing.metadata.get("agent_fingerprint_hash")
        if (
            existing.metadata.get("visibility_status") == "controlled"
            and current_fingerprint == fingerprint_hash
        ):
            return request

        metadata = dict(existing.metadata)
        metadata.update(self._runtime_identity_metadata(identity))
        metadata.setdefault("controlled_first_seen_at", datetime.now(UTC).isoformat())
        metadata["controlled_last_seen_at"] = datetime.now(UTC).isoformat()

        updates: dict[str, Any] = {
            "metadata": metadata,
            "model_provider": identity.model_provider or existing.model_provider,
            "model_name": identity.model_name or existing.model_name,
            "framework": identity.framework or existing.framework,
        }
        if identity.environment is not None:
            updates["environment"] = self._coerce_environment(
                identity.environment,
                existing.environment,
            )
        if identity.tools or identity.mcp_server_ids or identity.data_scopes:
            updates["capability_surface"] = self._merge_capability_surface(
                existing.capability_surface,
                identity,
            )

        registry.save(existing.model_copy(update=updates))
        return request

    def _build_controlled_agent_identity(
        self,
        *,
        agent_id: UUID,
        identity: AgentRuntimeIdentity | None,
        request: EvaluationRequest,
    ) -> AgentIdentity:
        now = datetime.now(UTC)
        metadata: dict[str, Any] = {
            "visibility_status": "controlled",
            "discovery_mode": "adjudication_derived",
            "controlled_first_seen_at": now.isoformat(),
            "controlled_last_seen_at": now.isoformat(),
            "first_controlled_request_id": str(request.request_id),
        }

        if identity is not None:
            metadata.update(self._runtime_identity_metadata(identity))

        return AgentIdentity(
            agent_id=agent_id,
            name=(
                identity.agent_name
                if identity is not None and identity.agent_name is not None
                else f"controlled-agent-{str(agent_id)[:8]}"
            ),
            owner=(
                identity.owner
                if identity is not None and identity.owner is not None
                else "unknown"
            ),
            description="Auto-registered by Tex from an adjudication request.",
            tenant_id=identity.tenant_id if identity is not None else "default",
            model_provider=identity.model_provider if identity is not None else None,
            model_name=identity.model_name if identity is not None else None,
            framework=identity.framework if identity is not None else None,
            environment=self._coerce_environment(
                identity.environment if identity is not None else request.environment,
                AgentEnvironment.PRODUCTION,
            ),
            trust_tier=AgentTrustTier.UNVERIFIED,
            lifecycle_status=AgentLifecycleStatus.ACTIVE,
            capability_surface=(
                self._capability_surface_from_runtime_identity(identity)
                if identity is not None
                else CapabilitySurface()
            ),
            tags=("controlled", "adjudication-derived"),
            metadata=metadata,
            registered_at=now,
            updated_at=now,
        )

    @staticmethod
    def _runtime_identity_metadata(identity: AgentRuntimeIdentity) -> dict[str, Any]:
        return {
            "visibility_status": "controlled",
            "agent_fingerprint_hash": identity.fingerprint_hash,
            "external_agent_id": identity.external_agent_id,
            "agent_type": identity.agent_type,
            "system_prompt_hash": identity.system_prompt_hash,
            "tool_manifest_hash": identity.tool_manifest_hash,
            "memory_hash": identity.memory_hash,
            "tools": list(identity.tools),
            "mcp_server_ids": list(identity.mcp_server_ids),
            "data_scopes": list(identity.data_scopes),
            "runtime_identity_metadata": dict(identity.metadata),
        }

    @staticmethod
    def _coerce_environment(
        value: str | None,
        fallback: AgentEnvironment,
    ) -> AgentEnvironment:
        if value is None:
            return fallback
        normalized = value.strip().upper()
        aliases = {"DEV": "SANDBOX", "DEVELOPMENT": "SANDBOX", "PROD": "PRODUCTION"}
        normalized = aliases.get(normalized, normalized)
        try:
            return AgentEnvironment(normalized)
        except ValueError:
            return fallback

    @staticmethod
    def _capability_surface_from_runtime_identity(
        identity: AgentRuntimeIdentity,
    ) -> CapabilitySurface:
        return CapabilitySurface(
            allowed_tools=identity.tools,
            allowed_mcp_servers=identity.mcp_server_ids,
            data_scopes=identity.data_scopes,
        )

    @staticmethod
    def _merge_capability_surface(
        current: CapabilitySurface,
        identity: AgentRuntimeIdentity,
    ) -> CapabilitySurface:
        return current.model_copy(
            update={
                "allowed_tools": tuple(sorted(set(current.allowed_tools) | set(identity.tools))),
                "allowed_mcp_servers": tuple(sorted(set(current.allowed_mcp_servers) | set(identity.mcp_server_ids))),
                "data_scopes": tuple(sorted(set(current.data_scopes) | set(identity.data_scopes))),
            }
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

    @staticmethod
    def _build_evidence_metadata(
        *,
        request: EvaluationRequest,
        decision: Decision,
    ) -> dict[str, object]:
        """
        Builds the metadata dict that decorates a recorded evidence
        envelope. Centralised so the legacy and MemorySystem write paths
        produce identical evidence payloads — the only difference between
        the two paths is durability, not audit content.
        """
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
        if request.agent_id is not None:
            metadata["agent_id"] = str(request.agent_id)
        if request.agent_identity is not None:
            metadata["agent_identity"] = request.agent_identity.model_dump(mode="json")
            metadata["agent_fingerprint_hash"] = (
                request.agent_identity.fingerprint_hash
            )

        return metadata

    @staticmethod
    def _build_full_input_payload(
        request: EvaluationRequest,
    ) -> dict[str, Any]:
        """
        Serialises the evaluation request to the canonical replay-input
        payload. ``mode='json'`` ensures every UUID/datetime/enum is
        coerced to a primitive; the result hashes stably across processes
        which is exactly what ``DecisionInputStore.input_sha256`` needs.
        """
        return request.model_dump(mode="json")

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

        metadata = self._build_evidence_metadata(
            request=request, decision=decision
        )

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
        evidence_hash: str | None = None,
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
            policy_version=decision.policy_version,
            evidence_hash=evidence_hash,
            capability_violations=capability_violations,
            asi_short_codes=asi_short_codes,
            system_prompt_hash=(
                request.agent_identity.system_prompt_hash
                if request.agent_identity is not None
                else None
            ),
            tool_manifest_hash=(
                request.agent_identity.tool_manifest_hash
                if request.agent_identity is not None
                else None
            ),
            memory_hash=(
                request.agent_identity.memory_hash
                if request.agent_identity is not None
                else None
            ),
            mcp_server_ids=(
                request.agent_identity.mcp_server_ids
                if request.agent_identity is not None
                else tuple()
            ),
            tools=(
                request.agent_identity.tools
                if request.agent_identity is not None
                else tuple()
            ),
            data_scopes=(
                request.agent_identity.data_scopes
                if request.agent_identity is not None
                else tuple()
            ),
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
