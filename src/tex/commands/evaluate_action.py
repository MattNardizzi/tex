from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid5

from tex.domain.agent import ActionLedgerEntry, AgentEnvironment, AgentIdentity, AgentLifecycleStatus, AgentTrustTier, CapabilitySurface
from tex.domain.decision import Decision
from tex.domain.evaluation import AgentRuntimeIdentity, EvaluationRequest, EvaluationResponse
from tex.domain.evidence import EvidenceRecord
from tex.evidence.c2pa_emitter import (
    ALL_RISK_CATEGORIES,
    REFUSAL_EVENT_PRE_GENERATION,
    RISK_OTHER,
    C2paEmissionContext,
    ScittRefusalEvent,
)
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

_logger = logging.getLogger(__name__)


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
        # Continuous provenance feed (optional). When wired, the command
        # notifies the feed after each action-ledger write so behavioural
        # identity seals on its own, off the hot path. Default ``None``
        # keeps the legacy path bit-for-bit.
        "_provenance_feed",
        # Thread 7: optional ecosystem-engine bridge. When wired AND
        # ``TEX_ECOSYSTEM=1`` is set, ``execute()`` forwards every
        # ``RoutingResult`` through the bridge and folds the
        # ``EcosystemVerdict`` axis scores into the response under the
        # ``ecosystem.*`` score namespace. Default ``None`` preserves
        # pre-Thread-7 behavior bit-for-bit for tests and callers that
        # construct the command directly.
        "_ecosystem_bridge",
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
        provenance_feed: Any | None = None,
        # Thread 7: optional ecosystem-engine bridge. Default ``None``
        # so every existing test that constructs the command directly
        # (without an ecosystem layer) keeps passing unchanged. When
        # wired AND ``TEX_ECOSYSTEM=1`` is set in the environment, the
        # command forwards every PDP ``RoutingResult`` through the
        # bridge and folds the resulting ``EcosystemVerdict`` axis
        # scores into the response. When the env flag is off, the
        # engine inside the bridge short-circuits and the command path
        # is bit-for-bit identical to its legacy shape.
        ecosystem_bridge: Any | None = None,
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
        self._provenance_feed = provenance_feed
        self._ecosystem_bridge = ecosystem_bridge

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
            # FAITHFUL CaMeL plan-emission (default-OFF behind TEX_CAMEL_EMIT_ENABLED):
            # the activation seam. When the request declares a GENUINE untrusted-
            # read-then-branch flow (request.metadata['camel_branch_flow']), compile
            # it into a metered CaMeL plan from the REAL request data and stamp it
            # onto the request metadata so the evolved CamelSpecialist runs the
            # CFI/CHOKE-X interpreter on it inside pdp.evaluate. ANTI-THEATER: the
            # compiler reads the untrusted content from the REAL request and emits
            # NOTHING when there is no real branch structure — it never synthesizes
            # a plan, untrusted source, or branch. Best-effort: a compile failure
            # must never break the gate verdict (the specialist simply abstains
            # without a plan, exactly as before).
            request = self._maybe_emit_camel_plan(request)
            # Ledgered value-class budget (default-OFF behind TEX_BUDGET_ENABLED):
            # the last mutable point before pdp.evaluate(). Derive this action's
            # confidentiality-class debit, reload the lineage's sealed cumulative
            # total, add the debit, and seal the new authoritative total as a
            # SealedFact(BUDGET) per-lineage. The structural floor (OVER→FORBID)
            # and the degraded hold (DEGRADED→ABSTAIN) then read the same sealed
            # total inside the PDP for this request_id. Observe exactly once here
            # so the action is metered exactly once; the floor/hold only peek.
            # Best-effort: a budget-seam failure must never break the gate verdict
            # — the floor independently fails closed to ABSTAIN on an unverifiable
            # ledger, so a raise here cannot silently allow.
            if os.environ.get("TEX_BUDGET_ENABLED", "").strip().casefold() in {
                "1",
                "true",
                "yes",
                "on",
            }:
                try:
                    from tex.deterministic.value_budget import observe_for_debit

                    observe_for_debit(request)
                except Exception:  # noqa: BLE001
                    pass
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
                # Thread 2 — emit first-class contract violation evidence
                # rows linked to this decision evidence row. See
                # _record_contract_violation_evidence for rationale.
                self._record_contract_violation_evidence(
                    decision=decision,
                    pdp_result=pdp_result,
                    parent_evidence_hash=evidence_record.record_hash,
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
                    # Thread 2 — emit first-class contract violation evidence
                    # rows linked to this decision evidence row.
                    self._record_contract_violation_evidence(
                        decision=decision,
                        pdp_result=pdp_result,
                        parent_evidence_hash=evidence_record.record_hash,
                    )

            # ── Thread 7: optional EcosystemEngine pass ─────────────────
            #
            # When a bridge is wired AND ``TEX_ECOSYSTEM=1`` is set in
            # the env, forward the PDP's ``RoutingResult`` through the
            # eight-step ecosystem engine. The engine populates an
            # ``EcosystemVerdict`` with six axis scores plus a computed
            # viability index and GAAT enforcement level; we project
            # the relevant scalars into the response under the
            # ``ecosystem.*`` score namespace so HTTP consumers can
            # read them without changing the response schema (the
            # response model is ``extra="forbid"``).
            #
            # When the env flag is off, the engine's internal
            # short-circuit returns an inert PERMIT in O(1) with
            # ``ecosystem_state_hash_before == "ecosystem_disabled"``;
            # we detect that sentinel and skip the response mutation
            # entirely. The legacy response is byte-for-byte unchanged.
            #
            # Failures here are non-fatal: the bridge sits BEHIND the
            # PDP verdict on the critical path; if the ecosystem layer
            # raises (e.g. a misconfigured ontology, a graph mutation
            # error mid-eval), we log telemetry and fall through to
            # the legacy response. The user-facing verdict still
            # lands. This matches the canonical doc's promise that
            # ``TEX_ECOSYSTEM=0`` is bit-for-bit safe — an exception
            # in ecosystem-land does not poison the existing 5-layer
            # contract.
            response = self._maybe_apply_ecosystem(
                response=response,
                request=request,
                pdp_result=pdp_result,
            )

            self._record_action_ledger_entry(
                request=request,
                decision=decision,
                pdp_result=pdp_result,
                evidence_hash=(
                    evidence_record.record_hash if evidence_record is not None else None
                ),
            )
            # Continuous provenance: notify the feed that this agent acted
            # so identity re-seals on its own. Cheap and non-blocking by
            # contract — a counter bump, at most one enqueue; all sealing
            # happens on the feed's worker. Wrapped so provenance can never
            # break the gate verdict the caller is waiting on.
            if self._provenance_feed is not None and request.agent_id is not None:
                try:
                    self._provenance_feed.note_action(request.agent_id)
                except Exception:  # noqa: BLE001
                    pass
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

    def _maybe_emit_camel_plan(
        self, request: EvaluationRequest
    ) -> EvaluationRequest:
        """Compile a faithful CaMeL plan from the request's REAL declared
        untrusted-read-then-branch structure and stamp it onto the request
        metadata, so the evolved ``CamelSpecialist`` runs the metered (CFI/CHOKE-X)
        interpreter on it inside ``pdp.evaluate``.

        FAITHFULNESS (the anti-theater contract): the plan + its untrusted
        provenance come ONLY from the real request (``tex.camel.plan_emission.
        compile_branch_flow``). When the request carries no genuine
        ``camel_branch_flow`` block (or one without real untrusted content / a real
        finite branch), ``compile_branch_flow`` returns ``None`` and this method
        leaves the request UNCHANGED — the specialist then abstains. We never
        fabricate a plan, an untrusted source, or a branch.

        Default-OFF behind ``TEX_CAMEL_EMIT_ENABLED``. If the caller ALREADY
        supplied a ``camel_plan`` (the legacy direct-injection path), we never
        overwrite it. Best-effort: any failure leaves the request unchanged.
        """
        if os.environ.get("TEX_CAMEL_EMIT_ENABLED", "").strip().casefold() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            return request
        try:
            from tex.camel.plan_emission import (
                compile_branch_flow,
                stash_emitted_plan,
            )

            metadata = getattr(request, "metadata", None) or {}
            if isinstance(metadata, dict) and metadata.get("camel_plan") is not None:
                # A plan is already present (legacy direct-injection path) — do not
                # overwrite, and do not also stash (the legacy path supplies its own
                # untrusted_env/projector on metadata).
                return request
            emitted = compile_branch_flow(request)
            if emitted is None:
                # No genuine untrusted-read-then-branch structure → emit nothing.
                return request
            # The Plan + projector are NOT JSON-serializable; the semantic layer
            # JSON-dumps request.metadata, so we MUST NOT stamp them there. Stow the
            # live emitted plan in the process-local, request-id-keyed sidecar; the
            # evolved CamelSpecialist pops it back out by request_id. Only the
            # JSON-safe provenance marker goes onto metadata (auditor-facing).
            stash_emitted_plan(str(request.request_id), emitted)
            new_metadata = dict(metadata) if isinstance(metadata, dict) else {}
            new_metadata["camel_plan_provenance"] = dict(emitted.provenance)
            return request.model_copy(update={"metadata": new_metadata})
        except Exception:  # noqa: BLE001 — never break the gate on a compile failure
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

        # Thread 12 — composite TEE attestation (Intel TDX + NVIDIA GPU).
        # Gated by TEX_TEE_MODE=1 so non-CC deployments pay zero cost and
        # existing tests are unaffected. When enabled, each decision's
        # evidence record carries a hardware-rooted attestation JWT whose
        # nonce is bound to the decision_id (CrossGuard pattern, arxiv
        # 2604.23280, Apr 28 2026). Failures are isolated: TEE collection
        # errors are recorded as a metadata flag but never block the
        # decision from being recorded — the decision path stays
        # fail-closed at the PDP layer, not at the audit layer.
        if os.environ.get("TEX_TEE_MODE", "").strip() == "1":
            try:
                from tex.tee import compose_attestation

                envelope = compose_attestation(
                    decision_id=str(decision.decision_id),
                    request_id=str(request.request_id),
                )
                metadata["tee_composite_attestation"] = envelope.model_dump(
                    mode="json"
                )
            except Exception as exc:  # noqa: BLE001
                # Record the failure as evidence so auditors can see the
                # operator wanted TEE binding but the attestation
                # collection failed. The decision itself is unaffected.
                metadata["tee_composite_attestation_error"] = {
                    "error_type": type(exc).__name__,
                    "error_message": str(exc)[:512],
                }

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

        # SCITT refusal receipt on FORBID (draft-kamimura-scitt-refusal-
        # events-02). Every refusal records WHY, inline in the hash-chained
        # evidence row, on a transparency-log standard an auditor can verify.
        # The recorder turns ``c2pa_context.refusal_event`` into the payload's
        # ``scitt.refusal_event`` block (it already gates on FORBID), so this is
        # the live wire that activates that path for real decisions.
        c2pa_context = self._build_refusal_context(decision)

        return recorder.record_decision(
            decision,
            metadata=metadata,
            c2pa_context=c2pa_context,
        )

    @staticmethod
    def _build_refusal_context(decision: Decision) -> "C2paEmissionContext | None":
        """
        Construct a SCITT refusal context for a FORBID decision, or ``None`` for
        any other verdict (so PERMIT/ABSTAIN recording is unchanged).

        The refusal is a PRE_GENERATION event — Tex forbade the action before it
        ran. The risk taxonomy is content-safety oriented; a governance FORBID
        maps to ``OTHER`` unless a finding carries an explicit SCITT category.
        The rationale is the decision's own reasons, auditor-facing and short.
        """
        if decision.verdict is not Verdict.FORBID:
            return None

        rationale = "; ".join(r for r in decision.reasons if r).strip()
        if not rationale:
            rationale = "policy forbade the action"
        # Keep the rationale short and free of sensitive payload content.
        rationale = rationale[:480]

        # Allow a finding to name an explicit SCITT risk category; otherwise the
        # generic governance category. Never fabricate a category not in the
        # taxonomy.
        risk_category = RISK_OTHER
        for reason in decision.reasons:
            token = reason.strip().upper().replace(" ", "_")
            if token in ALL_RISK_CATEGORIES:
                risk_category = token
                break

        issuer = "tex-governance"
        meta_tenant = decision.metadata.get("tenant_id") if decision.metadata else None
        if isinstance(meta_tenant, str) and meta_tenant.strip():
            issuer = meta_tenant.strip()

        try:
            event = ScittRefusalEvent(
                event_type=REFUSAL_EVENT_PRE_GENERATION,
                risk_category=risk_category,
                rationale=rationale,
                issued_at=datetime.now(UTC),
                issuer=issuer,
            )
        except ValueError:
            # Defensive: a malformed taxonomy value must not block recording.
            return None
        return C2paEmissionContext(refusal_event=event, tenant_id=issuer)

    def _record_contract_violation_evidence(
        self,
        *,
        decision: Decision,
        pdp_result: PDPResult,
        parent_evidence_hash: str,
    ) -> None:
        """
        Emit one evidence row per behavioral contract violation, each
        linked to the parent decision evidence row by
        ``parent_evidence_hash``.

        Why this is its own method
        --------------------------
        Contract findings already live inside ``decision.findings`` and
        are durable inside the parent decision row. But that makes them
        not separately addressable: an auditor cannot pull a single
        violation receipt without re-deriving it from the decision payload.
        First-class contract-violation evidence rows give every violation:
          * its own ``payload_sha256``
          * its own ``record_hash`` in the linear chain
          * a ``parent_evidence_hash`` cross-reference back to the
            decision row that triggered it

        This is the "evidence on demand" claim. See
        ``EvidenceRecorder.record_contract_violation`` for the per-row
        payload schema and its alignment to arxiv 2602.22302 §5.2.

        Best-effort semantics
        ---------------------
        A failure inside this method does NOT block the request. The
        parent decision evidence row has already been written and is
        the source of truth; the contract-violation rows are an
        addressable cross-reference. If the recorder raises, we log
        and continue — the violation is still durable in the parent
        decision row's findings array.

        Recorder discovery: the recorder must expose
        ``record_contract_violation`` for this method to do anything.
        The memory system's recorder may not — in that case we silently
        skip. Operators wiring a custom recorder can opt out simply by
        not implementing the method.
        """
        recorder = self._evidence_recorder
        if recorder is None:
            return
        record_method = getattr(recorder, "record_contract_violation", None)
        if record_method is None:
            return

        contract_findings = [
            f for f in decision.findings if f.source == "contracts.behavioral"
        ]
        if not contract_findings:
            return

        for finding in contract_findings:
            try:
                meta = dict(finding.metadata) if finding.metadata else {}
                contract_id = str(meta.get("contract_id", ""))
                violated_clause = str(meta.get("violated_clause", ""))
                clause_ltl = str(meta.get("clause_ltl", ""))
                step_index = int(meta.get("step_index", 0))
                compliance_gap = float(meta.get("compliance_gap", 0.0))
                severity_class = str(meta.get("severity_class", ""))
                is_soft = bool(meta.get("is_soft", False))
                session_key_val = meta.get("session_key")
                session_key = (
                    str(session_key_val) if session_key_val is not None else None
                )
                replayed_window_size = int(
                    meta.get("replayed_window_size", 0)
                )
                deadline_val = meta.get("recovery_deadline_step")
                recovery_deadline_step = (
                    int(deadline_val) if deadline_val is not None else None
                )

                record_method(
                    decision_id=decision.decision_id,
                    request_id=decision.request_id,
                    policy_version=decision.policy_version,
                    contract_id=contract_id,
                    violated_clause=violated_clause,
                    clause_ltl=clause_ltl,
                    step_index=step_index,
                    compliance_gap=compliance_gap,
                    severity_class=severity_class,
                    is_soft=is_soft,
                    rule_name=finding.rule_name,
                    message=finding.message,
                    parent_evidence_hash=parent_evidence_hash,
                    session_key=session_key,
                    replayed_window_size=replayed_window_size,
                    recovery_deadline_step=recovery_deadline_step,
                )
            except Exception as exc:  # noqa: BLE001
                # Best-effort. The parent decision evidence row carries
                # the violation in its findings array, so audit is not
                # lost — we just don't get the addressable receipt.
                _logger.warning(
                    "EvaluateActionCommand: failed to record contract-violation "
                    "evidence for decision %s contract %s: %s",
                    decision.decision_id,
                    meta.get("contract_id", "<unknown>"),
                    exc,
                )

    def _maybe_apply_ecosystem(
        self,
        *,
        response: EvaluationResponse,
        request: EvaluationRequest,
        pdp_result: PDPResult,
    ) -> EvaluationResponse:
        """
        Optionally forward the PDP result through the ecosystem bridge and
        fold the resulting axis scores into the response.

        Returns the (possibly updated) ``EvaluationResponse``.

        Behavior matrix:

          * ``self._ecosystem_bridge is None`` (default for legacy callers)
              → return ``response`` unchanged. No env read, no telemetry.
          * Bridge wired AND ``TEX_ECOSYSTEM != "1"``
              → bridge.emit_verdict() runs but the engine short-circuits
                to an inert PERMIT with state_hash_before ==
                "ecosystem_disabled". We detect that sentinel and return
                ``response`` unchanged (bit-for-bit identical legacy shape).
          * Bridge wired AND ``TEX_ECOSYSTEM == "1"``
              → bridge runs the eight-step pipeline, returns an
                ``EcosystemVerdict`` populated with six axis scores plus
                computed ``viability_index`` and ``graduated_level``. We
                merge a fixed set of scalars into ``response.scores``
                under the ``ecosystem.*`` namespace.
          * Bridge wired but raises
              → telemetry-only; return ``response`` unchanged. The legacy
                verdict survives — the ecosystem layer is advisory in
                Thread 7 per ``docs/ecosystem.md`` (composition gate to
                FORBID/SANCTION lands in Thread 8).

        Namespace contract for ``ecosystem.*`` scores (stable across
        Thread 7 and Thread 8):

          * ``ecosystem.viability_index``           — float ∈ [0, 1]
          * ``ecosystem.contract_violation_severity`` — float ∈ [0, 1]
          * ``ecosystem.governance_graph_legality`` — float ∈ [0, 1]
          * ``ecosystem.causal_attribution_confidence`` — float ∈ [0, 1]
          * ``ecosystem.drift_delta``               — float, clamped [0, 1]
          * ``ecosystem.systemic_risk_under_event`` — float ∈ [0, 1]
          * ``ecosystem.bounded_compromise_score``  — float ∈ [0, 1]

        The GAAT enforcement level (``L0_allow`` … ``L4_quarantine``) is
        published as an uncertainty flag of the form
        ``ecosystem_graduated_level:<value>`` so callers that read flags
        can branch on it without parsing the scores dict. We deliberately
        do NOT add a new response field — the response model is
        ``extra="forbid"`` and the score dict + uncertainty flags
        accommodate ecosystem state without schema migration.
        """
        bridge = self._ecosystem_bridge
        if bridge is None:
            return response

        if os.environ.get("TEX_ECOSYSTEM", "0") != "1":
            # Bridge wired but operator has not opted into ecosystem
            # governance. Skip the engine call entirely (cheaper than
            # letting the engine short-circuit, and zero telemetry).
            return response

        try:
            # The actor entity id seeds the ecosystem graph. For
            # adjudications that carry an agent_id, we use the stable
            # UUID string; for actions where Tex itself is the actor
            # (no agent context), we use the canonical "tex" sentinel
            # that matches the verdict_emitted EventKind contract.
            actor_entity_id = (
                str(request.agent_id) if request.agent_id is not None else "tex"
            )
            # The ecosystem graph requires the actor to be registered.
            # We auto-register it here on first sight — the graph is
            # process-local so this is cheap. A production deployment
            # that wants stricter registration can wire a custom graph
            # at construction time.
            graph = getattr(bridge, "_engine", None)
            if graph is not None:
                inner_graph = getattr(graph, "_graph", None)
                if inner_graph is not None and not inner_graph._has_entity(
                    actor_entity_id
                ):
                    try:
                        inner_graph.add_entity(
                            entity_id=actor_entity_id,
                            kind="agent",
                            attrs={"registered_at": request.requested_at},
                        )
                    except Exception:  # noqa: BLE001
                        # Auto-registration is best-effort; if it
                        # fails we let the engine surface a FORBID
                        # for unknown_actor and downgrade gracefully.
                        pass

            verdict = bridge.emit_verdict(
                routing_result=pdp_result.routing_result,
                actor_entity_id=actor_entity_id,
                proposed_at=request.requested_at,
                request_id=str(request.request_id),
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "ecosystem bridge raised; falling back to legacy response: %s",
                exc,
            )
            return response

        # Detect the disabled-path sentinel. The engine returns
        # ``ecosystem_state_hash_before == "ecosystem_disabled"`` when
        # ``TEX_ECOSYSTEM != "1"`` at construction time AND its
        # ``_enabled`` flag is False. We read the env every call, but
        # the engine reads it once at construction, so this defends
        # against the case where the operator flips the flag at runtime
        # without restarting (common in tests).
        if verdict.ecosystem_state_hash_before == "ecosystem_disabled":
            return response

        axis = verdict.axis_scores
        # Project axis scores into the response scores dict. The
        # response validator enforces ``0 <= value <= 1``; we clamp
        # ``drift_delta`` explicitly because the axis type allows
        # arbitrary floats but the response scores field constrains
        # to the unit interval.
        ecosystem_scores: dict[str, float] = dict(response.scores)
        ecosystem_scores["ecosystem.viability_index"] = max(
            0.0, min(1.0, float(axis.viability_index))
        )
        ecosystem_scores["ecosystem.contract_violation_severity"] = max(
            0.0, min(1.0, float(axis.contract_violation_severity))
        )
        ecosystem_scores["ecosystem.governance_graph_legality"] = max(
            0.0, min(1.0, float(axis.governance_graph_legality))
        )
        ecosystem_scores["ecosystem.causal_attribution_confidence"] = max(
            0.0, min(1.0, float(axis.causal_attribution_confidence))
        )
        ecosystem_scores["ecosystem.drift_delta"] = max(
            0.0, min(1.0, float(axis.drift_delta))
        )
        ecosystem_scores["ecosystem.systemic_risk_under_event"] = max(
            0.0, min(1.0, float(axis.systemic_risk_under_event))
        )
        ecosystem_scores["ecosystem.bounded_compromise_score"] = max(
            0.0, min(1.0, float(axis.bounded_compromise_score))
        )

        # Publish the GAAT enforcement level as an uncertainty flag so
        # callers that branch on flags (gateways, dashboards) can read
        # it without parsing the scores dict. The graduated_level is
        # a ``GraduatedEnforcementLevel`` enum — we serialize the value
        # ("L0_allow", "L1_alert", "L2_flag", "L3_redirect",
        # "L4_quarantine").
        new_flags = list(response.uncertainty_flags)
        graduated_flag = f"ecosystem_graduated_level:{axis.graduated_level.value}"
        if graduated_flag not in new_flags:
            new_flags.append(graduated_flag)

        return response.model_copy(
            update={
                "scores": ecosystem_scores,
                "uncertainty_flags": new_flags,
            }
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
