from __future__ import annotations

import hashlib
import time
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from tex.contracts.runtime_enforcement import ContractEnforcer
from tex.deterministic.gate import (
    DeterministicGate,
    DeterministicGateResult,
    build_default_deterministic_gate,
)
from tex.agent.behavioral_evaluator import neutral_behavioral_signal
from tex.agent.capability_evaluator import neutral_capability_signal
from tex.agent.identity_evaluator import neutral_identity_signal
from tex.domain.agent_signal import AgentEvaluationBundle
from tex.domain.asi_builder import build_asi_findings
from tex.domain.decision import Decision
from tex.domain.determinism import compute_determinism_fingerprint
from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.finding import Finding
from tex.domain.latency import LatencyBreakdown
from tex.domain.policy import PolicySnapshot
from tex.domain.retrieval import RetrievalContext
from tex.domain.verdict import Verdict
from tex.provenance.decision_seal import seal_decision
from tex.provenance.ledger import SealedFactLedger
from tex.engine.contract_bridge import (
    ContractEvaluationOutcome,
    NEUTRAL_OUTCOME,
    SessionEnforcerRegistry,
    evaluate_contracts_for_request,
)
from tex.engine.crc_gate import (
    ConformalRiskGate,
    CRCCertificate,
    build_default_crc_gate,
)
from tex.engine.hold import Hold, build_hold
from tex.engine.path_policy_bridge import (
    NEUTRAL_PATH_OUTCOME,
    PathPolicyOutcome,
    evaluate_path_policies_for_request,
)
from tex.engine.risk_spine import RiskSpine, apply_risk_spine
from tex.engine.router import RoutingResult, build_default_router
from tex.retrieval.orchestrator import (
    RetrievalOrchestrator,
    build_noop_retrieval_orchestrator,
)
from tex.semantic.analyzer import (
    SemanticAnalyzer,
    build_default_semantic_analyzer,
)
from tex.semantic.schema import SemanticAnalysis
from tex.specialists.base import SpecialistBundle
from tex.specialists.ifc_specialist import get_ifc_labels_cache
from tex.specialists.judges import SpecialistSuite, build_default_specialist_suite
from tex.specialists.structural_floor import (
    NEUTRAL_STRUCTURAL_FLOOR,
    StructuralFloorResult,
    detect_structural_floor,
)
from tex.systemic.probguard import apply_predictive_holds


@runtime_checkable
class Router(Protocol):
    """Contract for Tex's routing and fusion layer."""

    def route(
        self,
        *,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        policy: PolicySnapshot,
        action_type: str,
        channel: str,
        environment: str,
        agent_bundle: AgentEvaluationBundle | None = None,
    ) -> RoutingResult:
        """Returns the fused routing result for one evaluation."""


@runtime_checkable
class AgentEvaluator(Protocol):
    """
    Contract for the agent governance evaluation suite.

    Tex's PDP calls this once per evaluation. When the request carries
    no agent_id, the suite returns a neutral bundle and fusion behaves
    as if the agent layer were absent.
    """

    def evaluate(self, request: EvaluationRequest) -> AgentEvaluationBundle:
        """Run the three agent evaluation streams for one request."""


class PDPResult(BaseModel):
    """
    Full internal output of a single Tex evaluation pass.

    This is intentionally richer than the public EvaluationResponse because the
    engine needs to preserve intermediate artifacts for audit, evidence
    recording, replay, debugging, and later outcome analysis.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: EvaluationRequest
    policy: PolicySnapshot

    retrieval_context: RetrievalContext
    deterministic_result: DeterministicGateResult
    specialist_bundle: SpecialistBundle
    semantic_analysis: SemanticAnalysis
    agent_bundle: AgentEvaluationBundle
    routing_result: RoutingResult

    latency: LatencyBreakdown
    determinism_fingerprint: str

    decision: Decision
    response: EvaluationResponse


class PolicyDecisionPoint:
    """
    Tex's orchestration engine.

    Fixed evaluation order:
    deterministic recognizers
    -> retrieval grounding
    -> agent identity / capability / behavioral streams (when agent context present)
    -> specialist judges
    -> semantic judge
    -> routing / abstention
    -> durable decision + public response

    This class coordinates evaluation only. It does not own transport,
    persistence, policy activation, or outcome reporting.
    """

    __slots__ = (
        "_deterministic_gate",
        "_retrieval_orchestrator",
        "_agent_evaluator",
        "_specialist_suite",
        "_semantic_analyzer",
        "_router",
        "_contract_enforcer",
        "_contract_session_registry",
        "_contract_action_ledger",
        "_crc_gate",
        "_decision_ledger",
        "_risk_spine",
    )

    def __init__(
        self,
        *,
        deterministic_gate: DeterministicGate | None = None,
        retrieval_orchestrator: RetrievalOrchestrator | None = None,
        agent_evaluator: AgentEvaluator | None = None,
        specialist_suite: SpecialistSuite | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        router: Router | None = None,
        contract_enforcer: ContractEnforcer | None = None,
        contract_session_registry: SessionEnforcerRegistry | None = None,
        contract_action_ledger: object | None = None,
        crc_gate: ConformalRiskGate | None = None,
        decision_ledger: SealedFactLedger | None = None,
        risk_spine: RiskSpine | None = None,
    ) -> None:
        self._deterministic_gate = (
            deterministic_gate or build_default_deterministic_gate()
        )
        self._retrieval_orchestrator = (
            retrieval_orchestrator or build_noop_retrieval_orchestrator()
        )
        self._agent_evaluator = agent_evaluator
        self._specialist_suite = specialist_suite or build_default_specialist_suite()
        self._semantic_analyzer = semantic_analyzer or build_default_semantic_analyzer()
        self._router = router or build_default_router()
        # Contract layer wiring. Two calling modes per
        # FRONTIER_DELTA_thread_1.md §11 (Thread 1.5):
        #   * stateless: pass ``contract_enforcer`` only — pre-Thread-1.5
        #     behaviour, single global enforcer, no ledger replay.
        #   * session-scoped: pass ``contract_session_registry`` (and
        #     optionally ``contract_action_ledger``) — ABC §3.3
        #     (p, δ, k)-satisfaction-correct path with per-session
        #     enforcer instances and ledger replay on session bootstrap.
        # Passing neither preserves the original opt-out branch.
        if contract_enforcer is not None and contract_session_registry is not None:
            raise ValueError(
                "PolicyDecisionPoint accepts contract_enforcer OR "
                "contract_session_registry, not both"
            )
        self._contract_enforcer = contract_enforcer
        self._contract_session_registry = contract_session_registry
        self._contract_action_ledger = contract_action_ledger
        # Conformal Risk Control verdict gate. Inert by default
        # (``build_default_crc_gate`` carries no calibration), so the PDP
        # reproduces pre-CRC behaviour bit-for-bit until an operator supplies
        # a calibration set. When active, the gate may only ever demote a
        # PERMIT to ABSTAIN — never relax a verdict — so wiring it in cannot
        # introduce a new false-permit. See engine/crc_gate.py.
        self._crc_gate = crc_gate or build_default_crc_gate()
        # DECISION-sealing seam (Wave 2 / M0). When a SealedFactLedger is wired,
        # each finalized verdict is sealed as one canonical SealedFact(DECISION)
        # — the leaf six Wave-2 leaps consume. ``None`` (the default) is a
        # zero-cost no-op that reproduces today's behaviour bit-for-bit.
        self._decision_ledger = decision_ledger
        # Live multiplicative e-value spine (Wave 2 / L9). When wired, the routed
        # branch advances per-stream drift e-processes from opt-in request
        # observations, seals each composite step, and may demote PERMIT→ABSTAIN
        # on an anytime-valid breach. ``None`` (default) is a zero-cost no-op.
        self._risk_spine = risk_spine

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        policy: PolicySnapshot,
    ) -> PDPResult:
        """
        Evaluates one action request against one immutable policy snapshot.

        Returns both the durable internal Decision and the outward-facing
        EvaluationResponse, along with per-stage latency measurements
        and a deterministic input fingerprint suitable for stability audit.
        """
        pipeline_start = time.perf_counter()

        deterministic_start = time.perf_counter()
        deterministic_result = self._deterministic_gate.evaluate(
            request=request,
            policy=policy,
        )
        deterministic_ms = _elapsed_ms(deterministic_start)

        retrieval_start = time.perf_counter()
        retrieval_context = self._retrieval_orchestrator.retrieve(
            request=request,
            policy=policy,
        )
        retrieval_ms = _elapsed_ms(retrieval_start)

        # Agent governance evaluation. When no agent_evaluator is wired
        # in, we synthesize a neutral bundle so downstream code always
        # has a value. This keeps unit tests that bypass the runtime
        # composition root working without the agent stack.
        agent_start = time.perf_counter()
        if self._agent_evaluator is not None:
            agent_bundle = self._agent_evaluator.evaluate(request)
        else:
            agent_bundle = _neutral_agent_bundle()
        agent_ms = _elapsed_ms(agent_start)

        specialists_start = time.perf_counter()
        specialist_bundle = self._specialist_suite.evaluate(
            request=request,
            retrieval_context=retrieval_context,
        )
        specialists_ms = _elapsed_ms(specialists_start)

        semantic_start = time.perf_counter()
        semantic_analysis = self._semantic_analyzer.analyze(
            request=request,
            retrieval_context=retrieval_context,
        )
        semantic_ms = _elapsed_ms(semantic_start)

        # ── Behavioral contracts (LTLf) — wired in Thread 1 / 1.5 ──
        # See FRONTIER_DELTA_thread_1.md §4.2, §6, and §11.
        # Hard violations short-circuit FORBID before the router. Soft
        # violations feed the router as findings + an uncertainty flag
        # and promote PERMIT→ABSTAIN. When both registry and ledger are
        # configured, session-scoped enforcement with history replay is
        # used (ABC §3.3 (p, δ, k)-satisfaction). When only enforcer is
        # configured, the stateless path runs. When neither is wired,
        # this returns NEUTRAL_OUTCOME — zero-cost branch.
        contract_outcome = evaluate_contracts_for_request(
            enforcer=self._contract_enforcer,
            registry=self._contract_session_registry,
            request=request,
            action_ledger=self._contract_action_ledger,
        )

        # ── Path policies (LTLf over the execution path) — Thread: wired ──
        # Judges the candidate action by the SEQUENCE it occurs in, not in
        # isolation. Opt-in via request.metadata["path_policy"]; returns
        # NEUTRAL_PATH_OUTCOME (zero cost) when absent. A ``block``-severity
        # path violation is a hard violation that joins the FORBID floor
        # below; a ``warn`` is a soft violation that promotes PERMIT→ABSTAIN;
        # ``audit`` contributes findings only. See engine/path_policy_bridge.
        path_outcome = evaluate_path_policies_for_request(request=request)

        # ── Structural FORBID floor — Thread: wired ───────────────────────
        # PCAS / CaMeL / IFC / ARGUS do not estimate risk, they PROVE a
        # violation deterministically over structure (Datalog deny, capability
        # denial, IFC type violation, counterfactual injection proof). Such a
        # proof short-circuits to FORBID alongside the deterministic gate
        # rather than being diluted into the router's weighted sum (where a
        # proven deny on otherwise-clean content used to land at ABSTAIN).
        # Only deterministic-deny SIGNATURES qualify — never a merely high
        # probabilistic score. See specialists/structural_floor.py. Passing the
        # request also activates the label-driven structural proofs (Rule-of-Two
        # trifecta + RV4 permanent path violations) when their opt-in metadata
        # is present.
        structural_floor = detect_structural_floor(
            specialist_bundle, request=request
        )

        hard_violation = (
            contract_outcome.has_hard_violation
            or path_outcome.has_block
            or structural_floor.fired
        )

        if hard_violation:
            # Short-circuit. Build a FORBID-shaped RoutingResult, fold the
            # contract + path + structural findings in, and skip the router
            # entirely. This is the fail-closed path (Section 3 hard
            # constraint).
            #
            # We still call ``build_asi_findings`` so the response carries
            # the OWASP ASI 2026 evidence trail that the deterministic /
            # specialist / semantic layers produced — without this the
            # short-circuit would silently lose ASI evidence and break
            # downstream replay consumers.
            router_start = time.perf_counter()
            preserved_asi = build_asi_findings(
                deterministic_result=deterministic_result,
                specialist_bundle=specialist_bundle,
                semantic_analysis=semantic_analysis,
                semantic_dominance_override_fired=False,
            )
            routing_result = self._build_hard_forbid_routing_result(
                contract_outcome=contract_outcome,
                path_outcome=path_outcome,
                structural_floor=structural_floor,
                deterministic_findings=tuple(deterministic_result.findings),
                asi_findings=preserved_asi,
            )
            router_ms = _elapsed_ms(router_start)
        else:
            router_start = time.perf_counter()
            base_routing_result = self._router.route(
                deterministic_result=deterministic_result,
                specialist_bundle=specialist_bundle,
                semantic_analysis=semantic_analysis,
                policy=policy,
                action_type=request.action_type,
                channel=request.channel,
                environment=request.environment,
                agent_bundle=agent_bundle,
            )
            # If soft violations fired, merge their findings + uncertainty
            # flag into the router's result. We rebuild the immutable
            # ``RoutingResult`` rather than mutate it.
            routing_result = base_routing_result
            if contract_outcome.has_soft_violation:
                routing_result = self._merge_soft_contract_signals(
                    base=routing_result,
                    contract_outcome=contract_outcome,
                )
            # Path soft (warn) violations and audit findings merge after
            # contracts. Warn promotes PERMIT→ABSTAIN; audit appends findings.
            if path_outcome.checked and (
                path_outcome.has_soft_violation or path_outcome.findings
            ):
                routing_result = self._merge_path_signals(
                    base=routing_result,
                    path_outcome=path_outcome,
                )
            # Predictive holds — soft, monotone-lowering (PERMIT→ABSTAIN only):
            # Pro2Guard DTMC lookahead + RV4 recoverable path violations. Acts
            # only on a PERMIT; never raises a verdict, never fires the
            # deterministic floor. See systemic/probguard.py.
            routing_result = apply_predictive_holds(
                base=routing_result, request=request
            )
            # Live multiplicative e-value spine (L9) — monotone-lowering
            # (PERMIT→ABSTAIN only), each step sealed. Inert no-op when unwired.
            routing_result = apply_risk_spine(
                self._risk_spine, base=routing_result, request=request
            )
            router_ms = _elapsed_ms(router_start)

        # ── Conformal Risk Control verdict gate — the last touch ──────────
        # Sits on the final verdict. Only ever makes it MORE conservative: a
        # PERMIT whose fused score lies outside the certified permit region is
        # demoted to ABSTAIN. Never relaxes FORBID/ABSTAIN, never creates a
        # PERMIT. Inert (pass-through) until an operator supplies calibration.
        # Always attaches an auditable certificate. See engine/crc_gate.py.
        crc_start = time.perf_counter()
        crc_result = self._crc_gate.apply(
            verdict=routing_result.verdict,
            final_score=routing_result.final_score,
        )
        if crc_result.demoted:
            routing_result = self._apply_crc_demotion(
                base=routing_result,
                crc_reasons=crc_result.reasons,
                crc_uncertainty_flags=crc_result.uncertainty_flags,
            )
        crc_certificate = crc_result.certificate
        crc_ms = _elapsed_ms(crc_start)
        total_ms = _elapsed_ms(pipeline_start)

        # ── The hold — Tex's abstention made first-class ──────────────────
        # When (and only when) the final verdict is ABSTAIN, build the typed,
        # self-resolving hold object off the (now two-sided) CRC certificate:
        # epistemic vs aleatoric, the single pivotal fact that would resolve
        # it, and the resolution mode (self-heal / human-fact / human-judgment).
        # Pure and deterministic, so the determinism fingerprint is preserved.
        # See engine/hold.py and TEX_ABSTAIN_DOCTRINE.md.
        hold = build_hold(
            verdict=routing_result.verdict,
            final_score=routing_result.final_score,
            uncertainty_flags=tuple(routing_result.uncertainty_flags),
            certificate=crc_certificate,
            confidence=routing_result.confidence,
            agent_id=(str(request.agent_id) if request.agent_id is not None else None),
            action_type=request.action_type,
        )

        latency = LatencyBreakdown(
            deterministic_ms=round(deterministic_ms, 2),
            retrieval_ms=round(retrieval_ms, 2),
            agent_ms=round(agent_ms, 2),
            specialists_ms=round(specialists_ms, 2),
            semantic_ms=round(semantic_ms, 2),
            router_ms=round(router_ms, 2),
            total_ms=round(total_ms, 2),
        )

        content_sha256 = self._sha256_hex(request.content)
        determinism_fingerprint = compute_determinism_fingerprint(
            content_sha256=content_sha256,
            policy_version=policy.version,
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            agent_bundle=agent_bundle,
        )

        decision = self._build_decision(
            request=request,
            policy=policy,
            retrieval_context=retrieval_context,
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            agent_bundle=agent_bundle,
            routing_result=routing_result,
            latency=latency,
            determinism_fingerprint=determinism_fingerprint,
            content_sha256=content_sha256,
            contract_outcome=contract_outcome,
            path_outcome=path_outcome,
            structural_floor=structural_floor,
            crc_certificate=crc_certificate,
            crc_ms=crc_ms,
            hold=hold,
        )

        # ── DECISION seal (Wave 2 / M0) ───────────────────────────────────
        # The verdict is final. Seal it as one SealedFact(DECISION) when a
        # ledger is wired. Observation-only: this never alters the verdict and
        # never raises into the request path (seal_decision is fail-closed).
        seal_decision(self._decision_ledger, decision)

        response = self._build_response(
            decision=decision,
            routing_result=routing_result,
            latency=latency,
            determinism_fingerprint=determinism_fingerprint,
        )

        return PDPResult(
            request=request,
            policy=policy,
            retrieval_context=retrieval_context,
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            agent_bundle=agent_bundle,
            routing_result=routing_result,
            latency=latency,
            determinism_fingerprint=determinism_fingerprint,
            decision=decision,
            response=response,
        )

    def _build_decision(
        self,
        *,
        request: EvaluationRequest,
        policy: PolicySnapshot,
        retrieval_context: RetrievalContext,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        agent_bundle: AgentEvaluationBundle,
        routing_result: RoutingResult,
        latency: LatencyBreakdown,
        determinism_fingerprint: str,
        content_sha256: str,
        contract_outcome: ContractEvaluationOutcome = NEUTRAL_OUTCOME,
        path_outcome: PathPolicyOutcome = NEUTRAL_PATH_OUTCOME,
        structural_floor: StructuralFloorResult = NEUTRAL_STRUCTURAL_FLOOR,
        crc_certificate: CRCCertificate | None = None,
        crc_ms: float = 0.0,
        hold: Hold | None = None,
    ) -> Decision:
        metadata = self._build_decision_metadata(
            request=request,
            policy=policy,
            retrieval_context=retrieval_context,
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            agent_bundle=agent_bundle,
            routing_result=routing_result,
            content_sha256=content_sha256,
            latency=latency,
            determinism_fingerprint=determinism_fingerprint,
            contract_outcome=contract_outcome,
            path_outcome=path_outcome,
            structural_floor=structural_floor,
            crc_certificate=crc_certificate,
            crc_ms=crc_ms,
            hold=hold,
        )

        return Decision(
            request_id=request.request_id,
            verdict=routing_result.verdict,
            confidence=routing_result.confidence,
            final_score=routing_result.final_score,
            action_type=request.action_type,
            channel=request.channel,
            environment=request.environment,
            recipient=request.recipient,
            content_excerpt=self._build_content_excerpt(request.content),
            content_sha256=content_sha256,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            scores=dict(routing_result.scores),
            findings=list(routing_result.findings),
            reasons=list(routing_result.reasons),
            uncertainty_flags=list(routing_result.uncertainty_flags),
            asi_findings=list(routing_result.asi_findings),
            determinism_fingerprint=determinism_fingerprint,
            latency=latency,
            retrieval_context=self._serialize_retrieval_context(retrieval_context),
            metadata=metadata,
        )

    @staticmethod
    def _build_hard_forbid_routing_result(
        *,
        contract_outcome: ContractEvaluationOutcome,
        path_outcome: PathPolicyOutcome = NEUTRAL_PATH_OUTCOME,
        structural_floor: StructuralFloorResult = NEUTRAL_STRUCTURAL_FLOOR,
        deterministic_findings: tuple[Finding, ...] = (),
        asi_findings: tuple = (),
    ) -> RoutingResult:
        """
        Synthesise a FORBID-shaped ``RoutingResult`` for the hard-violation
        short-circuit path.

        Called when a behavioural-contract hard violation, a path-policy
        ``block``, OR a structural deny (PCAS / CaMeL / IFC / ARGUS proof)
        fired. Any of these is a ground-truth structural signal, so the router
        is skipped to keep the gate fail-closed and latency-bounded.

        ``deterministic_findings`` and ``asi_findings`` are preserved from the
        upstream pipeline so replay / durability consumers still see the
        non-contract evidence even though the router never ran. Contract, path,
        and structural findings are folded in, and the ``scores`` axes
        attribute the FORBID to whichever structural layer(s) fired.

        Score / confidence rationale:
          * ``final_score = 1.0`` — maximum risk; a structural violation is a
            ground-truth signal, not a fused inference.
          * ``confidence = 1.0`` — these signals are deterministic.
        """
        merged_findings = (
            tuple(deterministic_findings)
            + tuple(contract_outcome.findings)
            + tuple(path_outcome.findings)
            + tuple(structural_floor.findings)
        )

        reasons: list[str] = []
        if contract_outcome.has_hard_violation:
            reasons.append(
                contract_outcome.forbid_reason
                or "behavioral contract hard violation"
            )
        if path_outcome.has_block:
            reasons.append(
                path_outcome.forbid_reason
                or "path policy hard violation (block)"
            )
        if structural_floor.fired:
            reasons.extend(structural_floor.reasons)
        if not reasons:
            reasons.append("structural hard violation")

        scores: dict[str, float] = {}
        if contract_outcome.has_hard_violation:
            scores["contracts"] = 1.0
        if path_outcome.has_block:
            scores["path_policy"] = 1.0
        if structural_floor.fired:
            scores["structural_floor"] = 1.0
            for specialist in structural_floor.denying_specialists:
                scores[f"structural_{specialist}"] = 1.0
        if not scores:
            scores["contracts"] = 1.0

        return RoutingResult(
            verdict=Verdict.FORBID,
            confidence=1.0,
            final_score=1.0,
            reasons=tuple(reasons),
            findings=merged_findings,
            scores=scores,
            uncertainty_flags=(),
            asi_findings=asi_findings,
            semantic_dominance_override_fired=False,
        )

    @staticmethod
    def _merge_path_signals(
        *,
        base: RoutingResult,
        path_outcome: PathPolicyOutcome,
    ) -> RoutingResult:
        """
        Merge path-policy soft (warn) + audit signals into a routed result.

        Mirrors ``_merge_soft_contract_signals``: a ``warn`` violation
        promotes a router PERMIT to ABSTAIN (paper-Steer → human review);
        FORBID and existing ABSTAIN verdicts are preserved. ``audit`` findings
        are folded in regardless of verdict. The result is rebuilt immutably.
        """
        merged_findings = tuple(base.findings) + tuple(path_outcome.findings)
        merged_flags = tuple(base.uncertainty_flags) + tuple(
            path_outcome.soft_uncertainty_flags
        )
        merged_scores = dict(base.scores)
        if path_outcome.violated_policy_ids:
            merged_scores["path_policy"] = min(1.0, max(0.0, path_outcome.violation_score))

        verdict = base.verdict
        reasons = base.reasons
        if path_outcome.has_soft_violation and verdict == Verdict.PERMIT:
            verdict = Verdict.ABSTAIN
            reasons = tuple(base.reasons) + (
                "path policy soft violation (warn) — promoted to ABSTAIN",
            )

        return RoutingResult(
            verdict=verdict,
            confidence=base.confidence,
            final_score=base.final_score,
            reasons=reasons,
            findings=merged_findings,
            scores=merged_scores,
            uncertainty_flags=merged_flags,
            asi_findings=base.asi_findings,
            semantic_dominance_override_fired=base.semantic_dominance_override_fired,
        )

    @staticmethod
    def _apply_crc_demotion(
        *,
        base: RoutingResult,
        crc_reasons: tuple[str, ...],
        crc_uncertainty_flags: tuple[str, ...],
    ) -> RoutingResult:
        """
        Rebuild ``base`` with the CRC gate's PERMIT→ABSTAIN demotion applied.

        Called only when ``crc_result.demoted`` is True, which the gate sets
        only for a router PERMIT whose fused score lies outside the certified
        permit region. Score and confidence are preserved; only the
        categorical verdict moves, plus the CRC reasons + uncertainty flag.
        """
        merged_reasons = tuple(base.reasons) + tuple(crc_reasons)
        merged_flags = tuple(base.uncertainty_flags) + tuple(crc_uncertainty_flags)
        return RoutingResult(
            verdict=Verdict.ABSTAIN,
            confidence=base.confidence,
            final_score=base.final_score,
            reasons=merged_reasons,
            findings=base.findings,
            scores=base.scores,
            uncertainty_flags=merged_flags,
            asi_findings=base.asi_findings,
            semantic_dominance_override_fired=base.semantic_dominance_override_fired,
        )

    @staticmethod
    def _merge_soft_contract_signals(
        *,
        base: RoutingResult,
        contract_outcome: ContractEvaluationOutcome,
    ) -> RoutingResult:
        """
        Rebuild ``base`` with contract-derived soft signals merged in.

        Contract findings are appended after the router's own findings so a
        consumer iterating in order sees the canonical pipeline findings
        first, then the contract-layer additions. Uncertainty flags from
        the soft-violation path are added without disturbing any
        router-emitted flags; ``RoutingResult.normalize_string_sequences``
        de-duplicates by validator.

        Verdict adjustment
        ------------------
        The router's ``_should_abstain`` consults only specific named
        uncertainty flags (e.g. ``no_retrieval_context``), not arbitrary
        custom flags. To honor the FRONTIER_DELTA_thread_1.md §4.2 design
        (soft violation → ABSTAIN), we promote a router-emitted PERMIT to
        ABSTAIN whenever a soft contract violation fired. Existing FORBID
        verdicts are preserved (a hard signal from deterministic /
        semantic / specialist always wins over a soft contract signal).
        Existing ABSTAIN verdicts are unchanged.

        Score and confidence are preserved as-is; we are adjusting the
        *categorical* verdict only, not the underlying risk inference.
        """
        merged_findings = tuple(base.findings) + tuple(contract_outcome.findings)
        merged_flags = tuple(base.uncertainty_flags) + tuple(
            contract_outcome.soft_uncertainty_flags
        )
        merged_scores = dict(base.scores)
        # Surface a ``contracts`` axis at the soft-violation maximum so
        # operators can see how many soft hits this evaluation took. The
        # router does not consume it; it's purely for telemetry. Bounded
        # to [0, 1] so the existing RoutingResult validator is happy.
        merged_scores["contracts_soft"] = min(
            1.0, 0.5 + 0.1 * len(contract_outcome.findings)
        )

        # Verdict promotion on soft violation. See docstring.
        verdict = base.verdict
        if verdict == Verdict.PERMIT:
            verdict = Verdict.ABSTAIN
            # Augment reasons so downstream auditors can attribute the
            # ABSTAIN to the contract layer specifically.
            merged_reasons: tuple[str, ...] = tuple(base.reasons) + (
                "behavioral contract soft violation — promoted to ABSTAIN",
            )
        else:
            merged_reasons = base.reasons

        return RoutingResult(
            verdict=verdict,
            confidence=base.confidence,
            final_score=base.final_score,
            reasons=merged_reasons,
            findings=merged_findings,
            scores=merged_scores,
            uncertainty_flags=merged_flags,
            asi_findings=base.asi_findings,
            semantic_dominance_override_fired=base.semantic_dominance_override_fired,
        )

    @staticmethod
    def _build_response(
        *,
        decision: Decision,
        routing_result: RoutingResult,
        latency: LatencyBreakdown,
        determinism_fingerprint: str,
    ) -> EvaluationResponse:
        return EvaluationResponse(
            decision_id=decision.decision_id,
            verdict=decision.verdict,
            confidence=decision.confidence,
            final_score=decision.final_score,
            reasons=list(routing_result.reasons),
            findings=list(routing_result.findings),
            scores=dict(routing_result.scores),
            uncertainty_flags=list(routing_result.uncertainty_flags),
            asi_findings=list(routing_result.asi_findings),
            determinism_fingerprint=determinism_fingerprint,
            latency=latency,
            policy_version=decision.policy_version,
            evidence_hash=decision.evidence_hash,
            evaluated_at=decision.decided_at,
        )

    def _build_decision_metadata(
        self,
        *,
        request: EvaluationRequest,
        policy: PolicySnapshot,
        retrieval_context: RetrievalContext,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        agent_bundle: AgentEvaluationBundle,
        routing_result: RoutingResult,
        content_sha256: str,
        latency: LatencyBreakdown,
        determinism_fingerprint: str,
        contract_outcome: ContractEvaluationOutcome = NEUTRAL_OUTCOME,
        path_outcome: PathPolicyOutcome = NEUTRAL_PATH_OUTCOME,
        structural_floor: StructuralFloorResult = NEUTRAL_STRUCTURAL_FLOOR,
        crc_certificate: CRCCertificate | None = None,
        crc_ms: float = 0.0,
        hold: Hold | None = None,
    ) -> dict[str, Any]:
        """
        Produces a compact execution summary for audit, replay, and debugging.

        The durable Decision should not store full intermediate objects. This
        summary keeps the high-signal operational facts while leaving the full
        artifacts available in PDPResult when needed in-process.
        """
        metadata = dict(request.metadata)
        # Strip the optional contracts override out of the surfaced metadata
        # so it doesn't pollute the durable decision record. The override is
        # an internal hint consumed by the contract bridge, not a customer
        # field worth preserving end-to-end.
        metadata.pop("contract_event_kind", None)
        metadata["pdp"] = {
            "pdp_version": "v3",
            "request_id": str(request.request_id),
            "request_fingerprint": self._request_fingerprint(
                request=request,
                policy=policy,
                content_sha256=content_sha256,
            ),
            "determinism_fingerprint": determinism_fingerprint,
            "latency_ms": {
                "deterministic": latency.deterministic_ms,
                "retrieval": latency.retrieval_ms,
                "agent": latency.agent_ms,
                "specialists": latency.specialists_ms,
                "semantic": latency.semantic_ms,
                "router": latency.router_ms,
                "total": latency.total_ms,
                # Folded in here (not in ``LatencyBreakdown``) because that
                # model is ``extra="forbid"`` and modifying it would ripple
                # through every existing test. FRONTIER_DELTA_thread_1.md §4.2.
                "contracts": contract_outcome.contracts_ms,
                "path_policy": path_outcome.path_policy_ms,
                "crc": round(crc_ms, 2),
            },
            "evaluation_order": [
                "deterministic_recognizers",
                "policy_retrieval",
                "agent_governance_streams",
                "specialist_judges",
                "semantic_judge",
                "behavioral_contracts",
                "path_policies",
                "structural_floor",
                "routing",
                "crc_gate",
                "decision_materialization",
            ],
            "contracts": {
                "enforcer_present": (
                    self._contract_enforcer is not None
                    or self._contract_session_registry is not None
                ),
                "mode": (
                    "session_scoped"
                    if self._contract_session_registry is not None
                    else (
                        "stateless"
                        if self._contract_enforcer is not None
                        else "inert"
                    )
                ),
                "has_hard_violation": contract_outcome.has_hard_violation,
                "has_soft_violation": contract_outcome.has_soft_violation,
                "violation_count": len(contract_outcome.raw_violations),
                "violated_contract_ids": sorted(
                    {v.contract_id for v in contract_outcome.raw_violations}
                ),
                "violated_clauses": sorted(
                    {v.violated_clause for v in contract_outcome.raw_violations}
                ),
                "short_circuited_to_forbid": contract_outcome.has_hard_violation,
                # Thread 1.5: ABC §3.3 session-scoped audit fields.
                "session_key": contract_outcome.session_key,
                "replayed_window_size": contract_outcome.replayed_window_size,
                "step_index_at_check": contract_outcome.step_index_at_check,
            },
            "path_policy": {
                "checked": path_outcome.checked,
                "n_policies": path_outcome.n_policies,
                "history_length": path_outcome.history_length,
                "has_block": path_outcome.has_block,
                "has_warn": path_outcome.has_warn,
                "violation_score": round(path_outcome.violation_score, 6),
                "violated_policy_ids": list(path_outcome.violated_policy_ids),
                "block_policy_ids": list(path_outcome.block_policy_ids),
                "warn_policy_ids": list(path_outcome.warn_policy_ids),
                "audit_policy_ids": list(path_outcome.audit_policy_ids),
                "short_circuited_to_forbid": path_outcome.has_block,
            },
            "structural_floor": {
                "fired": structural_floor.fired,
                "denying_specialists": list(structural_floor.denying_specialists),
                "reasons": list(structural_floor.reasons),
                "short_circuited_to_forbid": structural_floor.fired,
            },
            "crc": (
                crc_certificate.model_dump()
                if crc_certificate is not None
                else {"enabled": False, "certified": False}
            ),
            "hold": (hold.model_dump() if hold is not None else None),
            "policy": {
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "policy_active": policy.is_active,
                "permit_threshold": policy.permit_threshold,
                "forbid_threshold": policy.forbid_threshold,
                "minimum_confidence": policy.minimum_confidence,
            },
            "request": {
                "request_id": str(request.request_id),
                "action_type": request.action_type,
                "channel": request.channel,
                "environment": request.environment,
                "recipient": request.recipient,
                "has_recipient": request.recipient is not None,
                "content_sha256": content_sha256,
                "requested_at": request.requested_at.isoformat(),
                "policy_id_hint": request.policy_id,
                "agent_id": (
                    str(request.agent_id) if request.agent_id is not None else None
                ),
                "session_id": request.session_id,
            },
            "deterministic": self._summarize_deterministic(deterministic_result),
            "retrieval": self._summarize_retrieval(retrieval_context),
            "agent": self._summarize_agent(agent_bundle),
            "specialists": self._summarize_specialists(specialist_bundle),
            "semantic": self._summarize_semantic(semantic_analysis),
            "routing": self._summarize_routing(routing_result),
        }
        # Thread 11 AC2: attach the IFC labels the IfcSpecialist
        # produced for this request_id onto the durable Decision so
        # audit and replay can answer "what label did Tex apply to
        # this flow?" The cache is consume-once to avoid leaks.
        ifc_labels = get_ifc_labels_cache().pop(
            request_id=str(request.request_id)
        )
        if ifc_labels is not None:
            metadata["ifc_labels"] = ifc_labels
        return metadata

    @staticmethod
    def _summarize_deterministic(
        deterministic_result: DeterministicGateResult,
    ) -> dict[str, Any]:
        return {
            "blocked": deterministic_result.blocked,
            "suggested_verdict": PolicyDecisionPoint._stringify_optional_enum(
                deterministic_result.suggested_verdict
            ),
            "enabled_recognizers": list(deterministic_result.enabled_recognizers),
            "finding_count": len(deterministic_result.findings),
            "critical_finding_count": len(deterministic_result.critical_findings),
            "warning_finding_count": len(deterministic_result.warning_findings),
            "info_finding_count": len(deterministic_result.info_findings),
            "blocking_reasons": list(deterministic_result.blocking_reasons),
        }

    @staticmethod
    def _summarize_retrieval(retrieval_context: RetrievalContext) -> dict[str, Any]:
        return {
            "is_empty": retrieval_context.is_empty,
            "policy_clause_count": len(retrieval_context.policy_clauses),
            "precedent_count": len(retrieval_context.precedents),
            "entity_count": len(retrieval_context.entities),
            "warning_count": len(retrieval_context.retrieval_warnings),
            "matched_policy_clause_ids": list(
                retrieval_context.matched_policy_clause_ids
            ),
            "matched_entity_names": list(retrieval_context.matched_entity_names),
            "retrieved_at": retrieval_context.retrieved_at.isoformat(),
        }

    @staticmethod
    def _summarize_agent(agent_bundle: AgentEvaluationBundle) -> dict[str, Any]:
        """
        Produce the agent-side summary saved on the durable Decision.

        Captures the seven-stream contract: identity, capability, and
        behavioral risk and confidence; capability violation dimensions;
        forbid-streak; cold-start flag; agent_id and lifecycle. This is
        what audit and replay need to reconstruct the agent posture at
        the moment of decision.
        """
        if not agent_bundle.agent_present:
            return {
                "agent_present": False,
                "agent_id": None,
            }

        return {
            "agent_present": True,
            "agent_id": agent_bundle.agent_id,
            "aggregate_risk_score": round(agent_bundle.aggregate_risk_score, 4),
            "aggregate_confidence": round(agent_bundle.aggregate_confidence, 4),
            "identity": {
                "risk_score": agent_bundle.identity.risk_score,
                "confidence": agent_bundle.identity.confidence,
                "trust_tier": agent_bundle.identity.trust_tier,
                "lifecycle_status": agent_bundle.identity.lifecycle_status,
                "environment_match": agent_bundle.identity.environment_match,
                "attestation_count": agent_bundle.identity.attestation_count,
                "active_attestation_count": agent_bundle.identity.active_attestation_count,
                "age_seconds": agent_bundle.identity.age_seconds,
                "sub_scores": dict(agent_bundle.identity.sub_scores),
                "uncertainty_flags": list(agent_bundle.identity.uncertainty_flags),
                "finding_count": len(agent_bundle.identity.findings),
            },
            "capability": {
                "risk_score": agent_bundle.capability.risk_score,
                "confidence": agent_bundle.capability.confidence,
                "surface_unrestricted": agent_bundle.capability.surface_unrestricted,
                "action_permitted": agent_bundle.capability.action_permitted,
                "channel_permitted": agent_bundle.capability.channel_permitted,
                "environment_permitted": agent_bundle.capability.environment_permitted,
                "recipient_permitted": agent_bundle.capability.recipient_permitted,
                "violated_dimensions": list(agent_bundle.capability.violated_dimensions),
                "uncertainty_flags": list(agent_bundle.capability.uncertainty_flags),
                "finding_count": len(agent_bundle.capability.findings),
            },
            "behavioral": {
                "risk_score": agent_bundle.behavioral.risk_score,
                "confidence": agent_bundle.behavioral.confidence,
                "sample_size": agent_bundle.behavioral.sample_size,
                "cold_start": agent_bundle.behavioral.cold_start,
                "novel_action_type": agent_bundle.behavioral.novel_action_type,
                "novel_channel": agent_bundle.behavioral.novel_channel,
                "novel_recipient_domain": agent_bundle.behavioral.novel_recipient_domain,
                "forbid_streak": agent_bundle.behavioral.forbid_streak,
                "capability_violation_rate": agent_bundle.behavioral.capability_violation_rate,
                "recent_abstain_rate": agent_bundle.behavioral.recent_abstain_rate,
                "deviation_components": dict(
                    agent_bundle.behavioral.deviation_components
                ),
                "uncertainty_flags": list(agent_bundle.behavioral.uncertainty_flags),
                "finding_count": len(agent_bundle.behavioral.findings),
            },
        }

    @staticmethod
    def _summarize_specialists(specialist_bundle: SpecialistBundle) -> dict[str, Any]:
        return {
            "judge_count": len(specialist_bundle.results),
            "is_empty": specialist_bundle.is_empty,
            "max_risk_score": specialist_bundle.max_risk_score,
            "min_confidence": specialist_bundle.min_confidence,
            "matched_policy_clause_ids": list(
                specialist_bundle.matched_policy_clause_ids
            ),
            "matched_entity_names": list(specialist_bundle.matched_entity_names),
            "uncertainty_flags": list(specialist_bundle.uncertainty_flags),
            "results": [
                {
                    "specialist_name": result.specialist_name,
                    "risk_score": result.risk_score,
                    "confidence": result.confidence,
                    "matched_policy_clause_ids": list(
                        result.matched_policy_clause_ids
                    ),
                    "matched_entity_names": list(result.matched_entity_names),
                    "uncertainty_flags": list(result.uncertainty_flags),
                    "evidence_count": len(result.evidence),
                }
                for result in specialist_bundle.results
            ],
        }

    @staticmethod
    def _summarize_semantic(semantic_analysis: SemanticAnalysis) -> dict[str, Any]:
        return {
            "provider_name": semantic_analysis.provider_name,
            "model_name": semantic_analysis.model_name,
            "summary": semantic_analysis.summary,
            "overall_confidence": semantic_analysis.overall_confidence,
            "evidence_sufficiency": semantic_analysis.evidence_sufficiency,
            "rationale_quality": semantic_analysis.rationale_quality,
            "recommended_verdict": semantic_analysis.recommended_verdict.verdict.value,
            "recommended_verdict_confidence": (
                semantic_analysis.recommended_verdict.confidence
            ),
            "matched_policy_clause_ids": list(
                semantic_analysis.matched_policy_clause_ids
            ),
            "uncertainty_flags": list(semantic_analysis.uncertainty_flags),
            "has_any_evidence": semantic_analysis.has_any_evidence,
            "has_low_confidence_dimension": (
                semantic_analysis.has_low_confidence_dimension
            ),
            "dimension_scores": dict(semantic_analysis.dimension_scores),
            "dimension_confidences": dict(semantic_analysis.dimension_confidences),
            "metadata": dict(semantic_analysis.metadata),
        }

    @staticmethod
    def _summarize_routing(routing_result: RoutingResult) -> dict[str, Any]:
        return {
            "verdict": routing_result.verdict.value,
            "confidence": routing_result.confidence,
            "final_score": routing_result.final_score,
            "finding_count": len(routing_result.findings),
            "reason_count": len(routing_result.reasons),
            "uncertainty_flag_count": len(routing_result.uncertainty_flags),
            "scores": dict(routing_result.scores),
            "reasons": list(routing_result.reasons),
            "uncertainty_flags": list(routing_result.uncertainty_flags),
        }

    @staticmethod
    def _request_fingerprint(
        *,
        request: EvaluationRequest,
        policy: PolicySnapshot,
        content_sha256: str,
    ) -> str:
        raw = "|".join(
            (
                str(request.request_id),
                request.action_type,
                request.channel,
                request.environment,
                request.recipient or "",
                policy.policy_id,
                policy.version,
                request.requested_at.isoformat(),
                content_sha256,
            )
        )
        return PolicyDecisionPoint._sha256_hex(raw)

    @staticmethod
    def _build_content_excerpt(content: str, limit: int = 400) -> str:
        normalized = " ".join(content.strip().split())
        if len(normalized) <= limit:
            return normalized
        return normalized[: limit - 1].rstrip() + "…"

    @staticmethod
    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _serialize_retrieval_context(
        retrieval_context: RetrievalContext,
    ) -> dict[str, object]:
        """
        Produces a compact retrieval summary for durable storage.

        Decision intentionally keeps retrieval_context generic for now. This
        preserves the contract without hard-coupling persistence to the full
        retrieval schema too early.
        """
        return {
            "is_empty": retrieval_context.is_empty,
            "policy_clause_ids": list(retrieval_context.matched_policy_clause_ids),
            "entity_names": list(retrieval_context.matched_entity_names),
            "precedent_decision_ids": [
                str(precedent.decision_id) for precedent in retrieval_context.precedents
            ],
            "retrieval_warnings": list(retrieval_context.retrieval_warnings),
            "policy_clause_count": len(retrieval_context.policy_clauses),
            "precedent_count": len(retrieval_context.precedents),
            "entity_count": len(retrieval_context.entities),
            "retrieved_at": retrieval_context.retrieved_at.isoformat(),
            "metadata": dict(retrieval_context.metadata),
        }

    @staticmethod
    def _stringify_optional_enum(value: object) -> str | None:
        if value is None:
            return None

        enum_value = getattr(value, "value", None)
        if isinstance(enum_value, str):
            return enum_value

        if isinstance(value, str):
            return value

        return str(value)


def build_default_pdp() -> PolicyDecisionPoint:
    """Returns Tex's default local PDP stack."""
    return PolicyDecisionPoint()


def _elapsed_ms(start: float) -> float:
    """Return elapsed wall-clock time in milliseconds since ``start``."""
    return (time.perf_counter() - start) * 1000.0


def _neutral_agent_bundle() -> AgentEvaluationBundle:
    """
    Build a neutral agent bundle for evaluations that have no agent
    context wired in (no agent_id on the request, or no agent
    evaluator registered with the PDP).

    The router treats a neutral bundle as "agent absent" and renormalizes
    fusion weights back to the original four content layers so behavior
    on the no-agent path reproduces pre-fusion Tex bit-for-bit.
    """
    return AgentEvaluationBundle(
        agent_present=False,
        agent_id=None,
        identity=neutral_identity_signal(),
        capability=neutral_capability_signal(),
        behavioral=neutral_behavioral_signal(),
    )


PDPResult.model_rebuild()
