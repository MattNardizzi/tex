from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.deterministic.gate import DeterministicGateResult
from tex.domain.agent_signal import AgentEvaluationBundle
from tex.domain.asi_builder import build_asi_findings
from tex.domain.asi_finding import ASIFinding
from tex.domain.finding import Finding
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.semantic.schema import SemanticAnalysis
from tex.specialists.base import SpecialistBundle


# Keys that belong to the agent fusion group. The router renormalizes
# these out of the weight vector when no agent is present.
_AGENT_WEIGHT_KEYS: tuple[str, ...] = (
    "agent_identity",
    "agent_capability",
    "agent_behavioral",
)
_CONTENT_WEIGHT_KEYS: tuple[str, ...] = (
    "deterministic",
    "specialists",
    "semantic",
    "criticality",
)

# Structural specialists whose mid-band firing promotes to ABSTAIN (R3). These
# are structural defenders, not generic probabilistic scorers — a moderate
# signal from one of them, corroborated by a matched policy clause, is enough
# to withhold an auto-PERMIT. (Thread 4 + 4.5 frontier additions.)
_DEFAULT_STRUCTURAL_SPECIALISTS: frozenset[str] = frozenset(
    {
        "clawguard",
        "mcpshield",
        "planguard",
        "mage",
        "agentarmor",
        "argus",
        "attriguard",
        "vigil",
    }
)


@dataclass(frozen=True, slots=True)
class SelectiveRiskRule:
    """The named constants of Tex's selective-risk verdict rule (R0–R4).

    Every magic number the router used to bury inline lives here, each tied to
    the branch it governs, so the verdict policy is one auditable object rather
    than a scatter of literals. The verdict ladder is strictly precedence-
    ordered and resolves uncertainty toward ABSTAIN:

      * **R0 — structural / deterministic floor.** A deterministic block, an
        agent capability violation (→ FORBID) or an agent quarantine
        (→ ABSTAIN). A *proof over structure*, never a probabilistic score —
        and never fired by a high probabilistic score alone.
      * **R1 — semantic-dominance FORBID override.** A high-confidence semantic
        FORBID on a strong dimension with sufficient evidence.
      * **R2 — score / soft-semantic FORBID escalation.** A soft semantic
        FORBID once the fused score clears PERMIT, or a fused score clearing
        the FORBID threshold on its own.
      * **R3 — ABSTAIN.** Every uncertainty trigger resolves here.
      * **R4 — PERMIT.** Only when positively clean (score within the permit
        region, confidence above the floor, semantic recommends PERMIT);
        otherwise the verdict falls through to ABSTAIN — never a default PERMIT.

    Probabilistic signals can only ever LOWER a verdict toward caution
    (PERMIT → ABSTAIN → FORBID); they never raise one, and R0 stays
    deterministic. This is the trust contract the gate downstream also enforces.
    """

    # R1 — semantic-dominance FORBID override bars.
    semantic_override_confidence: float = 0.85
    semantic_override_dimension: float = 0.90
    semantic_override_evidence: float = 0.40

    # R3 — abstention triggers.
    low_evidence_floor: float = 0.25  # evidence_sufficiency below this (+ score>=permit) → ABSTAIN
    specialist_abstain_risk: float = 0.60  # any specialist >= this (score<forbid) → ABSTAIN
    structural_specialist_risk: float = 0.30  # structural specialist >= this (+clause, score<forbid) → ABSTAIN
    agent_forbid_streak: int = 3  # behavioral forbid streak >= this → ABSTAIN
    agent_cold_start_fraction: float = 0.8  # cold-start abstains at score >= permit * this
    agent_pending_fraction: float = 0.5  # PENDING lifecycle abstains at score >= permit * this

    structural_specialists: frozenset[str] = field(
        default_factory=lambda: _DEFAULT_STRUCTURAL_SPECIALISTS
    )


DEFAULT_SELECTIVE_RISK_RULE = SelectiveRiskRule()


class RoutingResult(BaseModel):
    """
    Structured fusion and routing result for Tex's decision engine.

    This is the output of the routing layer before the final durable decision
    record is created by the PDP.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=1.0)

    reasons: tuple[str, ...] = Field(default_factory=tuple)
    uncertainty_flags: tuple[str, ...] = Field(default_factory=tuple)
    findings: tuple[Finding, ...] = Field(default_factory=tuple)

    scores: dict[str, float] = Field(default_factory=dict)

    asi_findings: tuple[ASIFinding, ...] = Field(
        default_factory=tuple,
        description=(
            "Structured OWASP ASI 2026 findings attributed to this "
            "decision, with evidence trail and verdict-influence "
            "classification."
        ),
    )
    semantic_dominance_override_fired: bool = Field(
        default=False,
        description=(
            "Whether the semantic-dominance override path moved the "
            "verdict to FORBID on this request."
        ),
    )

    @field_validator("reasons", "uncertainty_flags", mode="before")
    @classmethod
    def normalize_string_sequences(cls, value: object) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            raise TypeError("sequence fields must not be plain strings")
        if not isinstance(value, (list, tuple)):
            raise TypeError("sequence fields must be lists or tuples")

        normalized: list[str] = []
        seen: set[str] = set()

        for item in value:
            if not isinstance(item, str):
                raise TypeError("sequence items must be strings")
            candidate = item.strip()
            if not candidate:
                raise ValueError("sequence items must not be blank")
            dedupe_key = candidate.casefold()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            normalized.append(candidate)

        return tuple(normalized)

    @model_validator(mode="after")
    def validate_scores(self) -> "RoutingResult":
        for key, value in self.scores.items():
            if not isinstance(key, str):
                raise TypeError("score keys must be strings")
            if not 0.0 <= value <= 1.0:
                raise ValueError("score values must be between 0.0 and 1.0")
        return self


class DecisionRouter:
    """
    Fuses Tex's upstream signals into a final routed verdict.

    Evaluation order is preserved conceptually:
    - deterministic output is respected first
    - specialist and semantic signals are fused
    - policy criticality is added
    - abstention is treated as first-class, not an afterthought

    The verdict decision itself is the unified R0–R4 selective-risk rule (see
    ``SelectiveRiskRule``); its constants live in ``self._rule``.
    """

    __slots__ = ("_rule",)

    def __init__(self, *, rule: SelectiveRiskRule | None = None) -> None:
        self._rule = rule or DEFAULT_SELECTIVE_RISK_RULE

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
        criticality_score = policy.criticality_for(
            action_type=action_type,
            channel=channel,
            environment=environment,
        )

        deterministic_score = self._deterministic_score(deterministic_result)
        # Cross-specialist fusion: aggregates the bundle through a
        # corroboration-aware rule (pair signals + cascading-failure
        # detection). fused_risk >= max_risk_score always, so this only
        # increases sensitivity. See src/tex/specialists/fusion.py.
        from tex.specialists.fusion import fuse as _fuse_specialists
        _fusion_verdict = _fuse_specialists(specialist_bundle)
        specialist_score = _fusion_verdict.fused_risk
        semantic_score = semantic_analysis.max_dimension_score

        # Agent stream scores. When agent_bundle is None or marks
        # agent_present=False, these are 0.0 — the renormalization
        # path then redistributes the agent weight back to the
        # original four content layers.
        agent_present = agent_bundle is not None and agent_bundle.agent_present
        if agent_present:
            assert agent_bundle is not None
            agent_identity_score = agent_bundle.identity.risk_score
            agent_capability_score = agent_bundle.capability.risk_score
            agent_behavioral_score = agent_bundle.behavioral.risk_score
        else:
            agent_identity_score = 0.0
            agent_capability_score = 0.0
            agent_behavioral_score = 0.0

        final_score = self._fuse_scores(
            deterministic_score=deterministic_score,
            specialist_score=specialist_score,
            semantic_score=semantic_score,
            criticality_score=criticality_score,
            agent_identity_score=agent_identity_score,
            agent_capability_score=agent_capability_score,
            agent_behavioral_score=agent_behavioral_score,
            agent_present=agent_present,
            policy=policy,
        )

        confidence = self._compute_confidence(
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            agent_bundle=agent_bundle,
        )

        semantic_dominance_override_fired = self._semantic_dominance_override_fired(
            semantic_analysis=semantic_analysis,
            deterministic_result=deterministic_result,
        )

        reasons = self._build_reasons(
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            final_score=final_score,
            policy=policy,
            semantic_dominance_override_fired=semantic_dominance_override_fired,
            agent_bundle=agent_bundle,
        )

        uncertainty_flags = self._build_uncertainty_flags(
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            confidence=confidence,
            policy=policy,
            final_score=final_score,
            semantic_dominance_override_fired=semantic_dominance_override_fired,
            agent_bundle=agent_bundle,
        )

        verdict = self._determine_verdict(
            deterministic_result=deterministic_result,
            semantic_analysis=semantic_analysis,
            specialist_bundle=specialist_bundle,
            final_score=final_score,
            confidence=confidence,
            policy=policy,
            uncertainty_flags=uncertainty_flags,
            agent_bundle=agent_bundle,
        )

        asi_findings = build_asi_findings(
            deterministic_result=deterministic_result,
            specialist_bundle=specialist_bundle,
            semantic_analysis=semantic_analysis,
            semantic_dominance_override_fired=semantic_dominance_override_fired,
        )

        # Findings that bubble up to the durable decision = deterministic
        # findings + structural agent findings (capability + identity +
        # behavioral). Specialist and semantic evidence stays inside
        # their own bundles already attached to the PDPResult.
        all_findings: list[Finding] = list(deterministic_result.findings)
        if agent_present and agent_bundle is not None:
            all_findings.extend(agent_bundle.all_findings)

        scores: dict[str, float] = {
            "deterministic": round(deterministic_score, 4),
            "specialists": round(specialist_score, 4),
            "semantic": round(semantic_score, 4),
            "criticality": round(criticality_score, 4),
        }
        if agent_present:
            scores["agent_identity"] = round(agent_identity_score, 4)
            scores["agent_capability"] = round(agent_capability_score, 4)
            scores["agent_behavioral"] = round(agent_behavioral_score, 4)

        return RoutingResult(
            verdict=verdict,
            confidence=round(confidence, 4),
            final_score=round(final_score, 4),
            reasons=reasons,
            uncertainty_flags=uncertainty_flags,
            findings=tuple(all_findings),
            scores=scores,
            asi_findings=asi_findings,
            semantic_dominance_override_fired=semantic_dominance_override_fired,
        )

    def _semantic_dominance_override_fired(
        self,
        *,
        semantic_analysis: SemanticAnalysis,
        deterministic_result: DeterministicGateResult,
    ) -> bool:
        """
        Determine whether the R1 semantic-dominance override path would fire.

        This mirrors the R1 guard inside _determine_verdict exactly — both read
        the same ``self._rule`` constants — so downstream consumers (ASI
        finding classification, reasons, uncertainty flags) all agree on the
        same boolean.

        Returns False when the deterministic gate already blocked, since in
        that case the deterministic floor (R0) wins and the override is not
        what moved the verdict.
        """
        if deterministic_result.blocked:
            return False

        rule = self._rule
        recommendation = semantic_analysis.recommended_verdict
        return (
            recommendation.verdict == Verdict.FORBID
            and recommendation.confidence >= rule.semantic_override_confidence
            and semantic_analysis.max_dimension_score >= rule.semantic_override_dimension
            and semantic_analysis.evidence_sufficiency >= rule.semantic_override_evidence
        )

    def _deterministic_score(self, deterministic_result: DeterministicGateResult) -> float:
        if deterministic_result.blocked:
            return 1.0

        if not deterministic_result.findings:
            return 0.0

        severity_scores = {
            "CRITICAL": 1.0,
            "WARNING": 0.55,
            "INFO": 0.20,
        }

        highest = 0.0
        for finding in deterministic_result.findings:
            highest = max(highest, severity_scores.get(finding.severity.value, 0.0))

        return min(1.0, highest)

    def _fuse_scores(
        self,
        *,
        deterministic_score: float,
        specialist_score: float,
        semantic_score: float,
        criticality_score: float,
        agent_identity_score: float,
        agent_capability_score: float,
        agent_behavioral_score: float,
        agent_present: bool,
        policy: PolicySnapshot,
    ) -> float:
        """
        Fuse the seven evidence streams into a single bounded risk score.

        When `agent_present` is False, the three agent stream weights
        are renormalized into the four content-layer weights so the
        fused score on a content-only request reproduces the original
        Tex behavior exactly. This is the backwards-compatibility
        contract.
        """
        weights = self._effective_weights(policy=policy, agent_present=agent_present)

        fused = (
            deterministic_score * weights["deterministic"]
            + specialist_score * weights["specialists"]
            + semantic_score * weights["semantic"]
            + criticality_score * weights["criticality"]
        )
        if agent_present:
            fused += agent_identity_score * weights["agent_identity"]
            fused += agent_capability_score * weights["agent_capability"]
            fused += agent_behavioral_score * weights["agent_behavioral"]

        return min(1.0, max(0.0, fused))

    @staticmethod
    def _effective_weights(
        *,
        policy: PolicySnapshot,
        agent_present: bool,
    ) -> dict[str, float]:
        """
        Compute the weight vector to actually use for this evaluation.

        - Agent present: return policy weights as-is.
        - Agent absent: zero the agent weights and redistribute their
          mass proportionally across the four content weights so the
          vector still sums to 1.0 and the original ratios are
          preserved.
        """
        weights = dict(policy.fusion_weights)
        if agent_present:
            return weights

        agent_mass = sum(weights.get(k, 0.0) for k in _AGENT_WEIGHT_KEYS)
        if agent_mass <= 0.0:
            # Policy has no agent weights at all; nothing to redistribute.
            for k in _AGENT_WEIGHT_KEYS:
                weights[k] = 0.0
            return weights

        content_mass = sum(weights.get(k, 0.0) for k in _CONTENT_WEIGHT_KEYS)
        if content_mass <= 0.0:
            # Pathological policy: no content weight at all. Distribute
            # agent mass uniformly across the four content keys.
            even = agent_mass / len(_CONTENT_WEIGHT_KEYS)
            for k in _CONTENT_WEIGHT_KEYS:
                weights[k] = weights.get(k, 0.0) + even
        else:
            scale = (content_mass + agent_mass) / content_mass
            for k in _CONTENT_WEIGHT_KEYS:
                weights[k] = weights.get(k, 0.0) * scale

        for k in _AGENT_WEIGHT_KEYS:
            weights[k] = 0.0

        return weights

    def _compute_confidence(
        self,
        *,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        agent_bundle: AgentEvaluationBundle | None,
    ) -> float:
        deterministic_confidence = 0.95 if deterministic_result.blocked else (
            0.75 if deterministic_result.findings else 0.85
        )

        if specialist_bundle.is_empty:
            specialist_confidence = 0.0
        else:
            specialist_confidence = sum(
                result.confidence for result in specialist_bundle.results
            ) / len(specialist_bundle.results)

        semantic_confidence = semantic_analysis.overall_confidence

        # Content-layer base. Identical to pre-fusion behavior.
        base = (
            deterministic_confidence * 0.25
            + specialist_confidence * 0.20
            + semantic_confidence * 0.55
        )

        if semantic_analysis.has_low_confidence_dimension:
            base -= 0.08

        if semantic_analysis.evidence_sufficiency < 0.30:
            base -= 0.05

        # Agent-side confidence contribution. When present, blend in
        # the conservative aggregate confidence of the three agent
        # streams. Capability mismatch flips this to a confidence
        # *boost* because we are highly certain a structural mismatch
        # is real.
        if agent_bundle is not None and agent_bundle.agent_present:
            agent_conf = agent_bundle.aggregate_confidence
            # 80% content / 20% agent contribution.
            base = base * 0.80 + agent_conf * 0.20

            if agent_bundle.has_capability_violations:
                base = min(1.0, base + 0.10)

        return min(1.0, max(0.0, base))

    def _determine_verdict(
        self,
        *,
        deterministic_result: DeterministicGateResult,
        semantic_analysis: SemanticAnalysis,
        specialist_bundle: SpecialistBundle,
        final_score: float,
        confidence: float,
        policy: PolicySnapshot,
        uncertainty_flags: tuple[str, ...],
        agent_bundle: AgentEvaluationBundle | None,
    ) -> Verdict:
        """The unified R0–R4 selective-risk verdict rule.

        A strict precedence ladder (see ``SelectiveRiskRule``). It resolves
        uncertainty toward ABSTAIN: R0–R2 are the FORBID/quarantine escalations,
        R3 is the catch-all ABSTAIN, and R4 emits PERMIT *only* when the
        decision is positively clean — every other path falls through to
        ABSTAIN, never to a default PERMIT.
        """
        rule = self._rule
        semantic_recommendation = semantic_analysis.recommended_verdict

        # ── R0 — structural / deterministic floor (a proof, not a score) ──
        # A deterministic block is a structural FORBID. An agent quarantine
        # routes everything that agent produces to human review (ABSTAIN) until
        # cleared; an agent capability violation is the agent-surface analogue
        # of a deterministic block (FORBID). None of these is a probabilistic
        # score — they are deterministic and cannot be fired by a high score.
        if deterministic_result.blocked:
            return Verdict.FORBID
        if agent_bundle is not None and agent_bundle.agent_present:
            if agent_bundle.identity.lifecycle_status == "QUARANTINED":
                return Verdict.ABSTAIN
            if agent_bundle.has_capability_violations:
                return Verdict.FORBID

        # ── R1 — semantic-dominance FORBID override ──
        # When the semantic layer confidently recommends FORBID on a strong
        # dimension with sufficient evidence, route to FORBID regardless of the
        # fused score. This prevents the "obvious violation buried in ABSTAIN"
        # failure mode where deterministic and specialist layers both miss a
        # novel attack (e.g. wire-fraud language with no keyword match) that the
        # semantic layer correctly flags at high confidence.
        if (
            semantic_recommendation.verdict == Verdict.FORBID
            and semantic_recommendation.confidence >= rule.semantic_override_confidence
            and semantic_analysis.max_dimension_score >= rule.semantic_override_dimension
            and semantic_analysis.evidence_sufficiency >= rule.semantic_override_evidence
        ):
            return Verdict.FORBID

        # ── R2 — score / soft-semantic FORBID escalation ──
        # A softer semantic FORBID (below the R1 bar) escalates once the fused
        # score clears the permit threshold; otherwise a low-evidence semantic
        # FORBID with weak corroboration falls through to ABSTAIN. A fused score
        # crossing the forbid threshold on its own is also a FORBID.
        if (
            semantic_recommendation.verdict == Verdict.FORBID
            and final_score >= policy.permit_threshold
        ):
            return Verdict.FORBID
        if final_score >= policy.forbid_threshold:
            return Verdict.FORBID

        # ── R3 — ABSTAIN (every uncertainty trigger resolves here) ──
        if self._should_abstain(
            semantic_analysis=semantic_analysis,
            specialist_bundle=specialist_bundle,
            final_score=final_score,
            confidence=confidence,
            policy=policy,
            uncertainty_flags=uncertainty_flags,
            agent_bundle=agent_bundle,
        ):
            return Verdict.ABSTAIN

        # ── R4 — PERMIT only if positively clean; else ABSTAIN ──
        if (
            final_score <= policy.permit_threshold
            and confidence >= policy.minimum_confidence
            and semantic_recommendation.verdict == Verdict.PERMIT
        ):
            return Verdict.PERMIT
        return Verdict.ABSTAIN

    def _should_abstain(
        self,
        *,
        semantic_analysis: SemanticAnalysis,
        specialist_bundle: SpecialistBundle,
        final_score: float,
        confidence: float,
        policy: PolicySnapshot,
        uncertainty_flags: tuple[str, ...],
        agent_bundle: AgentEvaluationBundle | None,
    ) -> bool:
        """R3 — the uncertainty triggers. Any one firing routes to ABSTAIN.

        Every constant is named in ``self._rule``; the triggers themselves are
        unchanged. They share one shape: a probabilistic or evidential signal
        that is not strong enough to FORBID but too uncertain to auto-PERMIT.
        """
        rule = self._rule

        if semantic_analysis.recommended_verdict.verdict == Verdict.ABSTAIN:
            return True

        if confidence < policy.minimum_confidence:
            return True

        if semantic_analysis.has_low_confidence_dimension:
            return True

        if (
            semantic_analysis.evidence_sufficiency < rule.low_evidence_floor
            and final_score >= policy.permit_threshold
        ):
            return True

        if (
            specialist_bundle.max_risk_score >= rule.specialist_abstain_risk
            and final_score < policy.forbid_threshold
        ):
            return True

        # Frontier structural specialists firing in the mid-band should promote
        # to ABSTAIN even when other layers see nothing. The paper SOTA numerics
        # (arxiv 2604.10134 §IV, 2605.03228 §5, 2603.10749, 2601.05755,
        # 2605.03378, 2604.11790, 2604.05969) are specialist-level, not
        # pipeline-fused; without this rule the specialist signal is diluted to
        # PERMIT by zero-scoring downstream layers. Benign-traffic calibration
        # is preserved because these specialists return floor (0.05) on benign
        # content and a matched policy clause is required.
        for spec in specialist_bundle.results:
            if (
                spec.specialist_name in rule.structural_specialists
                and spec.risk_score >= rule.structural_specialist_risk
                and spec.matched_policy_clause_ids
                and final_score < policy.forbid_threshold
            ):
                return True

        if any(flag.casefold() == "no_retrieval_context" for flag in uncertainty_flags):
            if final_score >= policy.permit_threshold:
                return True

        if policy.permit_threshold < final_score < policy.forbid_threshold:
            return True

        # Agent-side abstain triggers.
        if agent_bundle is not None and agent_bundle.agent_present:
            # On a forbid streak, abstain even if content is clean — something
            # upstream is wrong with the agent.
            if agent_bundle.behavioral.forbid_streak >= rule.agent_forbid_streak:
                return True

            # Cold-start agents on borderline content abstain.
            if (
                agent_bundle.behavioral.cold_start
                and final_score >= policy.permit_threshold * rule.agent_cold_start_fraction
            ):
                return True

            # PENDING lifecycle abstains on anything not clearly clean.
            if (
                agent_bundle.identity.lifecycle_status == "PENDING"
                and final_score >= policy.permit_threshold * rule.agent_pending_fraction
            ):
                return True

        return False

    def _build_reasons(
        self,
        *,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        final_score: float,
        policy: PolicySnapshot,
        semantic_dominance_override_fired: bool,
        agent_bundle: AgentEvaluationBundle | None,
    ) -> tuple[str, ...]:
        reasons: list[str] = []

        if deterministic_result.blocked:
            reasons.extend(deterministic_result.blocking_reasons)

        if deterministic_result.findings and not deterministic_result.blocked:
            reasons.append(
                f"Deterministic layer produced {len(deterministic_result.findings)} finding(s)."
            )

        if not specialist_bundle.is_empty:
            highest_specialist = max(
                specialist_bundle.results,
                key=lambda result: result.risk_score,
            )
            reasons.append(
                f"Highest specialist risk came from {highest_specialist.specialist_name} "
                f"({highest_specialist.risk_score:.2f})."
            )

        reasons.append(
            f"Semantic layer recommended {semantic_analysis.recommended_verdict.verdict.value} "
            f"with confidence {semantic_analysis.recommended_verdict.confidence:.2f}."
        )
        reasons.append(
            f"Fused final score was {final_score:.2f} "
            f"(permit <= {policy.permit_threshold:.2f}, forbid >= {policy.forbid_threshold:.2f})."
        )

        if semantic_analysis.matched_policy_clause_ids:
            reasons.append(
                f"Matched {len(semantic_analysis.matched_policy_clause_ids)} policy clause(s) in semantic analysis."
            )

        if semantic_dominance_override_fired:
            semantic_recommendation = semantic_analysis.recommended_verdict
            reasons.append(
                "Semantic dominance override engaged: "
                f"max_dimension={semantic_analysis.max_dimension_score:.2f}, "
                f"recommendation_confidence={semantic_recommendation.confidence:.2f}."
            )

        # Agent reasons. Surface a compact summary of why each agent
        # stream contributed what it did, so the durable decision is
        # self-explanatory in audit.
        if agent_bundle is not None and agent_bundle.agent_present:
            if agent_bundle.identity.reasons:
                reasons.append(
                    "Agent identity: "
                    + " | ".join(agent_bundle.identity.reasons[:3])
                )
            if agent_bundle.capability.reasons:
                reasons.append(
                    "Agent capability: "
                    + " | ".join(agent_bundle.capability.reasons[:3])
                )
            if agent_bundle.behavioral.reasons:
                reasons.append(
                    "Agent behavioral: "
                    + " | ".join(agent_bundle.behavioral.reasons[:3])
                )
            reasons.append(
                f"Agent stream scores: identity={agent_bundle.identity.risk_score:.2f}, "
                f"capability={agent_bundle.capability.risk_score:.2f}, "
                f"behavioral={agent_bundle.behavioral.risk_score:.2f}."
            )

        return tuple(reasons)

    def _build_uncertainty_flags(
        self,
        *,
        deterministic_result: DeterministicGateResult,
        specialist_bundle: SpecialistBundle,
        semantic_analysis: SemanticAnalysis,
        confidence: float,
        policy: PolicySnapshot,
        final_score: float,
        semantic_dominance_override_fired: bool,
        agent_bundle: AgentEvaluationBundle | None,
    ) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()

        def add(flag: str) -> None:
            key = flag.casefold()
            if key in seen:
                return
            seen.add(key)
            ordered.append(flag)

        for flag in semantic_analysis.uncertainty_flags:
            add(flag)

        for flag in semantic_analysis.recommended_verdict.uncertainty_flags:
            add(flag)

        for flag in specialist_bundle.uncertainty_flags:
            add(flag)

        if deterministic_result.findings and not deterministic_result.blocked:
            add("deterministic_findings_present")

        if confidence < policy.minimum_confidence:
            add("confidence_below_policy_minimum")

        if semantic_analysis.has_low_confidence_dimension:
            add("low_confidence_semantic_dimension")

        if semantic_analysis.evidence_sufficiency < 0.25:
            add("weak_semantic_evidence")

        if policy.permit_threshold < final_score < policy.forbid_threshold:
            add("borderline_fused_score")

        if semantic_dominance_override_fired:
            add("semantic_dominance_override")

        # Agent uncertainty flags.
        if agent_bundle is not None and agent_bundle.agent_present:
            for flag in agent_bundle.all_uncertainty_flags:
                add(flag)

        # ASI tags are no longer emitted here. They are surfaced as
        # first-class structured ``asi_findings`` on the RoutingResult
        # instead. uncertainty_flags is reserved for fusion / confidence
        # diagnostics.
        return tuple(ordered)


def build_default_router() -> DecisionRouter:
    """Convenience constructor for the default decision router."""
    return DecisionRouter()