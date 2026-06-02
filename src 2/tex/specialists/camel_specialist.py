"""
CamelSpecialist — exposes CaMeL capability-tracking decisions to the PDP.

When the request carries a CaMeL plan (in ``request.metadata['camel_plan']``)
plus an untrusted-env (``request.metadata['camel_untrusted_env']``), this
specialist:

1. Builds an interpreter over the configured tool-policy registry.
2. Runs the plan.
3. Inspects the trace for halts. A policy-denied tool call surfaces
   as FORBID weight (risk 1.0). A successful execution with all
   tool-call capabilities within policy surfaces as PERMIT (risk 0.0).
4. If no CaMeL plan is provided, the specialist abstains (risk 0.0,
   confidence 0.0).

This is the first PDP specialist that integrates dual-LLM execution
into a single, deterministic verdict — competitors ship either
isolation (Microsoft Agent 365) or policy enforcement (Zenity) but
not both fused on one chain.

ASI mapping
-----------
- Halt on tool-policy denial → ASI09 (Information Leakage) and ASI06
  (Identity Spoofing) prevention.
"""

from __future__ import annotations

from typing import Any

from tex.camel.interpreter import (
    CamelInterpreter,
    CamelInterpreterError,
    ExecutionTrace,
)
from tex.camel.plan import Plan
from tex.camel.policy import ToolPolicyRegistry
from tex.camel.q_llm import QuarantinedLLM, StubQuarantinedLLM
from tex.camel.value import CapValue
from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.base import SpecialistEvidence, SpecialistResult


class CamelSpecialist:
    """CaMeL capability interpreter as a PDP specialist."""

    name: str = "camel"

    def __init__(
        self,
        *,
        tool_policies: ToolPolicyRegistry | None = None,
        tool_impls: dict[str, Any] | None = None,
        q_llm: QuarantinedLLM | None = None,
    ) -> None:
        # If no policies supplied, build an empty frozen registry. This
        # makes the default behavior fail-closed: every tool call gets
        # the TRUSTED-only auto-policy.
        if tool_policies is None:
            tool_policies = ToolPolicyRegistry().freeze()
        elif not tool_policies.is_frozen:
            tool_policies = tool_policies.freeze()
        self._tool_policies = tool_policies
        self._tool_impls = dict(tool_impls or {})
        self._q_llm = q_llm or StubQuarantinedLLM()

    @property
    def tool_policies(self) -> ToolPolicyRegistry:
        return self._tool_policies

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        metadata = getattr(request, "metadata", None) or {}
        plan_obj: Plan | None = None
        untrusted_env: dict[str, str] = {}
        user_prompt = ""

        if isinstance(metadata, dict):
            plan_obj = metadata.get("camel_plan")
            untrusted_env = dict(metadata.get("camel_untrusted_env") or {})
            user_prompt = str(metadata.get("camel_user_prompt") or "")

        if plan_obj is None or not isinstance(plan_obj, Plan):
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                summary="CaMeL specialist abstaining: no plan supplied in request metadata",
                rationale="The request did not carry a CaMeL Plan object; "
                "capability tracking was not exercised.",
                uncertainty_flags=("no_plan",),
            )

        interp = CamelInterpreter(
            tool_policies=self._tool_policies,
            tool_impls=self._tool_impls,
            q_llm=self._q_llm,
            untrusted_env=untrusted_env,
        )

        try:
            final_value, trace = interp.run(plan_obj, user_prompt=user_prompt)
        except CamelInterpreterError as exc:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=1.0,
                confidence=1.0,
                summary=f"CaMeL interpreter rejected the plan: {exc}",
                rationale="The capability-tracking interpreter halted "
                "before completing the plan; fail-closed.",
                uncertainty_flags=("interpreter_error",),
            )

        return self._to_specialist_result(final_value, trace)

    @staticmethod
    def _to_specialist_result(
        final: CapValue, trace: ExecutionTrace
    ) -> SpecialistResult:
        if trace.halted:
            risk = 1.0
            summary = (
                f"CaMeL plan halted on capability check: {trace.halt_reason}"
            )
        elif final.is_untrusted:
            risk = 0.5
            summary = (
                "CaMeL plan completed but final value is UNTRUSTED-tainted "
                f"(sources: {', '.join(trace.final_sources)})"
            )
        else:
            risk = 0.0
            summary = (
                f"CaMeL plan completed with final capability "
                f"{trace.final_level}"
            )

        evidence: list[SpecialistEvidence] = []
        for entry in trace.entries[:12]:
            evidence.append(
                SpecialistEvidence(
                    text=(
                        f"[{entry.node_index}] {entry.op} -> "
                        f"{entry.target or '_'} ({entry.cap_level})"
                    ),
                    explanation=(entry.note or "capability propagation")[:900],
                )
            )

        return SpecialistResult(
            specialist_name="camel",
            risk_score=risk,
            confidence=1.0,
            summary=summary,
            rationale=(
                f"CaMeL interpreter executed {len(trace.entries)} plan node(s). "
                f"final_level={trace.final_level} "
                f"halted={trace.halted}"
            ),
            evidence=tuple(evidence),
        )


__all__ = ["CamelSpecialist"]
