"""
CamelSpecialist — the EVOLVED CaMeL specialist (iter-6 activation).

This is the specialist that runs the **metered** CaMeL interpreter on the real PDP
path. It replaces the iter-0 *static plan-ahead* behaviour: the old specialist only
ever exercised straight-line capability tracking (it had no notion of a metered
``Branch``), so on Tex's recipe traffic — which carries no ``camel_plan`` — it
abstained ~99% of the time and never priced control-flow influence. The retired
static behaviour is preserved in spirit only as the *clean-completion* and
*denial* contract the structural floor keys off; everything the interpreter now
does (CFI cumulative pricing + CHOKE-X per-branch leverage certification + the
signed token grant's three budgets) is the live, beyond-static frontier.

How it fires on the REAL path
-----------------------------
``EvaluateActionCommand.execute()`` compiles a faithful CaMeL plan from the
request's REAL declared untrusted-read-then-branch structure (``camel_branch_flow``,
see ``tex.camel.plan_emission``) and stamps it onto ``request.metadata`` as
``camel_plan`` / ``camel_untrusted_env`` / a bound projector. ``pdp.evaluate`` runs
the default specialist suite (this specialist included) →
``detect_structural_floor`` consumes this specialist's result. So a real request
that genuinely branches over untrusted data produces a real CFI/CHOKE-X verdict on
the live path — no rigging, no synthetic provenance.

Three real signals to the floor / hold
--------------------------------------
1. **HALT → risk 1.0 (FORBID).** A policy-denied tool call, an out-of-domain
   projection, an untyped guard, or any fail-closed interpreter error halts the
   plan → ``risk_score == 1.0`` → the structural floor's existing ``camel`` leg
   short-circuits to FORBID. (The 1.0 ⟺ denial contract is unchanged.)
2. **ABSTAIN → risk 0.5 + flag (CHOKE-X / CFI).** The plan ran to completion but a
   high-stakes ``Branch`` was NOT committed because CHOKE-X certified more attacker
   leverage than its budget, or the cumulative CFI steering budget was exhausted.
   This is deliberate caution, NOT a deny — risk 0.5, an
   ``camel_branch_abstain`` uncertainty flag, and the
   ``branch_leverage`` clause id the ``BranchLeverageSpecialist`` /
   ``apply_branch_leverage_hold`` demote PERMIT→ABSTAIN on.
3. **Clean completion → risk 0.0.** Straight-line / in-budget branching with no
   denial; an UNTRUSTED-tainted-but-completed final is risk 0.5 (unchanged).

The signed token grant
-----------------------
When ``TEX_CAP_TOKEN_ENABLED`` is set and the request carries a verifiable
capability token (plus its PoP proof), the interpreter spends the SIGNED budgets
(steer / branch-leverage) in place of its defaults. Verify-before: an unverifiable
token yields no grant and the interpreter falls back to its generous defaults
(never silently runs on an unverified budget). Default-OFF: with the flag unset no
token is consulted and the budgets are the constructor defaults.

ASI mapping
-----------
- Halt on tool-policy denial → ASI09 (Information Leakage) / ASI06 (Identity
  Spoofing) prevention. Over-budget ABSTAIN → ASI bounded-influence caution.
"""

from __future__ import annotations

import os
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

# Clause ids the structural floor / hold key off (sturdier than a bare score).
CAMEL_HALT_CODE = "camel.interpreter_halt"
CAMEL_BRANCH_ABSTAIN_CODE = "camel.branch_leverage_abstain"
CAMEL_BRANCH_ABSTAIN_FLAG = "camel_branch_abstain"


def _capability_grant_for(request: EvaluationRequest, *, lineage: str) -> Any | None:
    """Verify-before: return the SIGNED three-budget grant when the capability-token
    flag is on AND the request carries a verifiable token (+ PoP proof), else None.

    Default-OFF / no-token / unverifiable-token all yield None → the interpreter
    uses its generous constructor defaults. Never raises; never runs on an
    unverified budget.
    """
    from tex.camel.capability_token import (
        capability_tokens_enabled,
        verify_capability_token,
    )

    if not capability_tokens_enabled():
        return None
    metadata = getattr(request, "metadata", None) or {}
    if not isinstance(metadata, dict):
        return None
    token = metadata.get("camel_capability_token")
    if not isinstance(token, str) or not token.strip():
        return None
    pop_proof = metadata.get("camel_capability_pop_proof")
    pop_proof = pop_proof if isinstance(pop_proof, str) and pop_proof.strip() else None
    audience = metadata.get("camel_capability_audience")
    audience = (
        audience.strip()
        if isinstance(audience, str) and audience.strip()
        else "tex.camel.interpreter"
    )
    try:
        return verify_capability_token(
            token,
            expected_audience=audience,
            pop_proof=pop_proof,
            lineage=lineage,
        )
    except Exception:  # noqa: BLE001 — a verify failure is a no-grant, never a raise
        return None


class CamelSpecialist:
    """The evolved CaMeL capability interpreter as a PDP specialist."""

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
        # An optional per-run projector (the deterministic enum-projection oracle)
        # the faithful plan-emission seam binds to a compiled plan's declared
        # finite domain. When present it is used IN PLACE OF the constructor q_llm
        # so the Q-LLM projection matches the declared domain.
        run_q_llm: QuarantinedLLM = self._q_llm

        if isinstance(metadata, dict):
            plan_obj = metadata.get("camel_plan")
            untrusted_env = dict(metadata.get("camel_untrusted_env") or {})
            user_prompt = str(metadata.get("camel_user_prompt") or "")
            projector = metadata.get("camel_projector")
            if projector is not None and isinstance(projector, QuarantinedLLM):
                run_q_llm = projector

        # When no plan was directly injected on metadata (the legacy path), look for
        # a faithfully-emitted plan in the request-keyed sidecar (the activation seam
        # in evaluate_action stows it there because Plan/projector are not
        # JSON-serializable and the semantic layer JSON-dumps metadata). The sidecar
        # plan carries its OWN untrusted_env (the real request content) + the
        # deterministic projector bound to the declared domain.
        if plan_obj is None or not isinstance(plan_obj, Plan):
            from tex.camel.plan_emission import take_emitted_plan

            emitted = take_emitted_plan(str(getattr(request, "request_id", "") or ""))
            if emitted is not None:
                plan_obj = emitted.plan
                untrusted_env = dict(emitted.untrusted_env)
                user_prompt = emitted.user_prompt
                run_q_llm = emitted.projector

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

        # Verify-before: spend the SIGNED token budgets when present (flag-gated),
        # else the interpreter's generous constructor defaults. Lineage keys the
        # grant to this request's flow.
        lineage = str(getattr(request, "request_id", "") or "default")
        grant = _capability_grant_for(request, lineage=lineage)

        interp = CamelInterpreter(
            tool_policies=self._tool_policies,
            tool_impls=self._tool_impls,
            q_llm=run_q_llm,
            untrusted_env=untrusted_env,
        )

        try:
            final_value, trace = interp.run(
                plan_obj, user_prompt=user_prompt, capability_grant=grant
            )
        except CamelInterpreterError as exc:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=1.0,
                confidence=1.0,
                summary=f"CaMeL interpreter rejected the plan: {exc}",
                rationale="The capability-tracking interpreter halted "
                "before completing the plan; fail-closed.",
                uncertainty_flags=("interpreter_error",),
                matched_policy_clause_ids=(CAMEL_HALT_CODE,),
            )

        return self._to_specialist_result(final_value, trace)

    @staticmethod
    def _to_specialist_result(
        final: CapValue, trace: ExecutionTrace
    ) -> SpecialistResult:
        clause_ids: tuple[str, ...] = ()
        flags: tuple[str, ...] = ()
        if trace.halted:
            risk = 1.0
            clause_ids = (CAMEL_HALT_CODE,)
            summary = (
                f"CaMeL plan halted on capability check: {trace.halt_reason}"
            )
        elif trace.abstained:
            # CHOKE-X over-leverage or CFI cumulative-budget exhaustion: a
            # high-stakes / over-budget branch was NOT committed. This is
            # deliberate caution, NOT a deny → risk 0.5, a flag + clause id the
            # BranchLeverageSpecialist / hold demote PERMIT→ABSTAIN on.
            risk = 0.5
            clause_ids = (CAMEL_BRANCH_ABSTAIN_CODE,)
            flags = (CAMEL_BRANCH_ABSTAIN_FLAG,)
            summary = (
                "CaMeL metered branch ABSTAINED (a high-stakes branch's certified "
                f"attacker leverage exceeded budget, or the cumulative CFI steering "
                f"budget was exhausted): {trace.abstain_reason}"
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
                f"halted={trace.halted} abstained={trace.abstained} "
                f"cfi_bits_spent={trace.cfi_bits_spent}"
            ),
            evidence=tuple(evidence),
            matched_policy_clause_ids=clause_ids,
            uncertainty_flags=flags,
        )


__all__ = [
    "CamelSpecialist",
    "CAMEL_HALT_CODE",
    "CAMEL_BRANCH_ABSTAIN_CODE",
    "CAMEL_BRANCH_ABSTAIN_FLAG",
]
