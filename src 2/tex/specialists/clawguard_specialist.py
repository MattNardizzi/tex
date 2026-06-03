"""
ClawGuard Specialist Judge.

Wraps the ClawGuard runtime boundary enforcer (src/tex/runtime/clawguard/) as
a specialist judge that participates in Layer 3 of Tex's six-layer PDP
pipeline. The boundary enforcer's deterministic verdicts (DENY/ALLOW/
AMBIGUOUS) are converted into structured SpecialistResult evidence that the
SpecialistBundle aggregator and downstream router consume.

Reference
---------
- arxiv 2604.11790v1 (ClawGuard, Zhao et al., 13 Apr 2026)

  Three primary IPI attack channels the paper enumerates:
    1. Web and local content injection
    2. MCP server injection
    3. Skill file injection
  Defended by user-confirmed rule sets at every tool-call boundary.
  Reports AgentDojo IPI ASR 0.6-3.1% → 0.0%; MCPSafeBench 36.5-46.1%
  → 7.1-11.2% across five SOTA LLMs.

Frontier delta (FRONTIER_DELTA_thread_4.md §1.3, §6)
----------------------------------------------------
ARGUS (arxiv 2605.03378, May 5 2026) provides "provenance-aware decision
auditing" — newer than ClawGuard and orthogonal. We surface ARGUS-style
provenance reason codes here for content patterns ClawGuard would flag as
boundary violations driven by untrusted observation propagation. The full
ARGUS influence-provenance graph stays in AgentArmorSpecialist where the
PDG is already constructed.

Hybrid aggregation
------------------
This specialist short-circuits to high risk_score on deterministic DENY
verdicts. The PDP semantic-fusion layer treats high-risk specialist signal
as forbid-class. PlanGuard/MAGE/AgentArmor specialists vote into the
aggregate; this one and McpShieldSpecialist are deterministic-DENY-class.

Priority
--------
P0 — ships in the live request path for /v1/guardrail.
"""

from __future__ import annotations

import re
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_GOAL_HIJACK,
    ASI_MEMORY_POISONING,
    ASI_SUPPLY_CHAIN,
    ASI_TOOL_MISUSE,
    ASI_UNEXPECTED_CODE_EXECUTION,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.runtime.clawguard.boundary_enforcer import ToolCallBoundaryEnforcer
from tex.runtime.clawguard.rule_set import (
    BaseRuleSet,
    Rule,
    RuleAction,
    RuleDomain,
    TaskRuleSet,
)
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── Indirect prompt injection lexical signals (paper §II, §III-A.1) ──────
#
# These are the classic IPI markers that appear in tool-returned content
# the agent treats as trusted observation. Detection is in addition to the
# rule-evaluator boundary check so that even content that does NOT yet
# include a tool-call attempt is flagged as an IPI signal.

_IPI_INSTRUCTION_INJECTION_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "ignore prior instructions",
    "disregard previous instructions",
    "disregard all instructions",
    "override previous instructions",
    "override your instructions",
    "new system prompt",
    "new instructions:",
    "updated instructions:",
    "important: from now on",
    "you are now",
    "your new role is",
    "your new instructions are",
    "respond in the following format only",
    "do not reveal these instructions",
    "system override",
    "developer mode enabled",
    "jailbreak",
    "dan mode",
)

_IPI_TOOL_HIJACK_PATTERNS: tuple[str, ...] = (
    "call this tool",
    "call the following tool",
    "invoke the tool",
    "execute this tool",
    "use this api",
    "fetch this url",
    "send this email",
    "transfer the funds",
    "delete the file",
    "delete all files",
    # Path traversal + sensitive-system-path access (InjecAgent Type II)
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\windows\\system32",
    ".ssh/id_rsa",
    ".aws/credentials",
    "/proc/self/environ",
)

_IPI_OBSERVATION_TRUST_PATTERNS: tuple[str, ...] = (
    "from the document:",
    "as the user requested,",
    "the user has authorized",
    "the user pre-approved",
    "user has approved this action",
    "user has authorized this transfer",
    "pre-authorized by user",
)

# Skill file injection markers (paper §II.C). Skills are arbitrary
# content files an agent loads at session init; the paper documents
# this as the third primary attack channel.
_SKILL_INJECTION_PATTERNS: tuple[str, ...] = (
    "skill description override",
    "tool description override",
    "hidden in skill metadata",
    "skill metadata override",
    "skill file injection",
    "manifest injection",
    "skill.md inject",
)

# ARGUS-style provenance signal patterns (frontier delta, arxiv 2605.03378).
# These match content where the *justification* for an action is being
# manufactured inside the observation itself — the influence-provenance
# bridge between an untrusted observation and a privileged decision.
_ARGUS_UNJUSTIFIED_DECISION_PATTERNS: tuple[str, ...] = (
    "because the document says",
    "the file confirms that",
    "per the retrieved content",
    "as stated in the tool output",
    "the search result authorizes",
    "the email instructs us to",
)


# ── Scoring constants (calibrated to match existing specialist floors) ───

_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.40
_CONF_PER_HIT = 0.07
_CONF_CAP = 0.88

# Severity weights. Deterministic boundary DENY drives risk to 1.0.
_SEV_INSTRUCTION_INJECTION = 0.38
_SEV_TOOL_HIJACK = 0.34
_SEV_OBSERVATION_TRUST = 0.24
_SEV_SKILL_INJECTION = 0.36
_SEV_ARGUS_PROVENANCE = 0.22
_SEV_BOUNDARY_DENY = 1.00  # short-circuit signal


class ClawGuardSpecialist:
    """
    Specialist wrapping ClawGuard's deterministic boundary enforcement.

    Two parallel detection paths run inside ``evaluate``:

      1. Lexical IPI scan over the action's content. This catches the
         three paper attack channels (web/local content injection, MCP
         server injection, skill file injection) and the ARGUS-style
         influence-provenance "unjustified decision" pattern.

      2. Optional boundary-enforcer dispatch when a tool-call shape is
         embedded in metadata. When the enforcer returns ``deny:*``, the
         risk_score short-circuits to 1.0 with high confidence; this is
         the deterministic-FORBID class signal the PDP semantic layer
         treats as forbid-class.

    The specialist returns risk_floor when no signals match, preserving
    router calibration on benign fixtures.
    """

    name = "clawguard"

    def __init__(
        self,
        *,
        boundary_enforcer: ToolCallBoundaryEnforcer | None = None,
    ) -> None:
        """
        Args:
            boundary_enforcer: Optional pre-configured enforcer. When None,
                a default enforcer with the base rule set is constructed
                lazily on the first tool-call check.
        """
        self._enforcer = boundary_enforcer

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        content = request.content
        lowered = content.casefold()

        all_evidence: list[SpecialistEvidence] = []
        reason_codes: list[str] = []
        asi_tags: list[str] = []
        risk_accum = 0.0

        # 1. Instruction injection (paper attack channel 1: content).
        for code, patterns, weight, asi in (
            (
                "CLAW_INSTRUCTION_INJECTION",
                _IPI_INSTRUCTION_INJECTION_PATTERNS,
                _SEV_INSTRUCTION_INJECTION,
                (ASI_GOAL_HIJACK,),
            ),
            (
                "CLAW_TOOL_HIJACK_IPI",
                _IPI_TOOL_HIJACK_PATTERNS,
                _SEV_TOOL_HIJACK,
                (ASI_TOOL_MISUSE, ASI_GOAL_HIJACK),
            ),
            (
                "CLAW_OBSERVATION_TRUST_VIOLATION",
                _IPI_OBSERVATION_TRUST_PATTERNS,
                _SEV_OBSERVATION_TRUST,
                (ASI_GOAL_HIJACK, ASI_TOOL_MISUSE),
            ),
            (
                "CLAW_SKILL_FILE_INJECTION",
                _SKILL_INJECTION_PATTERNS,
                _SEV_SKILL_INJECTION,
                (ASI_SUPPLY_CHAIN, ASI_GOAL_HIJACK),
            ),
            (
                "CLAW_ARGUS_PROVENANCE_UNJUSTIFIED",
                _ARGUS_UNJUSTIFIED_DECISION_PATTERNS,
                _SEV_ARGUS_PROVENANCE,
                (ASI_GOAL_HIJACK,),
            ),
        ):
            matched = _match_pattern_set(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=code,
            )
            if matched:
                all_evidence.extend(matched)
                reason_codes.append(code)
                risk_accum += weight
                for tag in asi:
                    if tag not in asi_tags:
                        asi_tags.append(tag)

        # 2. Optional boundary-enforcer dispatch on embedded tool-call shape.
        tool_call = _extract_tool_call_from_metadata(request.metadata)
        if tool_call is not None:
            tool_name, tool_input = tool_call
            enforcer = self._enforcer or _default_enforcer()
            allowed, reason = enforcer.check_call(
                tool_name=tool_name, tool_input=tool_input
            )
            if not allowed:
                # Deterministic DENY short-circuit.
                deny_reason = reason or "clawguard:deny"
                all_evidence.append(
                    SpecialistEvidence(
                        text=f"tool_call:{tool_name}",
                        explanation=(
                            f"CLAW_BOUNDARY_DENY: enforcer rejected tool call "
                            f"'{tool_name}' — {deny_reason}"
                        ),
                    )
                )
                reason_codes.append("CLAW_BOUNDARY_DENY")
                # ASI: unauthorized tool invocation primarily maps to ASI02
                # plus ASI05 when the deny reason mentions exec.
                if ASI_TOOL_MISUSE not in asi_tags:
                    asi_tags.append(ASI_TOOL_MISUSE)
                if any(
                    marker in deny_reason.lower()
                    for marker in ("exec", "shell", "rce", "bash", "code_exec", "sh ")
                ):
                    if ASI_UNEXPECTED_CODE_EXECUTION not in asi_tags:
                        asi_tags.append(ASI_UNEXPECTED_CODE_EXECUTION)
                risk_accum = _SEV_BOUNDARY_DENY  # short-circuit overrides accum

        if not reason_codes:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary="No ClawGuard IPI boundary signals detected.",
                rationale=(
                    "Specialist scans for indirect prompt injection per arxiv "
                    "2604.11790: instruction injection, tool-hijack IPI, "
                    "observation-trust violations, skill file injection, and "
                    "ARGUS-style influence-provenance unjustified-decision "
                    "patterns (arxiv 2605.03378). No signals matched."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        risk_score = min(1.0, risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(all_evidence))

        all_evidence.sort(
            key=lambda ev: (
                ev.start_index if ev.start_index is not None else 10**9,
                ev.text.casefold(),
            )
        )
        deduped_codes = _dedupe_preserve_order(reason_codes)
        deduped_asi = _dedupe_preserve_order(asi_tags)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            reason_codes=tuple(deduped_codes),
        )

        summary = (
            f"ClawGuard IPI boundary signals detected: {len(deduped_codes)} "
            f"reason code(s) — {', '.join(deduped_codes)}."
        )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Per arxiv 2604.11790 §III-A, ClawGuard enforces boundary "
                "constraints at every tool-call. This specialist surfaces "
                "the four paper attack channels plus an ARGUS-style "
                "(arxiv 2605.03378) influence-provenance signal as "
                "specialist evidence inside Tex's six-layer pipeline."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple([*deduped_codes, *deduped_asi]),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _default_enforcer() -> ToolCallBoundaryEnforcer:
    """Build a default enforcer with the canonical base rule set.

    Conservative: deny network egress to private RFC1918 ranges and the
    AWS IMDS metadata endpoint by default. Task-rule layer can override.
    """
    base = BaseRuleSet(
        rules=(
            Rule(
                rule_id="claw_base_deny_imds",
                domain=RuleDomain.NET,
                action=RuleAction.DENY,
                pattern=r"169\.254\.169\.254",
                description="Block AWS IMDS metadata endpoint",
            ),
            Rule(
                rule_id="claw_base_deny_rce",
                domain=RuleDomain.CMD,
                action=RuleAction.DENY,
                pattern=r"\b(?:rm\s+-rf\s+/|curl\s+[^|]+\|\s*(?:bash|sh))",
                description="Block destructive root delete and curl-pipe-bash",
            ),
        )
    )
    task = TaskRuleSet(rules=tuple())
    return ToolCallBoundaryEnforcer(base_rules=base, task_rules=task)


def _extract_tool_call_from_metadata(
    metadata: dict[str, Any],
) -> tuple[str, dict[str, Any]] | None:
    """Pull (tool_name, tool_input) out of metadata when present.

    Expected shapes (in priority order):
      metadata['tool_call'] = {'name': str, 'input': dict}
      metadata['proposed_tool_call'] = {'name': str, 'input': dict}
    """
    for key in ("tool_call", "proposed_tool_call"):
        candidate = metadata.get(key)
        if not isinstance(candidate, dict):
            continue
        name = candidate.get("name")
        tool_input = candidate.get("input", {})
        if isinstance(name, str) and name.strip() and isinstance(tool_input, dict):
            return name.strip(), tool_input
    return None


def _match_pattern_set(
    *,
    content: str,
    lowered_content: str,
    keywords: tuple[str, ...],
    reason_code: str,
) -> tuple[SpecialistEvidence, ...]:
    """Find every occurrence of every keyword, tag with the reason code."""
    out: list[SpecialistEvidence] = []
    seen: set[tuple[int, int, str]] = set()
    for keyword in keywords:
        lowered_kw = keyword.casefold()
        if not lowered_kw:
            continue
        start = 0
        while True:
            found_at = lowered_content.find(lowered_kw, start)
            if found_at == -1:
                break
            end = found_at + len(lowered_kw)
            key = (found_at, end, lowered_kw)
            if key not in seen:
                seen.add(key)
                out.append(
                    SpecialistEvidence(
                        text=content[found_at:end],
                        start_index=found_at,
                        end_index=end,
                        explanation=f"{reason_code}: matched pattern '{keyword}'",
                    )
                )
            start = end
    return tuple(out)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _emit(*, request_id: str, risk_score: float, reason_codes: tuple[str, ...]) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "clawguard",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
    }
    emit_event("specialist.clawguard.evaluated", **fields)


__all__ = ["ClawGuardSpecialist"]
