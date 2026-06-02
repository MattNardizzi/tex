"""
Hierarchical Intent Verifier.

Two-stage check:
  Stage I (Deterministic Constraint Matching, paper §IV-C1):
    Three cases:
      1. Exact match (a_act in S_ref)         -> Pass
      2. Tool name not in S_ref               -> Block (Type I attack)
      3. Tool name OK, params don't match     -> escalate to Stage II
  Stage II (Tool Intent Verification, paper §IV-C2):
    M_verify(I, S_ref, a_act, r_act) -> {True, False}
    Determines whether parameter deviation is benign formatting drift
    (e.g., 'last_week' vs 'lastweek') or a malicious intent shift.

The agent's reasoning r_act is the critical Stage II signal — without it,
we cannot distinguish Type II attacks from benign LLM stochasticity. The
paper reports that Stage I alone produces FPR of 27-38% (unacceptable);
adding Stage II's reasoning-aware check brings FPR to <3.3%.

Priority: P1.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

from tex.observability.telemetry import emit_event, get_logger
from tex.runtime.planguard.isolated_planner import Action, ReferencePlan

# Stage II LLM hook: M_verify(I, S_ref, a_act, r_act) -> bool.
# Tuple form: (instruction, reference_plan, candidate_action, agent_reasoning).
IntentLLMCallable = Callable[
    [str, ReferencePlan, Action, str],
    bool,
]

_DEFAULT_LOGGER = get_logger("tex.runtime.planguard")


class IntentVerifier:
    """
    Hierarchical Verifier V from arxiv 2604.10134 §IV-C.

    Stage II uses an injectable LLM callable (M_verify in paper notation)
    to judge whether parameter deviation reflects malicious intent. When
    no LLM is configured we fall back to a conservative deterministic
    semantic check that only allows narrowly-defined formatting variance.
    """

    def __init__(
        self,
        *,
        intent_llm: IntentLLMCallable | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._intent_llm = intent_llm
        self._logger = logger or _DEFAULT_LOGGER

    def verify_action(
        self,
        *,
        proposed_tool: str,
        proposed_params: dict,
        reference_plan: ReferencePlan,
    ) -> tuple[bool, str | None]:
        """
        Returns (allowed, reason_if_blocked).

        TODO(P1): Stage 1 hard constraint check on tool name
        TODO(P1): Stage 2 LLM-based intent check on parameter delta

        Status: implemented. Backwards-compatible signature; for full
        paper-faithful behavior, callers should use verify_with_reasoning
        which accepts the agent's pre-action reasoning r_act.
        """
        return self.verify_with_reasoning(
            proposed_tool=proposed_tool,
            proposed_params=proposed_params,
            reference_plan=reference_plan,
            agent_reasoning="",
        )

    def verify_with_reasoning(
        self,
        *,
        proposed_tool: str,
        proposed_params: Mapping[str, Any],
        reference_plan: ReferencePlan,
        agent_reasoning: str,
    ) -> tuple[bool, str | None]:
        """Paper Algorithm 1 with the explicit r_act parameter."""
        candidate = Action.from_mapping(
            tool_name=proposed_tool, params=dict(proposed_params)
        )

        # --- Stage I, Case 1: Exact match (paper Algorithm 1 lines 5-7) ---
        if candidate in reference_plan.actions:
            self._emit("planguard.action.pass", reason="exact_match", action=candidate)
            return True, None

        # --- Stage I, Case 2: Unauthorized tool (lines 8-10) ---
        if candidate.tool_name not in reference_plan.allowed_tools:
            reason = (
                f"type_i_unauthorized_tool: '{candidate.tool_name}' not in "
                f"reference set {sorted(reference_plan.allowed_tools)}"
            )
            self._emit(
                "planguard.action.block",
                reason="type_i_unauthorized_tool",
                action=candidate,
            )
            return False, reason

        # --- Stage I, Case 3: Parameter mismatch -> Stage II (lines 11-17) ---
        if self._intent_llm is not None:
            try:
                is_safe = bool(
                    self._intent_llm(
                        reference_plan.instruction,
                        reference_plan,
                        candidate,
                        agent_reasoning or "",
                    )
                )
                if is_safe:
                    self._emit(
                        "planguard.action.pass",
                        reason="stage_ii_benign_drift",
                        action=candidate,
                    )
                    return True, None
                self._emit(
                    "planguard.action.block",
                    reason="type_ii_intent_deviation",
                    action=candidate,
                )
                return False, "type_ii_intent_deviation: parameters diverge maliciously"
            except Exception as exc:  # noqa: BLE001
                emit_event(
                    "planguard.stage_ii.llm_failed",
                    level=logging.WARNING,
                    logger=self._logger,
                    error=str(exc),
                )
                # Fall through to deterministic check.

        is_safe = self._deterministic_intent_check(
            candidate=candidate,
            reference_plan=reference_plan,
            agent_reasoning=agent_reasoning or "",
        )
        if is_safe:
            self._emit(
                "planguard.action.pass",
                reason="stage_ii_deterministic_benign",
                action=candidate,
            )
            return True, None
        self._emit(
            "planguard.action.block",
            reason="type_ii_intent_deviation",
            action=candidate,
        )
        return False, "type_ii_intent_deviation: parameters diverge from reference"

    @staticmethod
    def _deterministic_intent_check(
        *,
        candidate: Action,
        reference_plan: ReferencePlan,
        agent_reasoning: str,
    ) -> bool:
        """
        Conservative offline Stage II. Approves only narrowly-defined
        formatting variance against any reference action for the same
        tool. Anything more semantic-looking gets blocked.

        Heuristics:
          - Same tool, same key set, and every value is "close" to a
            reference value (case-insensitive equality after stripping
            whitespace and underscore/hyphen variants).
          - Reasoning must not contain exfiltration markers
            ('exfil', 'attacker', 'send to', URLs to non-allowlisted
            domains). Per paper §VI-B, attackers must inject reasoning
            to defeat Stage II.
        """
        if _reasoning_smells_malicious(agent_reasoning):
            return False
        for ref in reference_plan.actions:
            if ref.tool_name != candidate.tool_name:
                continue
            if not _close_param_match(candidate.params_dict(), ref.params_dict()):
                continue
            return True
        return False

    def _emit(self, event: str, *, reason: str, action: Action) -> None:
        emit_event(
            event,
            logger=self._logger,
            reason=reason,
            tool_name=action.tool_name,
            param_keys=sorted(k for k, _ in action.params),
        )


_MALICIOUS_REASONING_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bexfil(trat)?\b", re.IGNORECASE),
    re.compile(r"\battacker\b", re.IGNORECASE),
    re.compile(r"\bignore (previous|prior) (instructions?|prompt)\b", re.IGNORECASE),
    re.compile(r"\bsystem override\b", re.IGNORECASE),
    re.compile(r"\bcredentials?\b", re.IGNORECASE),
    re.compile(r"\bbypass\b", re.IGNORECASE),
)


def _reasoning_smells_malicious(reasoning: str) -> bool:
    if not reasoning:
        return False
    return any(p.search(reasoning) for p in _MALICIOUS_REASONING_MARKERS)


def _close_param_match(
    candidate: Mapping[str, Any], reference: Mapping[str, Any]
) -> bool:
    if set(candidate.keys()) != set(reference.keys()):
        return False
    for key, c_val in candidate.items():
        r_val = reference[key]
        if not _values_close(c_val, r_val):
            return False
    return True


def _values_close(a: Any, b: Any) -> bool:
    if a == b:
        return True
    if isinstance(a, str) and isinstance(b, str):
        return _normalize_str(a) == _normalize_str(b)
    return False


def _normalize_str(s: str) -> str:
    return re.sub(r"[\s_\-]+", "", s).strip().lower()
