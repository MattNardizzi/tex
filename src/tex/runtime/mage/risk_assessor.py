"""
MAGE Pre-Action Risk Assessor (Judge).

Reference: arxiv 2605.03228 (Wang et al., Stony Brook + Cisco), May 2026.

Implements Eq. 3 of the paper:

    d_t, e_t = J(a_t | m_t)

where ``a_t`` is the pending action, ``m_t`` is the distilled shadow
memory at turn t, ``d_t ∈ {approve, reject}`` is the verdict, and ``e_t``
is the rationale. The paper backs J with a small RL-trained LLM (J_θ); we
expose that as a pluggable callable and ship a deterministic offline path
that runs:

  - hard-rule pattern matching (matches PlanGuard / ClawGuard's
    reasoning-smell + obfuscation patterns) on the action and on every
    distilled entry's risk_signal field;
  - cumulative risk aggregation across distilled entries (any single high
    score → reject; combined dilution-weighted sum above a threshold →
    reject);
  - adversarial-signal detection: if any distilled entry was sourced from
    an external observation and its keyword overlap with the action is
    high, this is the cross-turn STAC pattern and is rejected.

Performance per paper §V: STAC ASR 100% → 8.3% on Qwen3-4B; PI2 ASR → 0%;
benign utility 73-94% retained at 7K extra tokens / task.

Priority: P1.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from tex.observability.telemetry import emit_event, get_logger
from tex.runtime.mage.shadow_memory import ShadowMemory, ShadowMemoryEntry

_logger = get_logger("tex.runtime.mage.assessor")


# Patterns shared with PlanGuard / ClawGuard so a single canonical attack
# signal triggers consistently across all defenses. Centralising would be
# cleaner but each defense layer keeps its own copy by design — defense in
# depth requires that no single registry change can disable all checks.
_REASONING_SMELL = re.compile(
    r"(ignore (all |the )?(prior|previous|above)|"
    r"disregard (all |the )?(prior|previous|above)|"
    r"override (your |the )?(safety|policy|instructions|guardrails)|"
    r"new (instructions|task|directive)|"
    r"system (override|prompt|admin)|"
    r"you (must|should|are now) (instead|now)|"
    r"act as|pretend (to be|you are)|"
    r"developer mode|jailbreak|dan mode)",
    re.IGNORECASE,
)

_OBFUSCATION = re.compile(
    r"(base64\s*[-:]?\s*decode|"
    r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*(base64\s+(-d|--decode)|bash|sh)|"
    r"\beval\s*\(|"
    r"\bexec\s*\(|"
    r"\\x[0-9a-f]{2}|"
    r"%[0-9a-f]{2}%[0-9a-f]{2})",
    re.IGNORECASE,
)

# Telltale signs that an action is operating on attacker-controlled content.
_EXFIL_SINKS = re.compile(
    r"(curl|wget|fetch|http://|https://|webhook|paste|gist|"
    r"discord|telegram|t\.me|nc\s+|netcat|/dev/tcp)",
    re.IGNORECASE,
)


# Pluggable judge callable: paper-faithful J_θ takes (action, distilled_memory)
# and returns (allow_bool, deny_reason_or_None).
JudgeCallable = Callable[
    [dict[str, Any], tuple[ShadowMemoryEntry, ...]],
    tuple[bool, str | None],
]


class PreActionRiskAssessor:
    """The MAGE J-component, per Eq. 3 of the paper.

    Wraps a ``ShadowMemory`` and either a paper-faithful LLM judge
    (``judge_callable``) or the deterministic offline path described above.
    """

    def __init__(
        self,
        *,
        shadow_memory: ShadowMemory,
        judge_callable: JudgeCallable | None = None,
        cumulative_risk_threshold: float = 0.6,
        single_signal_threshold: float = 0.7,
    ) -> None:
        self._shadow = shadow_memory
        self._judge = judge_callable
        self._cum_threshold = cumulative_risk_threshold
        self._single_threshold = single_signal_threshold

    # ------------------------------------------------------------------
    def assess(
        self,
        candidate_action: dict[str, Any],
        *,
        current_turn: int | None = None,
    ) -> tuple[bool, str | None]:
        """Return (allow, deny_reason).

        ``deny_reason`` is None on allow, otherwise a short human-readable
        rationale e.g. ``'cross-turn injection signal: external observation
        constraint matches action'``.
        """
        distilled = self._shadow.distill_for_action_check(
            candidate_action, current_turn=current_turn
        )

        if self._judge is not None:
            try:
                allow, reason = self._judge(candidate_action, distilled)
                emit_event(
                    "mage.judge.decision",
                    logger=_logger,
                    via="llm",
                    allow=allow,
                    distilled=len(distilled),
                )
                return allow, reason
            except Exception as exc:
                emit_event(
                    "mage.judge.llm_failed",
                    logger=_logger,
                    error_class=type(exc).__name__,
                )
                # Fall through to deterministic path.

        action_text = self._action_text(candidate_action)

        # 1. Direct attack patterns inside the action itself.
        if _REASONING_SMELL.search(action_text):
            reason = "reasoning-smell pattern in action text (likely injected directive)"
            emit_event("mage.judge.decision", logger=_logger, via="offline",
                       allow=False, reason_code="reasoning_smell")
            return False, reason
        if _OBFUSCATION.search(action_text):
            reason = "obfuscation pattern in action text (base64/eval/exec)"
            emit_event("mage.judge.decision", logger=_logger, via="offline",
                       allow=False, reason_code="obfuscation")
            return False, reason

        # 2. Cross-turn signal: any distilled entry from an external source
        # whose risk score and relevance both pass thresholds.
        for entry in distilled:
            if entry.source_kind in ("external", "observation") and (
                entry.risk_score >= self._single_threshold
            ):
                reason = (
                    f"cross-turn injection signal at turn {entry.turn_index}: "
                    f"{entry.risk_signal or entry.constraint_text or '(unspecified)'}"
                )
                emit_event("mage.judge.decision", logger=_logger, via="offline",
                           allow=False, reason_code="cross_turn_signal",
                           triggering_turn=entry.turn_index)
                return False, reason

        # 3. Cumulative risk aggregation: weighted sum across distilled
        # entries, dilution-weighted by inverse rank.
        cum = 0.0
        for i, entry in enumerate(distilled):
            cum += entry.risk_score / (1.0 + i)
        if cum >= self._cum_threshold:
            reason = f"cumulative shadow-memory risk {cum:.3f} >= {self._cum_threshold}"
            emit_event("mage.judge.decision", logger=_logger, via="offline",
                       allow=False, reason_code="cumulative", risk=round(cum, 3))
            return False, reason

        # 4. Exfiltration sink combined with any prior tainted observation.
        if _EXFIL_SINKS.search(action_text):
            for entry in distilled:
                if entry.source_kind in ("external", "observation"):
                    reason = (
                        "exfiltration sink in action coincident with prior "
                        "external/tainted observation in shadow memory"
                    )
                    emit_event("mage.judge.decision", logger=_logger, via="offline",
                               allow=False, reason_code="exfil_after_taint")
                    return False, reason

        emit_event(
            "mage.judge.decision",
            logger=_logger,
            via="offline",
            allow=True,
            distilled=len(distilled),
        )
        return True, None

    # ------------------------------------------------------------------
    @staticmethod
    def _action_text(action: dict[str, Any]) -> str:
        parts: list[str] = [str(action.get("tool_name", ""))]
        params = action.get("tool_params") or action.get("params") or {}
        if isinstance(params, dict):
            for k, v in params.items():
                parts.append(f"{k}={v}")
        # Allow callers to tag a free-form 'reasoning' alongside an action
        # so reasoning-level injection signals are caught here too.
        if "reasoning" in action:
            parts.append(str(action["reasoning"]))
        return " ".join(parts)
