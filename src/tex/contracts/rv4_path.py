"""
RV4 path-policy bridge — split LTLf path-policy violations into FORBID vs HOLD.

[Architecture: Layer 4 (Execution Governance)]

The existing path-policy layer (``tex.engine.path_policy_bridge``) maps a
policy's *declared severity* to a verdict: ``block`` → FORBID, ``warn`` →
ABSTAIN. That is orthogonal to **whether the violation can still be cured**.
This bridge adds the missing axis using the four-valued RV-LTL classifier
(``tex.governance.path_policy.ltlf.evaluate_rv4``):

  * **PERMANENTLY_VIOLATED (⊥)** — a proven *bad prefix*: no future step can
    satisfy the policy. This is a deterministic proof → **FORBID** (it joins
    the structural floor).
  * **CURRENTLY_VIOLATED (⊥_p)** — violated *now* but still curable by a
    future step (e.g. a pending approval that hasn't happened yet). This is
    uncertainty, not a proof → **ABSTAIN** (a hold).
  * satisfied (⊤ / ⊤_p) — the policy passes.

So the same LTLf formula yields FORBID when the violation is permanent and a
hold when it is recoverable — exactly the distinction the four-valued upgrade
exists to make. This is the doctrinal split: FORBID stands on a proof; an
uncertain (recoverable) state resolves to ABSTAIN.

Opt-in (``request.metadata["rv4_path_policies"]``), shape mirrors the existing
path-policy bridge::

    {"policies": [{"policy_id": "...", "ltl_formula": "G(...)",
                   "description": "..."}],
     "trace": [{"state": {...}, "action": {"tool": "..."}, "observation": {...}}],
     "candidate_action": {"tool": "issue_refund", ...}}   # optional

When absent, ``classify`` returns ``NEUTRAL_RV4_PATH`` — a zero-cost no-op.

Fail-closed posture: a formula that fails to parse is **not** turned into a
fabricated FORBID (a parse error is not a proof of a bad prefix). It resolves
to a RECOVERABLE violation → ABSTAIN, surfacing the misconfiguration to a human
without ever silently passing the action.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from tex.governance.path_policy.ltlf import (
    LtlfParseError,
    RV4Verdict,
    compile_formula,
    evaluate_rv4_compiled,
)
from tex.governance.path_policy.policy import PathStep


_METADATA_KEY = "rv4_path_policies"


@dataclass(frozen=True, slots=True)
class RV4PathViolation:
    """One policy's RV4 violation outcome."""

    policy_id: str
    verdict: RV4Verdict
    formula: str
    reason: str

    @property
    def is_permanent(self) -> bool:
        return self.verdict is RV4Verdict.PERMANENTLY_VIOLATED


@dataclass(frozen=True, slots=True)
class RV4PathOutcome:
    """PDP-shaped result of evaluating the active RV4 path policies."""

    checked: bool
    violations: tuple[RV4PathViolation, ...]

    @property
    def permanent(self) -> tuple[RV4PathViolation, ...]:
        """Violations that are proven bad prefixes → FORBID."""
        return tuple(v for v in self.violations if v.is_permanent)

    @property
    def recoverable(self) -> tuple[RV4PathViolation, ...]:
        """Violations that are still curable → ABSTAIN (a hold)."""
        return tuple(v for v in self.violations if not v.is_permanent)

    @property
    def has_permanent(self) -> bool:
        return any(v.is_permanent for v in self.violations)

    @property
    def has_recoverable(self) -> bool:
        return any(not v.is_permanent for v in self.violations)


NEUTRAL_RV4_PATH = RV4PathOutcome(checked=False, violations=())


def _coerce_step(raw: Any) -> PathStep | None:
    """Coerce one trace entry into a (state, action, observation) tuple."""
    if isinstance(raw, (list, tuple)) and len(raw) == 3:
        state, action, observation = raw
    elif isinstance(raw, Mapping):
        state = raw.get("state", {})
        action = raw.get("action", {})
        observation = raw.get("observation", {})
    else:
        return None
    if (
        isinstance(state, Mapping)
        and isinstance(action, Mapping)
        and isinstance(observation, Mapping)
    ):
        return (dict(state), dict(action), dict(observation))
    return None


def _build_trace(raw: Mapping[str, Any], request: Any) -> list[PathStep]:
    """history + [candidate] — same convention as the path-policy checker."""
    history: list[PathStep] = []
    raw_trace = raw.get("trace", [])
    if isinstance(raw_trace, Sequence) and not isinstance(raw_trace, (str, bytes)):
        for entry in raw_trace:
            step = _coerce_step(entry)
            if step is not None:
                history.append(step)

    candidate = raw.get("candidate_action")
    if isinstance(candidate, Mapping):
        candidate_action: dict[str, object] = dict(candidate)
    else:
        candidate_action = {
            "tool": getattr(request, "action_type", ""),
            "type": getattr(request, "action_type", ""),
            "channel": getattr(request, "channel", ""),
            "recipient": getattr(request, "recipient", None) or "",
        }
    # Candidate position carries empty state + observation (its output is not
    # yet known), matching PathPolicyChecker.check.
    history.append(({}, candidate_action, {}))
    return history


def classify(request: Any) -> RV4PathOutcome:
    """Classify each RV4 path policy on the request into FORBID / HOLD / pass."""
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return NEUTRAL_RV4_PATH
    raw = metadata.get(_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return NEUTRAL_RV4_PATH

    policies = raw.get("policies")
    if not isinstance(policies, Sequence) or not policies:
        return NEUTRAL_RV4_PATH

    trace = _build_trace(raw, request)
    violations: list[RV4PathViolation] = []

    for entry in policies:
        if not isinstance(entry, Mapping):
            continue
        policy_id = entry.get("policy_id")
        formula = entry.get("ltl_formula", "")
        if not isinstance(policy_id, str) or not policy_id.strip():
            continue
        formula = str(formula)
        if not formula.strip():
            # No constraint — nothing to violate.
            continue

        try:
            ast = compile_formula(formula)
        except LtlfParseError as exc:
            # A misconfigured policy is uncertainty, not a proof of a bad
            # prefix → recoverable → ABSTAIN (never a fabricated FORBID).
            violations.append(
                RV4PathViolation(
                    policy_id=policy_id,
                    verdict=RV4Verdict.CURRENTLY_VIOLATED,
                    formula=formula,
                    reason=(
                        f"RV4 path policy '{policy_id}' formula failed to parse "
                        f"({exc}); held for review."
                    ),
                )
            )
            continue

        verdict = evaluate_rv4_compiled(ast, trace)
        if verdict.is_satisfied:
            continue

        if verdict is RV4Verdict.PERMANENTLY_VIOLATED:
            reason = (
                f"RV4 path policy '{policy_id}' is permanently violated "
                f"(bad prefix: no future step can satisfy '{formula}') — "
                "structural FORBID."
            )
        else:
            reason = (
                f"RV4 path policy '{policy_id}' is currently violated but "
                f"recoverable (a future step could satisfy '{formula}') — "
                "held for review."
            )
        violations.append(
            RV4PathViolation(
                policy_id=policy_id,
                verdict=verdict,
                formula=formula,
                reason=reason,
            )
        )

    return RV4PathOutcome(checked=True, violations=tuple(violations))


__all__ = [
    "RV4PathViolation",
    "RV4PathOutcome",
    "NEUTRAL_RV4_PATH",
    "classify",
]
