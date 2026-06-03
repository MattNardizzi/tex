"""
Path-policy bridge.

[Architecture: Layer 4 (Execution Governance)]

Wires the (previously dormant) ``tex.governance.path_policy`` runtime checker
into the PDP, mirroring the way ``engine.contract_bridge`` wires the behavioural
contracts layer in. Path policies judge an action by the **sequence it occurs
in** — "tool X only after tool Y", "never tool A after observing condition B",
"at most N invocations of C per session" — closing the PDP's structural blind
spot: until now every stream judged a single action in isolation, with no memory
of the trace that led to it. Sequence-shaped attacks (cross-turn injection, plan
hijacking, causality laundering) live exactly in that blind spot.

Reference: Kaptein, Khan & Podstavnychy, "Runtime Governance for AI Agents:
Policies on Paths," arXiv:2603.16586 (Mar 2026).

Opt-in, deterministic, fail-closed
-----------------------------------
The PDP stays stateless. Path context arrives on the request:

    request.metadata["path_policy"] = {
        "policies": [
            {"policy_id": "refund_after_idcheck",
             "description": "refund only after identity verified",
             "ltl_formula": "...",
             "severity": "block" | "warn" | "audit"},
            ...
        ],
        "trace": [                      # prior COMPLETED steps in this session
            {"state": {...}, "action": {"tool": "confirm_identity", ...},
             "observation": {...}},
            ...
        ],
        "candidate_action": {"tool": "issue_refund", "input": {...}},  # optional
        "window_size": 256,             # optional
    }

When the key is absent the bridge returns ``NEUTRAL_PATH_OUTCOME`` — a
zero-cost branch that leaves PDP behaviour identical to pre-wiring. The
underlying ``PathPolicyChecker`` is already fail-closed (malformed formulae and
raising callables are treated as full violations), so this bridge inherits that
property: a path block routes to FORBID, never to PERMIT.

Severity mapping (paper Section 4.4)
------------------------------------
- ``block``  → paper-Block  → hard violation → PDP short-circuits to FORBID,
               joining the deterministic / structural FORBID floor.
- ``warn``   → paper-Steer  → soft violation → promotes a router PERMIT to
               ABSTAIN (human review), with findings + an uncertainty flag.
- ``audit``  → paper-Pass-with-audit → an INFO finding only; verdict untouched.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from tex.domain.evaluation import EvaluationRequest
from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.governance.path_policy.checker import PathPolicyChecker
from tex.governance.path_policy.policy import PathPolicy, PathStep
from tex.observability import telemetry


PATH_POLICY_FINDING_SOURCE = "path_policy.runtime"
PATH_BLOCK_FORBID_REASON = (
    "behavioral path policy hard violation (block) — action forbidden by its "
    "position in the agent's execution path"
)
SOFT_PATH_UNCERTAINTY_FLAG = "path_policy_soft_violation"
_METADATA_KEY = "path_policy"


@dataclass(frozen=True, slots=True)
class PathPolicyOutcome:
    """PDP-shaped result of evaluating the active path policies.

    Field shape intentionally parallels ``ContractEvaluationOutcome`` so the
    PDP can treat path and contract signals uniformly.
    """

    checked: bool
    has_block: bool
    has_warn: bool
    violated_policy_ids: tuple[str, ...]
    block_policy_ids: tuple[str, ...]
    warn_policy_ids: tuple[str, ...]
    audit_policy_ids: tuple[str, ...]
    violation_score: float
    findings: tuple[Finding, ...]
    forbid_reason: str | None
    soft_uncertainty_flags: tuple[str, ...]
    path_policy_ms: float
    n_policies: int
    history_length: int

    @property
    def has_hard_violation(self) -> bool:
        return self.has_block

    @property
    def has_soft_violation(self) -> bool:
        return self.has_warn


NEUTRAL_PATH_OUTCOME = PathPolicyOutcome(
    checked=False,
    has_block=False,
    has_warn=False,
    violated_policy_ids=(),
    block_policy_ids=(),
    warn_policy_ids=(),
    audit_policy_ids=(),
    violation_score=0.0,
    findings=(),
    forbid_reason=None,
    soft_uncertainty_flags=(),
    path_policy_ms=0.0,
    n_policies=0,
    history_length=0,
)


def _coerce_step(raw: Any) -> PathStep | None:
    """Coerce one trace entry into a (state, action, observation) tuple."""
    if isinstance(raw, (list, tuple)) and len(raw) == 3:
        state, action, observation = raw
        if (
            isinstance(state, Mapping)
            and isinstance(action, Mapping)
            and isinstance(observation, Mapping)
        ):
            return (dict(state), dict(action), dict(observation))
        return None
    if isinstance(raw, Mapping):
        state = raw.get("state", {})
        action = raw.get("action", {})
        observation = raw.get("observation", {})
        if (
            isinstance(state, Mapping)
            and isinstance(action, Mapping)
            and isinstance(observation, Mapping)
        ):
            return (dict(state), dict(action), dict(observation))
    return None


def _coerce_policies(raw: Any) -> tuple[PathPolicy, ...]:
    policies: list[PathPolicy] = []
    if not isinstance(raw, Sequence):
        return ()
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        policy_id = entry.get("policy_id")
        ltl_formula = entry.get("ltl_formula", "")
        severity = entry.get("severity", "audit")
        description = entry.get("description", "")
        if not isinstance(policy_id, str) or not policy_id.strip():
            continue
        if severity not in ("block", "warn", "audit"):
            severity = "audit"
        policies.append(
            PathPolicy(
                policy_id=policy_id,
                description=str(description),
                ltl_formula=str(ltl_formula),
                severity=severity,  # type: ignore[arg-type]
            )
        )
    return tuple(policies)


def _default_candidate_action(request: EvaluationRequest) -> dict[str, object]:
    """Derive a candidate action from the request when none is supplied."""
    return {
        "tool": request.action_type,
        "type": request.action_type,
        "channel": request.channel,
        "recipient": request.recipient or "",
    }


def evaluate_path_policies_for_request(
    *,
    request: EvaluationRequest,
) -> PathPolicyOutcome:
    """Evaluate the candidate action against the request's active path policies.

    Returns ``NEUTRAL_PATH_OUTCOME`` (zero-cost) when the request carries no
    ``path_policy`` metadata. Otherwise builds a fresh, per-request checker,
    replays the supplied trace into its sliding window, checks the candidate
    action, and maps the result onto PDP-shaped block / warn / audit signals.
    """
    raw = request.metadata.get(_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return NEUTRAL_PATH_OUTCOME

    policies = _coerce_policies(raw.get("policies"))
    if not policies:
        return NEUTRAL_PATH_OUTCOME

    start = time.perf_counter()

    window_size = raw.get("window_size", 256)
    if not isinstance(window_size, int) or window_size <= 0:
        window_size = 256

    severity_by_id = {p.policy_id: p.severity for p in policies}

    agent_id = str(request.agent_id) if request.agent_id is not None else "default-agent"
    checker = PathPolicyChecker(
        policies=policies,
        window_size=window_size,
        agent_id=agent_id,
    )

    # Replay prior completed steps into the sliding window.
    history_length = 0
    raw_trace = raw.get("trace", [])
    if isinstance(raw_trace, Sequence):
        for entry in raw_trace:
            step = _coerce_step(entry)
            if step is None:
                continue
            checker.record(state=step[0], action=step[1], observation=step[2])
            history_length += 1

    candidate = raw.get("candidate_action")
    if not isinstance(candidate, Mapping):
        candidate_action: dict[str, object] = _default_candidate_action(request)
    else:
        candidate_action = dict(candidate)

    allowed, violated_ids = checker.check(candidate_action=candidate_action)
    violation_score = checker.violation_score

    block_ids: list[str] = []
    warn_ids: list[str] = []
    audit_ids: list[str] = []
    findings: list[Finding] = []

    for pid in violated_ids:
        sev = severity_by_id.get(pid, "audit")
        if sev == "block":
            block_ids.append(pid)
            severity = Severity.CRITICAL
        elif sev == "warn":
            warn_ids.append(pid)
            severity = Severity.WARNING
        else:
            audit_ids.append(pid)
            severity = Severity.INFO
        findings.append(
            Finding(
                source=PATH_POLICY_FINDING_SOURCE,
                rule_name=pid,
                severity=severity,
                message=(
                    f"Path policy '{pid}' ({sev}) violated by the candidate "
                    f"action given the {history_length}-step execution path."
                ),
                metadata={
                    "policy_id": pid,
                    "severity_label": sev,
                    "violation_score": round(violation_score, 6),
                    "history_length": history_length,
                },
            )
        )

    has_block = bool(block_ids)
    has_warn = bool(warn_ids)
    path_policy_ms = round((time.perf_counter() - start) * 1000.0, 2)

    telemetry.emit_event(
        "path_policy.bridge.evaluated",
        level=logging.INFO,
        agent_id=agent_id,
        n_policies=len(policies),
        n_violations=len(violated_ids),
        has_block=has_block,
        has_warn=has_warn,
        allowed=allowed,
        violation_score=round(violation_score, 6),
    )

    return PathPolicyOutcome(
        checked=True,
        has_block=has_block,
        has_warn=has_warn,
        violated_policy_ids=tuple(violated_ids),
        block_policy_ids=tuple(block_ids),
        warn_policy_ids=tuple(warn_ids),
        audit_policy_ids=tuple(audit_ids),
        violation_score=violation_score,
        findings=tuple(findings),
        forbid_reason=PATH_BLOCK_FORBID_REASON if has_block else None,
        soft_uncertainty_flags=(SOFT_PATH_UNCERTAINTY_FLAG,) if has_warn else (),
        path_policy_ms=path_policy_ms,
        n_policies=len(policies),
        history_length=history_length,
    )


__all__ = [
    "PathPolicyOutcome",
    "NEUTRAL_PATH_OUTCOME",
    "evaluate_path_policies_for_request",
    "PATH_POLICY_FINDING_SOURCE",
    "PATH_BLOCK_FORBID_REASON",
    "SOFT_PATH_UNCERTAINTY_FLAG",
]
