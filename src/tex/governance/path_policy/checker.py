"""
Path policy runtime checker.

Maintains a sliding window of recent (state, action, observation) tuples
and checks each candidate action against active path policies before allow.

Reference: Kaptein, Khan & Podstavnychy. "Runtime Governance for AI Agents:
Policies on Paths." arXiv:2603.16586 (Mar 2026), Sections 3.2-3.3 and 4.2.

Implementation notes
--------------------
The paper defines policy composition as

    v_i = 1 - prod_{j in J} (1 - pi_j(A, P_i, s*, Sigma))

The checker evaluates every active policy against the current trace
(the sliding window with the candidate action appended) and composes
their violation probabilities by this formula. Three intervention
outcomes are supported (paper Section 4.4): Pass, Steer, Block.

For audit, the checker emits one ``path_policy.checked`` event per
``check`` call. If any policy produces a non-zero violation probability,
a ``path_policy.violation`` event is emitted with the policy_id,
violation probability, severity, and the formula text (or callable id)
that fired. The event includes the full v_i so an auditor can reproduce
the decision.

The check() return contract is preserved from the original scaffolding:

    (allowed: bool, violated_policy_ids: tuple[str, ...])

allowed is True iff no severity="block" policy fired (paper-Block
outcome). severity="warn" and severity="audit" populate
violated_policy_ids without setting allowed=False — the caller can
inspect the second tuple element for steer/audit signals.

Priority: P1.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Mapping, Sequence

from tex.governance.path_policy.ltlf import (
    LtlfParseError,
    compile_formula,
    evaluate_compiled,
)
from tex.governance.path_policy.policy import (
    CallablePolicy,
    PathPolicy,
    PathStep,
)
from tex.observability import telemetry


# Default sliding-window size. The Kaptein paper notes paths "from a
# handful of steps to thousands of steps" but emphasizes that "the state
# vector is a sufficient statistic for each policy". Tex retains the
# raw trace within the window because LTLf needs it; longer histories
# are summarized by a separate state-vector projection (left to the
# caller; the path_policy_checker is intentionally history-only).
_DEFAULT_WINDOW_SIZE: int = 256

# When a callable policy returns a value outside [0, 1], we clamp and
# log. Bounds-checking by clamping (rather than raising) keeps the
# governance layer fail-closed: an out-of-range score does not crash
# the pipeline, but it does surface in the audit log so the bug can be
# tracked down.
_VIOLATION_PROB_MIN: float = 0.0
_VIOLATION_PROB_MAX: float = 1.0


class PathPolicyChecker:
    """
    Runtime path-policy checker.

    Holds the sliding window of completed steps. ``check`` evaluates a
    candidate action against the active policy set; ``record`` appends
    a completed step (with its observation) to the window after the
    candidate action has been allowed and executed.
    """

    def __init__(
        self,
        *,
        policies: tuple[PathPolicy, ...],
        callable_policies: tuple[CallablePolicy, ...] = (),
        window_size: int = _DEFAULT_WINDOW_SIZE,
        agent_id: str = "default-agent",
        shared_state: Mapping[str, object] | None = None,
    ) -> None:
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        self._policies = policies
        self._callable_policies = callable_policies
        self._window_size = window_size
        self._agent_id = agent_id
        self._shared_state: dict[str, object] = dict(shared_state or {})
        self._history: deque[PathStep] = deque(maxlen=window_size)

        # Pre-compile LTLf formulas for repeated evaluation. Failures
        # here surface as fail-closed: a malformed formula is treated
        # as a perpetually-violated policy of severity="block", which
        # the operator will see immediately.
        self._compiled: dict[str, object | None] = {}
        for policy in policies:
            try:
                self._compiled[policy.policy_id] = (
                    compile_formula(policy.ltl_formula)
                    if policy.ltl_formula
                    else None
                )
            except LtlfParseError as exc:
                telemetry.emit_event(
                    "path_policy.formula.invalid",
                    level=logging.ERROR,
                    policy_id=policy.policy_id,
                    formula=policy.ltl_formula,
                    error=str(exc),
                )
                # Marker that says "always violates"; the checker will
                # block when this policy is encountered.
                self._compiled[policy.policy_id] = "INVALID"

    # ----- runtime API ----------------------------------------------------

    def record(
        self,
        *,
        state: Mapping[str, object],
        action: Mapping[str, object],
        observation: Mapping[str, object],
    ) -> None:
        """
        Append a completed step (with its observed output) to the window.

        Called by the runtime after a candidate action has been allowed
        and executed. The observation is the d_out,i of the paper's
        path-step triple.
        """
        self._history.append((dict(state), dict(action), dict(observation)))

    def update_shared_state(self, **fields: object) -> None:
        """
        Mutate the shared governance state Sigma.

        Per the paper's Section 3.5 instantiation, Sigma "captures
        governance-relevant facts that no single agent's path contains,
        such as which agents have accessed which data categories or
        which information barriers have been activated."
        """
        for key, value in fields.items():
            self._shared_state[key] = value

    def check(
        self,
        *,
        candidate_action: dict,
    ) -> tuple[bool, tuple[str, ...]]:
        """
        Evaluate ``candidate_action`` against all active policies.

        Returns
        -------
        (allowed, violated_policy_ids)
            allowed is False if any severity="block" policy returned a
            non-zero violation probability against the trace
            ``history + [candidate_action]``. violated_policy_ids
            contains every policy_id that produced a non-zero score
            regardless of severity.

        Implementation
        --------------
        Evaluates LTLf-formula policies and CallablePolicy functions
        against the same trace. Composes violation probabilities per
        the paper's v_i = 1 - prod (1 - pi_j) formula. Emits one
        telemetry event per policy that fires plus one summary event
        per call.
        """
        # Build the trace: history + the candidate position. The
        # candidate has empty state-update and empty observation
        # (per paper: s* is "what the agent intends to do, not what
        # it has done", so d_out,i is unknown).
        candidate_step: PathStep = (
            {},
            dict(candidate_action),
            {},
        )
        trace: list[PathStep] = list(self._history) + [candidate_step]

        violated_policy_ids: list[str] = []
        violation_probs: list[float] = []
        any_block = False

        # 1. LTLf-formula policies.
        for policy in self._policies:
            compiled = self._compiled.get(policy.policy_id)
            if compiled is None:
                # No formula => no constraint from this policy.
                continue
            if compiled == "INVALID":
                # Malformed formula at construction time => fail closed.
                pi_j = 1.0
            else:
                # An LTLf formula expresses what should hold (the
                # "good" property). A violation is when the formula
                # is FALSE on the trace. So pi_j = 1.0 if the formula
                # is unsatisfied, else 0.0 — the binary policies the
                # paper observes are most common.
                holds = evaluate_compiled(compiled, trace)  # type: ignore[arg-type]
                pi_j = 0.0 if holds else 1.0
            self._record_policy_outcome(
                policy_id=policy.policy_id,
                pi_j=pi_j,
                severity=policy.severity,
                kind="ltlf",
                detail=policy.ltl_formula,
            )
            if pi_j > 0.0:
                violated_policy_ids.append(policy.policy_id)
                violation_probs.append(pi_j)
                if policy.severity == "block":
                    any_block = True

        # 2. Deterministic-function (pi_j) policies.
        agent_meta: dict[str, object] = {"agent_id": self._agent_id}
        for cp in self._callable_policies:
            try:
                raw = cp.fn(agent_meta, trace, candidate_step[1], self._shared_state)
            except Exception as exc:  # noqa: BLE001 - we want all failures
                # A failing callable fails closed: full violation.
                telemetry.emit_event(
                    "path_policy.callable.error",
                    level=logging.ERROR,
                    policy_id=cp.policy_id,
                    error=type(exc).__name__,
                )
                pi_j = 1.0
            else:
                pi_j = self._clamp_violation(cp.policy_id, raw)
            self._record_policy_outcome(
                policy_id=cp.policy_id,
                pi_j=pi_j,
                severity=cp.severity,
                kind="callable",
                detail=cp.description,
            )
            if pi_j > 0.0:
                violated_policy_ids.append(cp.policy_id)
                violation_probs.append(pi_j)
                if cp.severity == "block":
                    any_block = True

        # 3. Compose v_i per the paper's formula.
        v_i = self._compose_violation_score(violation_probs)

        telemetry.emit_event(
            "path_policy.checked",
            agent_id=self._agent_id,
            candidate_tool=candidate_action.get("tool")
            or candidate_action.get("type")
            or "unknown",
            n_policies=len(self._policies) + len(self._callable_policies),
            n_violations=len(violated_policy_ids),
            violation_score=round(v_i, 6),
            allowed=not any_block,
            history_length=len(self._history),
        )

        allowed = not any_block
        return allowed, tuple(violated_policy_ids)

    @property
    def violation_score(self) -> float:
        """
        Most recent step-level violation score v_i.

        Computed lazily on each call to check(). Defaults to 0.0 before
        any check() call. Callers that need v_i directly should grab it
        from the return-emitted telemetry event; this property exists
        so test code can assert on the score without touching logging.
        """
        return self._last_violation_score

    # ----- helpers --------------------------------------------------------

    _last_violation_score: float = 0.0

    def _compose_violation_score(self, probs: Sequence[float]) -> float:
        product = 1.0
        for p in probs:
            product *= 1.0 - p
        v_i = 1.0 - product
        # Numerical drift: clamp to [0, 1].
        if v_i < 0.0:
            v_i = 0.0
        elif v_i > 1.0:
            v_i = 1.0
        self._last_violation_score = v_i
        return v_i

    def _clamp_violation(self, policy_id: str, raw: object) -> float:
        if not isinstance(raw, (int, float)):
            telemetry.emit_event(
                "path_policy.callable.bad_type",
                level=logging.ERROR,
                policy_id=policy_id,
                got_type=type(raw).__name__,
            )
            return 1.0
        val = float(raw)
        if val < _VIOLATION_PROB_MIN:
            telemetry.emit_event(
                "path_policy.callable.out_of_range",
                level=logging.WARNING,
                policy_id=policy_id,
                value=val,
            )
            return _VIOLATION_PROB_MIN
        if val > _VIOLATION_PROB_MAX:
            telemetry.emit_event(
                "path_policy.callable.out_of_range",
                level=logging.WARNING,
                policy_id=policy_id,
                value=val,
            )
            return _VIOLATION_PROB_MAX
        return val

    def _record_policy_outcome(
        self,
        *,
        policy_id: str,
        pi_j: float,
        severity: str,
        kind: str,
        detail: str,
    ) -> None:
        if pi_j <= 0.0:
            return
        telemetry.emit_event(
            "path_policy.violation",
            policy_id=policy_id,
            policy_kind=kind,
            severity=severity,
            violation_probability=round(pi_j, 6),
            detail=detail[:200],
        )
