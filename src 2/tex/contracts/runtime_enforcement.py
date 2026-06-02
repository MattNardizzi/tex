"""
Runtime contract enforcer.

Per arxiv 2602.22302 (AgentAssert, ABC). The enforcer runs the per-turn
loop described in §5.3:

  1. Evaluate all contract constraints against the observed state.
  2. Update compliance and drift metrics.
  3. Emit notification events for violations.
  4. Attempt recovery for soft constraint violations within the
     bounded recovery window k.
  5. Reset recovery state for constraints that return to satisfaction.

Wiring conventions
------------------
The enforcer is purely a function of (contracts, current EcosystemState,
proposed/executed event). It does not own the ledger; if a caller wants
violations recorded into the cryptographic ledger, they pass
``ledger`` + ``provenance`` at construction — same convention as
``tex.drift.change_point.ChangePointDetector``.

Reference
---------
- arxiv 2602.22302 §3 (the formalism), §5.3 (the runtime monitor loop)
- AgentVerify (arxiv-prep 2604.1029) §3.2.1 — runtime monitor token
  semantics for invariant-response form ``G(p -> X q)``, which is the
  shape our soft constraints take after F<=k unrolling
- arxiv 2601.22136 (StepShield) — step_index instrumentation

Priority: P1.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterable

from tex.contracts._atoms import ContractContext, make_resolver, trace_for
from tex.contracts.contract import BehavioralContract, _ParsedFormulas
from tex.contracts.violation import ContractViolation
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState
from tex.observability.telemetry import emit_event


_KIND_POLICY_DECISION: str = "policy_decision"

# Recovery dispatcher protocol: called when a soft violation fires.
# The enforcer doesn't impose any structure beyond "callable that takes
# the violation and the current state" — full strategy taxonomy
# (inject_correction / retry / escalate / terminate, etc.) is owned by
# the future tex.intervention layer (P2).
RecoveryDispatcher = Callable[[ContractViolation, EcosystemState], None]


@dataclass(frozen=True, slots=True)
class ComplianceScores:
    """
    ABC §3.3 Definition 3.6: per-step compliance scores.

    Both scores live in [0, 1]. C_hard = 1 means all hard constraints
    held at the evaluated step; C_soft = 1 means the same for soft.
    The enforcer also returns the (p, δ, k) parameters in effect for
    the dominant contract so callers can compute (p, δ, k)-satisfaction
    upstream.
    """

    c_hard: float
    c_soft: float
    contracts_evaluated: int
    constraints_evaluated: int


@dataclass(slots=True)
class _SoftRecoveryEntry:
    """
    Per-(agent_id, contract_id, formula_index) recovery counter.

    When a soft constraint first fails at step S, this entry is
    inserted with ``deadline_step = S + k``. On every subsequent step
    we re-check the same constraint; if it now holds, the entry is
    discharged and ``recovered_at_step`` is recorded. If the deadline
    passes without recovery, the next pre/post check produces a
    fresh ContractViolation with severity escalated to ``block``
    (matches AgentAssert's "fallback chain" semantics in §5.4).
    """

    triggering_event_id: str
    started_at_step: int
    deadline_step: int
    clause_ltl: str
    violated_clause: str
    contract_id: str
    agent_id: str


class ContractEnforcer:
    """
    Per-turn contract enforcer over a population of BehavioralContracts.

    Construction
    ------------
    ``contracts`` must be non-empty. ``ledger``+``provenance`` are
    optional; pass both or neither (matches drift detector convention).

    >>> enforcer = ContractEnforcer(contracts=(c1, c2))                  # telemetry-only
    >>> enforcer = ContractEnforcer(                                      # full ledger emission
    ...     contracts=(c1, c2),
    ...     ledger=my_ledger,
    ...     provenance=my_provenance,
    ... )
    """

    def __init__(
        self,
        *,
        contracts: tuple[BehavioralContract, ...],
        ledger: Any = None,
        provenance: Any = None,
        actor_entity_id: str = "_contract_enforcer",
        recovery_dispatcher: RecoveryDispatcher | None = None,
    ) -> None:
        if not contracts:
            raise ValueError("ContractEnforcer requires at least one contract")
        if (ledger is None) != (provenance is None):
            raise ValueError(
                "ledger and provenance must be supplied together "
                "(supply both for ledger emission, or neither for telemetry-only)"
            )

        # Verify uniqueness of contract_id — duplicates are almost
        # always a config bug and would produce confusing violations.
        seen: set[str] = set()
        for c in contracts:
            if c.contract_id in seen:
                raise ValueError(f"duplicate contract_id {c.contract_id!r}")
            seen.add(c.contract_id)

        self._contracts: tuple[BehavioralContract, ...] = contracts
        self._parsed: dict[str, _ParsedFormulas] = {
            c.contract_id: c.parsed_formulas() for c in contracts
        }

        self._ledger = ledger
        self._provenance = provenance
        self._actor = actor_entity_id
        self._recovery = recovery_dispatcher

        # Step counter for StepShield-style Early Intervention Rate.
        # Increments once per (pre or post) check call so that
        # detections from one logical "turn" share a step_index.
        self._step_index: int = 0

        # Active soft-recovery deadlines, keyed by
        # (agent_id, contract_id, kind, formula_idx).
        self._soft_pending: dict[tuple[str, str, str, int], _SoftRecoveryEntry] = {}

        # Tracking of all violations ever emitted, in order — useful
        # for tests, for the future SPRT certifier, and for the
        # reliability index Θ time-window aggregator.
        self._violations: list[ContractViolation] = []

        # Compliance score history for the public Θ helper. Per ABC
        # §3.6 Def 3.20, Θ is a session-level composite over time-
        # averaged C(t).
        self._c_hard_history: list[float] = []
        self._c_soft_history: list[float] = []

    # ------------------------------------------------------------------
    # Public read-only views
    # ------------------------------------------------------------------

    @property
    def step_index(self) -> int:
        """Total checks performed so far (pre + post)."""
        return self._step_index

    @property
    def violations(self) -> tuple[ContractViolation, ...]:
        """All violations emitted this run, in order."""
        return tuple(self._violations)

    @property
    def pending_soft_recoveries(self) -> int:
        """Count of soft violations awaiting recovery within k."""
        return len(self._soft_pending)

    # ------------------------------------------------------------------
    # Pre/post checks
    # ------------------------------------------------------------------

    def check_pre(
        self,
        *,
        agent_id: str,
        proposed_event: ProposedEvent,
        current_state: EcosystemState,
        recent_window: tuple[ProposedEvent, ...] = (),
    ) -> tuple[bool, tuple[str, ...]]:
        """
        Evaluate contracts that apply to the proposed event BEFORE it
        executes.

        Returns ``(is_satisfied, violated_contract_ids)``:
          * ``is_satisfied=False`` iff at least one HARD constraint
            (precondition, hard invariant, or hard governance) failed.
            Soft violations do NOT clear is_satisfied — they track in
            the recovery queue.
          * ``violated_contract_ids`` includes both hard and soft
            violations from this step (ledger consumers want the
            complete list).

        Source-paper alignment
        ----------------------
        - arxiv 2602.22302 §3.2 Definition 3.4 — the deterministic
          satisfaction conditions for preconditions, invariants, and
          governance. We evaluate all three at the pre-step.
        - arxiv 2602.22302 §5.3 — the per-turn enforcement loop;
          recovery state is reset for constraints that return to
          satisfaction.

        TODO(P1): finish soft-violation deadline expiry handling
            — DONE. Expired deadlines fire an escalation
              ContractViolation with severity bumped to "block".
        TODO(P2): wire to tex.intervention for cost-bounded recovery
        action selection (currently dispatches to recovery_dispatcher).
        """
        return self._check(
            agent_id=agent_id,
            event=proposed_event,
            state=current_state,
            recent_window=recent_window,
            phase="pre",
        )

    def check_post(
        self,
        *,
        agent_id: str,
        executed_event: ProposedEvent,
        new_state: EcosystemState,
        recent_window: tuple[ProposedEvent, ...] = (),
    ) -> tuple[bool, tuple[str, ...]]:
        """
        Evaluate contracts AFTER ``executed_event`` has been admitted
        and ``new_state`` is the resulting EcosystemState snapshot.

        Same semantics as ``check_pre`` but additionally evaluates the
        legacy ``postcondition_ltl`` field (paper-divergent — see the
        contract docstring) and discharges soft-recovery deadlines
        that are now satisfied.

        TODO(P1): evaluate postcondition_ltl + invariants_ltl
            — DONE. Postcondition treated as a single LTL formula over
              the post-execution state; invariants and governance are
              re-checked per the ABC §5.3 enforcement loop.
        """
        return self._check(
            agent_id=agent_id,
            event=executed_event,
            state=new_state,
            recent_window=recent_window,
            phase="post",
        )

    # ------------------------------------------------------------------
    # ABC compliance scores + reliability index Θ (§3.3 Def 3.6, §3.6 Def 3.20)
    # ------------------------------------------------------------------

    def compliance_scores(
        self,
        *,
        agent_id: str,
        proposed_event: ProposedEvent,
        current_state: EcosystemState,
        recent_window: tuple[ProposedEvent, ...] = (),
    ) -> ComplianceScores:
        """
        Compute (C_hard, C_soft) at the current step without recording
        violations or advancing step_index.

        ABC §3.3 Definition 3.6:
          C_hard(t) = |{c in I_hard ∪ G_hard : c(s_t, a_t) = true}| / |I_hard ∪ G_hard|
          C_soft(t) = |{c in I_soft ∪ G_soft : c(s_t, a_t) = true}| / |I_soft ∪ G_soft|

        Used by callers that want the raw scores for downstream
        aggregation (drift score, Θ index) without polluting the
        violation history.
        """
        ctx = ContractContext(
            proposed_event=proposed_event,
            state=current_state,
            event_window=recent_window,
        )
        resolver = make_resolver(ctx)
        trace = trace_for(ctx)

        active_contracts = [
            c
            for c in self._contracts
            if c.applies_to(agent_id=agent_id, event_kind=proposed_event.event_kind)
        ]

        hard_total = 0
        hard_satisfied = 0
        soft_total = 0
        soft_satisfied = 0

        for contract in active_contracts:
            parsed = self._parsed[contract.contract_id]
            for f in parsed.hard_invariants:
                hard_total += 1
                if f.evaluate_finite(trace, resolver):
                    hard_satisfied += 1
            for f in parsed.hard_governance:
                hard_total += 1
                if f.evaluate_finite(trace, resolver):
                    hard_satisfied += 1
            for f in parsed.soft_invariants:
                soft_total += 1
                if f.evaluate_finite(trace, resolver):
                    soft_satisfied += 1
            for f in parsed.soft_governance:
                soft_total += 1
                if f.evaluate_finite(trace, resolver):
                    soft_satisfied += 1

        c_hard = 1.0 if hard_total == 0 else hard_satisfied / hard_total
        c_soft = 1.0 if soft_total == 0 else soft_satisfied / soft_total
        return ComplianceScores(
            c_hard=c_hard,
            c_soft=c_soft,
            contracts_evaluated=len(active_contracts),
            constraints_evaluated=hard_total + soft_total,
        )

    def reliability_index(
        self,
        *,
        weights: tuple[float, float, float, float] = (0.5, 0.2, 0.2, 0.1),
    ) -> float:
        """
        Per-session reliability index Θ ∈ [0, 1] (ABC §3.6 Def 3.20).

        Θ = α₁·C̄ + α₂·(1 − D̄) + α₃·1/(1+E) + α₄·S

        Today we ship a simplified version using:

          C̄  — mean of c_hard history (the dominant safety signal)
          D̄  — 1 − mean(c_soft); the soft-compliance gap stands in for
                the §3.5 drift score because the full distributional
                drift component lives in tex.drift
          E   — recovery effectiveness; we approximate as the share of
                soft violations that recovered within k
          S   — stress resilience; defaults to 1.0 here — the full
                metric requires baseline-vs-stress comparison and is
                out of scope for the contracts layer alone

        TODO(P2): integrate tex.drift's JSD-based D̄ for the full ABC
        §3.5 Def 3.12 drift component instead of using the soft-
        compliance gap as a proxy.

        TODO(P2): wire S from tex.systemic.risk_evaluator under
        contract-defined "stress profile" tags per ABC §6.2.
        """
        a1, a2, a3, a4 = weights
        if not 0.0 <= a1 <= 1.0 or not 0.0 <= a2 <= 1.0:
            raise ValueError("weights must lie in [0, 1]")
        if not 0.0 <= a3 <= 1.0 or not 0.0 <= a4 <= 1.0:
            raise ValueError("weights must lie in [0, 1]")
        # Tolerate float drift in the weight-sum check.
        if abs(a1 + a2 + a3 + a4 - 1.0) > 1e-6:
            raise ValueError("weights must sum to 1")

        if not self._c_hard_history:
            # No checks performed yet: optimistic 1.0, mirrors AgentAssert.
            return 1.0

        c_bar = sum(self._c_hard_history) / len(self._c_hard_history)
        if self._c_soft_history:
            soft_mean = sum(self._c_soft_history) / len(self._c_soft_history)
        else:
            soft_mean = 1.0
        d_bar = 1.0 - soft_mean

        soft_violations = [v for v in self._violations if v.violated_clause.startswith("soft_")]
        if soft_violations:
            recovered = sum(1 for v in soft_violations if v.recovered_at_step is not None)
            # ABC §3.18 normalises by violation severity; here we use
            # the simpler share-of-recovered ratio. Lower E = better
            # recovery. We map "fraction recovered" -> E via E = 1 - frac.
            frac_recovered = recovered / len(soft_violations)
            e = 1.0 - frac_recovered
        else:
            e = 0.0

        s = 1.0  # stress resilience — TODO(P2) above

        return a1 * c_bar + a2 * (1.0 - d_bar) + a3 * (1.0 / (1.0 + e)) + a4 * s

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check(
        self,
        *,
        agent_id: str,
        event: ProposedEvent,
        state: EcosystemState,
        recent_window: tuple[ProposedEvent, ...],
        phase: str,
    ) -> tuple[bool, tuple[str, ...]]:
        self._step_index += 1
        step = self._step_index

        ctx = ContractContext(
            proposed_event=event,
            state=state,
            event_window=recent_window,
        )
        resolver = make_resolver(ctx)
        trace = trace_for(ctx)

        active = [
            c
            for c in self._contracts
            if c.applies_to(agent_id=agent_id, event_kind=event.event_kind)
        ]

        # Per-step compliance counters for the score history.
        hard_total = 0
        hard_satisfied = 0
        soft_total = 0
        soft_satisfied = 0

        violated_contract_ids: list[str] = []
        any_hard_violated = False

        for contract in active:
            parsed = self._parsed[contract.contract_id]
            contract_had_violation = False

            # Pre/post phase: precondition or postcondition.
            if phase == "pre" and parsed.precondition is not None:
                if not parsed.precondition.evaluate_finite(trace, resolver):
                    self._record(
                        contract=contract,
                        clause_ltl=contract.precondition_ltl,
                        violated_clause="precondition",
                        is_soft=False,
                        event=event,
                        state=state,
                        step=step,
                    )
                    any_hard_violated = True
                    contract_had_violation = True

            if phase == "post" and parsed.postcondition is not None:
                if not parsed.postcondition.evaluate_finite(trace, resolver):
                    self._record(
                        contract=contract,
                        clause_ltl=contract.postcondition_ltl,
                        violated_clause="postcondition",
                        is_soft=False,
                        event=event,
                        state=state,
                        step=step,
                    )
                    any_hard_violated = True
                    contract_had_violation = True

            # Hard invariants
            for idx, f in enumerate(parsed.hard_invariants):
                hard_total += 1
                if f.evaluate_finite(trace, resolver):
                    hard_satisfied += 1
                else:
                    self._record(
                        contract=contract,
                        clause_ltl=contract.invariants_ltl[idx],
                        violated_clause="hard_invariant",
                        is_soft=False,
                        event=event,
                        state=state,
                        step=step,
                    )
                    any_hard_violated = True
                    contract_had_violation = True

            # Hard governance
            for idx, f in enumerate(parsed.hard_governance):
                hard_total += 1
                if f.evaluate_finite(trace, resolver):
                    hard_satisfied += 1
                else:
                    self._record(
                        contract=contract,
                        clause_ltl=contract.hard_governance_ltl[idx],
                        violated_clause="hard_governance",
                        is_soft=False,
                        event=event,
                        state=state,
                        step=step,
                    )
                    any_hard_violated = True
                    contract_had_violation = True

            # Soft invariants — these have recovery semantics.
            for idx, f in enumerate(parsed.soft_invariants):
                key = (agent_id, contract.contract_id, "soft_invariant", idx)
                soft_total += 1
                if f.evaluate_finite(trace, resolver):
                    soft_satisfied += 1
                    # Discharge any pending recovery for this constraint.
                    if key in self._soft_pending:
                        self._discharge_recovery(key, recovered_at_step=step)
                else:
                    self._handle_soft_violation(
                        key=key,
                        contract=contract,
                        clause_ltl=contract.soft_invariants_ltl[idx],
                        violated_clause="soft_invariant",
                        event=event,
                        state=state,
                        step=step,
                    )
                    contract_had_violation = True

            # Soft governance — mirror semantics.
            for idx, f in enumerate(parsed.soft_governance):
                key = (agent_id, contract.contract_id, "soft_governance", idx)
                soft_total += 1
                if f.evaluate_finite(trace, resolver):
                    soft_satisfied += 1
                    if key in self._soft_pending:
                        self._discharge_recovery(key, recovered_at_step=step)
                else:
                    self._handle_soft_violation(
                        key=key,
                        contract=contract,
                        clause_ltl=contract.soft_governance_ltl[idx],
                        violated_clause="soft_governance",
                        event=event,
                        state=state,
                        step=step,
                    )
                    contract_had_violation = True

            if contract_had_violation:
                violated_contract_ids.append(contract.contract_id)

        # Persist per-step compliance scores.
        c_hard = 1.0 if hard_total == 0 else hard_satisfied / hard_total
        c_soft = 1.0 if soft_total == 0 else soft_satisfied / soft_total
        self._c_hard_history.append(c_hard)
        self._c_soft_history.append(c_soft)

        # Sweep expired soft-recovery deadlines AFTER score
        # bookkeeping so the expiry violation lands on a step strictly
        # later than the original.
        self._sweep_expired_recoveries(state=state, step=step, event=event)

        emit_event(
            "contracts.check.completed",
            phase=phase,
            agent_id=agent_id,
            event_kind=event.event_kind,
            step_index=step,
            contracts_evaluated=len(active),
            c_hard=c_hard,
            c_soft=c_soft,
            violations_this_step=len(violated_contract_ids),
        )

        return (not any_hard_violated, tuple(violated_contract_ids))

    # ------------------------------------------------------------------

    def _handle_soft_violation(
        self,
        *,
        key: tuple[str, str, str, int],
        contract: BehavioralContract,
        clause_ltl: str,
        violated_clause: str,
        event: ProposedEvent,
        state: EcosystemState,
        step: int,
    ) -> None:
        """
        Soft violation handler with bounded-liveness recovery semantics.

        On first detection at step S we register a recovery deadline at
        ``S + k`` and emit a ContractViolation. On subsequent steps the
        same constraint is re-checked; recovery is discharged if it
        returns to satisfaction, or escalated when the deadline expires
        (handled by ``_sweep_expired_recoveries``).
        """
        agent_id, contract_id, _kind_tag, _idx = key
        if key in self._soft_pending:
            # Already pending — don't re-emit on every step it stays
            # violated. The expiry sweep will produce the escalation
            # record. This matches AgentAssert's "obligation token" model.
            return
        deadline = step + contract.recovery_window_k
        self._soft_pending[key] = _SoftRecoveryEntry(
            triggering_event_id=_event_id_or_synth(event),
            started_at_step=step,
            deadline_step=deadline,
            clause_ltl=clause_ltl,
            violated_clause=violated_clause,
            contract_id=contract_id,
            agent_id=agent_id,
        )
        self._record(
            contract=contract,
            clause_ltl=clause_ltl,
            violated_clause=violated_clause,
            is_soft=True,
            event=event,
            state=state,
            step=step,
            recovery_deadline_step=deadline,
        )

    def _discharge_recovery(
        self,
        key: tuple[str, str, str, int],
        *,
        recovered_at_step: int,
    ) -> None:
        """Mark a soft violation as recovered by mutating the latest record.

        Only discharges if recovery is within the original window. If
        the recovery_at_step is already past the deadline, the entry
        stays pending so the expiry sweep produces an escalation —
        otherwise we'd silently ignore late recoveries that should
        have escalated.
        """
        entry = self._soft_pending.get(key)
        if entry is None:
            return
        if recovered_at_step > entry.deadline_step:
            # Late recovery — leave the entry for the sweep to escalate.
            return
        # Recovery is in time; pop the entry and find the open
        # ContractViolation to mutate.
        self._soft_pending.pop(key, None)
        for i in range(len(self._violations) - 1, -1, -1):
            v = self._violations[i]
            if (
                v.contract_id == entry.contract_id
                and v.agent_id == entry.agent_id
                and v.violated_clause == entry.violated_clause
                and v.recovered_at_step is None
                and v.recovery_deadline_step is not None
            ):
                self._violations[i] = ContractViolation(
                    violation_id=v.violation_id,
                    contract_id=v.contract_id,
                    agent_id=v.agent_id,
                    violated_clause=v.violated_clause,
                    clause_ltl=v.clause_ltl,
                    detected_at=v.detected_at,
                    triggering_event_id=v.triggering_event_id,
                    step_index=v.step_index,
                    severity=v.severity,
                    compliance_gap=v.compliance_gap,
                    recovery_deadline_step=v.recovery_deadline_step,
                    recovered_at_step=recovered_at_step,
                    ledger_event_id=v.ledger_event_id,
                )
                emit_event(
                    "contracts.recovery.discharged",
                    contract_id=v.contract_id,
                    agent_id=v.agent_id,
                    violated_clause=v.violated_clause,
                    started_at_step=entry.started_at_step,
                    recovered_at_step=recovered_at_step,
                )
                return

    def _sweep_expired_recoveries(
        self,
        *,
        state: EcosystemState,
        step: int,
        event: ProposedEvent,
    ) -> None:
        """
        For every pending soft-recovery whose deadline is now past,
        emit an escalation ContractViolation with severity ``block``
        and clear the entry. Mirrors AgentAssert's "fallback chain"
        semantics in §5.4.
        """
        expired: list[tuple[str, str, str, int]] = []
        for key, entry in self._soft_pending.items():
            if step > entry.deadline_step:
                expired.append(key)

        for key in expired:
            entry = self._soft_pending.pop(key)
            # Find the originating contract to use its severity policy
            # for the escalation record.
            contract = next(
                (c for c in self._contracts if c.contract_id == entry.contract_id),
                None,
            )
            if contract is None:
                continue
            self._record(
                contract=contract,
                clause_ltl=entry.clause_ltl,
                violated_clause=entry.violated_clause,
                is_soft=False,  # escalated
                event=event,
                state=state,
                step=step,
                recovery_deadline_step=entry.deadline_step,
                severity_override="block",
                triggering_event_id_override=entry.triggering_event_id,
            )
            emit_event(
                "contracts.recovery.expired",
                contract_id=entry.contract_id,
                agent_id=entry.agent_id,
                violated_clause=entry.violated_clause,
                started_at_step=entry.started_at_step,
                deadline_step=entry.deadline_step,
                expired_at_step=step,
            )

    # ------------------------------------------------------------------

    def _record(
        self,
        *,
        contract: BehavioralContract,
        clause_ltl: str,
        violated_clause: str,
        is_soft: bool,
        event: ProposedEvent,
        state: EcosystemState,
        step: int,
        recovery_deadline_step: int | None = None,
        severity_override: str | None = None,
        triggering_event_id_override: str | None = None,
    ) -> ContractViolation:
        """
        Build, persist, and (if wired) ledger-emit a ContractViolation.
        """
        # Severity selection: hard violations always inherit the
        # contract's severity_on_violation; soft violations stay "warn"
        # until the recovery deadline expires, at which point they
        # escalate (severity_override="block").
        if severity_override is not None:
            severity: str = severity_override
        else:
            severity = (
                contract.severity_on_violation
                if not is_soft
                else "warn"
            )

        # ABC §3.6 compliance gap contribution: per-constraint share
        # of the contract's total constraint count, capped at 1.0
        # (degenerates to 1.0 for contracts with no other constraints).
        total = max(1, contract.total_constraint_count())
        compliance_gap = 1.0 / total

        violation = ContractViolation(
            violation_id=f"contract-violation-{uuid.uuid4().hex[:16]}",
            contract_id=contract.contract_id,
            agent_id=contract.agent_id,
            violated_clause=violated_clause,  # type: ignore[arg-type]
            clause_ltl=clause_ltl,
            detected_at=datetime.now(UTC),
            triggering_event_id=(
                triggering_event_id_override or _event_id_or_synth(event)
            ),
            step_index=step,
            severity=severity,  # type: ignore[arg-type]
            compliance_gap=compliance_gap,
            recovery_deadline_step=recovery_deadline_step,
            recovered_at_step=None,
            ledger_event_id=None,
        )

        # Ledger emission must happen BEFORE recovery dispatch so the
        # signed record exists even if the dispatcher raises.
        if self._ledger is not None and self._provenance is not None:
            ledger_event_id = self._append_to_ledger(violation=violation)
            violation = ContractViolation(
                violation_id=violation.violation_id,
                contract_id=violation.contract_id,
                agent_id=violation.agent_id,
                violated_clause=violation.violated_clause,
                clause_ltl=violation.clause_ltl,
                detected_at=violation.detected_at,
                triggering_event_id=violation.triggering_event_id,
                step_index=violation.step_index,
                severity=violation.severity,
                compliance_gap=violation.compliance_gap,
                recovery_deadline_step=violation.recovery_deadline_step,
                recovered_at_step=violation.recovered_at_step,
                ledger_event_id=ledger_event_id,
            )

        self._violations.append(violation)

        emit_event(
            "contracts.violation.detected",
            contract_id=violation.contract_id,
            agent_id=violation.agent_id,
            violated_clause=violation.violated_clause,
            severity=violation.severity,
            step_index=violation.step_index,
            ledger_event_id=violation.ledger_event_id,
            recovery_deadline_step=violation.recovery_deadline_step,
        )

        # Recovery dispatcher fires only for soft violations or for
        # severity="sanction" hard violations; "block"/"warn" do not
        # invoke recovery actions.
        if self._recovery is not None and (
            is_soft or violation.severity == "sanction"
        ):
            try:
                self._recovery(violation, state)
            except Exception as exc:  # pragma: no cover - defensive
                emit_event(
                    "contracts.recovery.dispatcher_failed",
                    contract_id=violation.contract_id,
                    error=str(exc),
                )

        return violation

    def _append_to_ledger(self, *, violation: ContractViolation) -> str:
        """
        Append a POLICY_DECISION event recording this violation.

        Determinism contract: identical (contract_id, agent_id,
        violated_clause, clause_ltl, step_index, compliance_gap_milli,
        provenance.signing_key_id) inputs produce a byte-identical
        record_hash. Signature bytes may differ for non-deterministic
        providers (today's ECDSA-P256 is non-deterministic; ML-DSA-65
        will be deterministic).

        Floats coerced to milli-units mirroring tex.drift's pattern.
        """
        payload = {
            "decision_kind": "contract_violation",
            "contract_id": violation.contract_id,
            "violated_clause": violation.violated_clause,
            "clause_ltl": violation.clause_ltl,
            "severity": violation.severity,
            "step_index": violation.step_index,
            "compliance_gap_milli": int(round(violation.compliance_gap * 1000)),
            "recovery_deadline_step": violation.recovery_deadline_step,
            "violation_id": violation.violation_id,
            "triggering_event_id": violation.triggering_event_id,
        }
        proposed = ProposedEvent(
            event_kind=_KIND_POLICY_DECISION,
            actor_entity_id=self._actor,
            target_entity_id=violation.agent_id,
            payload=payload,
            proposed_at=violation.detected_at,
        )
        appended = self._ledger.append_proposed(
            proposed, provenance=self._provenance
        )
        # `self._ledger` is typed Any (it's a Protocol-shaped duck-typed
        # injection — see ChangePointDetector for the same pattern), so
        # we annotate the return path explicitly.
        event_id: str = appended.event_id
        return event_id


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _event_id_or_synth(event: ProposedEvent) -> str:
    """
    A ProposedEvent doesn't carry an explicit event_id (it gets one
    when the ledger admits it). For violation records we need *some*
    stable identifier — synthesise from the canonical triple if absent.
    """
    return (
        f"proposed:{event.actor_entity_id}:{event.event_kind}"
        f":{event.proposed_at.isoformat()}"
    )


# Re-export ComplianceScores for convenience.
def all_active_contracts(
    contracts: Iterable[BehavioralContract],
    *,
    agent_id: str,
    event_kind: str,
) -> tuple[BehavioralContract, ...]:
    """Filter helper used by callers that need to introspect coverage."""
    return tuple(
        c for c in contracts if c.applies_to(agent_id=agent_id, event_kind=event_kind)
    )


__all__ = [
    "ComplianceScores",
    "ContractEnforcer",
    "RecoveryDispatcher",
    "all_active_contracts",
]
