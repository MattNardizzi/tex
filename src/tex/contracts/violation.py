"""
Contract violation record.

A typed, frozen dataclass capturing one detection event by the
ContractEnforcer. The fields are designed to satisfy three downstream
consumers in one shape:

  1. **The events ledger** (tex.events) — the violation is signed and
     appended as a POLICY_DECISION event.
  2. **The intervention layer** (tex.intervention, P2) — the
     ``severity`` + ``clause_kind`` decide whether to BLOCK / SANCTION
     / WARN.
  3. **Temporal-detection benchmarks** — the StepShield 2026 metrics
     (Early Intervention Rate, Intervention Gap, Tokens Saved) all
     require a step-of-detection timestamp, which is what
     ``step_index`` captures.

References
----------
- arxiv 2602.22302 (Bhardwaj, ABC) §3.6 — operational metrics
- arxiv 2601.22136 (Felicia et al., StepShield) — temporal detection
  metrics; ``step_index`` is the field they all derive from
- arxiv 2604.04035 (Agentic Reference Monitor) — denial events as
  first-class citizens; this record IS our denial event when severity
  is ``"block"``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


# Mirrors tex.contracts.contract.ConstraintKind but copied here to
# avoid the circular import (violation has to be importable by the
# enforcer which also imports the contract).
ViolatedClause = Literal[
    "precondition",
    "hard_invariant",
    "soft_invariant",
    "hard_governance",
    "soft_governance",
    "postcondition",
]


@dataclass(frozen=True, slots=True)
class ContractViolation:
    """
    One detected violation. Immutable once emitted.

    ``compliance_gap`` is the per-step ABC §3.6 contribution: 0.0 if
    the constraint was satisfied (so this record was not constructed
    in the first place) and 1.0 / |constraints| in the simple case of
    one violation, but we track it as the *normalised* fraction of
    constraints in this contract that were violated at the same step.
    The enforcer aggregates these to compute C_hard(t) / C_soft(t).

    ``recovery_deadline_step`` and ``recovered_at_step`` are populated
    only for soft violations. ``recovered_at_step`` may stay None if
    the soft constraint never recovers within the ``k`` window — at
    that point the violation is ESCALATED to hard and a *fresh*
    ContractViolation is emitted with severity bumped accordingly.
    """

    violation_id: str
    contract_id: str
    agent_id: str

    # The clause class in ABC's 6-tuple terminology.
    violated_clause: ViolatedClause
    clause_ltl: str  # the LTL source string, for replay / audit

    # When + what triggered this violation.
    detected_at: datetime
    triggering_event_id: str

    # StepShield-style temporal field — the index, within the
    # enforcement run, at which the detection fired. Pure step counter
    # owned by the enforcer; matches Early Intervention Rate semantics.
    step_index: int

    # Severity decision per the Tex action vocabulary
    # (block / sanction / warn). Not the same axis as hard/soft —
    # severity is the chosen policy response, the clause kind is the
    # ABC-paper category.
    severity: Literal["block", "sanction", "warn"]

    # ABC §3.6 — one-step compliance gap contribution in [0, 1].
    compliance_gap: float

    # Soft-violation recovery window bookkeeping. None for hard.
    recovery_deadline_step: int | None
    recovered_at_step: int | None

    # Cryptographic anchor — set when the enforcer is wired with a
    # ledger + provenance pair. Exact mirror of ChangePointEvent's
    # ledger_event_id field.
    ledger_event_id: str | None
