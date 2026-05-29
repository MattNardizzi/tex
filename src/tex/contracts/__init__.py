"""
[Architecture: Layer 4 (Execution Governance)] — LTLf behavioral contracts that gate the PDP routing stage

See ARCHITECTURE.md for the full six-layer model.

Contracts Layer — Agent Behavioral Contracts
============================================

Formal specifications + runtime enforcement for individual agent reliability.

Reference
---------
arxiv 2602.22302 (Bhardwaj 2026, "AgentAssert: Formal Behavioral
Contracts for Autonomous AI Agents"). The reference impl ships at
``github.com/qualixar/agentassert-abc`` (Elastic License 2.0).

A behavioral contract specifies, for a single agent, the formal 6-tuple
``C = (P, I_hard, I_soft, G_hard, G_soft, R)``:

  - precondition (P): must hold before any covered action
  - hard invariants (I_hard): must hold at every step (safety)
  - soft invariants (I_soft): may transiently fail, must recover within k
  - hard governance (G_hard): zero-tolerance bounds on actions
  - soft governance (G_soft): recoverable bounds on actions
  - recovery (R): partial map from violated soft constraint to corrective
    action sequence; modelled here as an injectable RecoveryDispatcher

Distinct from governance graphs (institution-level) and runtime
defenses (action-level): contracts are *agent-level* commitments. The
ABC paper's (p, δ, k)-satisfaction is exposed as fields on
``BehavioralContract`` so a future SPRT certifier
(``tex.contracts.certification``, P2) can compute statistical guarantees
without re-deriving the parameters.

Priority
--------
P1.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.contracts import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

from tex.contracts._atoms import ContractContext
from tex.contracts._ltl import LTLFormula, LTLParseError, RVVerdict
from tex.contracts.contract import BehavioralContract
from tex.contracts.runtime_enforcement import (
    ComplianceScores,
    ContractEnforcer,
    RecoveryDispatcher,
    all_active_contracts,
)
from tex.contracts.violation import ContractViolation

__all__ = [
    # Specification
    "BehavioralContract",
    # Enforcement
    "ContractEnforcer",
    "ComplianceScores",
    "RecoveryDispatcher",
    "all_active_contracts",
    # Violations
    "ContractViolation",
    # LTL surface
    "LTLFormula",
    "LTLParseError",
    "RVVerdict",
    # Atom resolution context
    "ContractContext",
]
