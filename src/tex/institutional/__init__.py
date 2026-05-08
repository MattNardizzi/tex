"""
Institutional Layer — Public Governance Graph + Oracle/Controller
==================================================================

The headline architecture from arxiv 2601.10599 + 2601.11369 (Institutional
AI). Reframes alignment from preference engineering in agent-space to
mechanism design in institution-space.

The governance graph is a public, immutable manifest declaring:
  - legal states (entity-state configurations the institution permits)
  - legal transitions between states (typed by EventKind)
  - sanctions for illegal transitions
  - restorative paths from sanctioned states back to legal ones

The Oracle observes; the Controller acts.

Empirical results (arxiv 2601.11369): mean collusion tier falls from 3.1
to 1.8 (Cohen's d=1.28); severe-collusion incidence drops from 50% to 5.6%.

Priority
--------
P1 — this is the architectural centerpiece of ecosystem governance.
"""

from tex.institutional.controller import (
    ControllerDecision,
    ControllerOutcome,
    GovernanceController,
)
from tex.institutional.governance_graph import (
    CANONICAL_COURNOT_STATES,
    GovernanceGraph,
    GovernanceGraphValidationError,
    LegalState,
    LegalTransition,
)
from tex.institutional.governance_log import GovernanceLog
from tex.institutional.oracle import (
    SIGNAL_HIGH_HHI,
    SIGNAL_SPECIALISATION,
    SIGNAL_SYNCHRONOUS_MOVE,
    SIGNAL_VARIANCE_COLLAPSE,
    GovernanceOracle,
    OracleCase,
    OracleObservation,
    OracleSignal,
    collusion_tier,
)
from tex.institutional.sanctions import RestorativePath, Sanction

__all__ = [
    # Topology
    "GovernanceGraph",
    "GovernanceGraphValidationError",
    "LegalState",
    "LegalTransition",
    "CANONICAL_COURNOT_STATES",
    # Sanctions / restoration
    "Sanction",
    "RestorativePath",
    # Engine
    "GovernanceOracle",
    "GovernanceController",
    "ControllerDecision",
    "ControllerOutcome",
    # Cases / observations
    "OracleCase",
    "OracleObservation",
    "OracleSignal",
    # Signal IDs
    "SIGNAL_SYNCHRONOUS_MOVE",
    "SIGNAL_VARIANCE_COLLAPSE",
    "SIGNAL_HIGH_HHI",
    "SIGNAL_SPECIALISATION",
    # Helpers
    "collusion_tier",
    # Log
    "GovernanceLog",
]
