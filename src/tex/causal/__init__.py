"""
Causal Layer — Hierarchical Causal Graphs + Reference Monitor
==============================================================

Two complementary mechanisms:

  CHIEF (arxiv 2602.23701)
    Hierarchical causal graph over agent traces. OTAR parsing
    (Observation-Thought-Action-Result). Hierarchical oracle-guided
    backtracking + counterfactual screening for failure attribution.

  ARM (arxiv 2604.04035) — Agentic Reference Monitor
    Treats DENIED actions as first-class graph nodes with counterfactual
    edges to subsequent actions that may have been causally influenced
    by the denial. Trust propagates through an integrity lattice.

Priority
--------
P1.
"""

from tex.causal.arm import (
    AgenticReferenceMonitor,
    LABEL_DERIVED_FROM_TAINTED,
    LABEL_TAINTED_BY_DENIAL,
    LABEL_TRUSTED,
    LABEL_UNTRUSTED_INPUT,
)
from tex.causal.chief import HierarchicalCausalGraph, HCGResult
from tex.causal.counterfactual import CounterfactualScreener, ScreeningOutcome
from tex.causal._denial_record import DenialRecord
from tex.causal._integrity import (
    DEFAULT_TRUST_THRESHOLD,
    IntegrityLevel,
    lattice_meet,
)

__all__ = [
    # Public API per scaffolding
    "HierarchicalCausalGraph",
    "AgenticReferenceMonitor",
    "CounterfactualScreener",
    # Result / record types
    "HCGResult",
    "ScreeningOutcome",
    "DenialRecord",
    # Integrity-lattice surfaces
    "IntegrityLevel",
    "DEFAULT_TRUST_THRESHOLD",
    "lattice_meet",
    # Public label constants for ARM.integrity_label_for
    "LABEL_TRUSTED",
    "LABEL_UNTRUSTED_INPUT",
    "LABEL_DERIVED_FROM_TAINTED",
    "LABEL_TAINTED_BY_DENIAL",
]
