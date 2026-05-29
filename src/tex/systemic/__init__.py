"""
[Architecture: Layer 4 (Execution Governance)] — systemic risk and digital-twin simulation — wired via ecosystem engine and twin route

See ARCHITECTURE.md for the full six-layer model.

Systemic Layer — Risk Evaluation + Digital Twin
=================================================

Top-of-stack systemic risk evaluator. Models the ecosystem as a complex
adaptive system with multi-time-scale risk propagation.

References
----------
- arxiv 2509.17878 (AI, Digital Platforms, and the New Systemic Risk)
- arxiv 2512.11933 (The Agentic Regulator: agent-based governance for finance)
- SR-DTMA (Digital Twin-Driven LLM Multi-Agent Framework, 2026)
- arxiv 2502.14143 (Multi-Agent Risks from Advanced AI)

Three components:
  risk_evaluator     Static + dynamic systemic risk scoring
  digital_twin       Replay-and-perturb simulator over the live ecosystem
  cascade_predictor  Predict cascade failure paths

Priority
--------
P2 — the digital twin is a 6-month build. Risk evaluator skeleton in P1.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.systemic import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

from tex.systemic.risk_evaluator import SystemicRiskEvaluator
from tex.systemic.digital_twin import EcosystemDigitalTwin, DEFAULT_HORIZON, MAX_HORIZON
from tex.systemic._koopman import TenantSignalProfile
from tex.systemic._sccal import (
    curvature_gated_attention_step,
    curvature_gated_recurrence,
)
from tex.systemic.cascade_predictor import (
    CascadePredictor,
    DependencyEdge,
    estimate_edge_probability,
)
from tex.systemic.trajectory import (
    CascadePath,
    SimulationTrajectory,
    SystemicWeights,
    TrajectoryStep,
)

__all__ = [
    "SystemicRiskEvaluator",
    "EcosystemDigitalTwin",
    "CascadePredictor",
    "DependencyEdge",
    "estimate_edge_probability",
    "CascadePath",
    "SimulationTrajectory",
    "SystemicWeights",
    "TrajectoryStep",
    "TenantSignalProfile",
    "curvature_gated_attention_step",
    "curvature_gated_recurrence",
    "DEFAULT_HORIZON",
    "MAX_HORIZON",
]
