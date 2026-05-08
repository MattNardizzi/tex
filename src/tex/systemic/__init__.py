"""
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

from tex.systemic.risk_evaluator import SystemicRiskEvaluator
from tex.systemic.digital_twin import EcosystemDigitalTwin
from tex.systemic.cascade_predictor import CascadePredictor

__all__ = [
    "SystemicRiskEvaluator",
    "EcosystemDigitalTwin",
    "CascadePredictor",
]
