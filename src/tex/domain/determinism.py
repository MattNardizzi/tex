"""
Determinism fingerprint for a single Tex evaluation.

The fingerprint is a stable SHA-256 hash over inputs that are supposed
to reproduce exactly the same verdict: content hash, policy version,
deterministic rule firings, semantic dimension scores, and specialist
scores. Two evaluations with the same inputs produce the same
fingerprint; any drift in verdict for the same fingerprint is a
calibration or model-stability issue worth investigating.

CISOs obsess over "AI that changes its mind." This field gives them a
deterministic anchor they can diff against.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

from tex.deterministic.gate import DeterministicGateResult
from tex.semantic.schema import SemanticAnalysis
from tex.specialists.base import SpecialistBundle


def compute_determinism_fingerprint(
    *,
    content_sha256: str,
    policy_version: str,
    deterministic_result: DeterministicGateResult,
    specialist_bundle: SpecialistBundle,
    semantic_analysis: SemanticAnalysis,
) -> str:
    """
    Compute a stable SHA-256 fingerprint over the evaluation inputs.

    Scores are quantized to 2 decimals before hashing so imperceptible
    floating-point jitter does not change the fingerprint across
    otherwise identical runs. This is the intended behavior: the
    fingerprint is a stability anchor, not a bit-for-bit content hash.
    """
    parts: list[str] = []

    parts.append(f"content:{content_sha256}")
    parts.append(f"policy:{policy_version}")

    # Deterministic recognizer firings, sorted for stability.
    deterministic_signatures = sorted(
        f"{finding.rule_name}:{finding.severity.value}"
        for finding in deterministic_result.findings
    )
    parts.append("deterministic:" + ",".join(deterministic_signatures))
    parts.append(f"deterministic_blocked:{deterministic_result.blocked}")

    # Specialist scores, sorted by name for stability.
    specialist_signatures = sorted(
        f"{result.specialist_name}:{_quantize(result.risk_score)}"
        for result in specialist_bundle.results
    )
    parts.append("specialists:" + ",".join(specialist_signatures))

    # Semantic dimension scores, sorted by dimension for stability.
    semantic_signatures = sorted(
        f"{result.dimension}:{_quantize(result.score)}"
        for result in semantic_analysis.dimension_results
    )
    parts.append("semantic:" + ",".join(semantic_signatures))

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _quantize(value: float) -> str:
    """Quantize a score to 2 decimals as a canonical string."""
    return f"{round(value, 2):.2f}"


def fingerprint_components(
    *,
    deterministic_result: DeterministicGateResult,
    specialist_bundle: SpecialistBundle,
    semantic_analysis: SemanticAnalysis,
) -> Iterable[str]:
    """
    Return the list of component strings that go into the fingerprint.

    Exposed for debugging and audit UIs that want to show exactly
    which inputs went into the fingerprint.
    """
    yield "deterministic_findings:" + ",".join(
        sorted(
            f"{finding.rule_name}:{finding.severity.value}"
            for finding in deterministic_result.findings
        )
    )
    yield "specialists:" + ",".join(
        sorted(
            f"{result.specialist_name}:{_quantize(result.risk_score)}"
            for result in specialist_bundle.results
        )
    )
    yield "semantic_dimensions:" + ",".join(
        sorted(
            f"{result.dimension}:{_quantize(result.score)}"
            for result in semantic_analysis.dimension_results
        )
    )
