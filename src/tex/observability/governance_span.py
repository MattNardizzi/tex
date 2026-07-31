"""
OpenTelemetry-compatible governance span attributes for ecosystem
verdicts.

Reference: Governance-Aware Agent Telemetry (GAAT, arxiv 2604.05119,
Apr 6 2026, Apple). GAAT extends OpenTelemetry's span attribute
schema with governance metadata so OpenTelemetry exporters (Jaeger,
Tempo, AWS X-Ray, Honeycomb) can render and query ecosystem verdicts
without bespoke tooling.

This module emits **attribute dicts**, not OpenTelemetry SDK objects.
We do NOT take a hard dependency on ``opentelemetry-api``; downstream
operators wrap the attribute dict into a real span via their existing
OTel pipeline. The shape is:

    {
        # OpenTelemetry standard
        "service.name": "tex",
        "service.namespace": "ecosystem",
        # GAAT-compatible governance attributes (GAAT §III.A)
        "governance.decision": "permit" | "abstain" | ...,
        "governance.enforcement_level": "L0_allow" | ... | "L4_quarantine",
        "governance.viability_index": 0.92,
        # Tex-specific decomposition (above-and-beyond GAAT)
        "tex.axis.contract_violation_severity": ...,
        ...
    }

The schema is stable and versioned via ``GAAT_SPAN_SCHEMA_VERSION``.

References
----------
- GAAT (arxiv 2604.05119, Apr 6 2026) — GTS schema, §III.A
- OpenTelemetry Semantic Conventions v1.32 — service / resource
"""

from __future__ import annotations

from typing import Any

from tex.ecosystem.verdict import EcosystemVerdict


# Schema version. Bump on any breaking change to the attribute set.
GAAT_SPAN_SCHEMA_VERSION: str = "1.0"


def verdict_to_otel_attributes(
    verdict: EcosystemVerdict,
    *,
    service_name: str = "tex",
    service_namespace: str = "ecosystem",
    additional: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Render an ``EcosystemVerdict`` as an OpenTelemetry span attribute
    dict in the GAAT-compatible governance schema.

    Parameters
    ----------
    verdict
        The verdict to render.
    service_name, service_namespace
        OpenTelemetry resource attributes.
    additional
        Optional dict of extra attributes to merge in (e.g. tenant id,
        request id from upstream middleware). Caller is responsible
        for ensuring keys don't collide with the governance schema.

    Returns
    -------
    Dict of attribute name → value. Values are OpenTelemetry-allowed
    types (str, bool, int, float, or list of those).
    """
    axes = verdict.axis_scores
    attrs: dict[str, Any] = {
        # OpenTelemetry resource attributes.
        "service.name": service_name,
        "service.namespace": service_namespace,
        # Schema version for downstream consumers.
        "tex.governance.schema_version": GAAT_SPAN_SCHEMA_VERSION,
        # GAAT-compatible governance attributes (the §III.A core set).
        "governance.decision": verdict.kind.value,
        "governance.enforcement_level": axes.graduated_level.value,
        "governance.viability_index": axes.viability_index,
        # Tex-specific six-axis decomposition.
        "tex.axis.contract_violation_severity": axes.contract_violation_severity,
        "tex.axis.governance_graph_legality": axes.governance_graph_legality,
        "tex.axis.causal_attribution_confidence": axes.causal_attribution_confidence,
        "tex.axis.drift_delta": axes.drift_delta,
        "tex.axis.systemic_risk_under_event": axes.systemic_risk_under_event,
        "tex.axis.bounded_compromise_score": axes.bounded_compromise_score,
        # Envelope fields useful for trace correlation.
        "tex.proposed_event_id": verdict.proposed_event_id,
        "tex.state_hash_before": verdict.ecosystem_state_hash_before,
        # Issued time as ISO string (OpenTelemetry forbids datetime).
        "tex.issued_at": verdict.issued_at.isoformat(),
    }
    if verdict.ecosystem_state_hash_after is not None:
        attrs["tex.state_hash_after"] = verdict.ecosystem_state_hash_after
    if verdict.evidence_record_id is not None:
        attrs["tex.evidence_record_id"] = verdict.evidence_record_id
    if verdict.recommended_intervention_id is not None:
        attrs["tex.recommended_intervention_id"] = (
            verdict.recommended_intervention_id
        )

    if additional:
        attrs.update(additional)
    return attrs


# GAAT-compatible enforcement-level → action map (arxiv 2604.05119
# §III.A Table I). Provided as a reference for downstream consumers
# that want to mirror GAAT's L0..L4 → action semantics.
GAAT_ACTION_TABLE: dict[str, str] = {
    "L0_allow": "ALLOW",
    "L1_alert": "ALERT",
    "L2_flag": "FLAG",
    "L3_redirect": "REDIRECT",
    "L4_quarantine": "QUARANTINE",
}
