"""
AIRO (AI Risk Ontology) bindings.

Per Golpayegani et al. 2022 + arxiv 2604.27713.

Maps Tex entity/event types into the AIRO compliance ontology so that
verdicts can be expressed in regulator-readable terms (EU AI Act roles,
high-risk classifications, deployer obligations).

Priority: P1.

References
----------
- AIRO is published under https://w3id.org/airo (resolves to a SKOS/OWL
  vocabulary). All term URIs use the canonical ``airo:`` prefix.
- AIRO core classes: AISystem, AICapability, AIDomain, AIPurpose, AIUser,
  AISubject, AIRisk, RiskSource, Consequence, Stakeholder.
- Some Tex entity kinds (CAPABILITY, POLICY, GOVERNANCE_GRAPH) don't
  cleanly correspond to a single AIRO class. We map them to the closest
  match and mark with TODO(verify-airo-spec) so a future thread can
  reconcile against the AIRO 2025 update.
"""

from __future__ import annotations


_AIRO_NS = "https://w3id.org/airo#"
_DPV_NS = "https://w3id.org/dpv#"


def _airo(*terms: str) -> tuple[str, ...]:
    return tuple(f"{_AIRO_NS}{t}" for t in terms)


def _dpv(*terms: str) -> tuple[str, ...]:
    return tuple(f"{_DPV_NS}{t}" for t in terms)


# Tex entity kind → AIRO term URIs
# TODO(verify-airo-spec): confirm class names against AIRO 2025 spec; some
# mappings (CAPABILITY, POLICY, GOVERNANCE_GRAPH) lean on extensions that
# may have shifted naming.
_ENTITY_TO_AIRO: dict[str, tuple[str, ...]] = {
    "agent": _airo("AISystem", "AICapability"),
    "tool": _airo("AICapability"),
    "mcp_server": _airo("AICapability"),
    "dataset": _airo("AISystem") + _dpv("PersonalData"),  # TODO(verify-airo-spec): AIRO-Tech adds dataset class
    "model": _airo("AISystem"),
    "human": _airo("AIUser", "AISubject", "Stakeholder"),
    "capability": _airo("AICapability"),  # TODO(verify-airo-spec): no native capability class
    "policy": _airo("RiskMitigationMeasure"),  # TODO(verify-airo-spec): AIRO 2025 introduces explicit policy class
    "governance_graph": _airo("RiskMitigationMeasure"),  # TODO(verify-airo-spec)
    "skill": _airo("AICapability"),
    "external_api": _airo("AISystem"),  # third-party AISystem from AIRO's perspective
    "contract": _airo("RiskMitigationMeasure"),  # TODO(verify-airo-spec)
}


# Tex event kind → AIRO term URIs
# Pattern: actions emit Consequences; capability changes are RiskMitigationMeasure
# transitions; drift/change-point events are RiskSource signals.
_EVENT_TO_AIRO: dict[str, tuple[str, ...]] = {
    # Action events
    "agent_emits_output": _airo("Consequence"),
    "agent_invokes_tool": _airo("Consequence", "RiskSource"),
    "agent_to_agent_message": _airo("Consequence"),
    "agent_reads_data": _airo("Consequence") + _dpv("Read"),
    "agent_writes_data": _airo("Consequence") + _dpv("Modify"),
    # Capability events
    "capability_granted": _airo("RiskMitigationMeasure"),
    "capability_revoked": _airo("RiskMitigationMeasure"),
    "capability_used": _airo("Consequence"),
    # Policy / verdict events
    "policy_decision": _airo("RiskMitigationMeasure"),
    "verdict_emitted": _airo("RiskMitigationMeasure"),
    "denial_event": _airo("RiskMitigationMeasure", "Consequence"),
    # Governance events
    "governance_graph_transition": _airo("RiskMitigationMeasure"),
    "sanction_applied": _airo("RiskMitigationMeasure", "Consequence"),
    "restorative_path_triggered": _airo("RiskMitigationMeasure"),
    # Lifecycle events
    "agent_registered": _airo("AISystem"),
    "agent_decommissioned": _airo("AISystem"),
    "tool_registered": _airo("AICapability"),
    "skill_installed": _airo("AICapability"),
    # Drift / detection events
    "drift_signal_emitted": _airo("RiskSource"),
    "change_point_detected": _airo("RiskSource", "AIRisk"),
    # External / boundary events
    "external_input_received": _airo("RiskSource"),
    # OUTBOUND_CONTENT_EMITTED is the regulator-facing event: it produces a
    # Consequence affecting an external Stakeholder. EU AI Act Art. 50
    # disclosure obligations attach here.
    "outbound_content_emitted": _airo("Consequence", "Stakeholder"),
}


def map_entity_to_airo(entity_kind: str) -> tuple[str, ...]:
    """
    Return AIRO term URIs for a Tex entity kind.

    TODO(P1): return AIRO term URIs for a Tex entity kind
    TODO(verify-airo-spec): some mappings (CAPABILITY, POLICY,
        GOVERNANCE_GRAPH, CONTRACT) lean on AIRO extensions whose class
        names may have changed in the 2025 update.
    """
    if not isinstance(entity_kind, str):
        raise TypeError(f"entity_kind must be str, got {type(entity_kind).__name__}")
    # Enum subclasses of str are accepted; coerce to plain str for the lookup
    # so the table key stays a single canonical type.
    key = str(entity_kind.value) if hasattr(entity_kind, "value") else str(entity_kind)
    try:
        return _ENTITY_TO_AIRO[key]
    except KeyError as exc:
        raise KeyError(
            f"no AIRO mapping for entity kind {entity_kind!r}"
        ) from exc


def map_event_to_airo(event_kind: str) -> tuple[str, ...]:
    """
    Return AIRO term URIs for a Tex event kind.

    TODO(P1): return AIRO term URIs for a Tex event kind
    TODO(verify-airo-spec): event-to-Consequence mappings are best-effort;
        AIRO does not natively distinguish action types at the granularity
        the Tex event taxonomy requires.
    """
    if not isinstance(event_kind, str):
        raise TypeError(f"event_kind must be str, got {type(event_kind).__name__}")
    key = str(event_kind.value) if hasattr(event_kind, "value") else str(event_kind)
    try:
        return _EVENT_TO_AIRO[key]
    except KeyError as exc:
        raise KeyError(
            f"no AIRO mapping for event kind {event_kind!r}"
        ) from exc
