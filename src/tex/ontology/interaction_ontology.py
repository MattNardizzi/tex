"""
Interaction ontology — how actors coordinate.

Models the legal interaction patterns between entity kinds. For a given
(from_kind, to_kind) pair, returns the set of EventKinds that are
syntactically permitted at the type level.

This is a cheap, mechanical filter. Whether an interaction is *actually*
permitted (capability-grant present, governance graph allows the
transition, contract not violated) is decided downstream in the
ecosystem engine. This module only refuses interactions that are
nonsensical at the type level (e.g. a TOOL trying to revoke a
HUMAN's capability).

Priority: P1.
"""

from __future__ import annotations


# Adjacency table: (from_kind, to_kind) → tuple of permitted EventKind values.
# Pairs not listed are assumed to admit no interaction.
_ALLOWED: dict[tuple[str, str], tuple[str, ...]] = {
    # --- AGENT → ... ---
    ("agent", "tool"): (
        "agent_invokes_tool",
        "tool_registered",
    ),
    ("agent", "agent"): (
        "agent_to_agent_message",
    ),
    ("agent", "dataset"): (
        "agent_reads_data",
        "agent_writes_data",
    ),
    ("agent", "external_api"): (
        "agent_invokes_tool",          # external API treated as tool-like
    ),
    ("agent", "human"): (
        "agent_emits_output",
        "outbound_content_emitted",    # boundary event
    ),
    ("agent", "mcp_server"): (
        "agent_invokes_tool",
    ),

    # --- HUMAN → ... ---
    ("human", "agent"): (
        "agent_registered",
        "agent_decommissioned",
        "external_input_received",
    ),
    ("human", "tool"): (
        "tool_registered",
    ),
    ("human", "skill"): (
        "skill_installed",
    ),
    ("human", "capability"): (
        "capability_granted",
        "capability_revoked",
    ),
    ("human", "policy"): (
        "policy_decision",
    ),
    ("human", "governance_graph"): (
        "governance_graph_transition",
    ),

    # --- POLICY → ... ---
    ("policy", "agent"): (
        "verdict_emitted",
        "denial_event",
        "sanction_applied",
    ),
    ("policy", "tool"): (
        "verdict_emitted",
        "denial_event",
    ),
    ("policy", "capability"): (
        "capability_revoked",
    ),

    # --- CAPABILITY → ... ---
    ("capability", "agent"): (
        "capability_granted",
        "capability_revoked",
        "capability_used",
    ),

    # --- GOVERNANCE_GRAPH → ... ---
    ("governance_graph", "agent"): (
        "sanction_applied",
        "restorative_path_triggered",
    ),
    ("governance_graph", "policy"): (
        "governance_graph_transition",
    ),

    # --- CONTRACT → ... ---
    ("contract", "agent"): (
        "denial_event",
    ),

    # --- External boundary ---
    ("external_api", "agent"): (
        "external_input_received",
    ),

    # --- Drift / detection (system → agent or system → policy) ---
    # These have no natural "from" entity. Convention: emit from the
    # POLICY entity that owns the drift detector.
    ("policy", "governance_graph"): (
        "drift_signal_emitted",
        "change_point_detected",
    ),
}


def allowed_interactions(*, from_kind: str, to_kind: str) -> tuple[str, ...]:
    """
    Return the EventKinds permitted between these entity kinds.

    Returns an empty tuple if the pair has no permitted interactions.

    TODO(P1): return the EventKinds permitted between these entity kinds
    """
    if not isinstance(from_kind, str) or not isinstance(to_kind, str):
        raise TypeError("from_kind and to_kind must both be str")
    f_key = str(from_kind.value) if hasattr(from_kind, "value") else str(from_kind)
    t_key = str(to_kind.value) if hasattr(to_kind, "value") else str(to_kind)
    return _ALLOWED.get((f_key, t_key), ())


def is_interaction_allowed(
    *, from_kind: str, to_kind: str, event_kind: str
) -> bool:
    """Convenience: is a specific event_kind permitted between these kinds?"""
    return event_kind in allowed_interactions(from_kind=from_kind, to_kind=to_kind)
