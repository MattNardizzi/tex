"""build_grounded_facts: the brain's fact sheet is derived from the gate's OWN
recompute, so the brain and gate agree on every number by construction. It surfaces
EXACTLY the aggregates the gate would seal (grounded + has evidence) and never the
parametric queries.
"""

from __future__ import annotations

from tex.presence.brain.grounded_facts import build_grounded_facts
from tex.presence.contract import ClaimKind
from tex.presence.gate.queries import QUERIES


def _by_key(sheet):
    return {f["claim_id"]: f for f in sheet["recomputable_facts"]}


def _sealable_aggregates(state, tenant):
    """What the gate would actually seal: every non-parametric AGGREGATE whose
    recompute is grounded AND backed by evidence (its value)."""
    out = {}
    for q in QUERIES:
        if q.needs_target or q.kind is not ClaimKind.AGGREGATE:
            continue
        rc = q.recompute(state, tenant, None)
        if rc.grounded and rc.evidence:
            out[q.key] = rc.value
    return out


def test_sheet_is_exactly_the_sealable_aggregates_with_gate_values(populated_state):
    """THE invariant: the sheet contains exactly the gate's sealable aggregates,
    each with the gate's own recomputed value — so a brain that uses it cannot
    state a number the gate would reject."""
    sheet = build_grounded_facts(populated_state, tenant="acme")
    got = {f["claim_id"]: f["value"] for f in sheet["recomputable_facts"]}
    assert got == _sealable_aggregates(populated_state, tenant="acme")


def test_agent_count_present_and_tenant_scoped(populated_state):
    facts = _by_key(build_grounded_facts(populated_state, tenant="acme"))
    agent_q = next(q for q in QUERIES if q.key == "agent_count")
    assert facts["agent_count"]["value"] == agent_q.recompute(populated_state, "acme", None).value
    # A tenant with no agents → zero count, no evidence → agent_count omitted.
    no_agents = _by_key(build_grounded_facts(populated_state, tenant="no-such-tenant"))
    assert "agent_count" not in no_agents


def test_never_surfaces_parametric_queries(populated_state):
    facts = _by_key(build_grounded_facts(populated_state, tenant="acme"))
    assert "agent_status" not in facts  # needs a named agent
    assert "root_cause_region" not in facts  # needs a named agent


def test_omits_unavailable_and_zero_count_queries(populated_state):
    facts = _by_key(build_grounded_facts(populated_state, tenant="acme"))
    # scan_run_store has only a RUNNING scan (no FAILED) → zero, no evidence → omitted.
    assert "failed_scan_count" not in facts
    # Anything present must be one the gate would seal.
    sealable = _sealable_aggregates(populated_state, tenant="acme")
    assert set(facts) == set(sealable)


def test_carries_canonical_phrase_and_dimension_context(populated_state):
    sheet = build_grounded_facts(
        populated_state, tenant="acme", dimension_facts={"dim": "identity"}
    )
    facts = _by_key(sheet)
    agent_q = next(q for q in QUERIES if q.key == "agent_count")
    # The phrase is the gate's own — what the voice speaks when sealed.
    assert facts["agent_count"]["phrase"] == agent_q.recompute(populated_state, "acme", None).canonical_phrase
    assert sheet["dimension_context"] == {"dim": "identity"}


def test_resolves_state_off_app_state():
    """Handed a request-like object, the builder reads request.app.state (the
    live-server shape), not the request itself."""
    from types import SimpleNamespace

    from tex.stores.agent_registry import InMemoryAgentRegistry
    from tex.domain.agent import AgentIdentity

    registry = InMemoryAgentRegistry()
    registry.save(AgentIdentity(name="solo", owner="acme", tenant_id="acme"))
    state = SimpleNamespace(agent_registry=registry)
    request = SimpleNamespace(app=SimpleNamespace(state=state))

    facts = _by_key(build_grounded_facts(request, tenant="acme"))
    assert facts["agent_count"]["value"] == 1
