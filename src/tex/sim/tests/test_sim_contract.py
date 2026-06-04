"""
Contract tests for tex.sim — these keep the mirror honest as Tex evolves.

They assert the three things that make the sandbox a faithful mirror rather
than a toy:
  1. the estate generator produces the configured population, deterministically
  2. every authored action draws its intended verdict from the REAL gate
  3. the estate flows through the REAL discovery connectors and is discovered

If Tex's recognizers, policy, or connectors change in a way that breaks the
mirror, these fail loudly — which is the point.
"""

from __future__ import annotations

import uuid

import pytest

from tex.sim.actions import TEMPLATES
from tex.sim.connectors import build_sandbox_connectors
from tex.sim.estate import cloudtrail_records, entra_pages, generate_estate


def test_estate_is_deterministic_and_sized():
    a = generate_estate(seed=7, idp_agents=170, shadow_agents=30)
    b = generate_estate(seed=7, idp_agents=170, shadow_agents=30)
    assert len(a.agents) == 200
    assert len(a.idp_agents) == 170
    assert len(a.shadow_agents) == 30
    # deterministic: same seed -> identical external ids in order
    assert [x.external_id for x in a.agents] == [x.external_id for x in b.agents]


def test_smoke_estate_small():
    est = generate_estate(seed=1, idp_agents=9, shadow_agents=3)
    assert len(est.agents) == 12


def test_authored_actions_draw_intended_verdict():
    """Every template's content must draw its intended verdict from the real
    DeterministicGate under the default policy. This is the contract that lets
    the oracle assert verdicts at all."""
    from tex.deterministic.gate import DeterministicGate
    from tex.domain.evaluation import EvaluationRequest
    from tex.policies.defaults import build_default_policy

    policy = build_default_policy()
    gate = DeterministicGate()

    def verdict(content: str) -> str:
        req = EvaluationRequest(
            request_id=uuid.uuid4(), action_type="x", content=content,
            channel="email", environment="prod",
        )
        res = gate.evaluate(request=req, policy=policy)
        sv = res.suggested_verdict
        return sv.value if sv else "PERMIT"

    mismatches = []
    for t in TEMPLATES:
        for content in t.contents:
            got = verdict(content)
            if got != t.intended_verdict:
                mismatches.append((t.profile, t.intended_verdict, got, content))
    assert not mismatches, f"verdict drift: {mismatches}"


def test_estate_flows_through_real_connectors():
    """The synthetic estate must be discoverable by the real connectors — the
    population seam. 170 via the IdP root, 30 via the audit catch."""
    from tex.discovery.connectors.base import ConnectorContext

    est = generate_estate(seed=7, idp_agents=170, shadow_agents=30)
    connectors = build_sandbox_connectors(est)
    ctx = ConnectorContext(tenant_id=est.tenant_id)
    counts = {type(c).__name__: len(list(c.scan(ctx))) for c in connectors}
    assert counts.get("EntraConsentGraphConnector") == 170
    assert counts.get("OcsfAuditConnector") == 30
    assert sum(counts.values()) == 200


def test_wire_shapes_nonempty():
    est = generate_estate(seed=7, idp_agents=12, shadow_agents=4)
    pages = entra_pages(est)
    assert "servicePrincipals" in pages and len(pages["servicePrincipals"]) == 12
    records = cloudtrail_records(est)
    assert records and all(r["eventSource"] == "bedrock-agentcore.amazonaws.com" for r in records)
