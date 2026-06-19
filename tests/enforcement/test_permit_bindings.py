"""``permit.verify`` binds tenant / agent / action_type (review should-fix).

The signer always binds ``tn``/``aid``/``act`` into the signature; these pin that
a verifier (the PEP, or any downstream Tex-aware service) can refuse a permit
minted for a different tenant, agent, or action — not just a different audience
or content.
"""

from __future__ import annotations

import uuid

from tex.enforcement import permit


def _mint(monkeypatch):
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "s3cret-test")
    return permit.mint(
        decision_id=uuid.uuid4(),
        tenant="acme",
        action_type="http_post",
        agent_id="agent-1",
        recipient="api.example",
        content=b"x",
        ttl_seconds=60,
    )


def test_tenant_mismatch_rejected(monkeypatch):
    m = _mint(monkeypatch)
    assert permit.verify(m.token, expected_tenant="acme").ok
    bad = permit.verify(m.token, expected_tenant="evil-corp")
    assert not bad.ok and "tenant" in bad.reason


def test_agent_mismatch_rejected(monkeypatch):
    m = _mint(monkeypatch)
    assert permit.verify(m.token, expected_agent_id="agent-1").ok
    bad = permit.verify(m.token, expected_agent_id="agent-2")
    assert not bad.ok and "agent" in bad.reason


def test_action_type_mismatch_rejected(monkeypatch):
    m = _mint(monkeypatch)
    assert permit.verify(m.token, expected_action_type="http_post").ok
    bad = permit.verify(m.token, expected_action_type="http_get")
    assert not bad.ok and "action_type" in bad.reason


def test_all_bindings_together_pass(monkeypatch):
    m = _mint(monkeypatch)
    v = permit.verify(
        m.token,
        expected_tenant="acme",
        expected_agent_id="agent-1",
        expected_action_type="http_post",
        expected_audience="api.example",
        expected_content_digest=permit.content_digest(b"x"),
    )
    assert v.ok
