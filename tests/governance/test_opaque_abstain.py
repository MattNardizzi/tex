"""Activation tests — un-inspectable TLS egress (``https_opaque``) resolves to
ABSTAIN in the live PDP (``StandingGovernance.decide``), closing G9's residual.

The proxy already LABELS un-inspectable egress ``https_opaque`` (it could not
MITM-terminate the TLS stream), but until now no rule consumed that label, so a
benign-scoring opaque request would PERMIT. These tests pin the deterministic
rule:

  * an opaque action that clears the structural floor -> ABSTAIN, NEVER PERMIT,
    even when deep adjudication WOULD permit (proves it is intercepted before the
    content-blind deep tier);
  * the ABSTAIN surfaces a held decision to the one voice;
  * the structural FORBID floor still WINS (unknown / out-of-surface agent stays
    FORBID — the more-cautious deterministic deny is never weakened to ABSTAIN);
  * a NORMAL action still reaches deep adjudication (no collateral change).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tex.domain.agent import CapabilitySurface
from tex.domain.evaluation import EvaluationResponse
from tex.domain.verdict import Verdict
from tex.governance.standing import StandingGovernance


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


class _Agent:
    def __init__(self, agent_id, *, surface=None, status="ACTIVE"):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = status
        self.capability_surface = surface
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


class _EmptyRegistry:
    def get(self, _uid):
        return None

    def list_all(self):
        return []


class _PermitEvaluate:
    """A deep PDP that ALWAYS permits — so an ABSTAIN can only come from the
    opaque rule intercepting BEFORE the deep tier, never from the deep verdict."""

    def execute(self, _request):
        return EvaluationResponse(
            decision_id=uuid4(),
            verdict=Verdict.PERMIT,
            confidence=0.99,
            final_score=0.01,
            reasons=["benign-scoring opaque blob"],
            policy_version="test",
            evaluated_at=datetime.now(UTC),
        )


class _ListSink:
    def __init__(self):
        self.items: list = []

    def append(self, item):
        self.items.append(item)


def _gov(agent, **kwargs) -> StandingGovernance:
    return StandingGovernance(
        agent_registry=_OneAgentRegistry(agent),
        evaluate_command=_PermitEvaluate(),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# The rule: opaque -> ABSTAIN, never PERMIT                                    #
# --------------------------------------------------------------------------- #


def test_https_opaque_abstains_never_permits():
    # Governable, in-surface (None surface => trivially in-bounds), and the deep
    # PDP would PERMIT — yet the opaque action ABSTAINs.
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    out = gov.decide(
        tenant="acme",
        action_type="https_opaque",
        content="TLS-opaque HTTPS egress to api.openai.com; content not inspectable",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.ABSTAIN
    assert out.released is False  # fail-closed: a hold never releases on its own
    assert out.held is True
    assert out.verdict is not Verdict.PERMIT


def test_https_opaque_raises_a_hold_to_the_voice():
    sink = _ListSink()
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id), held_sink=sink)
    gov.decide(
        tenant="acme",
        action_type="https_opaque",
        content="opaque",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert len(sink.items) == 1
    held = sink.items[0]
    assert held.kind == "https_opaque"
    assert held.detail["reason"] == "uninspectable_tls_content"
    assert "can't read" in held.note or "can't see" in held.note


# --------------------------------------------------------------------------- #
# The same rule for an un-decodable request BODY (http_opaque_body)            #
# --------------------------------------------------------------------------- #


def test_http_opaque_body_abstains_never_permits():
    # A request whose body uses a Content-Encoding the PEP cannot decode is
    # labelled http_opaque_body; like https_opaque it must ABSTAIN (held), never
    # a content-blind PERMIT, even though the deep PDP here would permit.
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    out = gov.decide(
        tenant="acme",
        action_type="http_opaque_body",
        content="POST /v1/chat/completions; body uses Content-Encoding 'br'",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.ABSTAIN
    assert out.released is False
    assert out.held is True


def test_http_opaque_body_raises_a_hold_with_body_reason():
    sink = _ListSink()
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id), held_sink=sink)
    gov.decide(
        tenant="acme",
        action_type="http_opaque_body",
        content="opaque body",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert len(sink.items) == 1
    held = sink.items[0]
    assert held.kind == "http_opaque_body"
    assert held.detail["reason"] == "uninspectable_request_body"


def test_http_opaque_body_unknown_agent_still_forbids():
    # Monotone: the structural FORBID floor still wins over the body-opaque rule.
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(), evaluate_command=_PermitEvaluate()
    )
    out = gov.decide(
        tenant="acme",
        action_type="http_opaque_body",
        content="opaque body",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=uuid4(),
    )
    assert out.verdict is Verdict.FORBID
    assert out.released is False
    assert out.tier == "floor"


# --------------------------------------------------------------------------- #
# Monotone safety — the structural FORBID floor still wins                     #
# --------------------------------------------------------------------------- #


def test_https_opaque_unknown_agent_still_forbids():
    # An unsealed agent is FORBIDden by the floor; the opaque rule must NOT
    # weaken that deterministic deny to ABSTAIN (FORBID is the more cautious
    # verdict — signals/rules may only move toward caution, never away).
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(), evaluate_command=_PermitEvaluate()
    )
    out = gov.decide(
        tenant="acme",
        action_type="https_opaque",
        content="opaque",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=uuid4(),
    )
    assert out.verdict is Verdict.FORBID
    assert out.released is False
    assert out.tier == "floor"


def test_https_opaque_out_of_surface_still_forbids():
    # The agent's sealed surface forbids this action type. The structural
    # capability floor FORBIDs it BEFORE the opaque rule can ABSTAIN.
    surface = CapabilitySurface(allowed_action_types=("send_email",))
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id, surface=surface))
    out = gov.decide(
        tenant="acme",
        action_type="https_opaque",
        content="opaque",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.FORBID
    assert out.released is False


def test_https_opaque_revoked_agent_still_forbids():
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id, status="REVOKED"))
    out = gov.decide(
        tenant="acme",
        action_type="https_opaque",
        content="opaque",
        channel="network",
        environment="production",
        recipient="api.openai.com",
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.FORBID


# --------------------------------------------------------------------------- #
# No collateral change to the normal (inspectable) path                       #
# --------------------------------------------------------------------------- #


def test_normal_action_still_reaches_deep_permit():
    # A readable action with a clean deep verdict still PERMITs — the opaque rule
    # is scoped to the https_opaque action class only.
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    out = gov.decide(
        tenant="acme",
        action_type="http_post",
        content="POST /v1/data",
        channel="network",
        environment="production",
        recipient="api.example",
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.PERMIT
    assert out.released is True
    assert out.tier == "deep"
