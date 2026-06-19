"""Call-site tests for the credential broker wired into the PEP proxy (G12).

These pin the behaviour the egress call-site must have:

  * flag OFF (default) => byte-for-byte today's behaviour: no credential is
    minted, the agent's standing Authorization header passes through untouched;
  * flag ON, released decision => a fresh, single-use, action-scoped Tex
    credential is minted, the agent's STANDING credential is STRIPPED, and the
    minted token is injected (sole-token-custody);
  * the minted credential is bound to the released decision (verifies under the
    SAME audience + action) and is sender-constrained to the agent's cnf key;
  * the scope the credential carries is the intersection with the decision's
    allowed scope (act:<action_type>), NOT an arbitrary requested scope;
  * single-use: the minted credential's store row is consumed (a replay is
    rejected by the broker);
  * fail-closed: flag ON but the agent presented no cnf key (PoP-only broker)
    => the released action is REFUSED, never forwarded with a weaker token.

A REAL ``MemorySystem`` backs the permit/credential store; the decision client,
forwarder, and orig_dst loader are fakes (matching the reference-monitor tests).
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority import pop
from tex.authority.broker import CredentialBroker, _use_binding
from tex.identity.agent_credential import AttestedIdentity
from tex.memory.system import MemorySystem
from tex.pep.decision_client import Decision, DecisionClient, DecisionResult
from tex.pep.proxy import (
    ProxyConfig,
    ResolvedDst,
    TexEnforcementProxy,
    UpstreamResponse,
)


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    """A hermetic signing secret so the permit gate AND the broker can mint."""
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "callsite-test-secret")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", "callsite-test-secret")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    yield


# --------------------------------------------------------------------------- #
# Fakes (mirror tests/pep/test_proxy_reference_monitor.py)                     #
# --------------------------------------------------------------------------- #


class _RecordingForwarder:
    def __init__(self):
        self.calls: list[dict] = []

    def send(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return UpstreamResponse(status=200, headers={"content-type": "text/plain"}, body=b"OK")


class _StaticClient(DecisionClient):
    def __init__(self, result: DecisionResult):
        self._result = result

    def decide(self, decision: Decision) -> DecisionResult:
        return self._result


class _FakeResolver:
    def __init__(self, dst: ResolvedDst | None):
        self._dst = dst

    def resolve(self, src_ip, src_port):
        return self._dst


def _permit_result() -> DecisionResult:
    return DecisionResult(
        released=True, verdict="PERMIT", reason="ok", decision_id=str(uuid4())
    )


def _mem() -> MemorySystem:
    d = tempfile.mkdtemp()
    return MemorySystem(tenant_id="default", evidence_path=os.path.join(d, "ev.jsonl"))


def _holder() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _cnf_jwk(holder: Ed25519PrivateKey) -> dict:
    raw = holder.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return pop.public_jwk(raw)


def _signed_card(agent_id: str, *, cnf: dict | None = None, issuer: str = "issuer-1"):
    """An Ed25519-signed identity card (+ its trusted_issuers map). When ``cnf`` is
    given, it is folded into the signed payload (RFC 7800 holder PoP key)."""
    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload: dict = {"agent_id": agent_id, "name": "demo"}
    if cnf is not None:
        payload["cnf"] = cnf
    jcs = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    card = {
        "payload": payload,
        "issuer": issuer,
        "signature_b64": base64.b64encode(sk.sign(jcs)).decode("ascii"),
    }
    issuers = {issuer: base64.b64encode(raw_pub).decode("ascii")}
    return card, issuers


def _cred_header(card: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(card).encode()).decode("ascii")


def _get_ci(headers: dict, name: str):
    """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def _build(*, broker: bool, issuers: dict, **cfg_over):
    fwd = _RecordingForwarder()
    mem = _mem()
    config = ProxyConfig(
        trusted_issuers=issuers,
        broker_credentials=broker,
        **cfg_over,
    )
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit_result()),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        permit_memory=mem,
        config=config,
    )
    return proxy, fwd, mem


def _handle(proxy, *, agent_id, card, standing="Bearer agent-standing-token"):
    headers = {
        "X-Tex-Agent-Id": agent_id,
        "X-Tex-Agent-Credential": _cred_header(card),
    }
    if standing is not None:
        headers["Authorization"] = standing
    return proxy.handle(
        method="POST", path="/p", headers=headers, body=b"payload", peer=("1.2.3.4", 5)
    )


# --------------------------------------------------------------------------- #
# Flag OFF — behaviour-neutral                                                 #
# --------------------------------------------------------------------------- #


def test_flag_off_is_behaviour_neutral_standing_cred_passes_through():
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, _ = _build(broker=False, issuers=issuers)

    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 200
    assert fwd.calls, "released action must still forward"
    sent = fwd.calls[0]["headers"]
    # The broker is off: the agent's own Authorization passes through unchanged,
    # and there is no minted Tex credential.
    assert sent.get("Authorization") == "Bearer agent-standing-token"
    assert "tex-cred" not in json.dumps(sent)


# --------------------------------------------------------------------------- #
# Flag ON — mint + inject + strip standing cred                               #
# --------------------------------------------------------------------------- #


def test_flag_on_mints_singleuse_actionscoped_token_and_strips_standing():
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, mem = _build(broker=True, issuers=issuers)

    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 200, resp.body
    assert fwd.calls
    sent = fwd.calls[0]["headers"]

    # Sole-token-custody: the agent's standing Authorization is REPLACED by a
    # freshly minted Tex credential (DPoP, since it is sender-constrained).
    auth = _get_ci(sent, "Authorization")
    assert auth is not None and auth != "Bearer agent-standing-token"
    # The agent's standing token never survives anywhere in the egress headers.
    assert "agent-standing-token" not in json.dumps(sent)
    token_type, _, token = auth.partition(" ")
    assert token_type == "DPoP"  # PoP-bound

    # The minted credential verifies under the decision's audience + action, is
    # bound to the attested subject, and carries the action-scoped scope.
    broker = proxy._cred_broker
    proof = pop.make_pop_proof(holder, bind=_use_binding(token))
    check = broker.verify(
        token,
        expected_audience="10.0.0.1",  # the resolved recipient (kernel dst host)
        expected_action="http_post",
        pop_proof=proof,
    )
    assert check.ok, check.reason
    assert check.claims["sub"] == agent_id
    assert check.claims["scope"] == ["act:http_post"]
    assert check.claims["cnf"]["jkt"] == pop.thumbprint(holder.public_key())


def test_minted_credential_is_single_use_consumed_in_store():
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, mem = _build(broker=True, issuers=issuers)

    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 200
    token = _get_ci(fwd.calls[0]["headers"], "Authorization").split(" ", 1)[1]
    jti = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))["jti"]

    # The store row for the minted credential exists and is recorded single-use.
    row = mem.permits.get_by_nonce(jti)
    assert row is not None
    assert row.metadata.get("kind") == "tex-credential"
    assert row.metadata.get("single_use") is True

    # A single-use verify after consuming the row rejects the replay.
    broker = proxy._cred_broker
    broker.consume(jti)
    proof = pop.make_pop_proof(holder, bind=_use_binding(token))
    replay = broker.verify(
        token,
        expected_audience="10.0.0.1",
        expected_action="http_post",
        pop_proof=proof,
        check_single_use=True,
    )
    assert replay.ok is False
    assert replay.reason == "already used"


def test_broker_audience_override_is_used():
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, _ = _build(
        broker=True, issuers=issuers, broker_audience="api://vault.acme"
    )
    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 200
    token = _get_ci(fwd.calls[0]["headers"], "Authorization").split(" ", 1)[1]
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    assert claims["aud"] == "api://vault.acme"


def test_custom_inject_header_strips_authorization_too():
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, _ = _build(
        broker=True, issuers=issuers, broker_inject_header="x-vault-token"
    )
    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 200
    sent = fwd.calls[0]["headers"]
    # The minted token goes into the custom header AND the agent's standing
    # Authorization is still stripped (sole-token-custody covers both).
    assert "X-Vault-Token" in sent or "x-vault-token" in sent
    assert "Authorization" not in sent and "authorization" not in sent


# --------------------------------------------------------------------------- #
# scope_policy — intersection with the released decision                       #
# --------------------------------------------------------------------------- #


def test_scope_policy_intersects_with_decision_scope():
    # The scope_policy closure over a decision must intersect the agent's
    # requested scope with what THAT decision allows: requesting an unrelated
    # scope yields nothing; requesting the action scope yields exactly it.
    decision = Decision(
        tenant="default",
        action_type="send_email",
        content="x",
        channel="http",
        environment="test",
        recipient="api.acme",
    )
    policy = TexEnforcementProxy._broker_scope_policy(decision)
    att = AttestedIdentity(
        verified=True, status="verified", issuer="i", claimed_agent_id="a"
    )
    assert policy(att, {"act:delete_db"}) == set()  # escalation refused
    assert policy(att, {"act:send_email"}) == {"act:send_email"}
    # recipient-narrowed scope is also allowed.
    assert policy(att, {"act:send_email@api.acme"}) == {"act:send_email@api.acme"}


# --------------------------------------------------------------------------- #
# Fail-closed                                                                  #
# --------------------------------------------------------------------------- #


def test_flag_on_without_cnf_key_fails_closed():
    # PoP-only broker: an agent card with NO cnf key cannot be sender-constrained,
    # so the released action is REFUSED rather than forwarded with a weaker token.
    agent_id = str(uuid4())
    card, issuers = _signed_card(agent_id, cnf=None)
    proxy, fwd, _ = _build(broker=True, issuers=issuers)

    resp = _handle(proxy, agent_id=agent_id, card=card)
    assert resp.status == 403
    assert fwd.calls == []  # never forwarded


def test_flag_on_without_verified_identity_fails_closed():
    # No credential presented at all (require_identity False, so the PEP would
    # normally proceed) — but with brokering on there is no identity to bind a
    # downstream credential to, so the released action is refused.
    proxy, fwd, _ = _build(broker=True, issuers={})
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"X-Tex-Agent-Id": str(uuid4())},  # no X-Tex-Agent-Credential
        body=b"payload",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert fwd.calls == []


def test_broker_strips_enumerated_standing_cred_headers():
    # Sole-token-custody over the ENUMERATED vectors: Cookie / X-Api-Key /
    # X-Amz-Security-Token must NOT leak past the strip — Authorization alone is
    # not enough (a resource may authenticate by cookie or api-key).
    agent_id = str(uuid4())
    holder = _holder()
    card, issuers = _signed_card(agent_id, cnf=_cnf_jwk(holder))
    proxy, fwd, mem = _build(broker=True, issuers=issuers)
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": agent_id,
            "X-Tex-Agent-Credential": _cred_header(card),
            "Authorization": "Bearer agent-standing-token",
            "Cookie": "session=SECRET-STANDING-SESSION",
            "X-Api-Key": "STANDING-API-KEY",
            "X-Amz-Security-Token": "AWS-STS-STANDING",
        },
        body=b"payload",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200, resp.body
    sent = json.dumps(fwd.calls[0]["headers"])
    assert "SECRET-STANDING-SESSION" not in sent  # Cookie stripped
    assert "STANDING-API-KEY" not in sent  # X-Api-Key stripped
    assert "AWS-STS-STANDING" not in sent  # X-Amz-Security-Token stripped
    assert "agent-standing-token" not in sent  # Authorization too
