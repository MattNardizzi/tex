"""Tests for the wired POST /v1/govern/mint route — CAPABILITY-BEFORE on the
out-of-path plane. Rule on one action, and mint a short-lived, action-scoped,
sender-bound (RFC 7800/9449 ``cnf``) Tex capability token ONLY when the ruling
RELEASED it. FORBID/HOLD ⇒ no token. Default-OFF behind ``TEX_GOVERN_MINT``
(inert 503 when unset).

Mirrors the test_local_forbid_route.py precedent: a bare FastAPI app mounting
``build_governance_standing_router()`` with a FAKE ``standing_governance`` whose
``.decide(**kwargs)`` returns a constructed ``DecisionOutcome``. No proxy is ever
constructed — proving capability-before lands on the out-of-path plane.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.authority import pop
from tex.domain.verdict import Verdict
from tex.governance.standing import DecisionOutcome

SECRET = "shared-authority-signing-secret"


class _FakeGovernance:
    """Minimal stand-in for StandingGovernance — records the decide() kwargs and
    returns a pre-seeded DecisionOutcome."""

    def __init__(self, outcome: DecisionOutcome) -> None:
        self._outcome = outcome
        self.last_kwargs: dict | None = None

    def decide(self, **kwargs) -> DecisionOutcome:
        self.last_kwargs = kwargs
        return self._outcome


def _client(gov: object | None) -> TestClient:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    if gov is not None:
        app.state.standing_governance = gov
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:write"}),
    )
    return TestClient(app)


def _permit_outcome(**over) -> DecisionOutcome:
    base = dict(
        verdict=Verdict.PERMIT,
        released=True,
        reason="released by deep adjudication",
        tier="deep",
        decision_id=uuid4(),
        evidence_hash="abc123",
    )
    base.update(over)
    return DecisionOutcome(**base)


def _dpop_proof(priv: Ed25519PrivateKey, *, audience: str, action: str) -> tuple[str, str]:
    """Build a real DPoP/PoP proof bound to the route's mint context, plus the
    expected jkt thumbprint of the holder public key."""
    jkt = pop.thumbprint(priv.public_key())
    bind = f"tex-pop-mint:{jkt}:{audience}:{action}"
    proof = pop.make_pop_proof(priv, bind=bind)
    return proof, jkt


# --------------------------------------------------------------------------- #
# 1. FORBID — no token (403)                                                   #
# --------------------------------------------------------------------------- #


def test_forbid_no_token(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = DecisionOutcome(
        verdict=Verdict.FORBID,
        released=False,
        reason="forbidden by floor",
        tier="floor",
    )
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 403
    payload = resp.json()
    assert payload["released"] is False
    assert payload["verdict"] == "FORBID"
    assert "access_token" not in payload
    assert "token" not in payload


# --------------------------------------------------------------------------- #
# 2. HOLD (ABSTAIN + held) — no token (202)                                    #
# --------------------------------------------------------------------------- #


def test_hold_no_token(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    did = uuid4()
    outcome = DecisionOutcome(
        verdict=Verdict.ABSTAIN,
        released=False,
        reason="awaiting human review",
        tier="deep",
        decision_id=did,
        held=True,
    )
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 202
    payload = resp.json()
    assert payload["released"] is False
    assert payload["held"] is True
    assert payload["decision_id"] == str(did)
    assert "access_token" not in payload
    assert "token" not in payload


# --------------------------------------------------------------------------- #
# 3. PERMIT — mints a scoped, sender-bound token (200)                         #
# --------------------------------------------------------------------------- #


def test_permit_mints_scoped_sender_bound_token(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, jkt = _dpop_proof(priv, audience="payroll.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
            "ttl": 120,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["access_token"]
    assert payload["token_type"] == "DPoP"
    assert payload["cnf"]["jkt"] == jkt
    # scope is requested ∩ allowed. ``requested`` is exactly {act:<action_type>},
    # so even with a recipient the surviving intersection is the bare action form
    # (the @recipient form lives only in ``allowed``, never in ``requested``) —
    # the narrowest binding, identical to the proxy's _broker_scope_policy.
    assert payload["scope"] == ["act:send_email"]
    assert payload["expires_in"] <= 300
    assert payload["expires_in"] == 120
    assert payload["decision_id"] == str(outcome.decision_id)
    assert payload["released"] is True
    assert payload["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"


# --------------------------------------------------------------------------- #
# 4. DEFAULT-OFF — byte-for-byte inert (503)                                   #
# --------------------------------------------------------------------------- #


def test_default_off_inert(monkeypatch) -> None:
    # Default boot: no TEX_GOVERN_MINT, no signing secret, no DPoP machinery.
    monkeypatch.delenv("TEX_GOVERN_MINT", raising=False)
    monkeypatch.delenv("TEX_AUTHORITY_SIGNING_SECRET", raising=False)
    # A PERMIT outcome is wired, yet the route must NEVER reach decide/mint.
    gov = _FakeGovernance(_permit_outcome())
    resp = _client(gov).post(
        "/v1/govern/mint",
        json={"action_type": "send_email", "content": "hi", "dpop_proof": "x.y"},
    )
    assert resp.status_code == 503
    # Inertness proof: the flag-off short-circuit happens BEFORE decide() runs,
    # so the governance brain was never touched (no broker, no secret needed).
    assert gov.last_kwargs is None


# --------------------------------------------------------------------------- #
# 5. Mints with NO in-path proxy present                                       #
# --------------------------------------------------------------------------- #


def test_mints_without_in_path_proxy(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    client = _client(_FakeGovernance(outcome))
    # No TexEnforcementProxy is constructed anywhere in this app — the only
    # objects on app.state are the fake governance + the test principal override.
    assert not hasattr(client.app.state, "proxy")
    assert not hasattr(client.app.state, "credential_broker")
    resp = client.post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    # A 200 mint with NO in-path Body proves capability-before on the out-of-path
    # plane: issuance is gated on the ruling, not on an intercepting proxy.
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"]


# --------------------------------------------------------------------------- #
# 6. Scope is intersected, not amplified                                       #
# --------------------------------------------------------------------------- #


def test_scope_intersected_not_amplified(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    # No recipient sent => scope must be ONLY act:send_email (no @recipient form).
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "audience": "payroll.example",
            "dpop_proof": proof,
            # A naive impl might echo caller scope — there is no scope field, and
            # any extra keys are ignored. Confirm none leak into the token.
            "scope": ["act:admin", "act:wire_transfer"],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["scope"] == ["act:send_email"]
    assert "act:admin" not in resp.json()["scope"]
    assert "act:wire_transfer" not in resp.json()["scope"]


# --------------------------------------------------------------------------- #
# 7. Fail-closed when no signing secret (403, NOT 500)                         #
# --------------------------------------------------------------------------- #


def test_fail_closed_on_no_signing_secret(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.delenv("TEX_AUTHORITY_SIGNING_SECRET", raising=False)
    # Prod-like env so permit_secret() also returns None => authority_secret None
    # => mint() returns None => fail-closed.
    monkeypatch.setenv("TEX_APP_ENV", "production")
    monkeypatch.delenv("TEX_PERMIT_SIGNING_SECRET", raising=False)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 403
    payload = resp.json()
    assert "access_token" not in payload
    assert "token" not in payload


# --------------------------------------------------------------------------- #
# 8. Fail-closed on missing / bad DPoP proof                                   #
# --------------------------------------------------------------------------- #


def test_fail_closed_on_malformed_dpop(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = _permit_outcome()
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": "not-a-real-proof",
        },
    )
    assert resp.status_code == 422
    assert "access_token" not in resp.json()


def test_fail_closed_on_bind_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    # Proof bound to the WRONG audience => bind mismatch at verify => 401.
    proof, _ = _dpop_proof(priv, audience="WRONG.example", action="send_email")
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 401
    assert "access_token" not in resp.json()


# --------------------------------------------------------------------------- #
# 9. Governance unwired => 503                                                 #
# --------------------------------------------------------------------------- #


def test_governance_unwired_503(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience="payroll.example", action="send_email")
    # No app.state.standing_governance attached.
    resp = _client(None).post(
        "/v1/govern/mint",
        json={
            "action_type": "send_email",
            "content": "hi",
            "recipient": "payroll.example",
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 503
