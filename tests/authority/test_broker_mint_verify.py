"""Mint + verify unit tests for the credential broker.

Pins the properties a resource relies on: a credential minted for one action
cannot be forged, redirected to a different audience/action, scope-escalated,
used after expiry, or accepted under a different issuer; minting fails closed in
production with no secret; and a credential is NEVER minted for an unverified
identity.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority import CredentialBroker, authority_secret
from tex.authority import pop
from tex.authority.broker import _sign_cred, _use_binding
from tex.enforcement import permit
from tex.enforcement.permit import _b64url_decode, _canonical
from tex.identity.agent_credential import AttestedIdentity


def _verified(agent_id="agent-7", issuer="entra://contoso") -> AttestedIdentity:
    return AttestedIdentity(
        verified=True, status="verified", issuer=issuer, claimed_agent_id=agent_id
    )


def _proof(priv, token, now):
    return pop.make_pop_proof(priv, bind=_use_binding(token), now=now)


def test_mint_verify_roundtrip(holder):
    b = CredentialBroker()
    cred = b.mint(
        _verified(),
        audience="vault.acme",
        action="read_secret",
        scope=["secret:db", "secret:cache"],
        ttl=60,
        cnf_public_key=holder.public_key,
        now=1000.0,
    )
    assert cred is not None
    assert cred.binding == "pop" and cred.cnf_jkt == holder.jkt
    assert cred.subject == "agent-7" and cred.issuer == "tex-authority"
    assert cred.scope == ("secret:cache", "secret:db")  # sorted, deduped

    check = b.verify(
        cred.token,
        expected_audience="vault.acme",
        expected_action="read_secret",
        required_scope=["secret:db"],
        pop_proof=_proof(holder.private_key, cred.token, 1005.0),
        now=1005.0,
    )
    assert check.ok and check.reason == "ok" and check.binding == "pop"
    assert check.claims["sub"] == "agent-7" and check.claims["idp"] == "entra://contoso"


def test_unverified_identity_never_minted(holder):
    b = CredentialBroker()
    unverified = AttestedIdentity(
        verified=False, status="untrusted_issuer", issuer=None, claimed_agent_id="x"
    )
    assert (
        b.mint(
            unverified,
            audience="a",
            action="act",
            scope=["s"],
            ttl=60,
            cnf_public_key=holder.public_key,
        )
        is None
    )


def test_bearer_refused_by_default_but_minted_when_allowed():
    # PoP-only broker (default): no cnf key => refuse to mint.
    assert (
        CredentialBroker().mint(
            _verified(), audience="a", action="act", scope=["s"], ttl=60
        )
        is None
    )
    # allow_bearer broker: a bearer credential is minted and labeled honestly.
    b = CredentialBroker(allow_bearer=True)
    cred = b.mint(_verified(), audience="a", action="act", scope=["s"], ttl=60, now=1000.0)
    assert cred is not None and cred.binding == "bearer" and cred.cnf_jkt is None
    assert cred.token_type == "Bearer"
    # A bearer credential verifies with no PoP proof.
    check = b.verify(cred.token, expected_audience="a", expected_action="act", now=1001.0)
    assert check.ok and check.binding == "bearer"


def test_expired_credential_rejected(holder):
    b = CredentialBroker()
    cred = b.mint(
        _verified(), audience="a", action="act", scope=["s"], ttl=10,
        cnf_public_key=holder.public_key, now=1000.0,
    )  # expires t=1010
    check = b.verify(
        cred.token, pop_proof=_proof(holder.private_key, cred.token, 2000.0), now=2000.0
    )
    assert not check.ok and check.reason == "expired"


def test_audience_action_subject_scope_mismatch_rejected(holder):
    b = CredentialBroker()
    cred = b.mint(
        _verified(agent_id="agent-7"),
        audience="vault.acme", action="read_secret", scope=["secret:db"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    proof = _proof(holder.private_key, cred.token, 1001.0)

    def chk(**kw):
        return b.verify(cred.token, pop_proof=proof, now=1001.0, **kw)

    assert chk(expected_audience="evil.host").reason == "audience mismatch"
    assert chk(expected_action="delete_secret").reason == "action mismatch"
    assert chk(expected_subject="agent-9").reason == "subject mismatch"
    assert chk(required_scope=["secret:db", "secret:admin"]).reason == "scope mismatch"
    # all-correct still passes
    assert chk(
        expected_audience="vault.acme",
        expected_action="read_secret",
        expected_subject="agent-7",
        required_scope="secret:db",
    ).ok


def test_issuer_mismatch_rejected(holder):
    b = CredentialBroker(issuer="tex-authority")
    cred = b.mint(
        _verified(), audience="a", action="act", scope=["s"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    proof = _proof(holder.private_key, cred.token, 1001.0)
    # A resource that pins a DIFFERENT issuer must reject a Tex credential.
    assert (
        b.verify(cred.token, expected_issuer="other-sts", pop_proof=proof, now=1001.0).reason
        == "issuer mismatch"
    )


def test_forged_signature_rejected(holder):
    b = CredentialBroker()
    cred = b.mint(
        _verified(), audience="a", action="act", scope=["s"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    body, _, sig = cred.token.partition(".")
    forged = f"{body}.{'A' * len(sig)}"
    assert b.verify(forged, now=1001.0).reason == "bad signature"


def test_tampered_claims_rejected(holder):
    # Flip the audience claim but keep the original signature: the MAC covers the
    # original body, so verification fails closed. No re-sign without the secret.
    b = CredentialBroker()
    cred = b.mint(
        _verified(), audience="vault.acme", action="act", scope=["s"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    body, _, sig = cred.token.partition(".")
    claims = json.loads(_b64url_decode(body))
    claims["aud"] = "evil.host"
    tampered = f"{_canonical(claims)}.{sig}"
    assert b.verify(tampered, now=1001.0).reason == "bad signature"


def test_scope_cannot_be_escalated_by_tampering(holder):
    # Add a scope to the claims and KEEP the old signature -> bad signature. The
    # only way to add scope is to re-sign, which requires the secret.
    b = CredentialBroker()
    cred = b.mint(
        _verified(), audience="a", action="act", scope=["secret:db"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    body, _, sig = cred.token.partition(".")
    claims = json.loads(_b64url_decode(body))
    claims["scope"] = ["secret:db", "secret:admin"]
    tampered = f"{_canonical(claims)}.{sig}"
    assert not b.verify(tampered, required_scope="secret:admin", now=1001.0).ok


def test_unsupported_version_and_type_rejected(holder):
    # Re-sign a bumped-version / wrong-type claim set with the REAL secret so the
    # MAC passes; the version/type gate must still reject it.
    b = CredentialBroker()
    cred = b.mint(
        _verified(), audience="a", action="act", scope=["s"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    body = cred.token.partition(".")[0]
    claims = json.loads(_b64url_decode(body))

    bad_v = dict(claims, v=999)
    body_v = _canonical(bad_v)
    tok_v = f"{body_v}.{_sign_cred(authority_secret(), body_v)}"
    assert b.verify(tok_v, now=1001.0).reason == "unsupported credential"

    bad_t = dict(claims, typ="tex-permit")
    body_t = _canonical(bad_t)
    tok_t = f"{body_t}.{_sign_cred(authority_secret(), body_t)}"
    assert b.verify(tok_t, now=1001.0).reason == "unsupported credential"


def test_malformed_token_rejected():
    b = CredentialBroker()
    assert not b.verify(None).ok
    assert not b.verify("").ok
    assert not b.verify("no-dot-here").ok


def test_production_no_secret_fails_closed(monkeypatch, holder):
    monkeypatch.delenv("TEX_AUTHORITY_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("TEX_PERMIT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    assert authority_secret() is None
    b = CredentialBroker()
    assert (
        b.mint(
            _verified(), audience="a", action="act", scope=["s"], ttl=60,
            cnf_public_key=holder.public_key,
        )
        is None
    )
    assert not b.verify("anything.anything").ok


def test_unusable_cnf_key_refused():
    # A garbage cnf key must make mint refuse rather than silently fall to bearer.
    b = CredentialBroker()
    assert (
        b.mint(
            _verified(), audience="a", action="act", scope=["s"], ttl=60,
            cnf_public_key=b"too-short",
        )
        is None
    )
