"""Token-exchange (RFC 8693) tests through the local identity-source seam.

Exercises the full flow: a signed subject assertion -> verified identity ->
exchange-time possession proof -> a fresh Tex-minted, action-scoped credential
that then verifies and is usable with a PoP proof. Plus the fail-closed paths:
unverified subject, missing/invalid exchange proof, wrong-audience assertion,
bearer-disabled, and scope down-scoping.
"""

from __future__ import annotations

from tex.authority import CredentialBroker, LocalEd25519IdentitySource
from tex.authority import pop
from tex.authority.broker import _exchange_binding, _use_binding


def _broker(issuer, **kw):
    src = LocalEd25519IdentitySource(trusted_issuers=issuer.trusted_map)
    # A real deployment configures a scope_policy; model a permissive one here so
    # the happy-path/PoP tests exercise the flow. The fail-closed no-policy case
    # has its own test below.
    kw.setdefault("scope_policy", lambda ident, requested: requested)
    return CredentialBroker(identity_source=src, **kw)


def test_exchange_without_scope_policy_is_fail_closed(issuer, holder, make_assertion):
    # No scope_policy and no allow_unrestricted_exchange => the broker REFUSES to
    # echo the agent's requested scope (the RFC-8693 escalation footgun the merge
    # review flagged: otherwise any proven identity mints any scope).
    src = LocalEd25519IdentitySource(trusted_issuers=issuer.trusted_map)
    b = CredentialBroker(identity_source=src)  # deliberately no scope_policy
    assertion = make_assertion(cnf_jwk=holder.jwk, audience="vault.acme")
    result = b.exchange(
        assertion,
        requested_scope=["secret:db"],
        audience="vault.acme",
        action="read_secret",
        now=1000.0,
        exchange_pop_proof=_exchange_proof(holder, "vault.acme", "read_secret", 1000.0),
    )
    assert not result.ok and "scope_policy" in result.reason
    assert result.credential is None


def _exchange_proof(holder, audience, action, now):
    bind = _exchange_binding(holder.jkt, audience, action)
    return pop.make_pop_proof(holder.private_key, bind=bind, now=now)


def test_exchange_happy_path_then_use(issuer, holder, make_assertion):
    b = _broker(issuer)
    assertion = make_assertion(agent_id="agent-7", cnf_jwk=holder.jwk, audience="vault.acme")
    result = b.exchange(
        assertion,
        requested_scope=["secret:db"],
        audience="vault.acme",
        action="read_secret",
        ttl=300,
        now=1000.0,
        exchange_pop_proof=_exchange_proof(holder, "vault.acme", "read_secret", 1000.0),
    )
    assert result.ok, result.reason
    assert result.token_type == "DPoP"
    assert result.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"
    assert result.expires_in == 300 and result.scope == ["secret:db"]
    cred = result.credential
    assert cred.subject == "agent-7" and cred.binding == "pop"

    # The minted credential is usable by the holder (PoP) but bound to identity.
    use_proof = pop.make_pop_proof(holder.private_key, bind=_use_binding(cred.token), now=1001.0)
    check = b.verify(
        cred.token, expected_audience="vault.acme", expected_action="read_secret",
        required_scope="secret:db", pop_proof=use_proof, now=1001.0,
    )
    assert check.ok and check.claims["idp"] == "entra://contoso"


def test_exchange_unverified_subject_mints_nothing(issuer, holder, make_assertion):
    # Card signed by an issuer NOT in the trusted map -> not verified -> no token.
    from tests.authority.conftest import Issuer
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    rogue = Issuer("rogue://evil", Ed25519PrivateKey.generate())
    assertion = make_assertion(cnf_jwk=holder.jwk, signing_issuer=rogue)
    b = _broker(issuer)  # trusts only `issuer`, not `rogue`
    result = b.exchange(
        assertion, requested_scope=["secret:db"], audience="vault.acme",
        action="read_secret", now=1000.0,
        exchange_pop_proof=_exchange_proof(holder, "vault.acme", "read_secret", 1000.0),
    )
    assert not result.ok and "subject not verified" in result.reason
    assert result.credential is None and result.access_token is None


def test_exchange_requires_possession_proof(issuer, holder, make_assertion):
    b = _broker(issuer)
    assertion = make_assertion(cnf_jwk=holder.jwk, audience="vault.acme")
    # No exchange pop proof -> a stolen assertion cannot mint a bound credential.
    result = b.exchange(
        assertion, requested_scope=["secret:db"], audience="vault.acme",
        action="read_secret", now=1000.0,
    )
    assert not result.ok and result.reason == "exchange pop proof required"

    # A possession proof signed by the WRONG key (attacker holds the stolen
    # assertion but not the cnf private key) is rejected.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    attacker = Ed25519PrivateKey.generate()
    bind = _exchange_binding(holder.jkt, "vault.acme", "read_secret")
    bad = pop.make_pop_proof(attacker, bind=bind, now=1000.0)
    result2 = b.exchange(
        assertion, requested_scope=["secret:db"], audience="vault.acme",
        action="read_secret", now=1000.0, exchange_pop_proof=bad,
    )
    assert not result2.ok and "exchange pop" in result2.reason


def test_exchange_wrong_audience_assertion_rejected(issuer, holder, make_assertion):
    # The assertion was issued for a DIFFERENT audience than the exchange targets.
    b = _broker(issuer)
    assertion = make_assertion(cnf_jwk=holder.jwk, audience="other.host")
    result = b.exchange(
        assertion, requested_scope=["secret:db"], audience="vault.acme",
        action="read_secret", now=1000.0,
        exchange_pop_proof=_exchange_proof(holder, "vault.acme", "read_secret", 1000.0),
    )
    assert not result.ok and "subject not verified" in result.reason


def test_exchange_downscopes_via_policy(issuer, holder, make_assertion):
    # Policy caps what this identity may ever obtain; the grant is the intersection
    # with the request and can only shrink it.
    def policy(identity, requested):
        return {"secret:db"}  # this agent may only ever get secret:db

    b = _broker(issuer, scope_policy=policy)
    assertion = make_assertion(cnf_jwk=holder.jwk, audience="vault.acme")
    result = b.exchange(
        assertion,
        requested_scope=["secret:db", "secret:admin"],  # asks for more
        audience="vault.acme", action="read_secret", now=1000.0,
        exchange_pop_proof=_exchange_proof(holder, "vault.acme", "read_secret", 1000.0),
    )
    assert result.ok and result.scope == ["secret:db"]  # admin dropped


def test_exchange_bearer_assertion_requires_allow_bearer(issuer, make_assertion):
    # Assertion with NO cnf key. Default broker is PoP-only -> refuse.
    assertion = make_assertion(cnf_jwk=None, audience="vault.acme")
    b = _broker(issuer)
    r1 = b.exchange(
        assertion, requested_scope=["s"], audience="vault.acme", action="act", now=1000.0
    )
    assert not r1.ok and "no cnf key" in r1.reason

    # allow_bearer broker mints a bearer credential (no exchange proof needed).
    b2 = _broker(issuer, allow_bearer=True)
    r2 = b2.exchange(
        assertion, requested_scope=["s"], audience="vault.acme", action="act", now=1000.0
    )
    assert r2.ok and r2.token_type == "Bearer" and r2.credential.binding == "bearer"


def test_exchange_without_identity_source_fails_closed(holder, make_assertion):
    b = CredentialBroker()  # no identity source wired
    result = b.exchange(
        make_assertion(cnf_jwk=holder.jwk), requested_scope=["s"],
        audience="a", action="act", now=1000.0,
    )
    assert not result.ok and result.reason == "no identity source configured"
