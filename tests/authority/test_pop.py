"""Proof-of-possession tests — the property that makes a stolen credential useless.

These are the load-bearing tests for the broker's headline claim ("PoP, not a
bearer token"). They prove: a sender-constrained credential cannot be used
without the holder's private key; a captured PoP proof cannot be replayed to a
different credential token; a stale/forged proof is rejected; and a PoP-bound
credential can NEVER be downgraded to bearer use.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority import CredentialBroker
from tex.authority import pop
from tex.authority.broker import _use_binding
from tex.enforcement import permit
from tex.identity.agent_credential import AttestedIdentity


def _verified() -> AttestedIdentity:
    return AttestedIdentity(
        verified=True, status="verified", issuer="entra://contoso", claimed_agent_id="agent-7"
    )


def _cred(broker, holder, now=1000.0, audience="vault.acme", action="read_secret"):
    return broker.mint(
        _verified(), audience=audience, action=action, scope=["secret:db"],
        ttl=120, cnf_public_key=holder.public_key, now=now,
    )


def test_stolen_token_without_proof_is_useless(holder):
    b = CredentialBroker()
    cred = _cred(b, holder)
    # An attacker who captured the token but not the key presents it bare.
    assert b.verify(cred.token, now=1001.0).reason == "pop proof required"


def test_proof_from_wrong_key_rejected(holder):
    b = CredentialBroker()
    cred = _cred(b, holder)
    attacker = Ed25519PrivateKey.generate()  # attacker's own key, wrong thumbprint
    bad = pop.make_pop_proof(attacker, bind=_use_binding(cred.token), now=1001.0)
    assert b.verify(cred.token, pop_proof=bad, now=1001.0).reason == "pop: cnf thumbprint mismatch"


def test_proof_bound_to_other_token_rejected(holder):
    b = CredentialBroker()
    cred_a = _cred(b, holder, action="read_secret")
    cred_b = _cred(b, holder, action="write_secret")
    # A genuine proof for cred_a is replayed against cred_b: binding mismatch.
    proof_a = pop.make_pop_proof(holder.private_key, bind=_use_binding(cred_a.token), now=1001.0)
    assert b.verify(cred_b.token, pop_proof=proof_a, now=1001.0).reason == "pop: pop binding mismatch"
    # ...and the same proof DOES work for cred_a (sanity: binding is real, not a always-fail).
    assert b.verify(cred_a.token, pop_proof=proof_a, now=1001.0).ok


def test_expired_and_future_proof_rejected(holder):
    b = CredentialBroker()
    # Long-lived credential so it is the PROOF freshness (not the credential exp)
    # under test — the two clocks are independent.
    cred = b.mint(
        _verified(), audience="vault.acme", action="read_secret", scope=["secret:db"],
        ttl=100_000, cnf_public_key=holder.public_key, now=1000.0,
    )
    bind = _use_binding(cred.token)
    stale = pop.make_pop_proof(holder.private_key, bind=bind, now=1000.0)
    # default max_age=120 -> a proof from t=1000 is stale at t=1200 (cred still valid)
    assert b.verify(cred.token, pop_proof=stale, now=1200.0).reason == "pop: pop expired"
    future = pop.make_pop_proof(holder.private_key, bind=bind, now=5000.0)
    assert b.verify(cred.token, pop_proof=future, now=1001.0).reason == "pop: pop not yet valid"


def test_tampered_proof_body_rejected(holder):
    b = CredentialBroker()
    cred = _cred(b, holder)
    proof = pop.make_pop_proof(holder.private_key, bind=_use_binding(cred.token), now=1001.0)
    body_b64, _, sig_b64 = proof.partition(".")
    body = json.loads(pop._b64url_decode(body_b64))
    body["bind"] = "tex-pop-use:evil"  # try to retarget the proof
    tampered = f"{pop._b64url(pop._canonical(body).encode())}.{sig_b64}"
    # The signature covers the original bytes -> bad pop signature, fail closed.
    assert b.verify(cred.token, pop_proof=tampered, now=1001.0).reason == "pop: bad pop signature"


def test_challenge_binding(holder):
    b = CredentialBroker()
    cred = _cred(b, holder)
    bind = _use_binding(cred.token)
    proof = pop.make_pop_proof(holder.private_key, bind=bind, now=1001.0, challenge="nonce-xyz")
    # Resource demands a specific server nonce; a proof without/with-wrong nonce fails.
    assert b.verify(cred.token, pop_proof=proof, pop_challenge="other", now=1001.0).reason == "pop: pop challenge mismatch"
    assert b.verify(cred.token, pop_proof=proof, pop_challenge="nonce-xyz", now=1001.0).ok


def test_pop_credential_cannot_be_downgraded_to_bearer(holder):
    # Even a broker that ALLOWS bearer credentials must still demand a PoP proof
    # for a credential that was minted sender-constrained — cnf lives inside the
    # signed claims, so it cannot be stripped.
    b = CredentialBroker(allow_bearer=True)
    cred = _cred(b, holder)
    assert cred.binding == "pop"
    assert b.verify(cred.token, now=1001.0).reason == "pop proof required"


def test_domain_separation_permit_and_credential_do_not_cross_verify(holder):
    # Same signing key (pinned identical in conftest). A permit token must not
    # verify as a credential, and a credential must not verify as a permit —
    # the texauth.v1 MAC prefix separates the two planes.
    from uuid import uuid4

    p = permit.mint(
        decision_id=uuid4(), tenant="acme", action_type="http_post",
        recipient="api.host", content=b"BODY", ttl_seconds=60,
    )
    b = CredentialBroker()
    cred = _cred(b, holder)

    # permit token -> credential verify: rejected (bad MAC, since cred MAC is prefixed)
    assert not b.verify(p.token, now=1001.0).ok
    # credential token -> permit verify: rejected
    assert not permit.verify(cred.token).ok
