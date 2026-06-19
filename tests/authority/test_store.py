"""Single-use + revocation via the durable ``PermitStore``.

These prove the broker's stateful guarantees are backed by the SAME store the
permit plane uses (in in-memory mode here): a one-shot credential cannot be
redeemed twice, a revoked credential stops verifying, an unknown (never-issued)
credential is rejected in single-use mode, and a store write-failure makes mint
refuse rather than hand out an unrecorded credential.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest

from tex.authority import CredentialBroker
from tex.authority import pop
from tex.authority.broker import _use_binding
from tex.identity.agent_credential import AttestedIdentity
from tex.memory.permit_store import PermitStore


def _verified() -> AttestedIdentity:
    return AttestedIdentity(
        verified=True, status="verified", issuer="entra://contoso", claimed_agent_id="agent-7"
    )


@pytest.fixture
def store(monkeypatch) -> PermitStore:
    # Force hermetic in-memory mode regardless of ambient env.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    s = PermitStore(tenant_id="authority-test")
    assert s.is_durable is False  # in-memory for the test
    return s


def _use_proof(holder, token, now):
    return pop.make_pop_proof(holder.private_key, bind=_use_binding(token), now=now)


def test_single_use_credential_redeemed_once(store, holder):
    b = CredentialBroker(store=store)
    cred = b.mint(
        _verified(), audience="bank", action="transfer", scope=["txn:once"], ttl=120,
        cnf_public_key=holder.public_key, single_use=True, now=1000.0,
    )
    assert cred is not None and cred.permit_id is not None
    # The store recorded the credential under its jti.
    assert store.get_by_nonce(cred.jti) is not None

    # First redeem succeeds and consumes.
    first = b.redeem(
        cred.token, expected_audience="bank", expected_action="transfer",
        pop_proof=_use_proof(holder, cred.token, 1001.0), now=1001.0,
    )
    assert first.ok, first.reason
    assert store.get_by_nonce(cred.jti).consumed_at is not None

    # Second redeem (replay) is rejected: already used.
    second = b.redeem(
        cred.token, expected_audience="bank", expected_action="transfer",
        pop_proof=_use_proof(holder, cred.token, 1002.0), now=1002.0,
    )
    assert not second.ok and second.reason == "already used"


def test_revoked_credential_stops_verifying(store, holder):
    b = CredentialBroker(store=store)
    cred = b.mint(
        _verified(), audience="bank", action="read", scope=["acct:r"], ttl=600,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    proof = _use_proof(holder, cred.token, 1001.0)
    # Valid before revocation.
    assert b.verify(cred.token, pop_proof=proof, now=1001.0).ok

    assert b.revoke(cred.token, reason="key compromise") is True
    # Revocation is checked on EVERY verify when a store is wired (not only single-use).
    after = b.verify(cred.token, pop_proof=_use_proof(holder, cred.token, 1002.0), now=1002.0)
    assert not after.ok and after.reason == "revoked"


def test_unknown_credential_rejected_in_single_use_mode(store, holder):
    # Minted by a broker with NO store, so no row exists; verified by a
    # store-backed broker in single-use mode -> unknown credential.
    storeless = CredentialBroker()
    cred = storeless.mint(
        _verified(), audience="bank", action="read", scope=["acct:r"], ttl=600,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    b = CredentialBroker(store=store)
    proof = _use_proof(holder, cred.token, 1001.0)
    check = b.verify(cred.token, pop_proof=proof, now=1001.0, check_single_use=True)
    assert not check.ok and check.reason.startswith("unknown credential")
    # Without single-use semantics the same (signature-valid) credential verifies.
    assert b.verify(cred.token, pop_proof=proof, now=1001.0).ok


def test_mint_refuses_when_store_write_fails(holder):
    class FailingStore:
        def issue(self, **kw):
            raise RuntimeError("db down")

        def get_by_nonce(self, nonce):  # pragma: no cover - not reached
            return None

        def consume(self, permit_id):  # pragma: no cover
            return None

        def revoke(self, permit_id, *, reason=None):  # pragma: no cover
            return None

    b = CredentialBroker(store=FailingStore())
    # A store that cannot persist must NOT yield an unrecorded single-use creds.
    assert (
        b.mint(
            _verified(), audience="bank", action="transfer", scope=["txn:once"],
            ttl=120, cnf_public_key=holder.public_key, single_use=True, now=1000.0,
        )
        is None
    )


def test_consume_and_revoke_are_noops_without_store(holder):
    b = CredentialBroker()  # no store
    cred = b.mint(
        _verified(), audience="bank", action="read", scope=["acct:r"], ttl=60,
        cnf_public_key=holder.public_key, now=1000.0,
    )
    assert b.consume(cred.token) is False
    assert b.revoke(cred.token) is False
