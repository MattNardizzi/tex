"""Freshness / audience (anti-replay) tests for ``verify_agent_credential``.

A signature-valid credential must ALSO be within its signed ``exp``/``nbf``
window and (when an audience is expected) name it — otherwise a captured
``X-Tex-Agent-Credential`` would be a non-expiring, anywhere-valid bearer token
(the replay flaw the merge review flagged). These pin the fix.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.identity.agent_credential import (
    CredentialVerification,
    verify_agent_credential,
)


def _card(payload: dict, issuer: str = "issuer-1"):
    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jcs = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    card = {
        "payload": payload,
        "issuer": issuer,
        "signature_b64": base64.b64encode(sk.sign(jcs)).decode("ascii"),
    }
    issuers = {issuer: base64.b64encode(raw_pub).decode("ascii")}
    return card, issuers


def test_no_exp_no_aud_still_verifies_backward_compat():
    card, issuers = _card({"agent_id": "a"})
    assert verify_agent_credential(card, trusted_issuers=issuers).verified


def test_expired_card_rejected():
    card, issuers = _card({"agent_id": "a", "exp": 1000})
    att = verify_agent_credential(card, trusted_issuers=issuers, now=2000)
    assert not att.verified
    assert att.status == CredentialVerification.EXPIRED.value


def test_unexpired_card_accepted():
    card, issuers = _card({"agent_id": "a", "exp": 5000})
    assert verify_agent_credential(card, trusted_issuers=issuers, now=2000).verified


def test_not_yet_valid_rejected():
    card, issuers = _card({"agent_id": "a", "nbf": 5000})
    att = verify_agent_credential(card, trusted_issuers=issuers, now=2000)
    assert not att.verified
    assert att.status == CredentialVerification.NOT_YET_VALID.value


def test_audience_mismatch_rejected():
    card, issuers = _card({"agent_id": "a", "aud": "pep-A"})
    att = verify_agent_credential(
        card, trusted_issuers=issuers, expected_audience="pep-B"
    )
    assert not att.verified
    assert att.status == CredentialVerification.AUDIENCE_MISMATCH.value


def test_audience_match_accepted():
    card, issuers = _card({"agent_id": "a", "aud": "pep-A", "exp": 9_999_999_999})
    assert verify_agent_credential(
        card, trusted_issuers=issuers, expected_audience="pep-A", now=1000
    ).verified


def test_require_expiry_rejects_card_without_exp():
    card, issuers = _card({"agent_id": "a"})
    att = verify_agent_credential(card, trusted_issuers=issuers, require_expiry=True)
    assert not att.verified
    assert att.status == CredentialVerification.STALE_NO_EXPIRY.value


def test_unparseable_exp_fails_closed():
    card, issuers = _card({"agent_id": "a", "exp": "not-a-number"})
    att = verify_agent_credential(card, trusted_issuers=issuers, now=2000)
    assert not att.verified
    assert att.status == CredentialVerification.EXPIRED.value


def test_replay_after_expiry_fails_even_with_valid_signature():
    # The exact replay scenario: a captured, signature-valid card stops working
    # the moment its exp passes.
    card, issuers = _card({"agent_id": "a", "exp": 1_700_000_000})
    assert verify_agent_credential(
        card, trusted_issuers=issuers, now=1_699_999_000
    ).verified
    replayed = verify_agent_credential(card, trusted_issuers=issuers, now=1_700_000_001)
    assert not replayed.verified
    assert replayed.status == CredentialVerification.EXPIRED.value


def test_tamper_still_beats_freshness_checks():
    # A tampered payload fails at the signature stage, never reaching exp/aud.
    card, issuers = _card({"agent_id": "a", "exp": 9_999_999_999})
    card["payload"]["agent_id"] = "b"  # signature now stale
    att = verify_agent_credential(card, trusted_issuers=issuers, now=1000)
    assert not att.verified
    assert att.status == CredentialVerification.TAMPERED.value
