"""Phase 2 — verify a signed agent identity credential (Ed25519/JCS) offline,
so an enforcement decision can bind to a CRYPTOGRAPHICALLY ATTESTED identity
rather than the self-declared agent_id the request carried.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tex.identity.agent_credential import CredentialVerification, verify_agent_credential


def _jcs(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _signed_card(agent_id: str = "agent-007", issuer: str = "issuer-1"):
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = {"agent_id": agent_id, "tenant": "acme"}
    sig = sk.sign(_jcs(payload))
    card = {
        "payload": payload,
        "issuer": issuer,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }
    trusted = {issuer: base64.b64encode(pk_raw).decode("ascii")}
    return card, trusted


def test_verified_credential_attests_identity():
    card, trusted = _signed_card()
    ai = verify_agent_credential(card, trusted_issuers=trusted)
    assert ai.verified is True
    assert ai.status == CredentialVerification.VERIFIED.value
    assert ai.issuer == "issuer-1"
    assert ai.claimed_agent_id == "agent-007"
    assert ai.method == "ed25519_agent_card"


def test_tampered_payload_is_not_attested():
    card, trusted = _signed_card()
    card["payload"] = {"agent_id": "attacker", "tenant": "acme"}  # mutate after signing
    ai = verify_agent_credential(card, trusted_issuers=trusted)
    assert ai.verified is False
    assert ai.status == CredentialVerification.TAMPERED.value


def test_untrusted_issuer_is_not_attested():
    card, _trusted = _signed_card()
    ai = verify_agent_credential(card, trusted_issuers={})  # nobody trusted
    assert ai.verified is False
    assert ai.status == CredentialVerification.UNTRUSTED_ISSUER.value


def test_unsigned_credential_is_not_attested():
    card, trusted = _signed_card()
    del card["signature_b64"]
    ai = verify_agent_credential(card, trusted_issuers=trusted)
    assert ai.verified is False
    assert ai.status == CredentialVerification.UNSIGNED.value
