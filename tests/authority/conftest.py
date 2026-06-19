"""Fixtures for the authority-plane (credential broker) tests.

Provides a hermetic signing secret and factories for the two pieces of holder
material these tests need: an Ed25519 PoP keypair, and an Ed25519-signed
AgentCard subject assertion built EXACTLY the way
``tex.identity.agent_credential.verify_agent_credential`` expects to consume it
(EdDSA over the JCS-canonical payload, allow-listed issuer).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tex.authority import pop


@pytest.fixture(autouse=True)
def _authority_secret(monkeypatch):
    """A fixed, hermetic credential signing secret so mint/verify agree.

    Also pin the permit secret to the SAME value so the domain-separation test can
    prove a permit MAC and a credential MAC do not cross-verify even under a
    shared key (not because the keys differ)."""
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", "authority-test-secret")
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "authority-test-secret")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    yield


def _raw_pub(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _jcs(payload: Any) -> bytes:
    # Mirror tex.identity.agent_credential._jcs exactly.
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass(frozen=True)
class Holder:
    """An agent's own PoP keypair (Tex never sees the private key)."""

    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def jwk(self) -> dict[str, str]:
        return pop.public_jwk(_raw_pub(self.public_key))

    @property
    def jkt(self) -> str:
        return pop.thumbprint(self.public_key)


@dataclass(frozen=True)
class Issuer:
    """A fake upstream IdP (stands in for Entra/SPIFFE) signing AgentCards."""

    issuer_id: str
    private_key: Ed25519PrivateKey

    @property
    def trusted_map(self) -> dict[str, str]:
        pub_b64 = base64.b64encode(_raw_pub(self.private_key.public_key())).decode("ascii")
        return {self.issuer_id: pub_b64}

    def sign_card(self, payload: dict[str, Any]) -> dict[str, Any]:
        sig = self.private_key.sign(_jcs(payload))
        return {
            "issuer": self.issuer_id,
            "payload": payload,
            "signature_b64": base64.b64encode(sig).decode("ascii"),
        }


@pytest.fixture
def holder() -> Holder:
    return Holder(Ed25519PrivateKey.generate())


@pytest.fixture
def issuer() -> Issuer:
    return Issuer("entra://contoso", Ed25519PrivateKey.generate())


@pytest.fixture
def make_assertion(issuer: Issuer):
    """Factory: a signed subject-assertion AgentCard binding agent_id + cnf key."""

    def _make(
        *,
        agent_id: str = "agent-7",
        cnf_jwk: dict[str, str] | None,
        audience: str = "vault.acme",
        exp: float = 9999999999.0,
        nbf: float | None = None,
        signing_issuer: Issuer | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"agent_id": agent_id, "aud": audience, "exp": exp}
        if cnf_jwk is not None:
            payload["cnf"] = cnf_jwk
        if nbf is not None:
            payload["nbf"] = nbf
        return (signing_issuer or issuer).sign_card(payload)

    return _make
