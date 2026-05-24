"""
A2A Signed Agent Cards.

A signed Agent Card is a cryptographically-signed declaration of:
  - The agent's identity (DID / domain)
  - The capabilities it advertises
  - The endpoints it serves
  - Its supported authentication methods

Per A2A v1.0 release notes (early 2026), the signature prevents card-forgery
attacks where an attacker stands up a fake Agent Card.

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SignedAgentCard:
    """An A2A v1.0+ signed Agent Card."""

    agent_did: str
    capabilities: tuple[str, ...]
    endpoints: tuple[str, ...]
    auth_methods: tuple[str, ...]  # api_key | http_basic | oauth2 | mtls
    signing_certificate_pem: str
    signature_b64: str


def verify_agent_card(card: SignedAgentCard, *, trust_anchors_pem: tuple[str, ...]) -> bool:
    """
    TODO(P1): verify signature against trust anchors
    TODO(P1): check certificate validity + revocation
    TODO(P1): match agent_did against signing certificate subject
    """
    raise NotImplementedError("A2A signed agent card verification")
