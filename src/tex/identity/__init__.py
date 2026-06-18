"""Agent identity attestation — verify a signed identity credential and bind the
attested identity into a decision. See ``agent_credential``."""

from __future__ import annotations

from tex.identity.agent_credential import (
    AttestedIdentity,
    CredentialVerification,
    verify_agent_credential,
    verify_signed_card,
)

__all__ = [
    "AttestedIdentity",
    "CredentialVerification",
    "verify_agent_credential",
    "verify_signed_card",
]
