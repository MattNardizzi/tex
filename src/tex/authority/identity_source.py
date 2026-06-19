"""
Identity-provider seam for the authority plane.

Token exchange (RFC 8693) starts from a *subject assertion*: an inbound identity
token an agent presents to prove who it is (an Entra/Azure AD OIDC token, a
SPIFFE SVID, an A2A AgentCard, ...). The broker must verify that assertion before
it will mint a Tex credential bound to it. ``IdentitySource`` is that seam:
verify the inbound assertion and surface (a) the attested identity and (b) the
holder's ``cnf`` public key (the proof-of-possession key the agent controls).

What is CLOSED here vs the honest boundary:
  * CLOSED — the seam (``IdentitySource``) and a fully-working local
    implementation (``LocalEd25519IdentitySource``) that REUSES the existing,
    audited ``tex.identity.agent_credential.verify_agent_credential`` (Ed25519
    over the JCS-canonical payload, allow-listed issuer, exp/nbf + audience
    freshness). No new identity crypto is introduced — this composes the
    enforcement-side verifier.
  * NOT CLOSED (``RUNTIME-DEPENDENT``) — verifying a *real* Microsoft Entra OIDC
    JWT (JWKS fetch, RS256/ES256, ``iss``/``aud``/``tid`` checks) or a real
    SPIFFE SVID (SPIRE trust bundle, X.509-SVID / JWT-SVID). Those are separate
    ``IdentitySource`` implementations that this package deliberately does NOT
    ship — they require live IdP integration and key distribution. The seam is
    here; the live wiring is deployment. Do not read the presence of this seam as
    "Tex already trusts Entra/SPIFFE."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from tex.identity.agent_credential import AttestedIdentity, verify_agent_credential

__all__ = [
    "SubjectVerification",
    "IdentitySource",
    "LocalEd25519IdentitySource",
]


@dataclass(frozen=True, slots=True)
class SubjectVerification:
    """The result of verifying an inbound subject assertion at the broker's edge."""

    verified: bool
    status: str  # the fail-closed reason when not verified
    agent_id: str | None
    issuer: str | None  # the upstream IdP that attested the subject
    cnf_jwk: dict[str, Any] | None  # the holder's proof-of-possession public key
    claims: dict[str, Any] | None = None
    method: str = "token-exchange"

    def as_attested_identity(self) -> AttestedIdentity:
        """Project onto the enforcement-side ``AttestedIdentity`` the broker mints from."""
        return AttestedIdentity(
            verified=self.verified,
            status=self.status,
            issuer=self.issuer,
            claimed_agent_id=self.agent_id,
            method=self.method,
        )


@runtime_checkable
class IdentitySource(Protocol):
    """Verify an inbound subject assertion. Implementations MUST fail closed:
    any defect returns ``verified=False`` with a reason in ``status`` and never
    raises. A real Entra / SPIFFE source implements exactly this one method."""

    def verify_subject_assertion(
        self,
        assertion: Any,
        *,
        now: float | None = None,
        expected_audience: str | None = None,
    ) -> SubjectVerification: ...


class LocalEd25519IdentitySource:
    """A working local ``IdentitySource`` for tests and in-trust-boundary use.

    The subject assertion is an Ed25519-signed AgentCard (the same object
    ``tex.identity.agent_credential`` verifies): ``{"issuer", "payload",
    "signature_b64"}`` where ``payload`` carries ``agent_id`` and a ``cnf`` JWK
    (the holder's PoP public key). Verification is delegated wholesale to the
    audited ``verify_agent_credential`` — this class only extracts the cnf key.
    """

    def __init__(
        self,
        *,
        trusted_issuers: dict[str, str],
        require_expiry: bool = True,
        max_bytes: int = 64 * 1024,
    ) -> None:
        self._trusted_issuers = dict(trusted_issuers)
        self._require_expiry = require_expiry
        self._max_bytes = max_bytes

    def verify_subject_assertion(
        self,
        assertion: Any,
        *,
        now: float | None = None,
        expected_audience: str | None = None,
    ) -> SubjectVerification:
        if not isinstance(assertion, dict):
            return SubjectVerification(False, "malformed_assertion", None, None, None)

        attested = verify_agent_credential(
            assertion,
            trusted_issuers=self._trusted_issuers,
            max_bytes=self._max_bytes,
            now=now,
            expected_audience=expected_audience,
            require_expiry=self._require_expiry,
        )
        payload = assertion.get("payload")
        payload = payload if isinstance(payload, dict) else None
        cnf = payload.get("cnf") if payload else None
        return SubjectVerification(
            verified=attested.verified,
            status=attested.status,
            agent_id=attested.claimed_agent_id,
            issuer=attested.issuer,
            cnf_jwk=cnf if isinstance(cnf, dict) else None,
            claims=payload,
            method="local_ed25519_agent_card",
        )
