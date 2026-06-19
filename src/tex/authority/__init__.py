"""
Tex authority plane — the credential broker.

WIRING STATUS (read first): BUILT + UNIT-TESTED, but NOT yet on the live path —
no module in ``src/tex`` calls the broker today, and the property that a resource
*refuses* anything but a Tex-issued credential is DEPLOYMENT configuration
(federation / sole-token-custody proxy), not closed by this code. This package
supplies the mint / verify / exchange / PoP machinery; "agents hold no standing
keys" becomes true only once a deployment routes credential issuance through it
and configures resources to demand it.

Designed to gate the *credential*, not the route: an inventoried agent holds no
standing keys; every action that needs one obtains a fresh, short-lived,
action-scoped credential from Tex, bound to its attested identity (and optionally
sender-constrained to a key the holder controls). See ``broker.py`` for the full
doctrine and the honest enforced-here-vs-deployment boundary.

Public surface:
  * :class:`~tex.authority.broker.CredentialBroker` — mint / verify / exchange /
    redeem / revoke.
  * :class:`~tex.authority.broker.MintedCredential`,
    :class:`~tex.authority.broker.CredentialCheck`,
    :class:`~tex.authority.broker.ExchangeResult` — result types.
  * :func:`~tex.authority.broker.authority_secret` — fail-closed secret resolution.
  * :class:`~tex.authority.identity_source.IdentitySource` (seam) +
    :class:`~tex.authority.identity_source.LocalEd25519IdentitySource` (working
    local impl). Real Entra/SPIFFE sources implement the same seam — not shipped
    here (RUNTIME-DEPENDENT).
  * :mod:`tex.authority.pop` — RFC 7800 / RFC 9449 proof-of-possession.
"""

from __future__ import annotations

from tex.authority.broker import (
    CredentialBroker,
    CredentialCheck,
    ExchangeResult,
    MintedCredential,
    RevocationStore,
    authority_secret,
)
from tex.authority.identity_source import (
    IdentitySource,
    JwksIdentitySource,
    JwksKeyProvider,
    LocalEd25519IdentitySource,
    StaticJwksProvider,
    SubjectVerification,
)

__all__ = [
    "CredentialBroker",
    "CredentialCheck",
    "ExchangeResult",
    "MintedCredential",
    "RevocationStore",
    "authority_secret",
    "IdentitySource",
    "JwksIdentitySource",
    "JwksKeyProvider",
    "LocalEd25519IdentitySource",
    "StaticJwksProvider",
    "SubjectVerification",
]
