"""
DirectoryGrant — the frozen record of exactly what read-only access a customer
granted Tex, sealed before any agent is read.

This is half of the headline differentiator. Everyone else seals *outputs*;
conduit seals the **connection grant itself**. The grant object is deliberately
minimal and secret-free: it records *what* least-privilege read access was
granted, *by whom*, *when*, and the provider's consent-artifact id — plus an
opaque ``credential_ref`` pointing at the deployment's secret store. The secret
itself is never held here and never sealed.

Fail-closed honesty: if any requested scope was *not* granted, the grant is
``degraded`` and records the gap (``missing_scopes``) rather than silently
pretending full access. A degraded grant still seals — "here is the partial,
least-privilege access you actually gave" — and downstream census is marked
partial. From the sealed ``granted_scopes`` falls out drift detection
(``conduit.seal.detect_scope_drift``): a later live scope set that diverges
from what was sealed is a self-auditing red flag.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.domain.discovery import DiscoverySource


def canonical_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    """Canonicalize a scope set: strip, casefold, drop blanks, dedupe, sort.

    Deterministic so the sealed scope set is byte-stable and drift comparison
    is order-insensitive — the same grant always hashes to the same leaf.
    """
    cleaned = {s.strip().casefold() for s in scopes if s and s.strip()}
    return tuple(sorted(cleaned))


class DirectoryGrant(BaseModel):
    """One read-only directory access grant, frozen and secret-free."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_id: UUID = Field(default_factory=uuid4)
    provider: DiscoverySource
    tenant_id: str = Field(min_length=1, max_length=200)

    # The exact least-privilege scopes we asked for, and the exact set the
    # provider confirmed landed. Both canonicalized + sorted.
    requested_scopes: tuple[str, ...] = Field(default_factory=tuple)
    granted_scopes: tuple[str, ...] = Field(default_factory=tuple)

    # Provider's consent-artifact id (Entra admin-consent grant id / Okta
    # service-app id / Google DWD client id / Ping service-account id).
    consent_artifact_id: str = Field(min_length=1, max_length=512)
    consented_by: str | None = Field(default=None, max_length=400)
    granted_at: datetime

    # Opaque pointer into the deployment secret store. NEVER the secret itself.
    credential_ref: str = Field(min_length=1, max_length=512)

    # Computed + sealed: any requested-but-not-granted scope marks the grant
    # degraded and records the gap (fail-closed, no silent proceed).
    degraded: bool = Field(default=False)
    missing_scopes: tuple[str, ...] = Field(default_factory=tuple)

    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _normalize_tenant(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("tenant_id must be a string")
        norm = value.strip().casefold()
        if not norm:
            raise ValueError("tenant_id must not be blank")
        return norm

    @field_validator("requested_scopes", "granted_scopes", mode="before")
    @classmethod
    def _canon_scopes(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            raise TypeError("scopes must be a sequence of strings, not a single string")
        return canonical_scopes(value)

    @field_validator("credential_ref")
    @classmethod
    def _ref_not_secretish(cls, value: str) -> str:
        # A credential_ref is a pointer (e.g. "vault://tex/okta/acme"), never a
        # secret. Reject obvious secret material so a careless caller can't seal
        # one by accident.
        if any(c.isspace() for c in value):
            raise ValueError("credential_ref must be an opaque pointer, not a secret blob")
        return value

    @field_validator("granted_at", mode="after")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("granted_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _compute_degradation(self) -> "DirectoryGrant":
        granted = set(self.granted_scopes)
        missing = tuple(sorted(s for s in self.requested_scopes if s not in granted))
        object.__setattr__(self, "missing_scopes", missing)
        object.__setattr__(self, "degraded", bool(missing))
        return self

    @property
    def is_partial(self) -> bool:
        """True when this grant is a fail-closed partial census."""
        return self.degraded

    def canonical_payload(self) -> dict[str, Any]:
        """The exact ordered, JSON-safe dict that gets hashed into a receipt
        leaf. Deterministic; contains no secret (only ``credential_ref``)."""
        return {
            "grant_id": str(self.grant_id),
            "provider": self.provider.value,
            "tenant_id": self.tenant_id,
            "requested_scopes": list(self.requested_scopes),
            "granted_scopes": list(self.granted_scopes),
            "missing_scopes": list(self.missing_scopes),
            "degraded": self.degraded,
            "consent_artifact_id": self.consent_artifact_id,
            "consented_by": self.consented_by,
            "granted_at": self.granted_at.isoformat(),
            "credential_ref": self.credential_ref,
            "detail": self.detail,
        }
