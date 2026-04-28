"""
API-key authentication for Tex's external integration surface.

Design properties:

1. **Off when no keys are configured.** If TEX_API_KEYS is unset, requests
   pass through unauthenticated. Local development and the existing smoke
   harness keep working without configuration. Production deployments
   configure keys via env var.

2. **Constant-time comparison.** Key matching uses hmac.compare_digest to
   avoid timing-side-channel leakage.

3. **Multi-tenant aware.** Keys can carry an optional tenant label that
   surfaces into evidence metadata, so multi-customer deployments can
   correlate decisions to the calling tenant without leaking key material.

4. **Two header names accepted.** Both `Authorization: Bearer <key>` and
   `X-Tex-API-Key: <key>` are recognized. Gateways differ in which they
   send.

Configuration:

    TEX_API_KEYS="key_abc:tenant_acme,key_xyz:tenant_globex,key_internal"

Each comma-separated entry is `<key>` or `<key>:<tenant>`. Whitespace
around entries is stripped. Empty entries are ignored.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Final

from fastapi import HTTPException, Request, status


_ENV_KEYS: Final[str] = "TEX_API_KEYS"
_DEFAULT_TENANT: Final[str] = "default"


@dataclass(frozen=True, slots=True)
class TexPrincipal:
    """Identity attached to an authenticated request."""

    api_key_fingerprint: str
    tenant: str

    @property
    def is_anonymous(self) -> bool:
        return self.api_key_fingerprint == ""


_ANONYMOUS: Final[TexPrincipal] = TexPrincipal(
    api_key_fingerprint="",
    tenant=_DEFAULT_TENANT,
)


def _load_keys_from_env() -> dict[str, str]:
    """Parse TEX_API_KEYS into {key: tenant} mapping. Empty if unset."""
    raw = os.environ.get(_ENV_KEYS, "").strip()
    if not raw:
        return {}

    keys: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            key_part, tenant_part = entry.split(":", 1)
            key = key_part.strip()
            tenant = tenant_part.strip() or _DEFAULT_TENANT
        else:
            key = entry
            tenant = _DEFAULT_TENANT
        if key:
            keys[key] = tenant
    return keys


def _extract_presented_key(request: Request) -> str | None:
    """Pull the presented key from either accepted header."""
    header = request.headers.get("authorization", "").strip()
    if header.lower().startswith("bearer "):
        candidate = header[7:].strip()
        if candidate:
            return candidate

    candidate = request.headers.get("x-tex-api-key", "").strip()
    if candidate:
        return candidate

    return None


def _fingerprint(key: str) -> str:
    """Short non-reversible fingerprint for logs/evidence (first 8 of sha256)."""
    import hashlib
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def authenticate_request(request: Request) -> TexPrincipal:
    """
    Authenticate one inbound request.

    Returns a TexPrincipal carrying the tenant for downstream use. Raises
    HTTPException(401) when keys are configured and no valid key was
    presented.

    When no keys are configured, returns the anonymous principal so that
    development and demo environments keep working without setup.
    """
    configured_keys = _load_keys_from_env()
    if not configured_keys:
        return _ANONYMOUS

    presented = _extract_presented_key(request)
    if presented is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing API key. Send 'Authorization: Bearer <key>' or 'X-Tex-API-Key: <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for known_key, tenant in configured_keys.items():
        if hmac.compare_digest(known_key, presented):
            return TexPrincipal(
                api_key_fingerprint=_fingerprint(presented),
                tenant=tenant,
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


__all__ = [
    "TexPrincipal",
    "authenticate_request",
]
