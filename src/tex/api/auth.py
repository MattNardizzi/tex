"""
API-key authentication for Tex's external integration surface.

Design properties:

1. **Production-mode enforcement.** When ``TEX_REQUIRE_AUTH=1`` is set,
   every request MUST present a valid key. The "off when no keys are
   configured" path is disabled. This is the production posture.

2. **Backwards-compatible default.** When ``TEX_REQUIRE_AUTH`` is unset
   AND no keys are configured, requests pass through anonymously. Local
   development and the existing smoke harness keep working.

3. **Constant-time comparison.** Key matching uses hmac.compare_digest
   to avoid timing-side-channel leakage.

4. **Scoped keys / RBAC.** Each key carries an explicit scope set such
   as ``decision:write``, ``policy:write``, ``admin:read``,
   ``learning:approve``. Routes declare which scope they require via
   ``RequireScope("...")``. Keys without the scope are 403'd.

5. **Multi-tenant isolation.** Each key carries a tenant. Routes that
   accept a tenant parameter call ``enforce_tenant_match(principal,
   requested)`` to ensure cross-tenant reads/writes are rejected unless
   the key has ``admin:cross_tenant``.

6. **Two header names accepted.** ``Authorization: Bearer <key>`` and
   ``X-Tex-API-Key: <key>``. Gateways differ.

Configuration:

    TEX_REQUIRE_AUTH=1
    TEX_API_KEYS="key_abc:tenant_acme:decision:write+evidence:read,
                  key_admin:internal:admin:read+admin:write+admin:cross_tenant,
                  key_legacy:tenant_globex"

Each comma-separated entry is ``<key>[:<tenant>[:<scopes>]]``.
``<scopes>`` is a ``+``-separated list. Whitespace and blank entries
are ignored. When scopes are not supplied, the key gets the default
read+write scope set.
"""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass, field
from typing import Final

from fastapi import Depends, HTTPException, Request, status

_logger = logging.getLogger(__name__)

_ENV_KEYS: Final[str] = "TEX_API_KEYS"
_ENV_REQUIRE_AUTH: Final[str] = "TEX_REQUIRE_AUTH"
_DEFAULT_TENANT: Final[str] = "default"


# Default scopes a key gets when none are explicitly listed.
DEFAULT_SCOPES: Final[frozenset[str]] = frozenset(
    {
        "decision:write",
        "decision:read",
        "evidence:read",
        "policy:read",
        "agent:read",
        "discovery:read",
        "learning:read",
        "tenant:read",
        "outcome:write",
    }
)


# Scopes that grant cross-tenant read/write. Reserved for internal
# admin keys.
SCOPE_CROSS_TENANT: Final[str] = "admin:cross_tenant"


@dataclass(frozen=True, slots=True)
class TexPrincipal:
    """Identity attached to an authenticated request."""

    api_key_fingerprint: str
    tenant: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_anonymous(self) -> bool:
        return self.api_key_fingerprint == ""

    def has_scope(self, scope: str) -> bool:
        if self.is_anonymous:
            # Anonymous == every scope. Only reachable when keys are not
            # configured AND require-auth is off; this is dev-only by
            # construction.
            return True
        return scope in self.scopes

    def can_access_tenant(self, tenant_id: str | None) -> bool:
        """
        Return True iff the principal can act on records for ``tenant_id``.
        Anonymous == True. Cross-tenant scope == True.
        Otherwise the tenants must match.
        """
        if self.is_anonymous:
            return True
        if SCOPE_CROSS_TENANT in self.scopes:
            return True
        if tenant_id is None:
            return True
        return tenant_id.strip() == self.tenant


_ANONYMOUS: Final[TexPrincipal] = TexPrincipal(
    api_key_fingerprint="",
    tenant=_DEFAULT_TENANT,
    scopes=frozenset(),
)


def _require_auth_enforced() -> bool:
    raw = os.environ.get(_ENV_REQUIRE_AUTH, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _load_keys_from_env() -> dict[str, tuple[str, frozenset[str]]]:
    """
    Parse ``TEX_API_KEYS`` into ``{key: (tenant, scopes)}``.

    Each comma-separated entry is one of:
      - ``<key>``                                    → default tenant + default scopes
      - ``<key>:<tenant>``                           → tenant + default scopes
      - ``<key>:<tenant>:<scope+scope+...>``         → tenant + explicit scopes
    """
    raw = os.environ.get(_ENV_KEYS, "").strip()
    if not raw:
        return {}

    parsed: dict[str, tuple[str, frozenset[str]]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue

        parts = [p.strip() for p in entry.split(":", 2)]
        key = parts[0]
        if not key:
            continue

        tenant = parts[1] if len(parts) >= 2 and parts[1] else _DEFAULT_TENANT

        if len(parts) == 3 and parts[2]:
            scopes_raw = parts[2]
            scopes = frozenset(
                s.strip() for s in scopes_raw.split("+") if s.strip()
            )
        else:
            scopes = DEFAULT_SCOPES

        parsed[key] = (tenant, scopes)

    return parsed


def _extract_presented_key(request: Request) -> str | None:
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
    """Short non-reversible fingerprint for logs/evidence."""
    import hashlib
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def authenticate_request(request: Request) -> TexPrincipal:
    """
    Authenticate one inbound request.

    - Production posture (``TEX_REQUIRE_AUTH=1``):
        keys MUST be configured AND a valid one MUST be presented;
        otherwise 401.

    - Development posture (default):
        if no keys configured, anonymous; otherwise enforce.
    """
    configured_keys = _load_keys_from_env()
    require_auth = _require_auth_enforced()

    if not configured_keys:
        if require_auth:
            _logger.error(
                "TEX_REQUIRE_AUTH=1 but %s is unset. Refusing all requests.",
                _ENV_KEYS,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="server requires authentication but no API keys are configured.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return _ANONYMOUS

    presented = _extract_presented_key(request)
    if presented is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing API key. Send 'Authorization: Bearer <key>' or 'X-Tex-API-Key: <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for known_key, (tenant, scopes) in configured_keys.items():
        if hmac.compare_digest(known_key, presented):
            return TexPrincipal(
                api_key_fingerprint=_fingerprint(presented),
                tenant=tenant,
                scopes=scopes,
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------- scope guards


class RequireScope:
    """
    FastAPI dependency that requires a specific scope on the principal.

    Usage:

        @router.post("/admin/policies/activate")
        def activate(
            principal: TexPrincipal = Depends(RequireScope("policy:write")),
        ):
            ...

    The dependency runs ``authenticate_request`` first, then enforces
    the scope.
    """

    __slots__ = ("_scope",)

    def __init__(self, scope: str) -> None:
        if not scope:
            raise ValueError("scope must be non-empty")
        self._scope = scope

    def __call__(
        self,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> TexPrincipal:
        if not principal.has_scope(self._scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing required scope: {self._scope}",
            )
        return principal


def enforce_tenant_match(
    principal: TexPrincipal,
    requested_tenant: str | None,
) -> str:
    """
    Resolve the effective tenant for a request and 403 on mismatch.

    Rules:
      - Anonymous principal ⇒ requested_tenant is honored if provided,
        else "default".
      - Cross-tenant scope ⇒ requested_tenant is honored if provided,
        else principal.tenant.
      - Scoped principal without cross-tenant ⇒ requested_tenant must
        either be unset or equal principal.tenant; mismatch is 403.
    """
    if principal.is_anonymous:
        return (requested_tenant or _DEFAULT_TENANT).strip()

    if SCOPE_CROSS_TENANT in principal.scopes:
        return (requested_tenant or principal.tenant).strip()

    if requested_tenant is None or requested_tenant.strip() == "":
        return principal.tenant

    if requested_tenant.strip() != principal.tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"tenant '{requested_tenant}' is not accessible to this API key. "
                "use a key with admin:cross_tenant or scope to your own tenant."
            ),
        )
    return principal.tenant


__all__ = [
    "DEFAULT_SCOPES",
    "RequireScope",
    "SCOPE_CROSS_TENANT",
    "TexPrincipal",
    "authenticate_request",
    "enforce_tenant_match",
]
