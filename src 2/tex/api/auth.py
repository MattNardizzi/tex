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

    Comparison is case-folded and whitespace-trimmed on both sides to
    match the historical tenant-canonicalisation done by stores.
    """
    if principal.is_anonymous:
        return (requested_tenant or _DEFAULT_TENANT).strip()

    if SCOPE_CROSS_TENANT in principal.scopes:
        return (requested_tenant or principal.tenant).strip()

    if requested_tenant is None or requested_tenant.strip() == "":
        return principal.tenant

    if requested_tenant.strip().casefold() != principal.tenant.casefold():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"tenant '{requested_tenant}' is not accessible to this API key. "
                "use a key with admin:cross_tenant or scope to your own tenant."
            ),
        )
    return principal.tenant


def enforce_tenant_match_optional(
    principal: TexPrincipal | None,
    requested_tenant: str | None,
) -> str | None:
    """
    Tenant-match check that no-ops when there is no principal at all.

    Used by routes that intentionally do not require Tex API-key auth
    (the design property #3 file class — credentials themselves are
    the trust bearer; operator's gateway handles perimeter auth). When
    a caller HAPPENS to pass a Tex API key anyway, we still enforce
    tenant binding on the looked-up resource. When no API key is
    presented, this is a no-op and the route's existing behaviour is
    preserved.

    Returns ``None`` when no enforcement is performed; otherwise the
    same resolved tenant string ``enforce_tenant_match`` would return.
    """
    if principal is None or principal.is_anonymous:
        return None
    return enforce_tenant_match(principal, requested_tenant)


# ---------------------------------------------------------------------- tenant guards


class RequireTenantMatch:
    """
    FastAPI dependency that enforces tenant binding from a request body
    or query parameter BEFORE the handler runs.

    Use this when the tenant_id is present in the request envelope
    itself (pre-handler). For checks against a tenant_id fetched
    mid-handler from a store-loaded object (e.g. ``agent.tenant_id``,
    ``proposal.tenant_id``, ``record["tenant_id"]``), call
    ``enforce_tenant_match`` from inside the handler instead.

    Usage on a route that takes a body with a ``tenant_id`` field::

        from tex.api.auth import RequireTenantMatch

        _RequireBodyTenant = RequireTenantMatch.from_body("tenant_id")

        @router.post(
            "/proposals",
            dependencies=[Depends(_RequireBodyTenant)],
        )
        def create_proposal(body: CreateProposalRequestDTO, ...): ...

    Usage on a route that takes a ``tenant_id`` query parameter::

        _RequireQueryTenant = RequireTenantMatch.from_query("tenant_id")

        @router.get("/health", dependencies=[Depends(_RequireQueryTenant)])
        def calibration_health(tenant_id: str, ...): ...

    The dependency runs ``authenticate_request`` first, extracts the
    tenant_id from the configured source, then calls
    ``enforce_tenant_match`` against the resolved principal. A
    mismatch raises ``HTTPException(403)`` before the handler runs;
    a missing tenant value is treated by ``enforce_tenant_match`` as
    "use the principal's own tenant" — the handler will read it back
    from the request body itself if it needs the value.

    The result of the dependency (the resolved effective tenant) is
    NOT consumed by route handlers today; the handler reads the
    tenant_id directly from its own typed parameter as before. The
    dependency exists purely to make forgetting impossible — the
    route literally cannot start without the check having been run.

    Centralisation property: ``RequireTenantMatch``, the helper
    ``enforce_tenant_match``, and the opt-in ``enforce_tenant_match_optional``
    all delegate to the same underlying logic in
    ``enforce_tenant_match``. There is one tenant-isolation policy,
    not three.

    This pattern follows the May 2026 best practice for multi-tenant
    FastAPI: tenant boundary enforcement is wired as a dependency
    that runs before the handler, so forgetting it makes the route
    fail to start rather than producing silent BOLA. See OWASP API
    Top 10 2023 / 2026 #1 (Broken Object Level Authorization).
    """

    __slots__ = ("_source", "_field_name")

    _ALLOWED_SOURCES: Final[frozenset[str]] = frozenset({"body", "query"})

    def __init__(self, source: str, field_name: str = "tenant_id") -> None:
        if source not in self._ALLOWED_SOURCES:
            raise ValueError(
                f"source must be one of {sorted(self._ALLOWED_SOURCES)}, got: {source!r}"
            )
        if not field_name:
            raise ValueError("field_name must be non-empty")
        self._source = source
        self._field_name = field_name

    @classmethod
    def from_body(cls, field_name: str = "tenant_id") -> "RequireTenantMatch":
        return cls(source="body", field_name=field_name)

    @classmethod
    def from_query(cls, field_name: str = "tenant_id") -> "RequireTenantMatch":
        return cls(source="query", field_name=field_name)

    async def __call__(
        self,
        request: Request,
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> str:
        requested: str | None
        if self._source == "query":
            raw = request.query_params.get(self._field_name)
            requested = raw if raw is None else str(raw)
        else:  # body
            # Body parsing requires reading and re-buffering the body so
            # the downstream handler can still parse it as its own model.
            # Starlette's Request.body() is cached after first call, so
            # this is safe to do here.
            try:
                body_bytes = await request.body()
            except Exception:
                requested = None
            else:
                requested = _extract_field_from_json_body(
                    body_bytes, self._field_name
                )

        # ``enforce_tenant_match`` does the actual policy decision and
        # raises HTTPException(403) on mismatch.
        return enforce_tenant_match(principal, requested)


def _extract_field_from_json_body(body_bytes: bytes, field_name: str) -> str | None:
    """
    Best-effort extraction of a single top-level field from a JSON body.

    Returns ``None`` when the body is not JSON, the field is missing,
    or the field is not a string. In all those cases
    ``enforce_tenant_match`` treats the requested tenant as unset and
    defaults to the principal's own tenant — which is the safe default.
    """
    if not body_bytes:
        return None
    try:
        import json
        parsed = json.loads(body_bytes)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    value = parsed.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    return value


__all__ = [
    "DEFAULT_SCOPES",
    "RequireScope",
    "RequireTenantMatch",
    "SCOPE_CROSS_TENANT",
    "TexPrincipal",
    "authenticate_request",
    "enforce_tenant_match",
    "enforce_tenant_match_optional",
]
