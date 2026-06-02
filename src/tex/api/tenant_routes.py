"""
Tenant content baseline HTTP routes.

Endpoints:

    GET    /v1/tenants/{tenant_id}/baseline   summary of recorded
                                              tenant signatures and
                                              recipient-domain counts
                                              by action_type

The baseline itself is read-only via this surface — writes happen
only through the EvaluateActionCommand on PERMITted, agent-attached
decisions. There is intentionally no "delete the baseline" route;
operators who need to reset baseline state in production deployments
should rotate the underlying store.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import (
    RequireScope,
    TexPrincipal,
    authenticate_request,
    enforce_tenant_match,
)
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


class TenantBaselineSummaryDTO(BaseModel):
    """
    Read shape for a tenant's content baseline summary.

    Lists per-action_type sample counts and recipient-domain counts.
    Buyers use this to understand "how much has Tex learned about
    normal output for this tenant" — useful for both demos and for
    deciding when the baseline is mature enough to lean on.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    action_type_sample_counts: dict[str, int] = Field(default_factory=dict)
    action_type_recipient_domain_counts: dict[str, dict[str, int]] = Field(
        default_factory=dict
    )
    total_signatures: int


def _resolve_tenant_baseline(request: Request) -> InMemoryTenantContentBaseline:
    baseline = getattr(request.app.state, "tenant_baseline", None)
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="tenant content baseline is not configured on this Tex deployment",
        )
    return baseline


def build_tenant_router() -> APIRouter:
    """
    Build the FastAPI router for tenant baseline introspection.

    All routes require authentication. Tenant ID in the path is
    cross-checked against the principal's tenant via
    ``enforce_tenant_match`` so a tenant_acme key cannot read
    tenant_globex's baseline.
    """
    router = APIRouter(
        prefix="/v1/tenants",
        tags=["tenant-baseline"],
        dependencies=[Depends(authenticate_request)],
    )

    @router.get(
        "/{tenant_id}/baseline",
        response_model=TenantBaselineSummaryDTO,
        summary="Summary of the tenant content baseline",
    )
    def get_tenant_baseline(
        request: Request,
        tenant_id: str = Path(..., min_length=1, max_length=200),
        principal: TexPrincipal = Depends(RequireScope("tenant:read")),
    ) -> TenantBaselineSummaryDTO:
        # Enforce that the requested tenant_id matches the principal's
        # scope unless they have admin:cross_tenant.
        enforce_tenant_match(principal, tenant_id)

        store = _resolve_tenant_baseline(request)
        normalized = tenant_id.strip().casefold()
        if not normalized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="tenant_id must not be blank",
            )

        # We iterate over the in-memory store's keyed view directly via
        # a tightly scoped read API to avoid leaking internal structure
        # to the route. _signatures is a private attribute, so we copy
        # the snapshot under lock by walking known action_types.
        # Strategy: build the listing by asking the store for every
        # (tenant, action_type) pair we know about. The store does not
        # expose that listing today, so we add a thin wrapper here that
        # asks it directly. Keep the public API of the store stable by
        # using its existing locks via list_for() per action_type.
        action_type_sample_counts: dict[str, int] = {}
        recipient_domain_counts: dict[str, dict[str, int]] = {}
        total = 0

        # _signatures is the private snapshot; we read it under the
        # store's lock by going through count_for / recipient_domains_for
        # one action_type at a time. To enumerate action_types known
        # for this tenant we use the same private snapshot directly.
        # This is the only place outside the store that reaches in;
        # if it grows further, lift this into a public store method.
        with store._lock:  # noqa: SLF001 — controlled read inside store's lock
            keys = [
                key for key in store._signatures.keys()  # noqa: SLF001
                if key[0] == normalized
            ]
            for key in keys:
                _, action_type = key
                queue = store._signatures.get(key)  # noqa: SLF001
                domains = store._recipient_domains.get(key) or {}  # noqa: SLF001
                count = len(queue) if queue else 0
                action_type_sample_counts[action_type] = count
                recipient_domain_counts[action_type] = dict(domains)
                total += count

        return TenantBaselineSummaryDTO(
            tenant_id=normalized,
            action_type_sample_counts=action_type_sample_counts,
            action_type_recipient_domain_counts=recipient_domain_counts,
            total_signatures=total,
        )

    return router
