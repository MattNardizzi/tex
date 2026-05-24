"""
Thread 4 — Layer 5 Export HTTP Routes
======================================

Tex is a five-layer AI agent governance platform deployed at companies
running AI agents (Layer 1 discovery → Layer 2 identity → Layer 3
monitoring → Layer 4 execution governance → Layer 5 reporting). This
module exposes three **Layer 5 (Reporting / Documenting / Logging)**
endpoints. Each surfaces the same underlying signed evidence chain to
a different audience the deploying company has to answer to:

    POST /v1/exports/insurer       — Offline-verifiable signed evidence
                                     packet. The audience is anyone who
                                     needs cryptographic proof of what
                                     the company's agents did over a
                                     period: cyber-insurance underwriter
                                     at renewal, EU AI Act Art. 17 QMS
                                     auditor, NAIC AI Systems Evaluation
                                     Tool examiner (pilot Jan-Sep 2026
                                     across 12 states, expected adoption
                                     Fall 2026 National Meeting), customer
                                     security review, internal compliance.
                                     Round-trips through the independent
                                     ``tex.pitch.verifier`` — verification
                                     needs no live connection back to Tex.

    POST /v1/exports/ciso          — MCP-runtime risk view for the
                                     security team operating the
                                     company's agents. Covers the four
                                     canonical MCP CVEs and the BlueRock
                                     Feb 2026 36.7% SSRF baseline against
                                     Tex's Layer 4 defence set.

    POST /v1/exports/vp-marketing  — Brand-safety / disclosure view for
                                     teams running customer-facing AI
                                     agents (AI SDRs, support agents,
                                     content agents). Anchors current
                                     FTC §5 enforcement signal, EU AI
                                     Act Art. 50 (effective 2 Aug 2026,
                                     Digital Omnibus transition to 2 Dec
                                     2026 for legacy systems), CA SB 942
                                     (operative 2 Aug 2026 per AB 853).

These are Layer 5 surfaces, not standalone pitch tools — they only
have content because Layers 1-4 are doing their job. The insurer
packet is empty if no agents are discovered (Layer 1), no actions
have been adjudicated (Layer 4), and no manifests have been emitted
(Layer 5 wiring). An empty signed packet is itself a useful Layer 5
output — it tells the auditor "no AI activity in this window" with
the same cryptographic guarantees as a populated one.

Design properties
-----------------
Each route enforces the May-2026 multi-tenant authorization posture
shipped in Thread 3:

  - **Pre-handler dependency** runs ``RequireTenantMatch.from_body(...)``
    on the insurer route so the route literally cannot start without
    the boundary check having been run. The dependency layer fails
    closed against OWASP API #1 BOLA.
  - **Scope gate** ``RequireScope("evidence:export")`` is the single
    authorization label for all three routes. Operators provision keys
    with this scope to opt them into Layer 5 export.
  - **Defence in depth** — even on routes without a body-tenant field
    (CISO, VP Marketing), the principal's tenant is bound into the
    response envelope and recorded in the structured emit_event for
    audit. A future caller cannot use a tenant-A key to attribute
    a tenant-B dossier to itself.

The insurer packet pulls C2PA manifests, evidence records, and tool
receipts from the deployment's stores (when wired) and signs them
with the algorithm-agile dispatcher. The default algorithm is
``ML-DSA-65`` (NIST FIPS 204 Level 3, the May-2026 enterprise
workhorse; AWS KMS, Microsoft AD CS, and AWS CloudHSM all added
support in 2025-2026). Operators on legacy stacks can set
``TEX_PITCH_SIGNING_ALGORITHM=ed25519`` for transition-period
compatibility per NSA CNSA 2.0.

Bleeding-edge anchors (verified May 22, 2026)
---------------------------------------------
  - EU AI Act Art. 50: draft Guidelines published 8 May 2026
    (consultation closes 3 June); Digital Omnibus provisional
    agreement 7 May grants legacy systems on EU market before
    2 August 2026 a transitional period to 2 December 2026.
  - C2PA 2.4 specification released April 2026 (2.3 was Jan 5 2026).
  - NAIC AI Systems Evaluation Tool pilot Jan-Sep 2026 across 12
    states; expected adoption at the 2026 Fall National Meeting.
  - NIST FIPS 204 ML-DSA: ML-DSA-65 is the recommended Level-3 default.
  - draft-ietf-lamps-pq-composite-sigs-18 (9 Apr 2026) provides PQ/T
    hybrid for jurisdictions that mandate (BSI 2021, ANSSI 2024).
  - OWASP API Security Top 10 2023 remains current; #1 BOLA is what
    ``RequireTenantMatch`` defends against.

References
----------
- ``tex.pitch.insurer_export`` — packet builder
- ``tex.pitch.ciso`` — MCP risk dossier builder
- ``tex.pitch.vp_marketing`` — brand safety dossier builder
- ``tex.pitch.verifier`` — independent verifier (round-trip target)
- TEX_CANONICAL.md §14 Thread 4 — scope and acceptance criteria
- THREAD_4_CHANGELOG.md — implementation notes

Priority: P0.
"""

from __future__ import annotations

import os
import threading
from dataclasses import asdict
from typing import Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import (
    RequireScope,
    RequireTenantMatch,
    TexPrincipal,
    authenticate_request,
    enforce_tenant_match,
)
from tex.observability.telemetry import emit_event
from tex.pitch import (
    BrandSafetyDossier,
    InsurerEvidencePacket,
    McpRiskDossier,
    build_brand_safety_dossier,
    build_insurer_evidence_packet,
    build_mcp_risk_dossier,
)
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


# -------------------------------------------------------------------- #
# Signing-key resolution                                               #
# -------------------------------------------------------------------- #

_EXPORT_SCOPE: Final[str] = "evidence:export"
_DEFAULT_SIGNING_ALGORITHM: Final[SignatureAlgorithm] = SignatureAlgorithm.ML_DSA_65

# Algorithms we will accept from the operator. We intentionally do not
# accept the genuine MPC threshold schemes here (Mithril) because they
# don't fit the single-key ``SignatureKeyPair`` API. Operators wanting
# threshold signing should wire a custom provider into app.state and
# bypass this resolution path.
_ALLOWED_ALGORITHMS: Final[frozenset[SignatureAlgorithm]] = frozenset({
    SignatureAlgorithm.ML_DSA_44,
    SignatureAlgorithm.ML_DSA_65,
    SignatureAlgorithm.ML_DSA_87,
    SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
    SignatureAlgorithm.ED25519,
    SignatureAlgorithm.ECDSA_P256,
})

# Algorithms that require liboqs / native ML-DSA. If the operator
# requests one but the provider can't instantiate, we fall back to
# ED25519 for dev/test convenience and log it.
_PQ_REQUIRED_ALGORITHMS: Final[frozenset[SignatureAlgorithm]] = frozenset({
    SignatureAlgorithm.ML_DSA_44,
    SignatureAlgorithm.ML_DSA_65,
    SignatureAlgorithm.ML_DSA_87,
    SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
})


_KEY_LOCK = threading.Lock()


def _resolve_signing_algorithm() -> SignatureAlgorithm:
    """
    Resolve the configured signing algorithm from env, with safe fallback.

    Reads ``TEX_PITCH_SIGNING_ALGORITHM``. Default is ML-DSA-65.
    Unknown values raise at startup-of-route-call (loud, not silent).
    """
    raw = os.environ.get("TEX_PITCH_SIGNING_ALGORITHM", "").strip().lower()
    if not raw:
        return _DEFAULT_SIGNING_ALGORITHM
    try:
        algo = SignatureAlgorithm(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"invalid TEX_PITCH_SIGNING_ALGORITHM={raw!r}; "
                f"must be one of {sorted(a.value for a in _ALLOWED_ALGORITHMS)}"
            ),
        ) from exc
    if algo not in _ALLOWED_ALGORITHMS:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"unsupported pitch signing algorithm: {algo.value}. "
                f"Allowed: {sorted(a.value for a in _ALLOWED_ALGORITHMS)}"
            ),
        )
    return algo


def _get_or_create_signing_key(request: Request) -> SignatureKeyPair:
    """
    Return the deployment's pitch signing key, generating one on first use.

    The key is cached on ``app.state.pitch_signing_key`` for the lifetime
    of the process. Lazy generation lets the routes work in dev without
    pre-wiring; production should pre-populate ``app.state.pitch_signing_key``
    from a KMS or HSM before the first request lands.

    Fallback semantics: if the configured algorithm is one that requires
    liboqs/native ML-DSA and the provider can't instantiate, we fall back
    to ED25519 and emit a telemetry warning. The fallback never silently
    upgrades — operators see it in logs.
    """
    cached = getattr(request.app.state, "pitch_signing_key", None)
    if isinstance(cached, SignatureKeyPair):
        return cached

    with _KEY_LOCK:
        cached = getattr(request.app.state, "pitch_signing_key", None)
        if isinstance(cached, SignatureKeyPair):
            return cached

        algorithm = _resolve_signing_algorithm()
        key_id = "pitch-export-signer-v1"

        try:
            provider = get_signature_provider(algorithm)
            keypair = provider.generate_keypair(key_id)
        except Exception as exc:  # noqa: BLE001 — dispatch + provider can raise many types
            if algorithm in _PQ_REQUIRED_ALGORITHMS:
                # PQ provider unavailable on this host. Fall back to
                # ED25519 so dev/test still works; never silently in prod.
                emit_event(
                    "pitch.signing_key.pq_unavailable_fallback",
                    requested_algorithm=algorithm.value,
                    fallback_algorithm=SignatureAlgorithm.ED25519.value,
                    error_class=exc.__class__.__name__,
                )
                provider = get_signature_provider(SignatureAlgorithm.ED25519)
                keypair = provider.generate_keypair(key_id)
            else:
                raise

        request.app.state.pitch_signing_key = keypair
        emit_event(
            "pitch.signing_key.generated",
            algorithm=keypair.algorithm.value,
            key_id=keypair.key_id,
        )
        return keypair


# -------------------------------------------------------------------- #
# Request / response models                                            #
# -------------------------------------------------------------------- #


class _DomainBody(BaseModel):
    """Request body for the CISO and VP Marketing routes."""

    model_config = ConfigDict(extra="forbid")

    company_domain: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description=(
            "The prospect's primary domain (e.g. 'acmecorp.com'). "
            "Normalized case-insensitively by the builder."
        ),
    )


class _InsurerExportBody(BaseModel):
    """Request body for the insurer route."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description=(
            "Tenant whose evidence is being exported. Must match the "
            "principal's tenant (enforced by RequireTenantMatch before "
            "the handler runs)."
        ),
    )
    period_start_iso: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description=(
            "ISO-8601 timestamp marking the inclusive start of the "
            "export period (e.g. '2026-04-01T00:00:00Z')."
        ),
    )
    period_end_iso: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description=(
            "ISO-8601 timestamp marking the exclusive end of the "
            "export period (e.g. '2026-05-01T00:00:00Z')."
        ),
    )
    include_evidence_records: bool = Field(
        default=True,
        description=(
            "When True (default), include hash-chained evidence records "
            "for the period. Set False only for connectivity diagnostics."
        ),
    )
    include_c2pa_manifests: bool = Field(
        default=True,
        description=(
            "When True (default), include C2PA 2.4 Content Credential "
            "manifests for the period."
        ),
    )
    include_tool_receipts: bool = Field(
        default=True,
        description=(
            "When True (default), include HMAC tool execution receipts "
            "(NabaOS pattern) for the period."
        ),
    )


def _dossier_to_json(obj: Any) -> dict[str, Any]:
    """Serialize a frozen dataclass (CISO / VP Marketing) to a plain dict."""
    return asdict(obj)


def _insurer_packet_to_json(packet: InsurerEvidencePacket) -> dict[str, Any]:
    """
    Serialize an insurer packet into a JSON-safe envelope.

    ``artifacts`` is bytes; we expose its SHA-256 digests under
    ``artifact_digests`` (already a string map on the dataclass) and
    include base64-encoded blobs only when the caller passes
    ``include_artifact_bytes=true``. Today we always include them so
    the response is independently verifiable; large deployments will
    likely want a follow-up "stream" variant.
    """
    import base64

    return {
        "tenant_id": packet.tenant_id,
        "period_start_iso": packet.period_start_iso,
        "period_end_iso": packet.period_end_iso,
        "algorithm": packet.algorithm.value,
        "layout_version": packet.layout_version,
        "artifact_digests": dict(packet.artifact_digests),
        "artifacts_b64": {
            name: base64.b64encode(blob).decode("ascii")
            for name, blob in packet.artifacts.items()
        },
        "manifest_signature_b64": packet.manifest_signature_b64,
        "signing_public_key_b64": base64.b64encode(packet.signing_public_key).decode("ascii"),
    }


# -------------------------------------------------------------------- #
# Artifact collection (P0 minimum)                                     #
# -------------------------------------------------------------------- #


def _collect_evidence_records_for_period(
    request: Request,
    tenant_id: str,
    period_start_iso: str,
    period_end_iso: str,
) -> tuple[Any, ...]:
    """
    Collect evidence records for the period from the deployment's stores.

    P0 contract: when stores are not wired (dev / fresh start) or the
    period has no records, return an empty tuple. The packet builder
    will still produce a verifiable empty-period packet (auditor sees
    "no AI activity in this window" which is itself a useful signal).

    The actual store-side time-window scan is a future thread; for P0
    we read ``app.state.evidence_exporter`` when present and let it
    handle the time-range filter, falling back to empty otherwise.
    """
    exporter = getattr(request.app.state, "evidence_exporter", None)
    if exporter is None:
        return tuple()
    try:
        # exporter API: `.export_for_tenant_period(...)` if present,
        # otherwise this returns an empty tuple. Avoids hard coupling
        # to a specific exporter signature.
        export = getattr(exporter, "export_for_tenant_period", None)
        if not callable(export):
            return tuple()
        records = export(
            tenant_id=tenant_id,
            period_start_iso=period_start_iso,
            period_end_iso=period_end_iso,
        )
        return tuple(records) if records else tuple()
    except Exception as exc:  # noqa: BLE001
        emit_event(
            "pitch.evidence_collect.failed",
            tenant_id=tenant_id,
            error_class=exc.__class__.__name__,
        )
        return tuple()


def _collect_c2pa_manifests_for_period(
    request: Request,
    tenant_id: str,
    period_start_iso: str,
    period_end_iso: str,
) -> tuple[Any, ...]:
    """Collect C2PA manifests for the period (Thread 5 will populate)."""
    mirror = getattr(request.app.state, "manifest_mirror", None)
    if mirror is None:
        return tuple()
    try:
        list_for = getattr(mirror, "list_for_tenant_period", None)
        if not callable(list_for):
            return tuple()
        manifests = list_for(
            tenant_id=tenant_id,
            period_start_iso=period_start_iso,
            period_end_iso=period_end_iso,
        )
        return tuple(manifests) if manifests else tuple()
    except Exception as exc:  # noqa: BLE001
        emit_event(
            "pitch.c2pa_collect.failed",
            tenant_id=tenant_id,
            error_class=exc.__class__.__name__,
        )
        return tuple()


def _collect_tool_receipts_for_period(
    request: Request,
    tenant_id: str,
    period_start_iso: str,
    period_end_iso: str,
) -> tuple[Any, ...]:
    """Collect HMAC tool execution receipts for the period."""
    receipt_store = getattr(request.app.state, "tool_receipt_store", None)
    if receipt_store is None:
        return tuple()
    try:
        list_for = getattr(receipt_store, "list_for_tenant_period", None)
        if not callable(list_for):
            return tuple()
        receipts = list_for(
            tenant_id=tenant_id,
            period_start_iso=period_start_iso,
            period_end_iso=period_end_iso,
        )
        return tuple(receipts) if receipts else tuple()
    except Exception as exc:  # noqa: BLE001
        emit_event(
            "pitch.receipt_collect.failed",
            tenant_id=tenant_id,
            error_class=exc.__class__.__name__,
        )
        return tuple()


# -------------------------------------------------------------------- #
# Router builder                                                       #
# -------------------------------------------------------------------- #


_RequireInsurerBodyTenant = RequireTenantMatch.from_body("tenant_id")


def build_pitch_router() -> APIRouter:
    """
    Build the FastAPI router for the three pitch export endpoints.

    Every route is authenticated (``authenticate_request`` as a router-
    level dependency) and scoped (``RequireScope("evidence:export")``
    per route). The insurer route additionally runs a
    pre-handler ``RequireTenantMatch.from_body("tenant_id")`` so the
    boundary check executes before the body is even parsed by the
    handler. This is the May-2026 OWASP API #1 BOLA-defence pattern
    Thread 3 standardized on.
    """
    router = APIRouter(
        prefix="/v1/exports",
        tags=["pitch-exports"],
        dependencies=[Depends(authenticate_request)],
    )

    # ----------------------------- VP Marketing ----------------------------- #

    @router.post(
        "/vp-marketing",
        status_code=status.HTTP_200_OK,
        summary="VP Marketing brand-safety dossier",
        description=(
            "Generate a personalized brand-safety dossier for a "
            "prospect company. Returns a structured exposure summary "
            "tied to current AI marketing enforcement signals (FTC §5 "
            "Operation AI Comply, EU AI Act Art. 50 effective 2 Aug "
            "2026, CA SB 942 operative 2 Aug 2026 per AB 853). The "
            "dossier is read-only — no tenant data is touched. The "
            "principal's tenant is recorded in telemetry for audit."
        ),
    )
    def export_vp_marketing(
        body: _DomainBody,
        principal: TexPrincipal = Depends(RequireScope(_EXPORT_SCOPE)),
    ) -> dict[str, Any]:
        dossier: BrandSafetyDossier = build_brand_safety_dossier(
            company_domain=body.company_domain,
        )
        emit_event(
            "pitch.export.vp_marketing.served",
            requesting_tenant=principal.tenant,
            requesting_key_fingerprint=principal.api_key_fingerprint,
            company_domain=body.company_domain,
        )
        return {
            "dossier_kind": "brand_safety",
            "requesting_tenant": principal.tenant,
            "dossier": _dossier_to_json(dossier),
        }

    # ----------------------------- CISO ----------------------------- #

    @router.post(
        "/ciso",
        status_code=status.HTTP_200_OK,
        summary="CISO MCP risk dossier",
        description=(
            "Generate a personalized MCP-vulnerability dossier for a "
            "prospect's CISO. Includes the four canonical MCP CVEs, "
            "the BlueRock February 2026 SSRF baseline (36.7% of 7,000+ "
            "public MCP servers), and the Tex runtime defense set. "
            "The dossier is read-only — no tenant data is touched."
        ),
    )
    def export_ciso(
        body: _DomainBody,
        principal: TexPrincipal = Depends(RequireScope(_EXPORT_SCOPE)),
    ) -> dict[str, Any]:
        dossier: McpRiskDossier = build_mcp_risk_dossier(
            company_domain=body.company_domain,
        )
        emit_event(
            "pitch.export.ciso.served",
            requesting_tenant=principal.tenant,
            requesting_key_fingerprint=principal.api_key_fingerprint,
            company_domain=body.company_domain,
        )
        return {
            "dossier_kind": "mcp_risk",
            "requesting_tenant": principal.tenant,
            "dossier": _dossier_to_json(dossier),
        }

    # ----------------------------- Insurer ----------------------------- #

    @router.post(
        "/insurer",
        status_code=status.HTTP_200_OK,
        summary="Offline-verifiable signed evidence packet",
        description=(
            "Build a signed evidence packet for a tenant + period. "
            "Combines hash-chained evidence records, C2PA 2.4 Content "
            "Credential manifests, and HMAC tool execution receipts "
            "into a single algorithm-agile-signed envelope. Default "
            "signing algorithm is NIST FIPS 204 ML-DSA-65 (Level 3, "
            "post-quantum). The packet round-trips through "
            "``tex.pitch.verifier.verify_insurer_evidence_packet`` "
            "without external state — any party that needs to verify "
            "what the company's agents did (cyber-insurance underwriter, "
            "EU AI Act Art. 17 QMS auditor, NAIC examiner, customer "
            "security review, internal compliance, downstream regulator) "
            "can do so entirely offline. The endpoint name is "
            "historical; the audience is anyone consuming the company's "
            "Layer 5 evidence.\n\n"
            "Tenant boundary is enforced before the handler runs via "
            "``RequireTenantMatch.from_body('tenant_id')`` (Thread 3 "
            "BOLA defence). Empty-period requests succeed and produce "
            "a verifiable empty packet — the auditor reads that as "
            "'no AI activity in this window', which is itself signal."
        ),
        dependencies=[Depends(_RequireInsurerBodyTenant)],
    )
    def export_insurer(
        request: Request,
        body: _InsurerExportBody,
        principal: TexPrincipal = Depends(RequireScope(_EXPORT_SCOPE)),
    ) -> dict[str, Any]:
        # Belt-and-suspenders: RequireTenantMatch already 403'd a
        # cross-tenant body, but if anyone ever bypasses the
        # dependency layer (e.g. via direct call in tests), this is
        # the second line of defence.
        effective_tenant = enforce_tenant_match(principal, body.tenant_id)

        evidence_records = (
            _collect_evidence_records_for_period(
                request, effective_tenant, body.period_start_iso, body.period_end_iso
            )
            if body.include_evidence_records
            else tuple()
        )
        c2pa_manifests = (
            _collect_c2pa_manifests_for_period(
                request, effective_tenant, body.period_start_iso, body.period_end_iso
            )
            if body.include_c2pa_manifests
            else tuple()
        )
        tool_receipts = (
            _collect_tool_receipts_for_period(
                request, effective_tenant, body.period_start_iso, body.period_end_iso
            )
            if body.include_tool_receipts
            else tuple()
        )

        signing_key = _get_or_create_signing_key(request)

        try:
            packet: InsurerEvidencePacket = build_insurer_evidence_packet(
                effective_tenant,
                body.period_start_iso,
                body.period_end_iso,
                evidence_records=evidence_records,
                c2pa_manifests=c2pa_manifests,
                receipts=tool_receipts,
                signing_key=signing_key,
            )
        except (TypeError, ValueError) as exc:
            # Builder rejects partial input; surface as 422 for the
            # caller so they know it's an input issue, not a server one.
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"insurer packet build failed: {exc}",
            ) from exc

        emit_event(
            "pitch.export.insurer.served",
            requesting_tenant=principal.tenant,
            effective_tenant=effective_tenant,
            requesting_key_fingerprint=principal.api_key_fingerprint,
            period_start=body.period_start_iso,
            period_end=body.period_end_iso,
            evidence_record_count=len(evidence_records),
            c2pa_manifest_count=len(c2pa_manifests),
            tool_receipt_count=len(tool_receipts),
            algorithm=signing_key.algorithm.value,
        )

        return {
            "packet_kind": "insurer_evidence_packet",
            "packet": _insurer_packet_to_json(packet),
        }

    return router


__all__ = ["build_pitch_router"]
