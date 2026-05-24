"""
C2PA Content Credentials HTTP surface (Thread 5).

Two endpoints:

  GET  /v1/evidence/{record_id}/c2pa
       Returns the CBOR manifest bytes for the C2PA Content Credential
       attached to an evidence record. Content-Type: application/c2pa.
       404 when the record exists but carried no outbound artifact, or
       when the manifest mirror is disabled.

  POST /v1/c2pa/verify
       Accepts a base64-encoded outer signature + base64-encoded
       canonical claim CBOR, optionally the asset bytes (base64),
       and returns a structured verification result that includes the
       six-attack-defense status from arxiv 2604.24890.
       Content-Type: application/json (both ways).

Both routes are intentionally read-mostly and side-effect-free:
they query the manifest mirror and exercise the verifier. They
never write back into the evidence chain.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from tex.c2pa import (
    ALL_ATTACKS,
    C2paAssertion,
    C2paClaim,
    C2paManifest,
    full_file_sha256,
    verify_evidence_cosign,
    verify_manifest,
)
from tex.c2pa._cbor import decode as cbor_decode

from tex.api.auth import (
    authenticate_request,
    enforce_tenant_match_optional,
)


_logger = logging.getLogger(__name__)


router = APIRouter(tags=["c2pa"])


# ---------------------------------------------------------------------------
# GET /v1/evidence/{record_id}/c2pa
# ---------------------------------------------------------------------------


def _get_manifest_mirror(request: Request):
    """Resolve the manifest mirror from the runtime, if wired."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        return None
    return getattr(runtime, "manifest_mirror", None)


@router.get(
    "/v1/evidence/{record_id}/c2pa",
    summary="Fetch the C2PA Content Credential for an evidence record",
    response_class=Response,
)
def get_c2pa_manifest(
    record_id: str,
    request: Request,
) -> Response:
    """
    Return the CBOR-encoded C2PA manifest for ``record_id``.

    The wire format is the canonical claim CBOR (the same bytes the
    outer COSE_Sign1 signs over) prefixed by a small envelope JSON
    header carrying the outer signature and certificate chain.
    Returning a raw CBOR claim plus a side-channel signature is
    incompatible with how downstream c2pa-rs / c2patool consumers
    expect to receive credentials; we therefore return the
    COSE_Sign1 + claim wrapped in a small JSON document so the
    caller has everything offline-verifiable in one response.

    **Multi-tenant guard (truly opt-in, Thread 3):** this endpoint
    intentionally does not require Tex API-key auth — operator
    deployments handle perimeter auth at the gateway, and downstream
    audit tooling (EU AI Office reviewers, insurers, customer
    compliance teams) need to verify manifests without a Tex-issued
    key. However, when a caller voluntarily PRESENTS a Tex API key,
    we authenticate it and enforce that the key's tenant binding
    matches the manifest's stored ``tenant_id``. A tenant-A key
    fetching a record_id that belongs to tenant-B returns 403.
    Unauthenticated callers (no key in header at all) continue to
    behave as before — they reach the manifest mirror without
    tenant gating, leaving the perimeter to enforce perimeter-grade
    controls.

    We deliberately do NOT declare ``Depends(authenticate_request)``
    here, because that dependency 401s when ``TEX_API_KEYS`` is set
    and the caller didn't bring a key — which would break the
    unauthenticated audit-verifier path that is the WHOLE POINT of
    a public C2PA Content Credential. Instead we sniff for a key
    presence first and only authenticate when one is present.
    """
    # Truly opt-in: only authenticate when a key is presented. Allows
    # the unauthenticated-verifier path to keep working under
    # ``TEX_REQUIRE_AUTH=1`` deployments, while still binding the
    # response to the principal's tenant when a key IS in use.
    #
    # IMPORTANT: authenticate BEFORE any other resource lookup. A bad
    # key must 401 fail-closed; we must not leak even a 503 / 404
    # signal back to a caller who couldn't authenticate. The tenant
    # binding step happens later, after we know the manifest row.
    from tex.api.auth import _extract_presented_key
    principal = None
    if _extract_presented_key(request) is not None:
        principal = authenticate_request(request)
    # else: no key presented — preserve historical unauthenticated path.

    mirror = _get_manifest_mirror(request)
    if mirror is None or getattr(mirror, "disabled", False):
        raise HTTPException(
            status_code=503,
            detail=(
                "C2PA manifest mirror is not configured for this deployment. "
                "Set DATABASE_URL and restart the service."
            ),
        )
    row = mirror.fetch_by_record_id(record_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No C2PA manifest is recorded for evidence record {record_id!r}. "
                f"The record may exist but carried no outbound artifact, or this "
                f"deployment had no C2PA emitter wired at the time the verdict "
                f"was issued."
            ),
        )

    # Now bind the (authenticated) principal's tenant to the manifest's
    # tenant. No-op when no key was presented.
    if principal is not None:
        enforce_tenant_match_optional(principal, row.get("tenant_id"))

    # Content-Type application/c2pa is the IANA-pending type for
    # Content Credentials. We return the JSON envelope + base64 claim
    # CBOR + base64 outer signature so the client can re-derive the
    # manifest without a CBOR parser if needed.
    body = {
        "schema": "tex.evidence_manifests/v1",
        "record_id": row["record_id"],
        "decision_id": row["decision_id"],
        "tenant_id": row["tenant_id"],
        "claim_sha256": row["claim_sha256"],
        "claim_cbor_b64": row["claim_cbor_b64"],
        "outer_signature_b64": row["outer_signature_b64"],
        "certificate_chain_pem": row["certificate_chain_pem"],
        "title": row["title"],
        "format": row["format"],
        "instance_id": row["instance_id"],
        "claim_generator": row["claim_generator"],
        "assertion_labels": row["assertion_labels"],
        "has_cosign": row["has_cosign"],
        "cosign_algorithm": row["cosign_algorithm"],
        "cosign_key_id": row["cosign_key_id"],
        "full_file_sha256": row["full_file_sha256"],
        "canonicalization_version": row["canonicalization_version"],
        "bound_timestamp": row["bound_timestamp"],
        "recorded_at": row["recorded_at"],
    }

    import json as _json

    return Response(
        content=_json.dumps(body).encode("utf-8"),
        media_type="application/c2pa+json",
    )


# ---------------------------------------------------------------------------
# POST /v1/c2pa/verify
# ---------------------------------------------------------------------------


class C2paVerifyRequest(BaseModel):
    """
    Verification request body.

    Two ways to supply the manifest:

      (a) ``claim_cbor_b64`` + ``outer_signature_b64`` +
          optional ``certificate_chain_pem`` — the
          ``GET /v1/evidence/{record_id}/c2pa`` response format.

      (b) ``record_id`` — look it up from the manifest mirror on
          this server.

    ``asset_bytes_b64`` is optional. When provided, the cosign's
    ``full_file_sha256`` field is checked against the SHA-256 of
    the supplied bytes (closing arxiv 2604.24890 attack #4).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str | None = Field(default=None)
    claim_cbor_b64: str | None = Field(default=None)
    outer_signature_b64: str | None = Field(default=None)
    certificate_chain_pem: str | None = Field(default=None)
    asset_bytes_b64: str | None = Field(default=None)


class C2paAttackDefenseStatus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    attack: str
    defended: bool


class C2paVerifyResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    outer_signature_valid: bool
    outer_issues: tuple[str, ...]
    outer_signing_certificate_subject: str | None = None
    outer_trust_list_anchored: bool

    cosign_present: bool
    cosign_valid: bool
    cosign_issues: tuple[str, ...]
    cosign_algorithm: str | None = None
    cosign_key_id: str | None = None
    attack_defenses: tuple[C2paAttackDefenseStatus, ...]

    # --- Thread 6 fields (Durable Content Credentials, Attestation,
    # CPSA formal verification). All optional so Thread-5-only
    # manifests continue to verify with the same response shape.
    watermark_present: bool = False
    watermark_scheme: str | None = None
    watermark_score: str | None = None
    watermark_cross_layer_consistent: bool | None = None
    watermark_issues: tuple[str, ...] = ()

    attestation_present: bool = False
    attestation_verifier: str | None = None
    attestation_user_data_bound: bool | None = None
    attestation_issues: tuple[str, ...] = ()

    formal_verification_present: bool = False
    formal_verification_all_goals_satisfied: bool | None = None
    formal_verification_goals: tuple[str, ...] = ()

    paper_reference: str = "arxiv:2604.24890"
    durable_content_credentials_reference: str = "arxiv:2603.02378, arxiv:2605.12456"
    formal_verification_reference: str = "CPSA v4.4.5 (MITRE)"


def _rebuild_manifest_from_cbor(
    *,
    claim_cbor_b64: str,
    outer_signature_b64: str,
    certificate_chain_pem: str | None,
) -> C2paManifest:
    try:
        claim_cbor = base64.b64decode(claim_cbor_b64.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"claim_cbor_b64 is not valid base64: {exc}",
        ) from exc
    try:
        decoded = cbor_decode(claim_cbor)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"claim_cbor_b64 is not valid CBOR: {exc}",
        ) from exc
    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=400,
            detail="Canonical claim CBOR must decode to a map.",
        )
    try:
        assertions = tuple(
            C2paAssertion(label=a["label"], data=a["data"])
            for a in decoded["assertions"]
        )
        claim = C2paClaim(
            title=decoded["title"],
            format=decoded["format"],
            instance_id=decoded["instance_id"],
            claim_generator=decoded["claim_generator"],
            claim_generator_info=decoded["claim_generator_info"],
            created_at=datetime.fromisoformat(decoded["created_at"]),
            assertions=assertions,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Claim CBOR structure is malformed: {exc}",
        ) from exc
    return C2paManifest(
        claim=claim,
        signature_b64=outer_signature_b64,
        certificate_chain_pem=certificate_chain_pem,
    )


@router.post(
    "/v1/c2pa/verify",
    summary="Verify a C2PA Content Credential and its Tex evidence cosign",
    response_model=C2paVerifyResponse,
)
def post_c2pa_verify(
    body: C2paVerifyRequest, request: Request
) -> C2paVerifyResponse:
    """
    Verify a manifest's outer C2PA signature AND the Tex evidence
    cosign. Reports the five-attack-defense status from
    arxiv 2604.24890.
    """
    # Resolve manifest source.
    if body.record_id is not None:
        mirror = _get_manifest_mirror(request)
        if mirror is None or getattr(mirror, "disabled", False):
            raise HTTPException(
                status_code=503,
                detail=(
                    "Cannot resolve record_id without a configured manifest "
                    "mirror. Provide claim_cbor_b64 + outer_signature_b64 "
                    "directly instead."
                ),
            )
        row = mirror.fetch_by_record_id(body.record_id)
        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"No C2PA manifest for record_id={body.record_id!r}.",
            )
        claim_cbor_b64 = row["claim_cbor_b64"]
        outer_signature_b64 = row["outer_signature_b64"]
        certificate_chain_pem = row["certificate_chain_pem"]
    else:
        if not body.claim_cbor_b64 or not body.outer_signature_b64:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Either record_id OR (claim_cbor_b64 + outer_signature_b64) "
                    "must be provided."
                ),
            )
        claim_cbor_b64 = body.claim_cbor_b64
        outer_signature_b64 = body.outer_signature_b64
        certificate_chain_pem = body.certificate_chain_pem

    manifest = _rebuild_manifest_from_cbor(
        claim_cbor_b64=claim_cbor_b64,
        outer_signature_b64=outer_signature_b64,
        certificate_chain_pem=certificate_chain_pem,
    )

    # Outer signature verification.
    outer_result = verify_manifest(manifest)

    # Asset hash binding (optional, attack #4).
    expected_full_hash: str | None = None
    if body.asset_bytes_b64:
        try:
            asset_bytes = base64.b64decode(body.asset_bytes_b64.encode("ascii"))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=f"asset_bytes_b64 is not valid base64: {exc}",
            ) from exc
        expected_full_hash = full_file_sha256(asset_bytes)

    cosign_result = verify_evidence_cosign(
        manifest,
        expected_full_file_sha256=expected_full_hash,
    )

    cosign_present = "texCosign.missing" not in cosign_result.issues

    # --- Thread 6 assertion inspection -----------------------------------
    from tex.c2pa import (
        ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
        ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
        ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
        cross_layer_audit,
    )

    watermark_data = None
    attestation_data = None
    formal_data = None
    for assertion in manifest.claim.assertions:
        if assertion.label == ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK:
            watermark_data = dict(assertion.data)
        elif assertion.label == ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION:
            attestation_data = dict(assertion.data)
        elif assertion.label == ASSERTION_LABEL_TEX_FORMAL_VERIFICATION:
            formal_data = dict(assertion.data)

    # Watermark + cross-layer audit (arxiv 2603.02378).
    watermark_present = watermark_data is not None
    watermark_scheme = None
    watermark_score = None
    watermark_cross_layer_consistent: bool | None = None
    watermark_issues: tuple[str, ...] = ()
    if watermark_data is not None:
        watermark_scheme = watermark_data.get("scheme")
        score_raw = watermark_data.get("detection_score")
        watermark_score = str(score_raw) if score_raw is not None else None
        audit = cross_layer_audit(watermark_assertion=watermark_data)
        watermark_cross_layer_consistent = audit.is_consistent
        watermark_issues = audit.issues

    # Attestation EAT JWT.
    attestation_present = attestation_data is not None
    attestation_verifier = None
    attestation_user_data_bound: bool | None = None
    attestation_issues: tuple[str, ...] = ()
    if attestation_data is not None:
        from tex.c2pa import verify_attestation_assertion

        attestation_verifier = attestation_data.get("attestation_verifier")
        expected_claim_hash = attestation_data.get("claim_cbor_sha256", "")
        att_result = verify_attestation_assertion(
            attestation_data,
            expected_claim_cbor_sha256=expected_claim_hash,
        )
        attestation_user_data_bound = att_result.user_data_bound
        attestation_issues = att_result.issues

    # Formal verification.
    formal_present = formal_data is not None
    formal_all_goals_satisfied: bool | None = None
    formal_goals: tuple[str, ...] = ()
    if formal_data is not None:
        formal_all_goals_satisfied = bool(formal_data.get("all_satisfied"))
        formal_goals = tuple(formal_data.get("all_goals", []))

    return C2paVerifyResponse(
        outer_signature_valid=outer_result.is_valid,
        outer_issues=outer_result.issues,
        outer_signing_certificate_subject=outer_result.signing_certificate_subject,
        outer_trust_list_anchored=outer_result.is_trust_list_anchored,
        cosign_present=cosign_present,
        cosign_valid=cosign_result.is_valid,
        cosign_issues=cosign_result.issues,
        cosign_algorithm=cosign_result.cosign_algorithm,
        cosign_key_id=cosign_result.cosign_key_id,
        attack_defenses=tuple(
            C2paAttackDefenseStatus(attack=attack, defended=defended)
            for attack, defended in cosign_result.defenses_satisfied
        ),
        watermark_present=watermark_present,
        watermark_scheme=watermark_scheme,
        watermark_score=watermark_score,
        watermark_cross_layer_consistent=watermark_cross_layer_consistent,
        watermark_issues=watermark_issues,
        attestation_present=attestation_present,
        attestation_verifier=attestation_verifier,
        attestation_user_data_bound=attestation_user_data_bound,
        attestation_issues=attestation_issues,
        formal_verification_present=formal_present,
        formal_verification_all_goals_satisfied=formal_all_goals_satisfied,
        formal_verification_goals=formal_goals,
    )


__all__ = [
    "router",
    "C2paVerifyRequest",
    "C2paVerifyResponse",
    "C2paAttackDefenseStatus",
]
