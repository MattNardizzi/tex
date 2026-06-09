"""
``/v1/tee`` API surface for composite TEE attestation (Thread 12).

Provides:
  * ``POST /v1/tee/verify`` — independent third-party verification of a
    composite ITA JWT. Operators (and downstream auditors / insurers /
    regulators) call this endpoint to confirm a TEE binding without
    needing to run their own ITA stack.
  * ``GET  /v1/tee/status`` — reports whether the host is TEE-capable
    (Intel TDX kernel + NVIDIA CC GPU) and whether ``TEX_TEE_MODE`` is
    active. Used by ops dashboards and by Tex's own self-attestation
    flow on startup.

Design properties
-----------------
1. Both endpoints route through the same algorithm-agile verifier in
   ``tex.tee.attestation_client.verify_attestation`` so the same code
   path that gates Tex's own evidence records is the one external
   auditors hit. Single source of trust.
2. ``POST /v1/tee/verify`` accepts an optional ``expected_measurements``
   block so RPs can pin policy (e.g. "must be Blackwell, must run
   model hash X").
3. **Authentication is required** (Wave-0 credibility floor): the router
   carries a ``RequireScope("evidence:read")`` dependency, so both
   endpoints need an authenticated principal. Both are read-only
   verification surfaces, so ``evidence:read`` is the only scope
   required. Against a keyless dev backend (no ``TEX_API_KEYS``) the
   anonymous principal carries every scope and dev workflows keep
   working. The JWT remains the bearer of trust for the *attestation*
   itself; auth is the gate on *who may ask the verifier*.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope

from tex.tee.attestation_client import (
    ExpectedMeasurements,
    verify_attestation,
)
from tex.tee.h100_attestation import is_gpu_cc_capable
from tex.tee.tdx_attestation import is_tdx_capable


__all__ = ["router"]


# Baseline: both /v1/tee/* routes require an authenticated principal
# carrying ``evidence:read``. Wired at the router level so a future
# endpoint cannot accidentally ship unauthenticated.
router = APIRouter(
    prefix="/v1/tee",
    tags=["tee"],
    dependencies=[Depends(RequireScope("evidence:read"))],
)


# --------------------------------------------------------------------------- #
# Request / response models                                                   #
# --------------------------------------------------------------------------- #


class _PinnedMeasurements(BaseModel):
    """Optional operator-pinned values for fail-closed verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tdx_mrtd: str | None = Field(
        default=None,
        max_length=128,
        description="Expected Intel TDX MRTD (initial-state measurement).",
    )
    tdx_rtmr0: str | None = Field(
        default=None,
        max_length=128,
        description="Expected Intel TDX RTMR0 (firmware/OS measurement).",
    )
    gpu_hwmodel: str | None = Field(
        default=None,
        max_length=32,
        description="Expected GPU SKU (e.g. 'GB200' to require Blackwell).",
    )
    gpu_measurement_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Expected SHA-256 over (driver|vbios|measres) triple.",
    )
    eat_ai_model_id: str | None = Field(
        default=None,
        max_length=512,
        description="Expected EAT-AI ai_model_id (URN) per "
        "draft-messous-eat-ai-01 §4.1.1.",
    )
    eat_ai_model_hash_b64: str | None = Field(
        default=None,
        max_length=256,
        description="Expected EAT-AI ai_model_hash (base64url).",
    )


class TeeVerifyRequest(BaseModel):
    """Request body for ``POST /v1/tee/verify``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    jwt: str = Field(
        min_length=20,
        max_length=64_000,
        description="The composite ITA JWT (header.payload.signature).",
    )
    expected_nonce: str = Field(
        min_length=1,
        max_length=128,
        description="The freshness nonce the JWT must be bound to. Tex "
        "derives this from the decision_id via "
        "tex.tee.decision_bound_nonce.",
    )
    expected_issuer: str | None = Field(
        default=None,
        max_length=512,
        description="Expected ITA issuer. Defaults to the production "
        "issuer ``https://portal.trustauthority.intel.com/``.",
    )
    expected_measurements: _PinnedMeasurements | None = Field(
        default=None,
        description="Optional operator-pinned expected measurements.",
    )


class TeeVerifyResponse(BaseModel):
    """Response body for ``POST /v1/tee/verify``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool = Field(description="True iff verification fully succeeded.")
    reason: str = Field(description="Stable, machine-readable status code.")
    test_mode: bool = Field(
        description="True iff the JWT was a development stub; auditors "
        "MUST refuse to honour test_mode=True for production evidence."
    )
    trustworthiness: dict[str, str] = Field(
        description="AR4SI trustworthiness vector per "
        "draft-ietf-rats-ear-03 §3."
    )
    cpu_tee_type: str | None
    gpu_tee_type: str | None
    tdx_mrtd: str | None
    gpu_measurement_sha256: str | None
    issuer: str | None
    expires_at_unix: int | None
    eat_ai_subjects: list[str] = Field(
        description="Names of EAT-AI claims that were both present "
        "AND matched operator-pinned expected values."
    )


class TeeStatusResponse(BaseModel):
    """Response body for ``GET /v1/tee/status``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tee_mode_enabled: bool
    tdx_capable: bool
    gpu_cc_capable: bool
    attestation_mode: str = Field(
        description="'production' or 'test'. Reflects "
        "``TEX_TEE_ATTESTATION_MODE``.",
    )


# --------------------------------------------------------------------------- #
# Endpoints                                                                   #
# --------------------------------------------------------------------------- #


@router.post(
    "/verify",
    response_model=TeeVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify a composite TDX+NVIDIA-GPU attestation JWT",
)
def verify(request: TeeVerifyRequest) -> TeeVerifyResponse:
    """Verify a composite ITA JWT fail-closed.

    Returns 200 with ``ok=False`` and a stable reason code on any
    verification failure. The endpoint never raises for verification
    failures — that's an audit signal, not a server error.
    """
    pinned = request.expected_measurements
    expected_obj = ExpectedMeasurements(
        tdx_mrtd=pinned.tdx_mrtd if pinned else None,
        tdx_rtmr0=pinned.tdx_rtmr0 if pinned else None,
        gpu_hwmodel=pinned.gpu_hwmodel if pinned else None,
        gpu_measurement_sha256=pinned.gpu_measurement_sha256 if pinned else None,
        eat_ai_model_id=pinned.eat_ai_model_id if pinned else None,
        eat_ai_model_hash_b64=pinned.eat_ai_model_hash_b64 if pinned else None,
    )

    result = verify_attestation(
        request.jwt,
        expected_issuer=request.expected_issuer,
        expected_nonce=request.expected_nonce,
        expected=expected_obj,
    )

    trust_dict: dict[str, str] = {
        "instance_identity": result.trustworthiness.instance_identity.value,
        "configuration": result.trustworthiness.configuration.value,
        "executables": result.trustworthiness.executables.value,
        "hardware": result.trustworthiness.hardware.value,
        "runtime_opaque": result.trustworthiness.runtime_opaque.value,
    }

    return TeeVerifyResponse(
        ok=result.ok,
        reason=result.reason,
        test_mode=result.test_mode,
        trustworthiness=trust_dict,
        cpu_tee_type=result.cpu_tee_type.value if result.cpu_tee_type else None,
        gpu_tee_type=result.gpu_tee_type.value if result.gpu_tee_type else None,
        tdx_mrtd=result.tdx_mrtd,
        gpu_measurement_sha256=result.gpu_measurement_sha256,
        issuer=result.issuer,
        expires_at_unix=result.expires_at_unix,
        eat_ai_subjects=list(result.eat_ai_subjects),
    )


@router.get(
    "/status",
    response_model=TeeStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Report TEE capabilities of this Tex host",
)
def status_endpoint() -> TeeStatusResponse:
    """Return TEE-capability status of the running Tex host.

    Used by operator dashboards and by external auditors who want to
    know whether a specific Tex deployment is producing
    hardware-rooted evidence.
    """
    import os as _os

    return TeeStatusResponse(
        tee_mode_enabled=_os.environ.get("TEX_TEE_MODE", "").strip() == "1",
        tdx_capable=is_tdx_capable(),
        gpu_cc_capable=is_gpu_cc_capable(),
        attestation_mode=_os.environ.get(
            "TEX_TEE_ATTESTATION_MODE", "production"
        ).lower(),
    )


def render_envelope_as_dict(envelope: Any) -> dict[str, Any]:
    """Helper for callers that want a stable dict shape from an envelope.

    Avoids exposing pydantic v2 internals in code that crosses module
    boundaries.
    """
    if hasattr(envelope, "model_dump"):
        return envelope.model_dump(mode="json")
    raise TypeError("envelope must be a pydantic model")
