"""
Composite TEE attestation client (Intel Trust Authority + NVIDIA GPU).

Public entry points:
  * ``compose_attestation(...)`` — collect CPU TEE + GPU TEE evidence,
    submit to ITA via ``ITAConnector.get_token_v2``, return
    ``CompositeAttestationEnvelope``.
  * ``verify_attestation(jwt, expected_nonce=..., expected=...)`` —
    fail-closed verification with AR4SI trustworthiness vector.
  * ``decision_bound_nonce(decision_id, request_id)`` — CrossGuard
    pattern for per-decision freshness nonce.
  * ``build_test_mode_composite_jwt(...)`` — deterministic dev-mode
    token mirroring the ITA composite token shape.

Trust model
-----------
* ITA signing certificates pinned via ``TEX_ITA_PUBLIC_KEY_PEM`` or
  ``TEX_ITA_JWKS_PATH``. No outbound network on the hot path.
* Trustworthiness vector follows draft-ietf-rats-ear-03 (Mar 15 2026).
* ``test_mode`` only honored when ``TEX_TEE_ATTESTATION_MODE=test`` AND
  payload carries ``x-tex-test-mode: true``.

Algorithm agility
-----------------
PS384/RS256/ES384/ES256 verified via ``cryptography``. ML-DSA-44/65/87
and hybrid-ml-dsa-65-ed25519 verified via
``tex.pqcrypto.algorithm_agility`` — supports a future ITA migration
to PQ signing per NIST PQC authentication roadmaps (Mar–Apr 2026).

References as of May 18 2026
----------------------------
* Intel Trust Authority composite v2 attestation:
  https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html
* ITA composite token sample:
  https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-attestation-tokens.html
* draft-messous-eat-ai-01 (Feb 23 2026)
* draft-ietf-rats-ear-03 (Mar 15 2026)
* arxiv 2605.03213 (May 7 2026)
* arxiv 2604.23280 (Apr 28 2026)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from tex.tee.composite import (
    CompositeAttestationEnvelope,
    CompositeVerificationResult,
    CompoundAttestationLink,
    CpuTeeType,
    EatAiClaims,
    GpuTeeType,
    TrustworthinessVector,
    _TrustState,
)
from tex.tee.h100_attestation import GpuEvidence, collect_gpu_evidence
from tex.tee.tdx_attestation import TdxEvidence, collect_tdx_evidence


_logger = logging.getLogger(__name__)


__all__ = [
    "compose_attestation",
    "compose_from_evidence",
    "verify_attestation",
    "decision_bound_nonce",
    "build_test_mode_composite_jwt",
    "ExpectedMeasurements",
    "ITA_PROD_ISSUER",
]


# Per Intel Trust Authority docs.
ITA_PROD_ISSUER = "https://portal.trustauthority.intel.com/"

_ENV_MODE = "TEX_TEE_ATTESTATION_MODE"
_ENV_ISSUER = "TEX_ITA_ISSUER"
_ENV_ITA_PEM = "TEX_ITA_PUBLIC_KEY_PEM"
_ENV_ITA_JWKS = "TEX_ITA_JWKS_PATH"
_ENV_ITA_API_URL = "TEX_ITA_API_URL"
_ENV_ITA_API_KEY = "TEX_ITA_API_KEY"


# --------------------------------------------------------------------------- #
# CrossGuard nonce binding (arxiv 2604.23280)                                 #
# --------------------------------------------------------------------------- #


def decision_bound_nonce(decision_id: str, request_id: str | None = None) -> str:
    """Derive a freshness nonce bound to a specific decision.

    The pattern is from CrossGuard (arxiv 2604.23280, Apr 28 2026):
    binding the attestation nonce to a unique per-operation identifier
    prevents an attacker who captures one valid JWT from replaying it
    on a different decision.
    """
    if not decision_id:
        raise ValueError("decision_id must not be blank")
    material = f"tex|{decision_id}|{request_id or ''}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# JWT parsing                                                                 #
# --------------------------------------------------------------------------- #


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _parse_jwt(jwt: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(sig_b64) if sig_b64 else b""
    return header, payload, signing_input, signature


# --------------------------------------------------------------------------- #
# Composer                                                                    #
# --------------------------------------------------------------------------- #


def compose_attestation(
    *,
    decision_id: str,
    request_id: str | None = None,
    eat_ai_claims: EatAiClaims | None = None,
    compound_link: CompoundAttestationLink | None = None,
    include_full_jwt: bool = True,
    cpu_tee_type: CpuTeeType = CpuTeeType.TDX,
    gpu_tee_type: GpuTeeType = GpuTeeType.NVIDIA_HOPPER,
) -> CompositeAttestationEnvelope:
    """Collect CPU+GPU evidence, submit to ITA, return composite envelope."""
    nonce = decision_bound_nonce(decision_id, request_id)

    upper = bytes.fromhex(nonce.ljust(64, "0"))[:32]
    lower = hashlib.sha256(upper).digest()
    user_data = upper + lower

    tdx_ev = collect_tdx_evidence(user_data=user_data)
    gpu_ev = collect_gpu_evidence(nonce=user_data)

    return compose_from_evidence(
        tdx_evidence=tdx_ev,
        gpu_evidence=gpu_ev,
        decision_id=decision_id,
        request_id=request_id,
        eat_ai_claims=eat_ai_claims,
        compound_link=compound_link,
        include_full_jwt=include_full_jwt,
        cpu_tee_type=cpu_tee_type,
        gpu_tee_type=gpu_tee_type,
    )


def compose_from_evidence(
    *,
    tdx_evidence: TdxEvidence,
    gpu_evidence: GpuEvidence,
    decision_id: str,
    request_id: str | None = None,
    eat_ai_claims: EatAiClaims | None = None,
    compound_link: CompoundAttestationLink | None = None,
    include_full_jwt: bool = True,
    cpu_tee_type: CpuTeeType = CpuTeeType.TDX,
    gpu_tee_type: GpuTeeType = GpuTeeType.NVIDIA_HOPPER,
) -> CompositeAttestationEnvelope:
    """Lower-level composer for callers that already have evidence."""
    nonce = decision_bound_nonce(decision_id, request_id)

    is_dev = tdx_evidence.is_dev_mode or gpu_evidence.is_dev_mode
    mode = os.environ.get(_ENV_MODE, "production").lower()

    if is_dev:
        if mode != "test":
            raise RuntimeError(
                "TEE composition called with dev-stub evidence in "
                "production mode; refusing to emit. Set "
                "TEX_TEE_ATTESTATION_MODE=test for development."
            )
        jwt = build_test_mode_composite_jwt(
            tdx_evidence=tdx_evidence,
            gpu_evidence=gpu_evidence,
            nonce=nonce,
            eat_ai_claims=eat_ai_claims,
        )
    else:
        jwt = _request_ita_composite_token(
            tdx_evidence=tdx_evidence,
            gpu_evidence=gpu_evidence,
            nonce=nonce,
            eat_ai_claims=eat_ai_claims,
        )

    _header, payload, _signing_input, _sig = _parse_jwt(jwt)
    jwt_sha256 = hashlib.sha256(jwt.encode("utf-8")).hexdigest()

    tdx_block = payload.get("tdx") or {}
    nvgpu_block = payload.get("nvgpu") or {}

    gpu_meas = _extract_gpu_measurement(nvgpu_block)
    gpu_overall = bool(
        nvgpu_block.get("measres") == "comparison-successful"
        and nvgpu_block.get("x-nvidia-attestation-detailed-result", {}).get(
            "x-nvidia-gpu-attestation-report-signature-verified", False
        )
    )

    return CompositeAttestationEnvelope(
        ita_jwt=jwt if include_full_jwt else None,
        ita_jwt_sha256=jwt_sha256,
        issuer=str(payload.get("iss") or ""),
        nonce=nonce,
        cpu_tee_type=cpu_tee_type,
        tdx_mrtd=tdx_block.get("tdx_mrtd"),
        tdx_rtmr0=tdx_block.get("tdx_rtmr0"),
        tdx_tcb_status=tdx_block.get("attester_tcb_status"),
        tdx_is_debuggable=tdx_block.get("tdx_is_debuggable"),
        gpu_tee_type=gpu_tee_type,
        gpu_measurement_sha256=gpu_meas,
        gpu_hwmodel=nvgpu_block.get("hwmodel"),
        gpu_driver_version=nvgpu_block.get("x-nvidia-gpu-driver-version"),
        gpu_overall_result=gpu_overall,
        eat_ai=eat_ai_claims,
        compound_link=compound_link,
        test_mode=is_dev,
        ita_attest_type="tdx+nvgpu",
    )


def _extract_gpu_measurement(nvgpu_block: dict[str, Any]) -> str | None:
    driver = nvgpu_block.get("x-nvidia-gpu-driver-version") or ""
    vbios = nvgpu_block.get("x-nvidia-gpu-vbios-version") or ""
    measres = nvgpu_block.get("measres") or ""
    if not any((driver, vbios, measres)):
        return None
    payload = f"{driver}|{vbios}|{measres}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _request_ita_composite_token(
    *,
    tdx_evidence: TdxEvidence,
    gpu_evidence: GpuEvidence,
    nonce: str,
    eat_ai_claims: EatAiClaims | None,
) -> str:
    """Submit composite evidence to ITA, return JWT. Production path only."""
    api_url = os.environ.get(_ENV_ITA_API_URL)
    api_key = os.environ.get(_ENV_ITA_API_KEY)
    if not (api_url and api_key):
        raise RuntimeError(
            "ITA submission requires TEX_ITA_API_URL and TEX_ITA_API_KEY"
        )

    try:
        from inteltrustauthorityclient.connector.connector import (  # type: ignore[import-not-found]
            ITAConnector,
        )
        from inteltrustauthorityclient.connector.config import (  # type: ignore[import-not-found]
            Config,
            RetryConfig,
        )
        from inteltrustauthorityclient.connector.evidence import (  # type: ignore[import-not-found]
            Evidence,
            EvidenceType,
        )
    except ImportError as exc:
        raise RuntimeError(
            "inteltrustauthorityclient is not installed; cannot request "
            "production ITA token"
        ) from exc

    config = Config(
        retry_cfg=RetryConfig(retry_wait_min=1, retry_wait_max=5, retry_max=3),
        url=api_url,
        api_url=api_url,
        api_key=api_key,
    )
    connector = ITAConnector(config)

    tdx_arg = Evidence(
        type=EvidenceType.TDX,
        evidence=tdx_evidence.quote,
        user_data=tdx_evidence.user_data,
        runtime_data=None,
    )
    gpu_arg = Evidence(
        type=EvidenceType.NVGPU,
        evidence=gpu_evidence.evidence_blob,
        user_data=None,
        runtime_data=None,
    )

    if eat_ai_claims is not None:
        eat_ai_bytes = json.dumps(
            eat_ai_claims.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        tdx_arg = Evidence(
            type=EvidenceType.TDX,
            evidence=tdx_evidence.quote,
            user_data=tdx_evidence.user_data,
            runtime_data=eat_ai_bytes,
        )

    try:
        response = connector.get_token_v2(tdx_args=tdx_arg, gpu_args=gpu_arg)
        token = getattr(response, "token", None) or getattr(response, "Token", None)
        if not token or not isinstance(token, str):
            raise RuntimeError("ITA returned an empty or invalid token")
        return token
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"ITA composite attestation failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# Test-mode composite JWT                                                     #
# --------------------------------------------------------------------------- #


def build_test_mode_composite_jwt(
    *,
    tdx_evidence: TdxEvidence,
    gpu_evidence: GpuEvidence,
    nonce: str,
    eat_ai_claims: EatAiClaims | None = None,
    ttl_seconds: int = 3600,
) -> str:
    """Build a deterministic test-mode JWT mirroring the ITA composite shape."""
    issuer = os.environ.get(_ENV_ISSUER, ITA_PROD_ISSUER)
    now = int(time.time())

    tdx_mrtd = hashlib.sha256(b"mrtd|" + tdx_evidence.quote).hexdigest() + ("0" * 32)
    tdx_rtmr0 = hashlib.sha256(b"rtmr0|" + tdx_evidence.quote).hexdigest() + ("0" * 32)
    gpu_meas_hash = hashlib.sha256(
        b"gpu|" + gpu_evidence.evidence_blob
    ).hexdigest()

    header = {
        "alg": "none",
        "typ": "JWT",
        "kid": "tex-test-mode-composite",
    }
    payload: dict[str, Any] = {
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": f"tex-test-{nonce[:16]}",
        "ver": "2.0.0",
        "appraisal": {"method": "default", "ver": 2},
        "eat_profile": (
            "https://portal.trustauthority.intel.com/eat_profile.html"
        ),
        "intuse": "generic",
        "tdx": {
            "attester_type": "TDX",
            "attester_tcb_status": "UpToDate",
            "attester_tcb_date": "2026-02-11T00:00:00Z",
            "tdx_mrtd": tdx_mrtd,
            "tdx_rtmr0": tdx_rtmr0,
            "tdx_rtmr1": "0" * 96,
            "tdx_rtmr2": "0" * 96,
            "tdx_rtmr3": "0" * 96,
            "tdx_is_debuggable": False,
            "tdx_is_migratable": False,
            "tdx_seamsvn": 269,
            "tdx_report_data": (
                tdx_evidence.user_data.hex() if tdx_evidence.user_data else "0" * 128
            ),
        },
        "nvgpu": {
            "sub": "NVIDIA-GPU-ATTESTATION",
            "iss": "https://nras.attestation.nvidia.com",
            "attester_type": "NVGPU",
            "dbgstat": "disabled",
            "eat_nonce": nonce,
            "hwmodel": gpu_evidence.hwmodel,
            "measres": "comparison-successful",
            "oemid": "5703",
            "secboot": True,
            "ueid": gpu_meas_hash,
            "x-nvidia-attestation-type": "GPU",
            "x-nvidia-attestation-detailed-result": {
                "x-nvidia-gpu-arch-check": True,
                "x-nvidia-gpu-attestation-report-cert-chain-validated": True,
                "x-nvidia-gpu-attestation-report-parsed": True,
                "x-nvidia-gpu-attestation-report-signature-verified": True,
                "x-nvidia-gpu-driver-rim-cert-validated": True,
                "x-nvidia-gpu-driver-rim-driver-measurements-available": True,
                "x-nvidia-gpu-driver-rim-schema-fetched": True,
                "x-nvidia-gpu-driver-rim-schema-validated": True,
                "x-nvidia-gpu-driver-rim-signature-verified": True,
                "x-nvidia-gpu-measurements-match": True,
                "x-nvidia-gpu-nonce-match": True,
                "x-nvidia-gpu-vbios-rim-cert-validated": True,
                "x-nvidia-gpu-vbios-rim-measurements-available": True,
                "x-nvidia-gpu-vbios-rim-schema-fetched": True,
                "x-nvidia-gpu-vbios-rim-schema-validated": True,
                "x-nvidia-gpu-vbios-rim-signature-verified": True,
            },
            "x-nvidia-gpu-driver-version": "570.158.01",
            "x-nvidia-gpu-manufacturer": "NVIDIA Corporation",
            "x-nvidia-gpu-vbios-version": "96.00.74.00.1C",
        },
        "x-tex-test-mode": True,
    }

    if eat_ai_claims is not None:
        eat_ai_json = eat_ai_claims.model_dump(mode="json")
        compact = {k: v for k, v in eat_ai_json.items() if v not in (None, (), [])}
        payload["eat_ai"] = compact

    header_b64 = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    return f"{header_b64}.{payload_b64}."


# --------------------------------------------------------------------------- #
# Verifier                                                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ExpectedMeasurements:
    """Operator-pinned expected measurements for verification."""

    tdx_mrtd: str | None = None
    tdx_rtmr0: str | None = None
    gpu_hwmodel: str | None = None
    gpu_measurement_sha256: str | None = None
    eat_ai_model_id: str | None = None
    eat_ai_model_hash_b64: str | None = None


def verify_attestation(
    jwt: str,
    *,
    expected_issuer: str | None = None,
    expected_nonce: str,
    expected: ExpectedMeasurements | None = None,
) -> CompositeVerificationResult:
    """Verify a composite ITA JWT fail-closed."""
    mode = os.environ.get(_ENV_MODE, "production").lower()
    is_test_env = mode == "test"
    expected_issuer = expected_issuer or os.environ.get(_ENV_ISSUER, ITA_PROD_ISSUER)
    expected_measurements = expected or ExpectedMeasurements()

    # 1. Parse
    try:
        header, payload, signing_input, signature = _parse_jwt(jwt)
    except Exception as exc:  # noqa: BLE001
        return _fail("parse_error", str(exc))

    alg = str(header.get("alg", "")).strip()
    is_test_token = bool(payload.get("x-tex-test-mode"))

    # 2. alg=none gate
    if alg == "none":
        if not is_test_env:
            return _fail("test_mode_in_prod", "alg=none rejected in production")
        if not is_test_token:
            return _fail("alg_none_without_marker", "alg=none without test-mode marker")
    elif is_test_token and not is_test_env:
        return _fail("test_mode_in_prod", "x-tex-test-mode=true in production")

    # 3. Issuer
    iss = str(payload.get("iss") or "")
    if iss != expected_issuer:
        return _fail("issuer_mismatch", f"got iss={iss!r}")

    # 4. Nonce
    if not _nonce_matches(payload, expected_nonce):
        return _fail("nonce_mismatch", "nonce not present or did not match")

    # 5. Expiry
    exp_claim = payload.get("exp")
    if isinstance(exp_claim, (int, float)):
        if time.time() > float(exp_claim):
            return _fail("expired", f"exp={int(exp_claim)} < now")

    # 6. TDX debuggable
    tdx_block = payload.get("tdx") or {}
    if tdx_block.get("tdx_is_debuggable") is True:
        return _fail("tdx_debuggable", "TD is in debug mode")

    # 7. TCB status
    tcb = tdx_block.get("attester_tcb_status")
    if tcb in {"OutOfDate", "OutOfDateConfigurationNeeded", "Revoked"}:
        return _fail("tcb_out_of_date", f"tcb_status={tcb!r}")

    # 8. GPU result
    nvgpu_block = payload.get("nvgpu") or {}
    measres = nvgpu_block.get("measres")
    detail = nvgpu_block.get("x-nvidia-attestation-detailed-result", {})
    if measres != "comparison-successful":
        return _fail("gpu_measres_failed", f"measres={measres!r}")
    if not detail.get("x-nvidia-gpu-attestation-report-signature-verified"):
        return _fail("gpu_signature_unverified", "ITA reported sig not verified")

    # 9. EAT-AI claims (optional)
    eat_ai_claim_block = payload.get("eat_ai") or {}
    verified_eat_ai: list[str] = []
    if expected_measurements.eat_ai_model_id is not None:
        if eat_ai_claim_block.get("ai_model_id") != expected_measurements.eat_ai_model_id:
            return _fail(
                "eat_ai_model_id_mismatch",
                f"got ai_model_id={eat_ai_claim_block.get('ai_model_id')!r}",
            )
        verified_eat_ai.append("ai_model_id")

    if expected_measurements.eat_ai_model_hash_b64 is not None:
        observed = eat_ai_claim_block.get("ai_model_hash") or {}
        observed_hash = observed.get("hash_b64") if isinstance(observed, dict) else None
        if observed_hash != expected_measurements.eat_ai_model_hash_b64:
            return _fail("eat_ai_model_hash_mismatch", "ai_model_hash mismatch")
        verified_eat_ai.append("ai_model_hash")

    # 10. Pinned measurements
    if expected_measurements.tdx_mrtd is not None:
        if tdx_block.get("tdx_mrtd") != expected_measurements.tdx_mrtd:
            return _fail("tdx_mrtd_mismatch", "operator-pinned MRTD mismatch")
    if expected_measurements.tdx_rtmr0 is not None:
        if tdx_block.get("tdx_rtmr0") != expected_measurements.tdx_rtmr0:
            return _fail("tdx_rtmr0_mismatch", "RTMR0 mismatch")
    if expected_measurements.gpu_hwmodel is not None:
        if nvgpu_block.get("hwmodel") != expected_measurements.gpu_hwmodel:
            return _fail(
                "gpu_hwmodel_mismatch",
                f"got hwmodel={nvgpu_block.get('hwmodel')!r}",
            )

    # 11. Signature (production only)
    if alg != "none":
        ok, reason = _verify_signature(
            alg=alg,
            signing_input=signing_input,
            signature=signature,
        )
        if not ok and not is_test_env:
            return _fail("signature_invalid", reason)

    vector = _build_trust_vector(
        tdx_block=tdx_block,
        nvgpu_block=nvgpu_block,
        nvgpu_detail=detail,
        eat_ai_verified=bool(verified_eat_ai),
    )

    cpu_type = CpuTeeType.TDX if tdx_block else CpuTeeType.SEV_SNP
    gpu_type = _gpu_type_from_hwmodel(nvgpu_block.get("hwmodel"))

    return CompositeVerificationResult(
        ok=True,
        reason="ok_test_mode" if (is_test_env and is_test_token) else "ok",
        test_mode=bool(is_test_env and is_test_token),
        trustworthiness=vector,
        cpu_tee_type=cpu_type,
        gpu_tee_type=gpu_type,
        tdx_mrtd=tdx_block.get("tdx_mrtd"),
        gpu_measurement_sha256=_extract_gpu_measurement(nvgpu_block),
        issuer=iss,
        expires_at_unix=int(exp_claim) if isinstance(exp_claim, (int, float)) else None,
        eat_ai_subjects=tuple(verified_eat_ai),
    )


def _nonce_matches(payload: dict[str, Any], expected: str) -> bool:
    candidates = (
        (payload.get("nvgpu") or {}).get("eat_nonce"),
        payload.get("eat_nonce"),
        payload.get("verifier_nonce"),
    )
    return expected in {c for c in candidates if isinstance(c, str)}


def _gpu_type_from_hwmodel(hwmodel: str | None) -> GpuTeeType:
    if not isinstance(hwmodel, str):
        return GpuTeeType.NVIDIA_HOPPER
    upper = hwmodel.upper()
    if upper.startswith("GB"):
        return GpuTeeType.NVIDIA_BLACKWELL
    return GpuTeeType.NVIDIA_HOPPER


def _build_trust_vector(
    *,
    tdx_block: dict[str, Any],
    nvgpu_block: dict[str, Any],
    nvgpu_detail: dict[str, Any],
    eat_ai_verified: bool,
) -> TrustworthinessVector:
    """Map raw ITA claims to AR4SI trustworthiness axes."""

    chain_ok = bool(nvgpu_detail.get("x-nvidia-gpu-attestation-report-cert-chain-validated"))
    identity = _TrustState.AFFIRMING if chain_ok else _TrustState.WARNING

    config_axis: _TrustState
    if tdx_block.get("tdx_is_debuggable") is True:
        config_axis = _TrustState.CONTRAINDICATED
    elif tdx_block.get("attester_tcb_status") == "UpToDate":
        config_axis = _TrustState.AFFIRMING
    elif tdx_block.get("attester_tcb_status") in {
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded",
    }:
        config_axis = _TrustState.WARNING
    else:
        config_axis = _TrustState.NONE

    exe_match = bool(nvgpu_detail.get("x-nvidia-gpu-measurements-match"))
    if exe_match and eat_ai_verified:
        exe_axis = _TrustState.AFFIRMING
    elif exe_match:
        exe_axis = _TrustState.AFFIRMING
    else:
        exe_axis = _TrustState.CONTRAINDICATED

    hw_ok = bool(
        nvgpu_detail.get("x-nvidia-gpu-attestation-report-cert-chain-validated")
        and nvgpu_detail.get("x-nvidia-gpu-attestation-report-signature-verified")
    )
    hw_axis = _TrustState.AFFIRMING if hw_ok else _TrustState.CONTRAINDICATED

    secboot = bool(nvgpu_block.get("secboot"))
    opaque_axis = (
        _TrustState.AFFIRMING
        if secboot and tdx_block.get("tdx_is_debuggable") is False
        else _TrustState.WARNING
    )

    return TrustworthinessVector(
        instance_identity=identity,
        configuration=config_axis,
        executables=exe_axis,
        hardware=hw_axis,
        runtime_opaque=opaque_axis,
    )


def _verify_signature(
    *,
    alg: str,
    signing_input: bytes,
    signature: bytes,
) -> tuple[bool, str]:
    """Verify a JWT signature with algorithm-agile crypto."""
    pem_str = os.environ.get(_ENV_ITA_PEM, "").strip()
    jwks_path = os.environ.get(_ENV_ITA_JWKS, "").strip()

    if not (pem_str or jwks_path):
        return False, "no_ita_public_key_configured"

    public_key_pem: str | None = None
    if pem_str:
        public_key_pem = pem_str
    elif jwks_path:
        try:
            with open(jwks_path, "r", encoding="utf-8") as fp:
                jwks = json.load(fp)
            public_key_pem = _jwks_to_pem(jwks)
        except Exception as exc:  # noqa: BLE001
            return False, f"jwks_load_error:{exc}"

    if public_key_pem is None:
        return False, "no_resolved_key"

    # ML-DSA paths via tex.pqcrypto.algorithm_agility
    if alg.lower() in {"ml-dsa-65", "ml-dsa-87", "ml-dsa-44"}:
        try:
            from tex.pqcrypto.algorithm_agility import (
                SignatureAlgorithm,
                get_signature_provider,
            )

            alg_map = {
                "ml-dsa-44": SignatureAlgorithm.ML_DSA_44,
                "ml-dsa-65": SignatureAlgorithm.ML_DSA_65,
                "ml-dsa-87": SignatureAlgorithm.ML_DSA_87,
            }
            provider = get_signature_provider(alg_map[alg.lower()])
            ok = provider.verify(signing_input, signature, public_key_pem.encode("utf-8"))
            return (True, "") if ok else (False, "ml_dsa_signature_invalid")
        except Exception as exc:  # noqa: BLE001
            return False, f"ml_dsa_provider_error:{exc}"

    if alg.lower() == "hybrid-ml-dsa-65-ed25519":
        try:
            from tex.pqcrypto.algorithm_agility import (
                SignatureAlgorithm,
                get_signature_provider,
            )

            provider = get_signature_provider(
                SignatureAlgorithm.HYBRID_ML_DSA_ED25519
            )
            ok = provider.verify(signing_input, signature, public_key_pem.encode("utf-8"))
            return (True, "") if ok else (False, "hybrid_signature_invalid")
        except Exception as exc:  # noqa: BLE001
            return False, f"hybrid_provider_error:{exc}"

    # Classical algorithms (ITA's current PS384/RS256/ES384/ES256)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )

        pem_bytes = public_key_pem.encode("utf-8")
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
            public_key = cert.public_key()
        except Exception:
            public_key = serialization.load_pem_public_key(pem_bytes)

        if alg == "PS384":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "ps384_requires_rsa_key"
            public_key.verify(
                signature,
                signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA384(),
            )
            return True, ""

        if alg == "RS256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "rs256_requires_rsa_key"
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True, ""

        if alg in {"ES384", "ES256"}:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False, f"{alg.lower()}_requires_ec_key"
            sig_len = len(signature)
            if sig_len % 2 != 0:
                return False, "ecdsa_odd_signature_length"
            half = sig_len // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            der_sig = encode_dss_signature(r, s)
            hash_alg = hashes.SHA384() if alg == "ES384" else hashes.SHA256()
            public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))
            return True, ""

        return False, f"unsupported_alg:{alg}"
    except Exception as exc:  # noqa: BLE001
        return False, f"signature_invalid:{exc}"


def _jwks_to_pem(jwks: dict[str, Any]) -> str:
    """Convert the first RSA key in a JWKS dict to PEM."""
    keys = jwks.get("keys") or []
    if not keys:
        raise ValueError("JWKS has no keys")
    rsa_keys = [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"]
    if not rsa_keys:
        raise ValueError("JWKS has no RSA keys")
    key = rsa_keys[0]
    n_bytes = _b64url_decode(str(key["n"]))
    e_bytes = _b64url_decode(str(key["e"]))
    n_int = int.from_bytes(n_bytes, "big")
    e_int = int.from_bytes(e_bytes, "big")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
    public_key = public_numbers.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def _fail(code: str, _detail: str) -> CompositeVerificationResult:
    return CompositeVerificationResult(
        ok=False,
        reason=code,
        test_mode=False,
        trustworthiness=TrustworthinessVector(
            instance_identity=_TrustState.NONE,
            configuration=_TrustState.NONE,
            executables=_TrustState.NONE,
            hardware=_TrustState.CONTRAINDICATED,
            runtime_opaque=_TrustState.NONE,
        ),
    )
