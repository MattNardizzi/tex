"""
NVIDIA H100/H200/B200/B300 GPU attestation evidence collector.

Binds to NVIDIA's ``nv_attestation_sdk`` to collect a SPDM-compliant
GPU attestation report, then forwarded by the composer to Intel Trust
Authority's ``/appraisal/v2/attest`` endpoint with
``attest_type=tdx+nvgpu``.

References
----------
* NVIDIA Attestation SDK (NVAT):
  https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/
* Blackwell CC + NVLink encryption: 590-series driver release notes
  (confirmed GA May 2026).
* arxiv 2605.03213 (May 7 2026): GPU TEE attestation is the weakest
  link in CPU-only attestation; composite CPU+GPU is required for
  production agentic AI.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

_logger = logging.getLogger(__name__)


__all__ = [
    "GpuEvidence",
    "collect_gpu_evidence",
    "is_gpu_cc_capable",
]


@dataclass(frozen=True, slots=True)
class GpuEvidence:
    """Raw NVIDIA GPU attestation evidence ready for ITA submission."""

    evidence_blob: bytes
    nonce: bytes
    hwmodel: str
    is_dev_mode: bool


def is_gpu_cc_capable() -> bool:
    """Return True iff a NVIDIA CC-mode GPU is present AND the NVIDIA
    Attestation SDK Python bindings are importable."""
    try:
        import importlib

        importlib.import_module("nv_attestation_sdk")
    except ImportError:
        return False
    except Exception:  # noqa: BLE001
        return False

    return os.path.exists("/dev/nvidiactl") or os.path.exists("/dev/nvidia0")


def collect_gpu_evidence(*, nonce: bytes) -> GpuEvidence:
    """Collect NVIDIA GPU attestation evidence for the supplied nonce.

    Production path: invokes ``nv_attestation_sdk.attestation.Attestation``
    with the local-GPU verifier. Returns SPDM evidence bytes plus the
    GPU SKU. Dev-mode fallback: deterministic stub.

    The nonce is required: production without per-decision nonce is
    vulnerable to replay per CrossGuard (arxiv 2604.23280).
    """
    if not nonce:
        raise ValueError("nonce must be non-empty for GPU attestation")

    if is_gpu_cc_capable():
        try:
            from nv_attestation_sdk import attestation  # type: ignore[import-not-found]

            client = attestation.Attestation()
            client.set_name("tex-tee-collector")
            client.set_nonce(nonce.hex())
            client.add_verifier(
                attestation.Devices.GPU,
                attestation.Environment.LOCAL,
                "",
                "",
            )
            evidence = client.get_evidence()

            if isinstance(evidence, (list, tuple)):
                joined: list[bytes] = []
                for item in evidence:
                    if isinstance(item, (bytes, bytearray)):
                        joined.append(bytes(item))
                    elif isinstance(item, str):
                        import base64

                        try:
                            joined.append(base64.b64decode(item))
                        except Exception:
                            joined.append(item.encode("utf-8"))
                evidence_bytes = b"".join(joined)
            elif isinstance(evidence, (bytes, bytearray)):
                evidence_bytes = bytes(evidence)
            else:
                raise RuntimeError(
                    f"unexpected nv_attestation_sdk evidence type: "
                    f"{type(evidence).__name__}"
                )

            hwmodel = _detect_hwmodel_or_fallback()

            return GpuEvidence(
                evidence_blob=evidence_bytes,
                nonce=nonce,
                hwmodel=hwmodel,
                is_dev_mode=False,
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"GPU evidence collection failed on capable host: {exc}"
            ) from exc

    seed = hashlib.sha256(b"tex-gpu-dev-stub" + nonce).digest()
    evidence_stub = (seed * 32)[:1024]
    return GpuEvidence(
        evidence_blob=evidence_stub,
        nonce=nonce,
        hwmodel="DEV-STUB",
        is_dev_mode=True,
    )


def _detect_hwmodel_or_fallback() -> str:
    """Best-effort GPU model detection via NVML."""
    try:
        import pynvml  # type: ignore[import-not-found]

        pynvml.nvmlInit()
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            name = pynvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            upper = name.upper()
            if "B300" in upper:
                return "GB300"
            if "B200" in upper:
                return "GB200"
            if "H200" in upper:
                return "GH200"
            if "H100" in upper:
                return "GH100"
            return name
        finally:
            pynvml.nvmlShutdown()
    except Exception:  # noqa: BLE001
        return "GH100"
