"""
NVIDIA H100/B200/H200 GPU attestation collector.

Reads the GPU's signed attestation report from the CUDA driver via
NVIDIA Remote Attestation Service (NRAS) protocol.

Priority: P2.
"""

from __future__ import annotations


def collect_gpu_evidence() -> bytes:
    """
    TODO(P2): bind to NVIDIA Python attestation SDK (nv_attestation_sdk)
    TODO(P2): produce SPDM-compliant evidence blob
    """
    raise NotImplementedError("H100 attestation evidence collection")
