"""
Composite TEE attestation client.

Calls Intel Trust Authority (or AMD KDS) to produce a JWT containing:
  - CPU TEE measurement (TDX or SEV-SNP)
  - GPU TEE measurement (NVIDIA H100/B200/H200)
  - Tex software-stack measurements

Priority: P2.
"""

from __future__ import annotations


def compose_attestation(*, cpu_tee_evidence: bytes, gpu_tee_evidence: bytes) -> str:
    """
    TODO(P2): call Intel Trust Authority /appraisal/v2/attest endpoint
    TODO(P2): return JWT with intel_tee + nvidia_gpu sub-objects
    """
    raise NotImplementedError("composite TEE attestation")


def verify_attestation(jwt_token: str, *, expected_pcr_set: tuple[str, ...]) -> bool:
    """
    TODO(P2): verify JWT signature against ITA/AMD root certs
    TODO(P2): check measurements against expected PCR/MR set
    TODO(P2): check CRL / freshness
    """
    raise NotImplementedError("TEE attestation verification")
