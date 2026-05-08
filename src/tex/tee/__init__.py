"""
TEE Attestation Layer
=====================

Cryptographic proof that Tex specialist judges and the main adjudication
pipeline ran inside a hardware-attested Trusted Execution Environment.
Pairs CPU TEE (AMD SEV-SNP or Intel TDX) with GPU TEE (NVIDIA H100/B200/H200)
to produce composite attestation JWTs.

Reference
---------
- NVIDIA Confidential Computing on H100 (GA since CUDA 12.4, June 2024)
- NVIDIA Secure AI / Protected PCIe (HGX H100 8-GPU, May 2025)
- Intel Trust Authority composite attestation (TDX + NVIDIA GPU)
- AMD SEV-SNP

Performance
-----------
<7% overhead for typical LLM inference workloads, near-zero for long sequences.

Priority
--------
P2 spike — start in days 90+. Foundation for the host-independent verifiability
story for insurer / regulator buyers.
"""

from tex.tee.attestation_client import compose_attestation, verify_attestation

__all__ = ["compose_attestation", "verify_attestation"]
