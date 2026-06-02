#!/usr/bin/env python3
"""
Demo for Thread 10 — full post-quantum cryptography stack.

Exercises end-to-end:
1. ML-KEM-1024 encap/decap (CNSA 2.0 Level 5 KEM)
2. SLH-DSA-256s sign/verify with fault countermeasure (CNSA 2.0 code signing)
3. Threshold ML-DSA-87 quorum signing (3-of-5) on a FORBID evidence record
4. Composite ML-DSA-87 + ECDSA-P384 (BSI / ANSSI compliance composite)

Usage:
    python scripts/demo_thread_10.py
"""

from __future__ import annotations

import sys


def banner(label: str) -> None:
    print()
    print("=" * 78)
    print(f"  {label}")
    print("=" * 78)


def demo_ml_kem() -> None:
    banner("(1) ML-KEM-1024 confidential session key — CNSA 2.0 Level 5 KEM")
    from tex.pqcrypto.ml_kem import KemAlgorithm, MlKemProvider

    server = MlKemProvider(KemAlgorithm.ML_KEM_1024)
    sk = server.generate_keypair("agent-server")
    print(f"  server pk: {len(sk.public_key)} bytes (FIPS 203 §8 = 1568)")
    ct, ss_client = server.encapsulate(sk.public_key)
    ss_server = server.decapsulate(ct, sk.private_key)
    print(f"  ciphertext: {len(ct)} bytes  shared_secret: {len(ss_client)} bytes")
    print(f"  client_ss == server_ss: {ss_client == ss_server}")


def demo_slh_dsa() -> None:
    banner("(2) SLH-DSA-256s software signing with fault countermeasure")
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
    from tex.pqcrypto.slh_dsa import SlhDsaProvider

    p = SlhDsaProvider(SignatureAlgorithm.SLH_DSA_256S)  # CNSA 2.0 code signing
    kp = p.generate_keypair("tex-release-v1.16.0")
    artifact = b"# Tex v1.16.0 release binary (placeholder)"
    sig = p.sign(artifact, kp)
    print(f"  signature: {len(sig)} bytes (FIPS 205 §11 = 29792)")
    print(f"  verify:    {p.verify(artifact, sig, kp.public_key)}")
    print(f"  fault_check ran: {p.fault_check}")


def demo_threshold_quorum() -> None:
    banner("(3) Threshold ML-DSA-87 — 3-of-5 quorum on a FORBID evidence record")
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
    from tex.pqcrypto.evidence_quorum import (
        quorum_sign_evidence_record,
        serialize_quorum_signature,
        verify_quorum_evidence_signature,
    )
    from tex.pqcrypto.threshold_ml_dsa import ThresholdMlDsaProvider

    provider = ThresholdMlDsaProvider(SignatureAlgorithm.THRESHOLD_ML_DSA_87)
    keyset = provider.distributed_keygen(
        n=5, k=3,
        member_ids=["us-east", "us-west", "eu-central", "ap-south", "sa-east"],
    )
    print(f"  descriptor commitment: {keyset.descriptor.commitment[:16]}...")
    record = {
        "event_id": "evt-2026-0520-forbid-demo",
        "verdict": "FORBID",
        "reason": "agent attempted unauthorized wire transfer",
        "severity": "critical",
        "sequence_number": 1042,
        "timestamp": "2026-05-20T17:00:00+00:00",
    }
    qs = quorum_sign_evidence_record(record, keyset)
    print(f"  partials signed: {len(qs.partials)} of k={keyset.descriptor.k}")
    print(f"  signing members: {[p.member_id for p in qs.partials]}")
    ok = verify_quorum_evidence_signature(record, qs, keyset.descriptor)
    print(f"  quorum verify:   {ok}")

    embedded = serialize_quorum_signature(qs, keyset.descriptor)
    print(f"  serialized payload size: ~{len(str(embedded))} bytes JSON")


def demo_composite() -> None:
    banner("(4) Composite ML-DSA-87 + ECDSA-P384 (BSI / ANSSI compliance)")
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
    from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

    p = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384)
    kp = p.generate_keypair("eu-deployment-1")
    msg = b"cross-jurisdiction audit anchor"
    sig = p.sign(msg, kp)
    print(f"  signature: {len(sig)} bytes (ML-DSA-87 + ECDSA-P384)")
    print(f"  verify:    {p.verify(msg, sig, kp.public_key)}")
    print(f"  bit-flipped ML-DSA half rejected: "
          f"{not p.verify(msg, sig[:5] + bytes([sig[5] ^ 0x01]) + sig[6:], kp.public_key)}")


def main() -> int:
    print()
    print("┌─────────────────────────────────────────────────────────────────────┐")
    print("│  Tex Thread 10 — Post-Quantum Cryptography Wave demo          │")
    print("│  May 20, 2026 — bleeding-edge frontier for AI governance evidence   │")
    print("└─────────────────────────────────────────────────────────────────────┘")
    try:
        demo_ml_kem()
        demo_slh_dsa()
        demo_threshold_quorum()
        demo_composite()
    except Exception as exc:  # pragma: no cover
        print(f"\nDEMO FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    banner("All four PQ paths exercised successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
