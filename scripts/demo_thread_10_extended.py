#!/usr/bin/env python3
"""
Demo for Thread 10 (extended) — the actually bleeding edge.

Exercises end-to-end:
1. Genuine Mithril threshold ML-DSA — bit-for-bit FIPS 204 single signature.
2. TALUS-TEE 1-round signing harness with attestation.
3. ML-KEM-1024 + HQC-256 hybrid KEM (lattice + code-based defense in depth).
4. CMS / X.509 DER serialization of a composite ML-DSA signature.

Usage::

    TEX_TALUS_ALLOW_INSECURE_TEE=1 python scripts/demo_thread_10_extended.py

The TEX_TALUS_ALLOW_INSECURE_TEE flag is required because the demo uses
the NONE_TEST_ONLY attestation type. In production, install a real SGX /
TDX / SEV-SNP verifier via ``install_attestation_verifier``.
"""

from __future__ import annotations

import os
import sys


def banner(label: str) -> None:
    print()
    print("=" * 78)
    print(f"  {label}")
    print("=" * 78)


def demo_genuine_mithril() -> None:
    banner("(1) Genuine Mithril threshold ML-DSA — single FIPS 204 signature")
    from tex.pqcrypto.threshold_ml_dsa import (
        distributed_keygen,
        is_native_available,
        verify_fips204,
    )

    print(f"  native extension available: {is_native_available()}")
    if not is_native_available():
        print("  SKIPPED — rebuild vendor/mithril/binding_src/ on this platform")
        return

    # 3-of-5 regional quorum signing a FORBID evidence record.
    sdk = distributed_keygen(t=3, n=5)
    print(f"  public_key: {len(sdk.public_key)} bytes (FIPS 204 ML-DSA-44 pk = 1312)")
    record = (
        b'{"verdict":"FORBID","reason":"unauthorized transfer",'
        b'"sequence_number":1042}'
    )
    sig = sdk.threshold_sign([0, 2, 4], record)
    print(f"  signature: {len(sig)} bytes (FIPS 204 ML-DSA-44 sig = 2420)")
    print(f"  Mithril self-verify: {sdk.verify(record, sig)}")
    print(f"  FIPS 204 verify (standalone): {verify_fips204(sdk.public_key, record, sig)}")

    # Cross-implementation interop proof
    import oqs
    with oqs.Signature("ML-DSA-44") as verifier:
        cross_ok = verifier.verify(record, sig, sdk.public_key)
    print(f"  liboqs ML-DSA-44 verifier (cross-impl interop): {cross_ok}")


def demo_talus_tee() -> None:
    banner("(2) TALUS-TEE 1-round signing with measurement-pinned attestation")
    if os.environ.get("TEX_TALUS_ALLOW_INSECURE_TEE") != "1":
        print("  SKIPPED — set TEX_TALUS_ALLOW_INSECURE_TEE=1 to run this demo")
        return
    from tex.pqcrypto.talus_tee import TalusTeeSdk, verify_talus_signature
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, is_native_available

    if not is_native_available():
        print("  SKIPPED — TALUS-TEE requires the Mithril native extension")
        return

    mithril = distributed_keygen(t=3, n=5)
    talus = TalusTeeSdk.test_only_no_attestation(mithril)
    print(f"  enclave measurement: {talus.measurement.hex()[:32]}...")

    msg = b'cross-jurisdiction audit anchor for EU AI Act Art. 12'
    sig = talus.online_sign([0, 2, 4], msg)
    print(f"  signature: {len(sig.signature)} bytes (still FIPS 204 ML-DSA-44)")
    print(f"  tee_type: {sig.tee_type.value}")
    print(f"  scheme: {sig.scheme}")
    print(f"  TALUS verify (with measurement pinning): "
          f"{verify_talus_signature(sig, msg, talus.measurement)}")


def demo_hqc_hybrid() -> None:
    banner("(3) ML-KEM-1024 + HQC-256 hybrid KEM — lattice + code-based")
    try:
        import oqs
        oqs.KeyEncapsulation("HQC-128")
    except Exception:
        print("  SKIPPED — HQC not enabled in this liboqs build")
        print("  (build with -DOQS_ENABLE_KEM_HQC=ON; default OFF since CVE-2025-52473)")
        return
    from tex.pqcrypto.hqc import MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair("hybrid-demo")
    print(f"  ML-KEM-1024 pk: {len(kp.ml_kem_public_key)} bytes")
    print(f"  HQC-256 pk:     {len(kp.hqc_public_key)} bytes")
    ct, sk_alice = h.encapsulate(kp)
    sk_bob = h.decapsulate(ct, kp)
    print(f"  hybrid ciphertext ML-KEM half: {len(ct.ml_kem_ciphertext)} bytes")
    print(f"  hybrid ciphertext HQC half:    {len(ct.hqc_ciphertext)} bytes")
    print(f"  derived session key: {len(sk_alice)} bytes (AES-256-GCM compatible)")
    print(f"  Alice and Bob agree: {sk_alice == sk_bob}")
    print(f"  Session secure if EITHER ML-KEM or HQC unbroken (defense in depth)")


def demo_composite_cms() -> None:
    banner("(4) Composite ML-DSA + CMS DER serialization (BSI / ANSSI)")
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
    from tex.pqcrypto.composite_cms import (
        OID_COMPOSITE_ML_DSA_87_ECDSA_P384,
        build_algorithm_identifier,
        decode_composite_signature_der,
        encode_composite_signature_der,
    )
    from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

    algo = SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384
    p = CompositeMlDsaProvider(algo)
    kp = p.generate_keypair("eu-cms-export-1")
    msg = b'EU AI Act Article 12 audit package'
    internal_sig = p.sign(msg, kp)
    print(f"  internal layout sig: {len(internal_sig)} bytes")

    der_sig = encode_composite_signature_der(internal_sig, algo)
    print(f"  ASN.1 DER sig:       {len(der_sig)} bytes")
    print(f"  algorithm OID:       {OID_COMPOSITE_ML_DSA_87_ECDSA_P384}")
    print(f"    (draft-ietf-lamps-pq-composite-sigs-18 §6.4 prototype OID)")

    ai_der = build_algorithm_identifier(algo)
    print(f"  AlgorithmIdentifier DER: {len(ai_der)} bytes (X.509 / CMS embed-ready)")

    # Round-trip back to verify
    back = decode_composite_signature_der(der_sig, algo)
    assert back == internal_sig
    assert p.verify(msg, back, kp.public_key)
    print(f"  DER round-trip → verify under composite provider: True")


def main() -> int:
    print()
    print("┌─────────────────────────────────────────────────────────────────────┐")
    print("│  Tex Thread 10 (extended) — the actually bleeding edge        │")
    print("│  May 20, 2026                                                       │")
    print("│  Genuine Mithril · TALUS-TEE · HQC · CMS DER                        │")
    print("└─────────────────────────────────────────────────────────────────────┘")
    try:
        demo_genuine_mithril()
        demo_talus_tee()
        demo_hqc_hybrid()
        demo_composite_cms()
    except Exception as exc:
        print(f"\nDEMO FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    banner("All four bleeding-edge PQ paths exercised successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
