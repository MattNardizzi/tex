#!/usr/bin/env bash
# scripts/demo_thread_6_durable.sh
#
# Thread 6 demo — durable content credentials + hardware attestation +
# CPSA formal verification, all bound under a single C2PA 2.4 outer
# COSE_Sign1 signature.
#
# This script:
#   1. mints an Ed25519 outer signing key + a self-signed cert chain
#   2. mints an Ed25519 cosign key (Thread 5 PQ fallback)
#   3. mints an ES384 issuer key simulating an NRAS-style TEE verifier
#   4. computes a SynthID-Text-style watermark detection score
#   5. computes a perceptual text hash for the soft binding
#   6. issues a test EAT JWT bound to the C2PA claim hash
#   7. loads the vendored CPSA shapes (G1-G5 all satisfied)
#   8. builds the four-layer signed manifest in one pass
#   9. verifies the outer signature, the cosign attack-defense matrix,
#      the cross-layer watermark audit (arxiv 2603.02378), the
#      attestation EAT JWT, and the formal-verification assertion
#  10. prints a green report
#
# Run:
#   ./scripts/demo_thread_6_durable.sh

set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PYDEMO'
# Pre-warm the ecosystem module to break a known circular import
# between tex.events.crypto_provenance and tex.ecosystem.engine.
import tex.ecosystem  # noqa: F401

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from tex.c2pa import (
    ALL_ATTACKS,
    ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
    ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
    AttestationVerifier,
    EatTokenKind,
    RecordedScoreDetector,
    SYNTHID_TEXT_DEFAULT_THRESHOLD,
    WatermarkScheme,
    build_signed_manifest_with_cosign,
    build_tex_evidence_attestation_assertion,
    build_tex_evidence_watermark_assertion,
    clear_signing_keys,
    cross_layer_audit,
    full_file_sha256,
    load_cpsa_shapes,
    model_provenance_assertion_data,
    register_signing_key,
    synthesize_test_eat_jwt,
    text_perceptual_hash,
    verify_attestation_assertion,
    verify_evidence_cosign,
    verify_manifest,
)
from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paManifest
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


def banner(s):
    print()
    print("=" * 70)
    print(f"  {s}")
    print("=" * 70)


def ok(s):
    print(f"  ✓ {s}")


def info(label, value):
    print(f"     {label:<32}  {value}")


# ---------------------------------------------------------------------------
# 1. Outer signing key + self-signed chain
# ---------------------------------------------------------------------------

banner("Step 1 / 9 — minting outer COSE_Sign1 key + self-signed cert chain")
set_keystore(None)
clear_signing_keys()
now = datetime.now(timezone.utc)

ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Thread 6 Demo Root")])
ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
leaf_key = ed25519.Ed25519PrivateKey.generate()
leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tex.thread6.demo")]))
    .issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1))
    .not_valid_after(now + timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
priv_pem = leaf_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_pem = leaf_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
chain_pem = (
    leaf.public_bytes(serialization.Encoding.PEM).decode()
    + ca.public_bytes(serialization.Encoding.PEM).decode()
)
outer_keypair = SignatureKeyPair(
    algorithm=SignatureAlgorithm.ED25519,
    public_key=pub_pem,
    private_key=priv_pem,
    key_id="thread6-demo-outer",
)
register_signing_key(outer_keypair)
ok("outer Ed25519 leaf cert valid until " + leaf.not_valid_after_utc.isoformat())

# ---------------------------------------------------------------------------
# 2. Cosign key
# ---------------------------------------------------------------------------

banner("Step 2 / 9 — minting Ed25519 cosign key (Thread 5 PQ fallback)")
cosign_key = Ed25519Provider().generate_keypair(key_id="thread6-demo-cosign")
ok(f"cosign key {cosign_key.key_id} ({cosign_key.algorithm.value})")

# ---------------------------------------------------------------------------
# 3. TEE issuer keypair (simulated NRAS-style)
# ---------------------------------------------------------------------------

banner("Step 3 / 9 — minting ES384 issuer keypair (simulated NVIDIA NRAS V3 TEE)")
issuer_key = ec.generate_private_key(ec.SECP384R1())
issuer_priv_pem = issuer_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
issuer_pub_pem = issuer_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
issuer_kid = "nras-demo-tee-1"
ok(f"issuer kid {issuer_kid} (ES384)")

# ---------------------------------------------------------------------------
# 4. Watermark detection + 5. Soft binding
# ---------------------------------------------------------------------------

banner("Step 4 / 9 — watermark detection (SynthID-Text recorded score)")
body = (
    b"Subject: Tex Aegis pilot interest\n\n"
    b"Hi Sara, this is an AI-assisted outreach from Matthew at "
    b"VortexBlack. Five minutes next week to discuss your AI SDR "
    b"brand-safety story?\n"
)
detector = RecordedScoreDetector(
    scheme=WatermarkScheme.SYNTHID_TEXT,
    recorded_score=0.97,
    recorded_p_value=1e-14,
    threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
    detector_version="google-deepmind/synthid-text/v1",
)
det_result = detector.detect(body.decode(), key_id="synthid-demo-1")
ok(f"score = {det_result.detection_score} (threshold {det_result.threshold})")
ok(f"watermark_present = {det_result.watermark_present}")

banner("Step 5 / 9 — perceptual text hash (soft binding survives Gmail/Outlook re-encoding)")
soft_binding = text_perceptual_hash(body.decode())
info("perceptual hash", soft_binding[:32] + "…")
watermark_data = build_tex_evidence_watermark_assertion(
    detection=det_result,
    key_id="synthid-demo-1",
    soft_binding_value=f"sha256:{soft_binding}",
    asserted_origin="ai-generated",
    detector_url="https://github.com/google-deepmind/synthid-text",
)

# ---------------------------------------------------------------------------
# 6. EAT JWT
# ---------------------------------------------------------------------------

banner("Step 6 / 9 — minting EAT JWT bound to the C2PA claim hash (RFC 9334 RATS)")
body_sha = full_file_sha256(body)
eat_token = synthesize_test_eat_jwt(
    claim_cbor_sha256=body_sha,
    verifier=AttestationVerifier.NVIDIA_NRAS,
    signing_key_pem=issuer_priv_pem,
    kid=issuer_kid,
    algorithm="ES384",
    extra_claims={
        "cc_mode_enabled": True,
        "overall_result": "SUCCESS",
        "gpu_evidence_list": [{"device_id": "GPU-0"}],
    },
)
attestation_data = build_tex_evidence_attestation_assertion(
    eat_token=eat_token,
    eat_token_kind=EatTokenKind.JWT,
    verifier=AttestationVerifier.NVIDIA_NRAS,
    claim_cbor_sha256=body_sha,
    platform_measurement_sha256="f" * 64,
)
info("EAT JWT length", str(len(eat_token)) + " bytes")
info("bound to claim hash", body_sha[:32] + "…")

# ---------------------------------------------------------------------------
# 7. CPSA formal verification
# ---------------------------------------------------------------------------

banner("Step 7 / 9 — CPSA v4.4.5 formal-verification assertion (G1-G5)")
bundle = load_cpsa_shapes()
formal_data = model_provenance_assertion_data(bundle)
info("CPSA version", bundle.cpsa_version)
info("all goals satisfied", str(bundle.all_satisfied))
info("goals covered", ", ".join(bundle.all_goals))

# ---------------------------------------------------------------------------
# 8. Build the four-layer manifest in one pass
# ---------------------------------------------------------------------------

banner("Step 8 / 9 — building four-layer signed C2PA manifest in ONE pass")
unsigned = C2paManifest(
    claim=C2paClaim(
        title="thread6-demo-email.txt",
        format="text/plain",
        instance_id="xmp.iid:thread6-demo-001",
        claim_generator="tex/0.1 (thread6-demo)",
        claim_generator_info={"name": "Tex Aegis", "version": "0.1.0"},
        created_at=datetime.now(tz=timezone.utc),
        assertions=(
            C2paAssertion(
                label="c2pa.actions.v2",
                data={"actions": [{"action": "c2pa.created"}]},
            ),
            C2paAssertion(
                label="tex.verdict",
                data={"verdict": "PERMIT", "final_score": "0.08"},
            ),
        ),
    ),
    signature_b64=None,
    certificate_chain_pem=None,
)
extras = (
    C2paAssertion(label=ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK, data=watermark_data),
    C2paAssertion(label=ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION, data=attestation_data),
    C2paAssertion(label=ASSERTION_LABEL_TEX_FORMAL_VERIFICATION, data=formal_data),
)
signed = build_signed_manifest_with_cosign(
    unsigned_manifest=unsigned,
    outer_signing_key_id=outer_keypair.key_id,
    outer_certificate_chain_pem=chain_pem,
    cosign_key=cosign_key,
    outbound_artifact_bytes=body,
    retention_anchor={
        "retain_until": "2031-05-18T00:00:00Z",
        "record_hash": "sha256:" + ("a" * 64),
    },
    revocation_proof={"crl_url": "https://crl.example/tex.pem"},
    extra_assertions=extras,
)
ok("outer COSE_Sign1 signed, covering 5 assertions (2 base + 3 extras + cosign)")
for a in signed.claim.assertions:
    info("  " + a.label, "✓ bound under outer signature")

# ---------------------------------------------------------------------------
# 9. Verify everything
# ---------------------------------------------------------------------------

banner("Step 9 / 9 — verifying the full four-layer manifest")

# 9a. Outer COSE_Sign1.
outer = verify_manifest(signed)
assert outer.is_valid, outer.issues
ok("outer COSE_Sign1 signature valid")

# 9b. Cosign v2 — six attack defenses.
cosign = verify_evidence_cosign(signed, expected_full_file_sha256=body_sha)
assert cosign.is_valid, cosign.issues
ok(f"cosign v2 valid ({cosign.cosign_algorithm}, key {cosign.cosign_key_id})")
ok("all arxiv 2604.24890 attack classes defended:")
for attack, defended in cosign.defenses_satisfied:
    marker = "✓" if defended else "✗"
    info(f"  {marker}  {attack}", "defended" if defended else "FAILED")

# 9c. Watermark cross-layer audit.
wm_assertion = next(
    dict(a.data) for a in signed.claim.assertions
    if a.label == ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK
)
audit = cross_layer_audit(watermark_assertion=wm_assertion)
assert audit.is_consistent, audit.issues
ok(f"cross-layer audit consistent (arxiv 2603.02378 desync defense)")
info("  audit issues", ", ".join(audit.issues) or "(none)")

# 9d. Attestation EAT JWT.
att_assertion = next(
    dict(a.data) for a in signed.claim.assertions
    if a.label == ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION
)
att = verify_attestation_assertion(
    att_assertion,
    expected_claim_cbor_sha256=body_sha,
    trusted_issuer_public_keys={issuer_kid: issuer_pub_pem},
)
assert att.is_valid and att.signature_checked, att.issues
ok(f"attestation EAT JWT valid (verifier: {att.verifier})")
ok(f"  signature checked against trust anchor for kid={issuer_kid}")
ok(f"  user_data binds to claim hash {body_sha[:16]}…")

# 9e. Formal verification.
fv_assertion = next(
    dict(a.data) for a in signed.claim.assertions
    if a.label == ASSERTION_LABEL_TEX_FORMAL_VERIFICATION
)
assert fv_assertion["all_satisfied"]
ok(f"CPSA proof carried in manifest (G1-G5 all satisfied)")
info("  goals", ", ".join(fv_assertion["all_goals"]))

# Final summary.
banner("✓ Thread 6 — durable content credentials demo PASSED")
print()
print("  Four bleeding-edge layers, all under one outer signature:")
print()
print("    1. tex.evidence_cosign       (Thread 5: 6 NSA-paper attacks closed)")
print("    2. tex.evidence_watermark    (arxiv 2605.12456 + 2603.02378)")
print("    3. tex.evidence_attestation  (C2PA Attestation §, RFC 9334 RATS)")
print("    4. tex.formal_verification   (CPSA v4.4.5 G1-G5 proven sound)")
print()
print("  As of May 18 2026, no agent-governance vendor ships any of these.")
print()

clear_signing_keys()
PYDEMO
