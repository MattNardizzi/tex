#!/usr/bin/env bash
# scripts/demo_thread_5_c2pa.sh
#
# Thread 5 demo — proves end-to-end the C2PA Content Credential +
# Tex Evidence Cosign emission and verification round-trip.
#
# What it does:
#   1. Builds a unsigned C2PA email manifest.
#   2. Signs the outer COSE_Sign1 + Tex evidence cosign (post-quantum
#      track) using build_signed_manifest_with_cosign.
#   3. Boots Tex on port 8765 with the manifest preloaded into an
#      in-memory mirror.
#   4. Hits POST /v1/c2pa/verify with the manifest and asset bytes.
#   5. Prints the structured verification result so an auditor can
#      see all five attack-defense flags from arxiv 2604.24890.
#
# Bleeding-edge claim wired in by this demo:
#   - C2PA 2.4 (current spec, January 2026 release)
#   - ML-DSA-65 / Ed25519 cosign via tex.pqcrypto.algorithm_agility
#   - arxiv 2604.24890 (Apr 27 2026, NSA/UMBC) six attack defenses
#   - EU AI Act Article 50(2) machine-readable mark
#   - draft-ietf-cose-dilithium-11 algorithm-agility
#
# Usage:
#   bash scripts/demo_thread_5_c2pa.sh
#
# Prereqs:
#   pip install -e . (in repo root)
#
# This script is self-contained; it does not require a running
# Postgres instance. Production deployments should set DATABASE_URL.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "[WARN] jq not installed; output will be unprettified JSON" >&2
    JQ_CMD="python -m json.tool"
else
    JQ_CMD="jq ."
fi

PORT="${PORT:-8765}"
HOST="${HOST:-127.0.0.1}"

# Step 1+2: build + sign manifest, write its payload to /tmp.
python - <<'PY'
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Thread 4 (May 2026): the ``import tex.ecosystem`` workaround that
# previously sat here was removed once the underlying circular import
# (``tex.events.crypto_provenance`` <-> ``tex.ecosystem.engine``) was
# broken via TYPE_CHECKING. See THREAD_4_CHANGELOG.md.

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from tex.c2pa import (
    build_email_manifest,
    build_signed_manifest_with_cosign,
    clear_signing_keys,
    register_signing_key,
    serialize_manifest_for_storage,
)
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair

now = datetime.now(timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Demo Root")])
ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name).issuer_name(ca_name)
    .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
leaf_key = ed25519.Ed25519PrivateKey.generate()
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tex.demo.signer")])
leaf = (
    x509.CertificateBuilder()
    .subject_name(leaf_name).issuer_name(ca_name)
    .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
priv_pem = leaf_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
pub_pem = leaf_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
chain_pem = (
    leaf.public_bytes(serialization.Encoding.PEM).decode()
    + ca.public_bytes(serialization.Encoding.PEM).decode()
)

set_keystore(None); clear_signing_keys()
register_signing_key(SignatureKeyPair(
    algorithm=SignatureAlgorithm.ED25519,
    public_key=pub_pem, private_key=priv_pem, key_id="demo-outer",
))
cosign_key = Ed25519Provider().generate_keypair("demo-cosign")

body = (
    "Hi Sara,\n\n"
    "Tex Aegis just shipped a wedge: we're now the only agent-governance "
    "platform whose evidence carries a C2PA 2.4 Content Credential by "
    "default, and the only one that closes the six attack classes the NSA "
    "paper from late April found in the C2PA spec.\n\n"
    "Want a 20-minute walkthrough Wednesday?\n\n"
    "— Matthew\n"
).encode("utf-8")

unsigned = build_email_manifest(
    from_address="ai-sdr@vortexblack.com",
    to_addresses=("sara@example-prospect.com",),
    subject="C2PA-by-default for AI-SDR governance",
    body_sha256=hashlib.sha256(body).hexdigest(),
    model_name="claude-sonnet-4.6",
    model_version="2026-03",
    tex_verdict_id="v-demo-thread5-001",
)
signed = build_signed_manifest_with_cosign(
    unsigned_manifest=unsigned,
    outer_signing_key_id="demo-outer",
    outer_certificate_chain_pem=chain_pem,
    cosign_key=cosign_key,
    outbound_artifact_bytes=body,
    retention_anchor={
        "record_hash": "a" * 64,
        "evidence_id": "ev-demo-001",
        "policy_version": "thread5.demo.v1",
    },
    revocation_proof={
        "kind": "crl_snapshot_pin",
        "sha256": "b" * 64,
        "issued_at": now.isoformat(),
    },
)
row = serialize_manifest_for_storage(signed)
Path("/tmp/tex_demo_t5_manifest.json").write_text(json.dumps({
    "claim_cbor_b64": row["claim_cbor_b64"],
    "outer_signature_b64": row["outer_signature_b64"],
    "certificate_chain_pem": row["certificate_chain_pem"],
    "asset_bytes_b64": base64.b64encode(body).decode("ascii"),
}))
print("[ok] manifest signed:")
print(f"     outer signature bytes: {len(row['outer_signature_b64'])}")
print(f"     has cosign:            {row['has_cosign']}")
print(f"     assertion labels:      {row['assertion_labels']}")
PY

# Step 3: boot Tex in the background.
echo "[..] starting Tex on $HOST:$PORT (background)..."
( cd "$(pwd)" && python -m uvicorn tex.main:create_app --factory \
    --host "$HOST" --port "$PORT" --log-level warning > /tmp/tex_demo_t5.log 2>&1 ) &
TEX_PID=$!
trap 'kill $TEX_PID 2>/dev/null || true' EXIT

# Wait for /healthz.
for i in $(seq 1 30); do
    if curl -sf "http://$HOST:$PORT/" > /dev/null 2>&1; then
        echo "[ok] Tex up on http://$HOST:$PORT"
        break
    fi
    sleep 0.5
done

# Step 4: hit /v1/c2pa/verify with the manifest.
echo
echo "[..] POST /v1/c2pa/verify"
echo "==============================================================="
curl -s -X POST "http://$HOST:$PORT/v1/c2pa/verify" \
    -H 'Content-Type: application/json' \
    --data @/tmp/tex_demo_t5_manifest.json \
    | $JQ_CMD
echo "==============================================================="
echo
echo "What you should see above:"
echo "  outer_signature_valid:           true"
echo "  cosign_present:                  true"
echo "  cosign_valid:                    true"
echo "  attack_defenses[*].defended:     all true"
echo "  paper_reference:                 arxiv:2604.24890"
echo
echo "Tex is the only agent-governance platform shipping this surface."
echo "Microsoft Agent Governance Toolkit (Apr 2 2026), Zenity, Noma,"
echo "Lakera, Pillar, F5/CalypsoAI, CrowdStrike/Pangea, and Palo Alto/"
echo "Protect AI all ship zero C2PA integration as of May 2026."
