#!/usr/bin/env bash
#
# Thread 12 demo: composite TDX + NVIDIA GPU attestation bound to a
# /v1/guardrail decision, then verified via /v1/tee/verify.
#
# Run:
#   TEX_TEE_MODE=1 TEX_TEE_ATTESTATION_MODE=test \
#     uvicorn tex.main:create_app --factory --port 8000 &
#   bash scripts/demo_tee.sh
#
# Acceptance criterion: one curl request to /v1/guardrail produces a
# verdict, whose evidence record contains a composite ITA JWT, and that
# JWT verifies under /v1/tee/verify.

set -euo pipefail

BASE_URL="${TEX_BASE_URL:-http://127.0.0.1:8000}"

echo
echo "============================================================"
echo " Tex Thread 12 — Composite TEE Attestation Demo"
echo "============================================================"
echo
echo "Endpoints:"
echo "  POST $BASE_URL/v1/guardrail"
echo "  GET  $BASE_URL/v1/tee/status"
echo "  POST $BASE_URL/v1/tee/verify"
echo

# Step 1: status check ------------------------------------------------------- #
echo "[1/3] Checking TEE capability status..."
echo "------------------------------------------------------------"
STATUS_JSON=$(curl -sS "$BASE_URL/v1/tee/status")
echo "$STATUS_JSON" | python3 -m json.tool
echo

# Step 2: guardrail call ----------------------------------------------------- #
echo "[2/3] Sending /v1/guardrail request with TEE binding enabled..."
echo "------------------------------------------------------------"
GUARDRAIL_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/guardrail" \
    -H "Content-Type: application/json" \
    -d '{
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": "Hi Jordan, saw your hiring posts — happy to share what is working for similar teams. 15-min call next week?",
        "source": "tee_demo"
    }')

echo "$GUARDRAIL_RESPONSE" | python3 -m json.tool
echo

DECISION_ID=$(echo "$GUARDRAIL_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['decision_id'])")
echo "Decision ID: $DECISION_ID"
echo

# Step 3: extract JWT from evidence, verify ---------------------------------- #
echo "[3/3] Extracting composite ITA JWT from evidence record and verifying..."
echo "------------------------------------------------------------"

EVIDENCE_PATH="${TEX_EVIDENCE_PATH:-var/tex/evidence/evidence.jsonl}"
if [ ! -f "$EVIDENCE_PATH" ]; then
    echo "WARN: evidence file not found at $EVIDENCE_PATH"
    echo "      set TEX_EVIDENCE_PATH to point at the running app's evidence.jsonl"
    exit 1
fi

# Pluck the TEE block for this decision_id out of the evidence chain
TEE_BLOCK=$(python3 <<PY
import json, sys
decision_id = "$DECISION_ID"
with open("$EVIDENCE_PATH") as f:
    for line in f:
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("record_type") != "decision":
            continue
        payload = json.loads(rec["payload_json"])
        if payload.get("decision_id") != decision_id:
            continue
        tee = (payload.get("metadata") or {}).get("tee_composite_attestation")
        if tee:
            print(json.dumps({"jwt": tee["ita_jwt"], "expected_nonce": tee["nonce"]}))
            sys.exit(0)
sys.exit(2)
PY
)

if [ -z "$TEE_BLOCK" ]; then
    echo "ERROR: no composite TEE attestation found for decision $DECISION_ID"
    echo "       Did you start the server with TEX_TEE_MODE=1?"
    exit 1
fi

echo "Composite ITA JWT extracted from evidence chain."
echo "Posting to /v1/tee/verify..."
echo

VERIFY_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/tee/verify" \
    -H "Content-Type: application/json" \
    -d "$TEE_BLOCK")

echo "$VERIFY_RESPONSE" | python3 -m json.tool
echo

OK=$(echo "$VERIFY_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['ok'])")
REASON=$(echo "$VERIFY_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['reason'])")

echo "============================================================"
if [ "$OK" = "True" ]; then
    echo " ✓ TEE attestation verified — reason=$REASON"
    echo " ✓ Decision $DECISION_ID is hardware-attested end-to-end."
else
    echo " ✗ Verification FAILED — reason=$REASON"
    exit 2
fi
echo "============================================================"
