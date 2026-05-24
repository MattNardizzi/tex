#!/usr/bin/env bash
#
# Thread 13 demo: VET Web Proofs + Agent Identity Document with
# PQ-default selective disclosure.
#
# Run:
#   uvicorn tex.main:create_app --factory --port 8000 &
#   bash scripts/demo_thread_13.sh
#
# Walkthrough:
#   1. Issue an AID for a new agent under ML-DSA-65 (PQ default).
#      The response includes the W3C VC 2.0 envelope.
#   2. Look up the AID by agent_id via GET /v1/vet/aid/{agent_id}.
#   3. Derive a selective-disclosure presentation revealing only
#      compliance_assertions to a specific audience.
#   4. Verify the presentation against the expected audience.
#   5. Notarize a third-party LLM API session and verify the Web Proof.
#   6. Issue an OAuth Transaction Token for an agent transaction and
#      verify it against the issuer pubkey.
#
# Acceptance criterion: every step returns 200 and the verification
# steps return valid=true.

set -euo pipefail

BASE_URL="${TEX_BASE_URL:-http://127.0.0.1:8000}"

# Use ed25519 in the demo so it runs cleanly without liboqs installed.
# Production deployments default to ml-dsa-65.
ALGO="${TEX_DEMO_ALGO:-ed25519}"

echo
echo "============================================================"
echo " Tex Thread 13 — VET Web Proofs + Agent Identity Document"
echo "============================================================"
echo
echo "Endpoints:"
echo "  POST $BASE_URL/v1/vet/issue-aid"
echo "  GET  $BASE_URL/v1/vet/aid/{agent_id}"
echo "  POST $BASE_URL/v1/vet/present-aid"
echo "  POST $BASE_URL/v1/vet/verify-presentation"
echo "  POST $BASE_URL/v1/vet/notarize"
echo "  POST $BASE_URL/v1/vet/verify-web-proof"
echo "  POST $BASE_URL/v1/vet/issue-txn-token"
echo "  POST $BASE_URL/v1/vet/verify-txn-token"
echo
echo "Signing algorithm in this demo: $ALGO"
echo "(Production default: ml-dsa-65 — set TEX_DEMO_ALGO=ml-dsa-65 to use.)"
echo

AGENT_ID="demo-agent-$(date +%s)"
AUDIENCE="https://verifier.example.com"
NONCE="demo-nonce-$(date +%s)"

# ----------------------------------------------------------------- #
# Step 1: issue AID
# ----------------------------------------------------------------- #
echo "[1/7] Issuing AID for $AGENT_ID..."
echo "------------------------------------------------------------"
ISSUE_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/issue-aid" \
    -H "Content-Type: application/json" \
    -d "{
        \"agent_id\": \"$AGENT_ID\",
        \"issuer_did\": \"did:tex:issuer:demo-tenant\",
        \"model_measurement\": \"sha256:gpt-4o-2025-08-15\",
        \"software_stack_measurement\": \"sha256:tex-runtime-1.0\",
        \"supported_proof_systems\": [\"tee-tdx\", \"tee-h100-cc\", \"zktls-reclaim\", \"tlsnotary-mpc\"],
        \"compliance_assertions\": [\"SOC2\", \"HIPAA\", \"EU-AI-Act-Article-50\", \"NIST-AI-RMF\"],
        \"algorithm\": \"$ALGO\",
        \"include_aivs_micro\": true,
        \"include_ptv_attestation\": false
    }")
echo "$ISSUE_RESPONSE" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
aid = data['aid']
vc = data['vc_2_0']
print(f\"  agent_id:           {aid['agent_id']}\")
print(f\"  issuer_did:         {aid['issuer_did']}\")
print(f\"  algorithm:          {aid['agent_public_key_algorithm']}\")
print(f\"  status:             {aid['status']}\")
print(f\"  cryptosuite:        {vc['proof']['cryptosuite']}\")
print(f\"  AIVS-Micro present: {aid['aivs_micro'] is not None}\")
"
echo

# ----------------------------------------------------------------- #
# Step 2: lookup by agent_id
# ----------------------------------------------------------------- #
echo "[2/7] Looking up AID via GET /v1/vet/aid/$AGENT_ID..."
echo "------------------------------------------------------------"
LOOKUP_RESPONSE=$(curl -sS "$BASE_URL/v1/vet/aid/$AGENT_ID")
echo "$LOOKUP_RESPONSE" | python3 -c "
import sys, json
aid = json.loads(sys.stdin.read())
print(f\"  Found: agent_id={aid['agent_id']} status={aid['status']}\")
print(f\"  compliance_assertions={aid['compliance_assertions']}\")
"
echo

# ----------------------------------------------------------------- #
# Step 3: present
# ----------------------------------------------------------------- #
echo "[3/7] Deriving selective-disclosure presentation..."
echo "  Audience:  $AUDIENCE"
echo "  Reveal:    compliance_assertions"
echo "  (Hidden:   model_measurement, software_stack_measurement, ...)"
echo "------------------------------------------------------------"
PRESENT_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/present-aid?agent_id=$AGENT_ID" \
    -H "Content-Type: application/json" \
    -d "{
        \"reveal\": [\"compliance_assertions\"],
        \"audience\": \"$AUDIENCE\",
        \"nonce\": \"$NONCE\",
        \"expires_in_seconds\": 300
    }")
ENVELOPE=$(echo "$PRESENT_RESPONSE" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
print(json.dumps(data['envelope']))
")
echo "  Envelope issued; size $(echo -n "$ENVELOPE" | wc -c) bytes"
echo

# ----------------------------------------------------------------- #
# Step 4: verify presentation
# ----------------------------------------------------------------- #
echo "[4/7] Verifying presentation against expected audience..."
echo "------------------------------------------------------------"
VERIFY_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/verify-presentation" \
    -H "Content-Type: application/json" \
    -d "{
        \"envelope\": $ENVELOPE,
        \"expected_audience\": \"$AUDIENCE\",
        \"expected_nonce\": \"$NONCE\",
        \"expected_agent_id\": \"$AGENT_ID\"
    }")
echo "$VERIFY_RESPONSE" | python3 -c "
import sys, json
result = json.loads(sys.stdin.read())['result']
print(f\"  valid:    {result['valid']}\")
print(f\"  reason:   {result['reason']}\")
print(f\"  revealed: {sorted(result['revealed_claims'].keys())}\")
"
echo

# ----------------------------------------------------------------- #
# Step 5: notarize a session
# ----------------------------------------------------------------- #
echo "[5/7] Notarizing a third-party LLM API session..."
echo "------------------------------------------------------------"
# base64url of '{"choices":[{"text":"hello"}]}'
RESPONSE_BODY_B64U="eyJjaG9pY2VzIjpbeyJ0ZXh0IjoiaGVsbG8ifV19"
NOTARIZE_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/notarize" \
    -H "Content-Type: application/json" \
    -d "{
        \"target_host\": \"api.openai.com\",
        \"target_path\": \"/v1/chat/completions\",
        \"method\": \"POST\",
        \"response_body_b64u\": \"$RESPONSE_BODY_B64U\",
        \"session_log_b64u\": \"$RESPONSE_BODY_B64U\",
        \"mode\": \"zktls-reclaim\"
    }")
PROOF=$(echo "$NOTARIZE_RESPONSE" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
print(json.dumps(data['proof']))
")
IS_STUB=$(echo "$NOTARIZE_RESPONSE" | python3 -c "
import sys, json
print(json.loads(sys.stdin.read())['is_stub'])
")
RESPONSE_HASH=$(echo "$NOTARIZE_RESPONSE" | python3 -c "
import sys, json
print(json.loads(sys.stdin.read())['proof']['response_commitment'])
")
echo "  Proof emitted; is_stub=$IS_STUB"
echo "  response_commitment: $RESPONSE_HASH"
echo "  (set TEX_TLSNOTARY_BIN and TEX_RECLAIM_ATTESTOR_URL to disable stub mode)"
echo

# ----------------------------------------------------------------- #
# Step 6: verify Web Proof
# ----------------------------------------------------------------- #
echo "[6/7] Verifying Web Proof (allow_stub=true)..."
echo "------------------------------------------------------------"
VERIFY_PROOF_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/verify-web-proof" \
    -H "Content-Type: application/json" \
    -d "{
        \"proof\": $PROOF,
        \"expected_target_host\": \"api.openai.com\",
        \"expected_response_hash_hex\": \"$RESPONSE_HASH\",
        \"allow_stub\": true
    }")
echo "$VERIFY_PROOF_RESPONSE" | python3 -c "
import sys, json
print(f\"  valid: {json.loads(sys.stdin.read())['valid']}\")
"
echo

# ----------------------------------------------------------------- #
# Step 7: Txn-Token
# ----------------------------------------------------------------- #
echo "[7/7] Issuing OAuth Txn-Token for an agent transaction..."
echo "------------------------------------------------------------"
TXN_RESPONSE=$(curl -sS -X POST "$BASE_URL/v1/vet/issue-txn-token" \
    -H "Content-Type: application/json" \
    -d "{
        \"iss\": \"https://txn.texaegis.com\",
        \"sub\": \"did:tex:user:alice\",
        \"act\": \"did:tex:agent:$AGENT_ID\",
        \"aud\": \"https://payments.example.com\",
        \"scope\": {
            \"audience\": \"https://payments.example.com\",
            \"http_method\": \"POST\",
            \"http_path\": \"/v1/transfer\",
            \"request_body_hash_hex\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
        },
        \"ttl_seconds\": 60,
        \"algorithm\": \"$ALGO\"
    }")
TOKEN=$(echo "$TXN_RESPONSE" | python3 -c "
import sys, json
print(json.loads(sys.stdin.read())['artifact']['token'])
")
PUBKEY=$(echo "$TXN_RESPONSE" | python3 -c "
import sys, json
print(json.loads(sys.stdin.read())['issuer_public_key_b64u'])
")
echo "  Token issued; size $(echo -n "$TOKEN" | wc -c) bytes"
echo "  Verifying..."
TXN_VERIFY=$(curl -sS -X POST "$BASE_URL/v1/vet/verify-txn-token" \
    -H "Content-Type: application/json" \
    -d "{
        \"token\": \"$TOKEN\",
        \"expected_audience\": \"https://payments.example.com\",
        \"issuer_public_key_b64u\": \"$PUBKEY\",
        \"expected_act\": \"did:tex:agent:$AGENT_ID\"
    }")
echo "$TXN_VERIFY" | python3 -c "
import sys, json
r = json.loads(sys.stdin.read())['result']
print(f\"  valid: {r['valid']}\")
print(f\"  reason: {r['reason']}\")
"

echo
echo "============================================================"
echo " Thread 13 demo complete."
echo "============================================================"
echo
echo " Notes:"
echo "  - The AID's selective disclosure revealed only the audience-"
echo "    requested claims (compliance_assertions). Sensitive measurements"
echo "    (model_measurement, software_stack_measurement) stay hidden."
echo "  - The Web Proof verified end-to-end; in production set"
echo "    TEX_TLSNOTARY_BIN to a real notary binary to disable stub mode."
echo "  - The Txn-Token round-tripped under $ALGO; set TEX_DEMO_ALGO=ml-dsa-65"
echo "    to run the full PQ default end-to-end (requires liboqs)."
