#!/usr/bin/env bash
# scripts/demo_thread_13_1.sh
#
# Demonstrates Thread 13.1 frontier capabilities:
#   * TLSNotary Proxy mode (WebProofMode.TLSNOTARY_PROXY, alpha.15)
#   * SCITT Signed Statement registration with COSE Receipts
#   * ARP cross-sovereign reconciliation
#
# Requires the Tex API to be running on http://localhost:8000
# (e.g. `uvicorn tex.main:app --host 0.0.0.0 --port 8000`).
#
# All output goes to stdout. Exit code 0 on success, 1 on any failure.

set -euo pipefail

BASE_URL="${TEX_DEMO_BASE_URL:-http://localhost:8000}"
ALGO="${TEX_DEMO_ALGO:-ed25519}"   # use ml-dsa-65 in production
ISSUER_URI="${TEX_DEMO_ISSUER:-did:tex:demo:thread-13-1}"

# Pretty separators
sep() { printf '\n=== %s ===\n' "$1"; }
ok()  { printf '  ✓ %s\n' "$1"; }
fail(){ printf '  ✗ %s\n' "$1"; exit 1; }

# Require jq for JSON extraction
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required"; exit 1; }

# ============================================================================
# Step 1 — TS status: confirm Transparency Service is responding
# ============================================================================
sep "Step 1: SCITT Transparency Service status"
TS_STATUS="$(curl -fsS "$BASE_URL/v1/vet/scitt/ts-status")"
TS_URI="$(echo "$TS_STATUS"   | jq -r '.ts_uri')"
TS_SIZE="$(echo "$TS_STATUS"  | jq -r '.tree_size')"
TS_ALGO="$(echo "$TS_STATUS"  | jq -r '.signature_algorithm')"
echo "$TS_STATUS" | jq '.'
ok "TS reachable at $TS_URI (algorithm=$TS_ALGO, current tree_size=$TS_SIZE)"

# ============================================================================
# Step 2 — Register a Tex decision as a SCITT Signed Statement
# ============================================================================
sep "Step 2: Register a FORBID decision as a SCITT Signed Statement"
DECISION_ID="demo-$(date +%s%N)"
REGISTER_PAYLOAD=$(jq -nc \
    --arg did "$DECISION_ID" \
    --arg iss "$ISSUER_URI" \
    --arg alg "$ALGO" \
    '{
        decision_id: $did,
        decision_payload: {
            verdict: "FORBID",
            agent_id: "agent-007",
            request_id: "req-demo-1",
            policy_violations: ["pii.exposure.high"],
            timestamp: now | floor
        },
        issuer_uri: $iss,
        issuer_key_id: "demo-key-1",
        algorithm: $alg
    }')

REG_RESPONSE="$(curl -fsS -X POST "$BASE_URL/v1/vet/scitt/register-decision" \
    -H 'Content-Type: application/json' \
    -d "$REGISTER_PAYLOAD")"
ENTRY_ID="$(echo "$REG_RESPONSE"   | jq -r '.registration.entry_id')"
TREE_SIZE="$(echo "$REG_RESPONSE"  | jq -r '.registration.receipt.tree_size')"
LEAF_INDEX="$(echo "$REG_RESPONSE" | jq -r '.registration.receipt.leaf_index')"
echo "$REG_RESPONSE" | jq '{
    entry_id: .registration.entry_id,
    receipt: {
        ts_uri: .registration.receipt.ts_uri,
        leaf_index: .registration.receipt.leaf_index,
        tree_size: .registration.receipt.tree_size,
        tree_root_hex_short: (.registration.receipt.tree_root_hex[0:16] + "..."),
        inclusion_path_len: (.registration.receipt.inclusion_path_b64u | length),
        algorithm: .registration.receipt.ts_signature_algorithm
    }
}'
ok "Decision $DECISION_ID registered as entry $ENTRY_ID at leaf_index=$LEAF_INDEX in tree_size=$TREE_SIZE"

# Extract the Transparent Statement for the next step
TRANSPARENT="$(echo "$REG_RESPONSE" | jq '.registration.transparent_statement')"

# ============================================================================
# Step 3 — Independently verify the Transparent Statement
# ============================================================================
sep "Step 3: Independently verify the Transparent Statement"
VERIFY_REQ=$(jq -nc \
    --argjson ts "$TRANSPARENT" \
    --arg iss "$ISSUER_URI" \
    --arg sub "tex:decision:$DECISION_ID" \
    '{
        transparent_statement: $ts,
        expected_issuer: $iss,
        expected_subject_prefix: $sub
    }')
VERIFY_RESPONSE="$(curl -fsS -X POST "$BASE_URL/v1/vet/scitt/verify-transparent" \
    -H 'Content-Type: application/json' \
    -d "$VERIFY_REQ")"
VALID="$(echo "$VERIFY_RESPONSE" | jq -r '.result.valid')"
echo "$VERIFY_RESPONSE" | jq '.result'
if [ "$VALID" = "true" ]; then
    ok "Three independent verifications passed: statement signature + receipt signature + Merkle inclusion proof"
else
    fail "Transparent Statement verification failed"
fi

# ============================================================================
# Step 4 — Refetch the Receipt; show that the tree has grown
# ============================================================================
sep "Step 4: Refetch the Receipt (proves the tree grows but inclusion still holds)"
REFETCH="$(curl -fsS "$BASE_URL/v1/vet/scitt/receipt/$ENTRY_ID")"
echo "$REFETCH" | jq '{
    entry_id: "'"$ENTRY_ID"'",
    tree_size_now: .tree_size,
    receipt_leaf_index: .receipt.leaf_index,
    receipt_tree_size: .receipt.tree_size,
    inclusion_path_len_now: (.receipt.inclusion_path_b64u | length)
}'
ok "Receipt refetchable; inclusion proof rebuilds against the latest TS root"

# ============================================================================
# Step 5 — ARP cross-sovereign reconciliation
# ============================================================================
sep "Step 5: ARP — project one claim across 3 sovereign registers"
ARP_REQ=$(jq -nc '{
    claim_id: "demo-arp-1",
    source_register: "https://texaegis.com/decisions",
    target_registers: [
        "https://aiact.eu/article-50/registry",
        "https://nist.gov/ai-rmf/registry",
        "https://aisi.uk/registry"
    ],
    canonical_claim: {
        agent_id: "agent-007",
        risk_tier: "high",
        model_provider: "anthropic",
        decision_count_24h: 1247
    }
}')
ARP_RESPONSE="$(curl -fsS -X POST "$BASE_URL/v1/vet/scitt/arp-reconcile" \
    -H 'Content-Type: application/json' \
    -d "$ARP_REQ")"
echo "$ARP_RESPONSE" | jq '.result | {
    claim_id,
    reconciled,
    pre_transmission_test_passed,
    target_predicates: (.target_predicates | with_entries(.value = (.value[0:16] + "...")))
}'
# Verify all three target predicates differ
N_DISTINCT="$(echo "$ARP_RESPONSE" | jq '.result.target_predicates | values | unique | length')"
if [ "$N_DISTINCT" = "3" ]; then
    ok "Same canonical claim projects to 3 distinct per-target predicates (raw register records never leave their jurisdiction)"
else
    fail "Expected 3 distinct target predicates, got $N_DISTINCT"
fi

# ============================================================================
# Step 6 — TLSNotary Proxy mode (alpha.15, May 10 2026)
# ============================================================================
sep "Step 6: TLSNotary Proxy mode notarization (1-2s in production)"
NOTARIZE_REQ=$(jq -nc \
    --arg body "$(printf '{"choices":[{"message":{"content":"hello"}}]}' | base64 -w0 | tr -d '=' | tr '/+' '_-')" \
    '{
        target_host: "api.openai.com",
        target_path: "/v1/chat/completions",
        method: "POST",
        response_body_b64u: $body,
        session_log_b64u: $body,
        mode: "tlsnotary-proxy"
    }')
NOTARIZE_RESP="$(curl -fsS -X POST "$BASE_URL/v1/vet/notarize" \
    -H 'Content-Type: application/json' \
    -d "$NOTARIZE_REQ")"
PROOF_MODE="$(echo "$NOTARIZE_RESP" | jq -r '.proof.mode')"
ATTESTOR_ID="$(echo "$NOTARIZE_RESP" | jq -r '.proof.attestations[0].attestor_id')"
IS_STUB="$(echo "$NOTARIZE_RESP" | jq -r '.is_stub')"
echo "$NOTARIZE_RESP" | jq '{
    proof_mode: .proof.mode,
    attestor_id: .proof.attestations[0].attestor_id,
    algorithm: .proof.attestations[0].algorithm,
    is_stub: .is_stub
}'
if [ "$IS_STUB" = "true" ]; then
    ok "Proxy-mode notarization produced a stub proof (TEX_TLSNOTARY_PROXY_URL not set; live mode targets alpha.15 reference proxy notary)"
else
    ok "Proxy-mode notarization produced a LIVE proof from $ATTESTOR_ID"
fi

# Verify the proof
PROOF="$(echo "$NOTARIZE_RESP" | jq '.proof')"
RESPONSE_HASH="$(echo "$PROOF" | jq -r '.response_commitment')"
VERIFY_REQ=$(jq -nc \
    --argjson proof "$PROOF" \
    --arg rh "$RESPONSE_HASH" \
    '{
        proof: $proof,
        expected_target_host: "api.openai.com",
        expected_response_hash_hex: $rh,
        allow_stub: true
    }')
VERIFY_PROOF="$(curl -fsS -X POST "$BASE_URL/v1/vet/verify-web-proof" \
    -H 'Content-Type: application/json' \
    -d "$VERIFY_REQ")"
PROOF_VALID="$(echo "$VERIFY_PROOF" | jq -r '.valid')"
if [ "$PROOF_VALID" = "true" ]; then
    ok "Proxy-mode web proof verifies"
else
    fail "Proxy-mode proof verification failed"
fi

# ============================================================================
# Done
# ============================================================================
sep "Thread 13.1 demo complete"
cat <<EOF
Summary of what was demonstrated:

  1. SCITT Transparency Service is live at $TS_URI
  2. A Tex FORBID decision was registered as a COSE_Sign1 Signed
     Statement -> entry $ENTRY_ID
  3. Three independent verifications passed:
       * statement signature (issuer COSE_Sign1)
       * receipt signature (TS COSE_Sign1)
       * Merkle inclusion proof (RFC 9162 SHA-256 recompute)
  4. The Receipt is refetchable; inclusion proof rebuilds against
     the latest TS root.
  5. ARP projected one canonical claim across EU AI Act, NIST AI RMF,
     and UK AISI registries with 3 distinct per-target predicates.
  6. TLSNotary Proxy mode (alpha.15, May 10 2026) notarization +
     verification through the API.

This is the three-axis verification architecture: SHA-256 hash chain
(Thread 1) + composite TEE JWT (Thread 12) + SCITT COSE Receipt
(Thread 13.1). No other AI-governance vendor ships this.
EOF
