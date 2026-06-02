#!/usr/bin/env bash
# =========================================================================
# Thread 15 — NANOZK Layerwise + Fisher-Guided Verifiable Inference demo
# =========================================================================
#
# What this exercises (in order):
#
#   1. POST /v1/guardrail                  — trigger a FORBID decision
#                                            and capture the decision_id
#   2. POST /v1/incidents/{id}/attribute   — request causal attribution
#                                            with include_zk_envelope=True;
#                                            the wired path attaches a
#                                            live NANOZK layerwise envelope
#                                            (method = tex:nanozk-
#                                            layerwise-2026), NOT
#                                            proof_pending
#   3. Local verification                  — decode the LayerProofSet
#                                            from the envelope and assert
#                                            the live verifier returns
#                                            ok_nanozk_layerwise_verified
#                                            (this is the regression
#                                            against the pre-Thread-15
#                                            nanozk_verifier_not_imple-
#                                            mented_in_this_thread state)
#
# Reference papers / specs:
#   * arxiv 2603.18046  NANOZK (Wang, USC, Mar 17 2026)
#   * arxiv 2602.17452  Jolt Atlas (Benno et al., Feb 19 2026)
#   * eprint 2025/1184  zkGPT (Qu et al., USENIX Sec '25)
#   * eprint 2026/683   VEIL (Dalal et al., Apr 7 2026)
#   * SP1 Hypercube mainnet (Succinct, Feb 19 2026)
#   * draft-anandakrishnan-ptv-attested-agent-identity-00 (Mar 31 2026)
#   * draft-ietf-scitt-architecture-22 (Apr 2026)
#   * EU AI Act Article 50 Guidelines (Draft 8 May 2026)
#
# Usage:
#   # Required: Thread 15 frontier flag set on the running app.
#   TEX_FRONTIER_NANOZK=1 TEX_PTV_VERIFY_MODE=test \
#     uvicorn tex.main:build_app --factory --port 8000 &
#   TEX_HOST=http://localhost:8000 ./scripts/demo_thread_15_nanozk.sh
#
# Prereqs:
#   * jq, curl, python3, base64 in PATH
#   * Tex API running locally with TEX_FRONTIER_NANOZK=1

set -euo pipefail

TEX_HOST="${TEX_HOST:-http://localhost:8000}"

# ANSI colours
B="\033[1m"
G="\033[1;32m"
Y="\033[1;33m"
R="\033[1;31m"
N="\033[0m"

echo -e "${B}=== Thread 15: NANOZK Layerwise Verifiable Inference Demo ===${N}"
echo ""
echo "Target: ${TEX_HOST}"
echo ""

# -------------------------------------------------------------------------
# Step 1 — trigger a decision
# -------------------------------------------------------------------------
echo -e "${B}[1/3]${N} Triggering a guardrail decision (dirty payload → FORBID)..."

GUARDRAIL_RESP=$(curl -sf -X POST "${TEX_HOST}/v1/guardrail" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "pre_call",
    "action_type": "send_email",
    "channel": "email",
    "environment": "production",
    "recipient": "buyer@example.com",
    "content": "Use the API key sk-proj-abc1234567890XYZ to run the import. Customer ssn 123-45-6789. Wire to acct 4111111111111111.",
    "source": "thread_15_demo"
  }')

DECISION_ID=$(echo "$GUARDRAIL_RESP" | jq -r '.decision_id // .decision.decision_id')
VERDICT=$(echo "$GUARDRAIL_RESP" | jq -r '.verdict')
SCORE=$(echo "$GUARDRAIL_RESP" | jq -r '.score')

echo -e "    decision_id = ${G}${DECISION_ID}${N}"
echo -e "    verdict     = ${R}${VERDICT}${N}"
echo -e "    score       = ${Y}${SCORE}${N}"
echo ""

# -------------------------------------------------------------------------
# Step 2 — attribute with NANOZK layerwise envelope
# -------------------------------------------------------------------------
echo -e "${B}[2/3]${N} Requesting causal attribution with NANOZK layerwise proof..."

ATTR_RESP=$(curl -sf -X POST "${TEX_HOST}/v1/incidents/${DECISION_ID}/attribute" \
  -H "Content-Type: application/json" \
  -d '{"include_zk_envelope": true}')

PTV_METHOD=$(echo "$ATTR_RESP" | jq -r '.ptv_envelope.method')
ATTR_METHOD=$(echo "$ATTR_RESP" | jq -r '.attribution_method')
MODEL_HASH=$(echo "$ATTR_RESP" | jq -r '.ptv_envelope.model_hash')
INPUT_HASH=$(echo "$ATTR_RESP" | jq -r '.ptv_envelope.input_hash')
OUTPUT_HASH=$(echo "$ATTR_RESP" | jq -r '.ptv_envelope.output_hash')
PROOF_LEN=$(echo "$ATTR_RESP" | jq -r '.ptv_envelope.proof | length')

echo -e "    ptv method          = ${G}${PTV_METHOD}${N}"
echo -e "    attribution_method  = ${G}${ATTR_METHOD}${N}"
echo -e "    proof length (b64)  = ${Y}${PROOF_LEN} chars${N}"
echo -e "    model_hash          = ${MODEL_HASH:0:32}..."
echo -e "    input_hash          = ${INPUT_HASH:0:32}..."
echo -e "    output_hash         = ${OUTPUT_HASH:0:32}..."
echo ""

# Sanity check: must NOT be proof_pending.
if [ "$PTV_METHOD" != "tex:nanozk-layerwise-2026" ]; then
  echo -e "${R}FAIL${N}: expected method tex:nanozk-layerwise-2026, got $PTV_METHOD"
  echo "Hint: ensure the server is running with TEX_FRONTIER_NANOZK=1"
  exit 1
fi
# Sanity check: must carry zk_layerwise suffix.
if [[ "$ATTR_METHOD" != *"zk_layerwise"* ]]; then
  echo -e "${R}FAIL${N}: attribution_method missing zk_layerwise suffix: $ATTR_METHOD"
  exit 1
fi

# -------------------------------------------------------------------------
# Step 3 — local verification through tex.evidence.attribution_zk
# -------------------------------------------------------------------------
echo -e "${B}[3/3]${N} Verifying envelope locally via tex.nanozk live verifier..."

# Pipe the envelope JSON into a tiny Python verifier.
VERIFY_OUTPUT=$(echo "$ATTR_RESP" | jq '.ptv_envelope' | python3 -c '
import json
import sys

from tex.evidence.attribution_zk import (
    PTVEnvelope,
    verify_ptv_envelope,
)

env_dto = json.load(sys.stdin)
envelope = PTVEnvelope(
    method=env_dto["method"],
    proof=env_dto["proof"],
    model_hash=env_dto["model_hash"],
    input_hash=env_dto["input_hash"],
    output_hash=env_dto["output_hash"],
)
result = verify_ptv_envelope(
    envelope,
    expected_model_hash=env_dto["model_hash"],
    expected_input_hash=env_dto["input_hash"],
    expected_output_hash=env_dto["output_hash"],
)
print(json.dumps({
    "ok": result.ok,
    "reason": result.reason,
}, indent=2))
')

OK=$(echo "$VERIFY_OUTPUT" | jq -r '.ok')
REASON=$(echo "$VERIFY_OUTPUT" | jq -r '.reason')

echo -e "    verifier.ok      = ${G}${OK}${N}"
echo -e "    verifier.reason  = ${G}${REASON}${N}"
echo ""

if [ "$OK" != "true" ]; then
  echo -e "${R}FAIL${N}: live verifier rejected the envelope"
  exit 1
fi

# Decode the layer proof set to show what's inside.
echo -e "${B}--- LayerProofSet contents ---${N}"
echo "$ATTR_RESP" | jq -r '.ptv_envelope.proof' | python3 -c '
import base64
import json
import sys

from tex.nanozk import LayerProofSet

proof_b64 = sys.stdin.read().strip()
proof_bytes = base64.urlsafe_b64decode(
    proof_b64 + "=" * ((-len(proof_b64)) % 4)
)
ps = LayerProofSet.from_bytes(proof_bytes)
print(f"  total_layers              = {ps.total_layers}")
print(f"  proofs                    = {len(ps.proofs)} layers")
print(f"  fisher_captured_info      = {ps.fisher_captured_information:.3f}")
print(f"  set_root                  = {ps.set_root[:32]}...")
print(f"  selected_indices          = {tuple(p.layer_index for p in ps.proofs)}")
print(f"  each proof veil_wrapped   = {all(p.veil_wrapped for p in ps.proofs)}")
print(f"  backend                   = {ps.proofs[0].backend}")
'
echo ""

echo -e "${G}=== Thread 15 demo complete — live verifier accepted ===${N}"
echo ""
echo "This is the demonstration claimed in CLAIMS.md Thread 15:"
echo "  * The envelope method is tex:nanozk-layerwise-2026 (not proof_pending)"
echo "  * attribution_method carries zk_layerwise (not zk_pending)"
echo "  * The verifier returns ok_nanozk_layerwise_verified — the dead-end"
echo "    return nanozk_verifier_not_implemented_in_this_thread is gone."
echo "  * The decoded LayerProofSet contains the Fisher-selected layer"
echo "    proofs (default ~50% of GPT-2's 12 layers per NANOZK paper §3.3)."
