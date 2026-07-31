#!/usr/bin/env bash
# Thread 1 demo — Behavioral Contracts (LTLf temporal logic) wired into PDP.
#
# Boots Tex locally, fires a single /evaluate request whose content
# trips the seed hard-governance contract "content-no-api-keys", and
# pretty-prints the response to show:
#   1. The verdict is FORBID via the contract layer (not via deterministic).
#   2. The response findings include the LTLf formula that fired.
#   3. The decision metadata records the contracts step in the pipeline.
#
# What this proves
# ----------------
# Tex enforces a finite-trace LTLf formula
#   G(field:content~not_contains:sk-proj-)
# against the live request and short-circuits to FORBID before fusion when
# the formula is violated. This is the capability claimed in CLAIMS.md §1.
#
# Reference papers
# ----------------
# - arxiv 2602.22302 (Bhardwaj, ABC) §3.1 6-tuple
# - arxiv 2411.14581 (LTL3 finite-trace semantics)
#
# Usage
# -----
#   # In one terminal, start Tex:
#   PYTHONPATH=src uvicorn tex.main:create_app --factory --port 8000
#   # In another, run the demo:
#   bash scripts/demo_thread_1.sh

set -euo pipefail

TEX_URL="${TEX_URL:-http://127.0.0.1:8000}"
REQUEST_ID="$(python -c 'import uuid; print(uuid.uuid4())')"

echo "===> POST ${TEX_URL}/evaluate"
echo "===> Content contains 'sk-proj-' which trips contract 'content-no-api-keys'"
echo

RESPONSE="$(curl -sS -X POST "${TEX_URL}/evaluate" \
  -H "Content-Type: application/json" \
  -d "{
    \"request_id\": \"${REQUEST_ID}\",
    \"action_type\": \"send_email\",
    \"channel\": \"email\",
    \"environment\": \"production\",
    \"recipient\": \"buyer@example.com\",
    \"content\": \"Use the API key sk-proj-abc1234567890XYZ to run the import.\"
  }")"

echo "===> Full response:"
echo "${RESPONSE}" | python -m json.tool
echo

echo "===> Extracted: verdict, contract-layer finding, LTLf formula"
echo "${RESPONSE}" | python -c '
import json, sys
body = json.load(sys.stdin)
print(f"verdict       : {body[\"verdict\"]}")
print(f"final_score   : {body[\"final_score\"]}")
print(f"reasons       : {body[\"reasons\"]}")
contract_findings = [
    f for f in body.get("findings", [])
    if f.get("source") == "contracts.behavioral"
]
if contract_findings:
    f = contract_findings[0]
    print(f"contract_id   : {f[\"metadata\"][\"contract_id\"]}")
    print(f"violated      : {f[\"metadata\"][\"violated_clause\"]}")
    print(f"LTLf formula  : {f[\"metadata\"][\"clause_ltl\"]}")
    print(f"step_index    : {f[\"metadata\"][\"step_index\"]}")
    print(f"severity      : {f[\"severity\"]}")
else:
    print("WARNING: no contract findings in response — Thread 1 wiring may be off")
    sys.exit(1)
'

echo
echo "===> Now try replay to confirm decision is durable + evidence-hashed"
DECISION_ID="$(echo "${RESPONSE}" | python -c 'import json,sys; print(json.load(sys.stdin)["decision_id"])')"
echo "===> GET ${TEX_URL}/decisions/${DECISION_ID}"
curl -sS "${TEX_URL}/decisions/${DECISION_ID}" | python -m json.tool | head -40
