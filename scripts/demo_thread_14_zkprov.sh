#!/usr/bin/env bash
# =========================================================================
# Thread 14 — ZKPROV training-data provenance demo
# =========================================================================
#
# What this exercises (in order):
#
#   1. GET  /v1/zkprov/health                — feature flag, supported
#                                              backends, pinned standards
#   2. POST /v1/zkprov/issue-commitment      — CA-signed DatasetCommitment
#                                              over 3 records + a
#                                              VFT-shaped manifest
#   3. POST /v1/zkprov/prove                 — generate a ProvenanceProof
#                                              binding a response to the
#                                              commitment
#   4. POST /v1/zkprov/verify                — six fail-closed checks, no
#                                              regulator-grade
#   5. POST /v1/zkprov/verify                — same proof, regulator_grade=
#                                              true  ⇒ shim rejected
#   6. POST /v1/zkprov/aggregate             — recursive aggregation with
#                                              Mira parallel folding
#                                              (ZKTorch, 6.2x faster) AND
#                                              LatticeFold+ post-quantum
#                                              folding
#   7. POST /v1/zkprov/narrow                — SCITT ARP narrowed claim
#                                              (data-volume-bucket) per
#                                              draft-hillier-scitt-arp-00
#
# Reference papers:
#   * arxiv 2506.20915  ZKPROV (Dec 18 2025)
#   * arxiv 2510.16830  VFT v3 (Dec 29 2025)
#   * eprint 2026/683   VEIL hash-based ZK (Apr 8 2026)  <-- NEW
#   * Succinct          SP1 Hypercube mainnet (Feb 19 2026)  <-- NEW
#   * eprint 2026/721   LatticeFold+ ℓ2 (April 19 2026)
#   * arxiv 2507.07031  ZKTorch / Mira parallel (Jul 9 2025)  <-- NEW
#   * draft-hillier-scitt-arp-00 (May 1 2026)
#   * arxiv 2603.10060  NABAOS (Mar 9 2026)
#
# Usage:
#   TEX_HOST=http://localhost:8000 ./scripts/demo_thread_14_zkprov.sh
#
# Prereqs:
#   * Tex API running locally (uvicorn tex.main:build_app ...)
#   * jq, curl, base64 in PATH

set -euo pipefail

TEX_HOST="${TEX_HOST:-http://localhost:8000}"

# ANSI colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() { printf "${BLUE}==> %s${NC}\n" "$1"; }
ok()   { printf "${GREEN}    ✓ %s${NC}\n" "$1"; }
warn() { printf "${YELLOW}    ! %s${NC}\n" "$1"; }

# ----------------------------------------------------------------------- #
# 1. /health                                                              #
# ----------------------------------------------------------------------- #
step "1. ZKPROV health + standards pinned"
HEALTH=$(curl -fsS "$TEX_HOST/v1/zkprov/health")
echo "$HEALTH" | jq '{
  enabled, store_kind, circuit_version,
  merkle_hash_in_use,
  supported_backends, supported_folding_schemes, standards_pinned
}'
CIRCUIT_VERSION=$(echo "$HEALTH" | jq -r '.circuit_version')
MERKLE_HASH=$(echo "$HEALTH" | jq -r '.merkle_hash_in_use')
ok "circuit_version: $CIRCUIT_VERSION"
ok "merkle_hash_in_use: $MERKLE_HASH (poseidon-bn254-t3 expected when poseidon-hash installed)"

# ----------------------------------------------------------------------- #
# 2. /issue-commitment                                                    #
# ----------------------------------------------------------------------- #
step "2. Issue CA-signed DatasetCommitment over 3 records + VFT manifest"

# Three example records.
REC1=$(printf 'patient_a, dx=I25.10, treatment=metoprolol' | base64 -w0)
REC2=$(printf 'patient_b, dx=E11.9, treatment=metformin'  | base64 -w0)
REC3=$(printf 'patient_c, dx=J45.0, treatment=albuterol'  | base64 -w0)
SCHEMA_B64=$(printf '{"version":"v1","fields":["patient","dx","treatment"]}' | base64 -w0)

ISSUE_REQ=$(jq -n \
  --arg r1 "$REC1" --arg r2 "$REC2" --arg r3 "$REC3" \
  --arg schema "$SCHEMA_B64" \
  '{
    dataset_id: "clinical-cohort-2026-q1",
    record_bytes_b64: [$r1, $r2, $r3],
    manifest: {
      manifest_id: "manifest-clinical-q1-2026",
      model_card_uri: "https://acme.example.com/models/clinical-llm-v3/card",
      model_provider: "ACME Medical AI Inc",
      sources: [{
        source_id: "src-clinical-2026-q1",
        source_uri: "s3://acme-research/clinical-q1-2026",
        content_sha256: "a000000000000000000000000000000000000000000000000000000000000001",
        record_count: 3,
        tds_category: "privately-licensed-dataset",
        license: "TDS:Proprietary-Licensed",
        license_extra: "IRB-approved per protocol HRP-503-A; data use agreement DUA-2026-014.",
        max_epoch_participation: 2
      }],
      preprocessing: [],
      total_training_epochs: 2,
      base_model_sha256: "b000000000000000000000000000000000000000000000000000000000000002",
      training_window_start: "2026-01-01T00:00:00+00:00",
      training_window_end:   "2026-03-31T23:59:59+00:00",
      merkle_hash_alg: "poseidon2-bn254-t3",
      proof_backend: "halo2-ipa-2026",
      issued_at:    "2026-04-01T00:00:00+00:00",
      valid_until:  "2027-04-01T00:00:00+00:00"
    },
    schema_canonical_json_b64: $schema,
    use_deterministic_test_ca: true,
    test_ca_label: "demo-thread-14"
  }')

ISSUE_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$ISSUE_REQ" "$TEX_HOST/v1/zkprov/issue-commitment")

COMMITMENT=$(echo "$ISSUE_RESP" | jq '.commitment')
echo "$ISSUE_RESP" | jq '{
  commitment: {
    dataset_id: .commitment.dataset_id,
    manifest_root_hash: .commitment.manifest_root_hash,
    poseidon_root_hex: .commitment.poseidon_root_hex,
    audit_root_hex: .commitment.audit_root_hex,
    record_count: .commitment.record_count,
    ca_algorithm: .commitment.ca_algorithm,
    valid_until: .commitment.valid_until
  },
  tds_public_summary: .tds_public_summary
}'
DATASET_ID=$(echo "$COMMITMENT" | jq -r '.dataset_id')
ok "commitment dataset_id: $DATASET_ID"

# ----------------------------------------------------------------------- #
# 3. /prove                                                               #
# ----------------------------------------------------------------------- #
step "3. Generate ProvenanceProof for a model response"

RESPONSE_TEXT="Based on the clinical guidelines, the recommended first-line treatment is metoprolol 25mg BID for newly diagnosed stable angina without contraindications."
PROMPT_TEXT="What is the first-line treatment for newly diagnosed stable angina?"
WITNESS_B64=$(printf 'witness payload — opaque to ezkl, decoded inside the proving circuit' | base64 -w0)

PROVE_REQ=$(jq -n \
  --arg resp "$RESPONSE_TEXT" \
  --arg prompt "$PROMPT_TEXT" \
  --arg witness "$WITNESS_B64" \
  --argjson commitment "$COMMITMENT" \
  --argjson manifest "$(echo "$ISSUE_REQ" | jq '.manifest')" \
  '{
    response: $resp,
    prompt: $prompt,
    prompt_attributes: {
      topic: "cardiology",
      query_type: "treatment_recommendation"
    },
    model_commitment_hash: "c000000000000000000000000000000000000000000000000000000000000003",
    commitment: $commitment,
    manifest: $manifest,
    private_witness_b64: $witness,
    allow_shim_fallback: true,
    persist_to_store: true,
    tenant_id: "acme-medical"
  }')

PROVE_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$PROVE_REQ" "$TEX_HOST/v1/zkprov/prove")

echo "$PROVE_RESP" | jq '{
  backend, is_regulator_grade,
  proof_envelope_sha256
}'
PROOF_ENVELOPE_JSON=$(echo "$PROVE_RESP" | jq -r '.proof_envelope_json')
PROOF_ENVELOPE_SHA=$(echo "$PROVE_RESP" | jq -r '.proof_envelope_sha256')
PROOF_BACKEND=$(echo "$PROVE_RESP" | jq -r '.backend')
ok "proof envelope SHA-256: $PROOF_ENVELOPE_SHA"
warn "backend chosen: $PROOF_BACKEND (expected: deterministic-shim-v1 until Halo2-IPA circuit artifact ships)"

# Compute the response SHA-256 the verifier needs (cross-platform: BSD or GNU).
if command -v sha256sum >/dev/null 2>&1; then
  RESPONSE_HASH=$(printf '%s' "$RESPONSE_TEXT" | sha256sum | awk '{print $1}')
else
  RESPONSE_HASH=$(printf '%s' "$RESPONSE_TEXT" | shasum -a 256 | awk '{print $1}')
fi
ok "response SHA-256: $RESPONSE_HASH"

# ----------------------------------------------------------------------- #
# 4. /verify  (regulator_grade=false)                                     #
# ----------------------------------------------------------------------- #
step "4. Verify proof — six fail-closed checks, non-regulator-grade"

VERIFY_REQ=$(jq -n \
  --arg env "$PROOF_ENVELOPE_JSON" \
  --arg hash "$RESPONSE_HASH" \
  --argjson commitment "$COMMITMENT" \
  '{
    proof_envelope_json: $env,
    expected_commitment: $commitment,
    expected_response_sha256_hex: $hash,
    regulator_grade: false
  }')

VERIFY_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$VERIFY_REQ" "$TEX_HOST/v1/zkprov/verify")
echo "$VERIFY_RESP" | jq .
IS_VALID=$(echo "$VERIFY_RESP" | jq -r '.is_valid')
ok "is_valid: $IS_VALID"

# ----------------------------------------------------------------------- #
# 5. /verify  (regulator_grade=true ⇒ shim should be rejected)            #
# ----------------------------------------------------------------------- #
step "5. Verify proof — regulator_grade=true  ⇒  shim backend MUST be rejected"

VERIFY_REQ_REG=$(echo "$VERIFY_REQ" | jq '.regulator_grade = true')
VERIFY_RESP_REG=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$VERIFY_REQ_REG" "$TEX_HOST/v1/zkprov/verify")
echo "$VERIFY_RESP_REG" | jq '{
  is_valid, is_regulator_grade, reason
}'
REG_VALID=$(echo "$VERIFY_RESP_REG" | jq -r '.is_valid')
if [[ "$REG_VALID" == "false" ]]; then
  ok "shim correctly rejected under Article 53(1)(d) regulator-grade verification"
else
  echo "    ✗ FAIL: shim should have been rejected"
  exit 1
fi

# ----------------------------------------------------------------------- #
# 6. /aggregate  with LatticeFold+ post-quantum folding                   #
# ----------------------------------------------------------------------- #
step "6a. Mira parallel folding aggregation (ZKTorch, 6.2x faster proving)"

AGG_MIRA_REQ=$(jq -n \
  --arg env "$PROOF_ENVELOPE_JSON" \
  '{
    aggregation_id: "agg-clinical-2026-q1-mira",
    proof_envelopes_json: [$env],
    folding_scheme: "mira-parallel-2026",
    max_batch_size: 100,
    window_start: "2026-01-01T00:00:00+00:00",
    window_end:   "2026-03-31T23:59:59+00:00",
    epoch_index: 1
  }')
AGG_MIRA_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$AGG_MIRA_REQ" "$TEX_HOST/v1/zkprov/aggregate")
echo "$AGG_MIRA_RESP" | jq '{ folding_scheme, post_quantum, leaf_count }'
ok "Mira parallel folding aggregation OK (3x-10x proof-size reduction, 6.2x faster proving)"

step "6b. LatticeFold+ ℓ2-improved post-quantum folding (eprint 2026/721)"

AGG_REQ=$(jq -n \
  --arg env "$PROOF_ENVELOPE_JSON" \
  '{
    aggregation_id: "agg-clinical-2026-q1-latticefold",
    proof_envelopes_json: [$env],
    folding_scheme: "latticefold-plus-2026",
    max_batch_size: 100,
    window_start: "2026-01-01T00:00:00+00:00",
    window_end:   "2026-03-31T23:59:59+00:00",
    epoch_index: 1
  }')
AGG_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$AGG_REQ" "$TEX_HOST/v1/zkprov/aggregate")
echo "$AGG_RESP" | jq '{
  folding_scheme, post_quantum, leaf_count
}'
PQ=$(echo "$AGG_RESP" | jq -r '.post_quantum')
ok "post_quantum: $PQ (LatticeFold+ ℓ2-improved, Apr 19 2026)"

# ----------------------------------------------------------------------- #
# 7. /narrow  SCITT ARP                                                   #
# ----------------------------------------------------------------------- #
step "7. SCITT ARP narrowed claim (draft-hillier-scitt-arp-00, May 1 2026)"

NARROW_REQ=$(jq -n \
  --argjson manifest "$(echo "$ISSUE_REQ" | jq '.manifest')" \
  '{ manifest: $manifest, predicate: "data-volume-bucket" }')
NARROW_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$NARROW_REQ" "$TEX_HOST/v1/zkprov/narrow")
echo "$NARROW_RESP" | jq .
BUCKET=$(echo "$NARROW_RESP" | jq -r '.predicate_value')
ok "narrowed bucket: $BUCKET (no per-record information crosses the jurisdictional boundary)"

# Bonus: license-family narrow
NARROW2_RESP=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "$(echo "$NARROW_REQ" | jq '.predicate = "license-family-present"')" \
  "$TEX_HOST/v1/zkprov/narrow")
LICENSE_FAM=$(echo "$NARROW2_RESP" | jq -r '.predicate_value')
ok "license families present: $LICENSE_FAM"

# ----------------------------------------------------------------------- #
# 8. /proof/{envelope_sha256}   — durable retrieval                       #
# ----------------------------------------------------------------------- #
step "8. Retrieve stored proof from tex_provenance_proofs"
STORED=$(curl -fsS "$TEX_HOST/v1/zkprov/proof/$PROOF_ENVELOPE_SHA")
echo "$STORED" | jq '{
  envelope_sha256, backend, dataset_commitment_id, manifest_root_hash,
  is_regulator_grade, issued_at
}'

# ----------------------------------------------------------------------- #
# Summary                                                                 #
# ----------------------------------------------------------------------- #
printf "\n${GREEN}=== Thread 14 demo complete ===${NC}\n"
echo "  ZKPROV         arxiv 2506.20915"
echo "  VFT extensions arxiv 2510.16830 v3 (Dec 29 2025)"
echo "  VEIL           eprint 2026/683 (Apr 8 2026, 3% prover overhead PQ ZK)"
echo "  SP1 Hypercube  Succinct mainnet (Feb 19 2026)"
echo "  LatticeFold+   eprint 2026/721 (Apr 19 2026)"
echo "  Mira parallel  ZKTorch arxiv 2507.07031 (6.2x faster proving)"
echo "  Poseidon       Grassi et al. USENIX 2021, real BN254-t3 wired"
echo "  SCITT ARP      draft-hillier-scitt-arp-00 (May 1 2026)"
echo "  NABAOS         arxiv 2603.10060 (Mar 9 2026)"
echo "  EU AI Act      Article 53(1)(d) TDS template, enforcement Aug 2 2026"
