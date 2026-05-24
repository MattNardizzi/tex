#!/usr/bin/env bash
# Thread 9 demo: POST /v1/ecosystem/twin/simulate
#
# Run against a live tex service (default localhost:8000).
# Set TEX_HOST to override.

set -euo pipefail

TEX_HOST="${TEX_HOST:-http://localhost:8000}"

echo "==> POST ${TEX_HOST}/v1/ecosystem/twin/simulate"
echo

curl -sS -X POST "${TEX_HOST}/v1/ecosystem/twin/simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "fork_timestamp_iso": "2026-05-20T15:00:00+00:00",
    "perturbation": {
      "compromise_delta": 0.35,
      "drift_delta": 0.20,
      "label": "what_if_admit_high_risk_action_demo"
    },
    "steps": 16,
    "cascade_seed_event_id": "evt_seed_demo",
    "cascade_edges": [
      {
        "from_event_id": "evt_seed_demo",
        "to_event_id":   "evt_amplify_1",
        "propagation_probability": 0.75,
        "spark_to_fire_class": "cascade_amplification",
        "stpa_uca_class":      "PROVIDED_WHEN_NOT_NEEDED"
      },
      {
        "from_event_id": "evt_amplify_1",
        "to_event_id":   "evt_amplify_2",
        "propagation_probability": 0.6,
        "spark_to_fire_class": "consensus_inertia",
        "stpa_uca_class":      "WRONG_TIMING"
      },
      {
        "from_event_id": "evt_seed_demo",
        "to_event_id":   "evt_topology_break",
        "propagation_probability": 0.4,
        "spark_to_fire_class": "topological_sensitivity",
        "stpa_uca_class":      "NOT_PROVIDED"
      }
    ]
  }' | python3 -m json.tool

echo
echo "==> Done. Key fields to inspect:"
echo "    trajectory.twin_run_id      — SHA-256-derived run id"
echo "    trajectory.steps[*].fused_systemic_score with conformal_lower/upper"
echo "    cascade_paths sorted descending by aggregate_probability"
echo "    elapsed_ms"
