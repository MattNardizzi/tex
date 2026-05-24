#!/usr/bin/env bash
# scripts/demo_thread_8_intervention.sh
#
# Thread 8 demo. Constructs an EcosystemEngine with the Step 8
# intervention surface fully wired (BoundedCompromiseCalculator +
# candidate interventions + restorative executor), evaluates two
# events, and pretty-prints both verdicts so the operator can see:
#
#   - Axes clean -> PERMIT, bounded_compromise_score = 0.0.
#   - Axes dirty (contract severity high) -> SANCTION, with the
#     intervention's CompromiseCertificate carried in the audit chain.
#
# The Thread 8 wedge: every published competitor (Microsoft Agent
# Governance Toolkit, Microsoft Agent 365, Zenity, Noma) either stops
# at "block unsafe action" or routes remediation through tenant-admin
# workflows. Tex selects the lowest-cost intervention that satisfies
# the AAF Theorem 5 bound (arxiv 2512.18561 v3 §5.4), emits an
# ML-DSA-signed bounded-compromise certificate, and commits the audit
# chain in a single request.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python - <<'PY'
"""
Thread 8 end-to-end demo.

Constructs an engine with:
  - Thread 8 BoundedCompromiseCalculator (alpha=0.05, H=25, eta*=0.10).
  - Two candidate interventions: one too-weak to satisfy the bound,
    one cost-minimum satisfier.
  - A fake contracts collaborator that drives
    contract_violation_severity to 1.0 on the second request so the
    axis-derived FORBID predicate fires.
  - A separate governance log (ML-DSA / ECDSA-P256 / hybrid via
    tex.pqcrypto.algorithm_agility) for intervention records.

Then evaluates two events:
  1) Clean event -> PERMIT.
  2) Dirty event (forced by the fake contracts collaborator) ->
     SANCTION + recommended_intervention_id + signed log record.

No network, no API key, pure local Python. The "curl-equivalent" is
the single engine.evaluate() call per event; production deployments
route this through /v1/guardrail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from tex.contracts.runtime_enforcement import ComplianceScores
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.institutional.governance_log import GovernanceLog
from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
from tex.intervention.kinds import Intervention, InterventionKind
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


def banner(s: str) -> None:
    print("\n" + "=" * 72)
    print(s)
    print("=" * 72)


# ---------- crypto + ledger + graph setup --------------------------------
now = datetime(2026, 5, 19, 12, 0, 0, tzinfo=UTC)
signing_provider = default_signature_provider()
signing_key = signing_provider.generate_keypair("demo-thread8-events")
provenance = CryptoProvenance(
    signing_key=signing_key, signing_provider=signing_provider,
)
graph = InMemoryTemporalKG()
ledger = InMemoryLedger(
    verifying_public_key=signing_key.public_key,
    signing_provider=signing_provider,
)

graph.add_entity(
    entity_id="agent_demo",
    kind="agent",
    attrs={"registered_at": now - timedelta(minutes=1)},
)
graph.add_entity(
    entity_id="tool_demo",
    kind="tool",
    attrs={"registered_at": now - timedelta(minutes=1)},
)

# Separate signing key for the intervention governance log.
iv_log_keypair = signing_provider.generate_keypair("demo-thread8-iv-log")
iv_log = GovernanceLog(
    signing_key_id="demo-thread8-iv-log",
    signing_keypair=iv_log_keypair,
    signing_provider=signing_provider,
)


# ---------- contracts collaborator (state-flippable) ---------------------


@dataclass
class FlippableContracts:
    """Returns clean compliance scores on the first event, dirty on
    the second, simulating a real contract violation between calls."""

    severity_on: bool = False

    def compliance_scores(self, *, agent_id, proposed_event, current_state):
        return ComplianceScores(
            c_hard=0.0 if self.severity_on else 1.0,
            c_soft=1.0,
            contracts_evaluated=1,
            constraints_evaluated=1,
        )


contracts = FlippableContracts(severity_on=False)


# ---------- Thread 8 wire-in ---------------------------------------------

calc = BoundedCompromiseCalculator()  # defaults: α=0.05, H=25, η*=0.10

candidates = (
    Intervention(
        intervention_id="iv_weak",
        kind=InterventionKind.REWARD_SHAPE,
        target_entity_id="agent_demo",
        parameters={"shape": "-0.05/step"},
        expected_cost_to_system=0.01,
        expected_cost_to_adversary=0.5,  # fails the bound at g_max>=0.5
        rationale="cheap but weak",
    ),
    Intervention(
        intervention_id="iv_satisfier",
        kind=InterventionKind.TRUST_SCORE_REDUCE,
        target_entity_id="agent_demo",
        parameters={"delta": -0.3},
        expected_cost_to_system=0.05,
        expected_cost_to_adversary=15.0,  # satisfies the bound
        rationale="cost-minimum bound satisfier",
    ),
)

engine = EcosystemEngine(
    ontology=OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    ),
    graph=graph,
    projection=StateProjection(graph=graph),
    events=ledger,
    provenance=provenance,
    contracts=contracts,
    governance_log=iv_log,
    intervention_calc=calc,
    candidate_interventions=candidates,
    target_compromise_ratio=0.5,
    enabled=True,
)


def evaluate(label: str, proposed: ProposedEvent) -> None:
    """Submit, pretty-print the verdict, and surface the math."""
    banner(label)
    verdict = engine.evaluate(proposed)
    print(json.dumps(
        {
            "kind": verdict.kind.value,
            "proposed_event_id": verdict.proposed_event_id,
            "recommended_intervention_id": verdict.recommended_intervention_id,
            "rationale": verdict.rationale,
            "axis_scores": {
                "contract_violation_severity": verdict.axis_scores.contract_violation_severity,
                "governance_graph_legality": verdict.axis_scores.governance_graph_legality,
                "causal_attribution_confidence": verdict.axis_scores.causal_attribution_confidence,
                "drift_delta": verdict.axis_scores.drift_delta,
                "systemic_risk_under_event": verdict.axis_scores.systemic_risk_under_event,
                "bounded_compromise_score": verdict.axis_scores.bounded_compromise_score,
                "viability_index": verdict.axis_scores.viability_index,
            },
        },
        indent=2,
    ))


# ---------- Request 1: clean axes -> PERMIT -------------------------------

evaluate(
    "Request 1: clean event (contracts pass) -> PERMIT",
    ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id="agent_demo",
        target_entity_id="tool_demo",
        payload={"tool_id": "tool_demo", "arguments": {"q": "hello"}},
        proposed_at=now,
    ),
)


# ---------- Flip the dirty bit and resubmit -> SANCTION -------------------

contracts.severity_on = True

evaluate(
    "Request 2: contract violation -> Step 8 fires -> SANCTION",
    ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id="agent_demo",
        target_entity_id="tool_demo",
        payload={"tool_id": "tool_demo", "arguments": {"q": "world"}},
        proposed_at=now + timedelta(seconds=1),
    ),
)


# ---------- Inspect the audit chain --------------------------------------

banner("Governance-log audit chain — signed intervention records")
records = iv_log.all_records()
print(f"records: {len(records)}")
print(f"chain verifies: {iv_log.verify_chain()}")
if records:
    print("\nlast record payload (kind = 'intervention_applied'):")
    last = records[-1]
    # The ledger stores a record_hash; we surface the kind only here.
    # Production callers consume via iv_log.stream_after / the
    # FoundationDB snapshot API.
    print(f"  event_id:       {last.event_id}")
    print(f"  sequence:       {last.sequence_number}")
    print(f"  event_kind:     {last.kind}")
    print(f"  signing_key_id: demo-thread8-iv-log")
    print("  payload (canonicalised milli-unit ints visible):")
    print(json.dumps(last.payload, indent=4, sort_keys=True, default=str))

banner("Done. Thread 8 wedge demonstrated.")
print("Math: η* = αH/(λH−g_max). For iv_satisfier (λH=15, g_max≈0.5),")
print("  η* = 0.05·25 / (15−0.5) ≈ 0.0862, so bounded_compromise_score")
print("  = 1 − η* ≈ 0.914. The audit-chain record carries the certificate")
print("  for a regulator to verify offline.")
PY
