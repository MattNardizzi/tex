#!/usr/bin/env bash
# scripts/demo_thread_7_eightaxis.sh
#
# Thread 7 demo. Constructs a fully-wired EcosystemEngine, evaluates
# one tool-call event, and pretty-prints the resulting verdict so the
# operator can see all four newly-wired axes (contracts, causal, drift,
# systemic) populated from real collaborators.
#
# The Thread 7 wedge: every published competitor (Microsoft Agent 365 +
# AGT, Zenity, Noma) gives one decision per event. Tex gives an
# eight-axis decomposition cryptographically bound to the evidence chain.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Default ON for Thread 7.1 — ProbGuard PCTL now ships a working
# scorer, so flipping the flag is the realistic operator setting.
export TEX_ECOSYSTEM_SYSTEMIC="${TEX_ECOSYSTEM_SYSTEMIC:-1}"

python - <<'PY'
"""
Thread 7 end-to-end demo.

Constructs an engine with all four Thread-7-wired collaborators,
admits a seed event, then admits a chained event that probes every
axis. Prints the verdict + EcosystemAxisScores.

No network, no API key, pure local Python.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

from tex.causal.chief import HierarchicalCausalGraph
from tex.contracts.contract import BehavioralContract
from tex.contracts.runtime_enforcement import ContractEnforcer
from tex.drift.signal_registry import DriftSignalRegistry
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator
from tex.systemic.risk_evaluator import SystemicRiskEvaluator


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def main() -> None:
    banner("Thread 7 — Ecosystem engine eight-axis composition")
    print(
        "  Constructs a fully-wired engine and admits one event. The"
    )
    print(
        "  verdict's EcosystemAxisScores shows all four newly-wired"
    )
    print(
        "  axes populated from real collaborators."
    )

    now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
    flag = os.environ.get("TEX_ECOSYSTEM_SYSTEMIC", "0")
    print()
    print(f"  TEX_ECOSYSTEM_SYSTEMIC = {flag!r}")
    print(
        "  (default off — Thread 9 implements the systemic scorer; today"
    )
    print(
        "  the call site is wired but the scorer raises NotImplementedError)"
    )

    # ---- collaborators -------------------------------------------------
    signing_provider = default_signature_provider()
    signing_keypair = signing_provider.generate_keypair("demo-thread-7")
    provenance = CryptoProvenance(
        signing_key=signing_keypair,
        signing_provider=signing_provider,
    )

    graph = InMemoryTemporalKG()
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

    ledger = InMemoryLedger(
        verifying_public_key=signing_keypair.public_key,
        signing_provider=signing_provider,
    )

    contract = BehavioralContract.make(
        contract_id="demo_benign",
        agent_id="agent_demo",
        description="benign demo contract — exercises Step 3 wiring",
        precondition_ltl="true",
        hard_invariants_ltl=("true",),
        covered_event_kinds=("*",),
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
        contracts=ContractEnforcer(contracts=(contract,)),
        causal=HierarchicalCausalGraph(),
        drift=DriftSignalRegistry(seed_defaults=True),
        systemic=SystemicRiskEvaluator(),
        enabled=True,
    )

    # ---- seed event so the chained event has a real upstream id -------
    seed = engine.evaluate(
        ProposedEvent(
            event_kind=EventKind.AGENT_INVOKES_TOOL.value,
            actor_entity_id="agent_demo",
            target_entity_id="tool_demo",
            payload={"tool_id": "tool_demo", "arguments": {"q": "seed"}},
            proposed_at=now,
        )
    )

    banner("Seed event verdict")
    print(f"  kind:        {seed.kind.value}")
    print(f"  event_id:    {seed.proposed_event_id}")
    print(f"  rationale:   {seed.rationale}")

    # ---- chained event under test -------------------------------------
    proposed = ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id="agent_demo",
        target_entity_id="tool_demo",
        payload={"tool_id": "tool_demo", "arguments": {"q": "thread7-demo"}},
        proposed_at=now + timedelta(seconds=1),
        upstream_event_ids=(seed.proposed_event_id,),
    )

    verdict = engine.evaluate(proposed)

    banner("Thread 7 event verdict — all four axes populated")
    axes = verdict.axis_scores
    payload = {
        "verdict_kind": verdict.kind.value,
        "proposed_event_id": verdict.proposed_event_id,
        "rationale": verdict.rationale,
        "state_hash_before": verdict.ecosystem_state_hash_before,
        "state_hash_after": verdict.ecosystem_state_hash_after,
        "evidence_record_id": verdict.evidence_record_id,
        # Thread 7.1 — RiskGate viability scalar + GAAT enforcement tier
        "viability_index": axes.viability_index,
        "graduated_level": axes.graduated_level.value,
        "axis_scores": {
            "contract_violation_severity": axes.contract_violation_severity,
            "governance_graph_legality": axes.governance_graph_legality,
            "causal_attribution_confidence": axes.causal_attribution_confidence,
            "drift_delta": axes.drift_delta,
            "systemic_risk_under_event": axes.systemic_risk_under_event,
            "bounded_compromise_score": axes.bounded_compromise_score,
        },
    }
    print(json.dumps(payload, indent=2, default=str))

    # Thread 7.1 — render the same verdict in the GAAT-compatible
    # OpenTelemetry span schema so operators can drop the dict into
    # their existing OTel exporter.
    banner("GAAT-compatible OpenTelemetry span (Thread 7.1)")
    from tex.observability.governance_span import verdict_to_otel_attributes
    span_attrs = verdict_to_otel_attributes(verdict)
    print(json.dumps(span_attrs, indent=2, default=str))

    banner("What's new in Thread 7")
    print(
        "  Steps 3 / 5 / 6 / 7 used to return hardcoded 0.0 (the engine"
    )
    print(
        "  was a 2-of-8 implementation: only ontology + projection were"
    )
    print(
        "  live). Thread 7 wires all four into real collaborators:"
    )
    print()
    print(
        "    Step 3 — ContractEnforcer.compliance_scores (Bhardwaj ABC"
    )
    print(
        "             arxiv 2602.22302) → contract_violation_severity"
    )
    print(
        "    Step 5 — HierarchicalCausalGraph.fast_attribute (technique"
    )
    print(
        "             inspired by MASPrism arxiv 2605.07509, May 8 2026)"
    )
    print(
        "             → causal_attribution_confidence at <5ms p99"
    )
    print(
        "    Step 6 — evaluate_drift = BOCPD (Adams/MacKay) +"
    )
    print(
        "             anytime-valid e-process (Drift-to-Action arxiv"
    )
    print(
        "             2603.08578) → drift_delta blended"
    )
    print(
        "    Step 7 — SystemicRiskEvaluator.score call site behind the"
    )
    print(
        "             TEX_ECOSYSTEM_SYSTEMIC flag (Thread 9 implements"
    )
    print(
        "             ProbGuard arxiv 2508.00500 or GeomHerd arxiv"
    )
    print(
        "             2605.11645)"
    )
    print()
    print(
        "  Whole-engine p99 latency budget: 50ms (verified by"
    )
    print(
        "  tests/test_thread7_integration.py)."
    )


if __name__ == "__main__":
    main()
PY
