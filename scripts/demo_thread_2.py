#!/usr/bin/env python3
"""
Demo: Thread 2 — institutional governance-graph LTS wired into
EcosystemEngine step 4.

This script produces three EcosystemVerdicts and prints the signed
governance-log entries that back them:

  1. Active actor → PERMIT (legal transition logged)
  2. Fined actor → FORBID (sanctioned transition logged)
  3. Subagent of suspended parent → FORBID via inheritance per arxiv 2605.08460

Run from the repo root:
    python3 scripts/demo_thread_2.py
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Make src importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.institutional.governance_graph import GovernanceGraph
from tex.institutional.oracle import GovernanceOracle
from tex.ontology.entity_types import EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator


NOW = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)


def banner(s: str) -> None:
    print()
    print("=" * 78)
    print(s)
    print("=" * 78)


def build_manifest() -> dict:
    """An operator-style manifest with ontology-kind triggered_by values."""
    return {
        "schema_version": "v1",
        "graph_id": "demo_thread_2",
        "version": "1.0.0",
        "interpreter": {
            "name": "tex.institutional.oracle_controller",
            "version": "1.0.0",
        },
        "states": [
            {"state_id": "active", "description": "baseline compliant"},
            {"state_id": "fined", "description": "tier-1 fine in effect"},
            {"state_id": "suspended", "description": "removed from action"},
        ],
        "sanctions": [
            {
                "sanction_id": "fine_tier1",
                "description": "First fine: 35% of round profits, $200 floor",
                "cost_to_actor": 200.0,
                "cost_to_system": 0.0,
                "enforcement_action": "fine",
                "tier": 1,
                "fine_rate": 0.35,
                "fine_floor": 200.0,
            },
        ],
        "restorative_paths": [],
        "transitions": [
            {
                "rule_id": "TOOL_active",
                "from_state": "active",
                "to_state": "active",
                "triggered_by": EventKind.AGENT_INVOKES_TOOL.value,
                "edge_key": "TOOL_active:active->active",
            },
            {
                "rule_id": "TOOL_fined",
                "from_state": "fined",
                "to_state": "fined",
                "triggered_by": EventKind.AGENT_INVOKES_TOOL.value,
                "sanction_id": "fine_tier1",
                "edge_key": "TOOL_fined:fined->fined",
            },
        ],
    }


def build_engine(institutional_states: dict[str, str]) -> EcosystemEngine:
    provider = default_signature_provider()
    keypair = provider.generate_keypair("demo-key")
    provenance = CryptoProvenance(
        signing_key=keypair, signing_provider=provider
    )
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key,
        signing_provider=provider,
    )
    graph = InMemoryTemporalKG()
    projection = StateProjection(graph=graph)
    ontology = OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    )

    # Register entities used by the three scenarios.
    base = NOW - timedelta(minutes=1)
    graph.add_entity(
        entity_id="agent_active", kind="agent",
        attrs={"registered_at": base},
    )
    graph.add_entity(
        entity_id="agent_fined", kind="agent",
        attrs={"registered_at": base},
    )
    graph.add_entity(
        entity_id="agent_suspended_parent", kind="agent",
        attrs={"registered_at": base},
    )
    graph.add_entity(
        entity_id="agent_subagent", kind="agent",
        attrs={"registered_at": base, "spawned_by": "agent_suspended_parent"},
    )
    graph.add_entity(
        entity_id="tool_x", kind="tool",
        attrs={"registered_at": base},
    )

    manifest = GovernanceGraph.from_dict(build_manifest())
    oracle = GovernanceOracle(graph=manifest)

    return EcosystemEngine(
        ontology=ontology,
        graph=graph,
        projection=projection,
        events=ledger,
        provenance=provenance,
        enabled=True,
        governance_graph=manifest,
        oracle=oracle,
        institutional_states=institutional_states,
    )


def propose(actor: str) -> ProposedEvent:
    return ProposedEvent(
        event_kind=EventKind.AGENT_INVOKES_TOOL.value,
        actor_entity_id=actor,
        target_entity_id="tool_x",
        payload={"tool_id": "tool_x", "arguments": {"q": "demo"}},
        proposed_at=NOW,
    )


def dump_verdict(v) -> None:
    print(f"  kind:                 {v.kind.value}")
    print(f"  rationale:            {v.rationale}")
    print(f"  state_hash_before:    {v.ecosystem_state_hash_before[:32]}...")
    print(f"  axis.governance_legality: {v.axis_scores.governance_graph_legality}")


def dump_log(engine: EcosystemEngine) -> None:
    log = engine._governance_log
    if log is None:
        print("  (no governance log)")
        return
    print(f"  signing key id:       {log.signing_key_id}")
    print(f"  chain verifies:       {log.verify_chain()}")
    records = log.all_records()
    print(f"  total log records:    {len(records)}")
    for r in records:
        payload = r.payload
        print(f"    record_hash:        {r.record_hash[:32]}...")
        print(f"      is_legal:         {payload['is_legal']}")
        print(f"      effective_state:  {payload['effective_institutional_state']}")
        if payload.get("inherited_from"):
            print(f"      inherited_from:   {payload['inherited_from']}")
            print(f"      direct_state:    {payload['direct_institutional_state']}")
        if payload.get("sanction_id"):
            print(f"      sanction_id:      {payload['sanction_id']}")
        print(f"      signing_algorithm:{payload['signing_algorithm']}")


def main() -> int:
    banner("Scenario 1: ACTIVE actor invokes tool -> PERMIT")
    engine1 = build_engine({"agent_active": "active"})
    v1 = engine1.evaluate(propose("agent_active"))
    print("\nverdict:")
    dump_verdict(v1)
    print("\ngovernance log:")
    dump_log(engine1)

    banner("Scenario 2: FINED actor invokes tool -> FORBID (sanctioned)")
    engine2 = build_engine({"agent_fined": "fined"})
    v2 = engine2.evaluate(propose("agent_fined"))
    print("\nverdict:")
    dump_verdict(v2)
    print("\ngovernance log:")
    dump_log(engine2)

    banner("Scenario 3: SUBAGENT of SUSPENDED parent invokes tool -> FORBID (inherited)")
    engine3 = build_engine({
        "agent_suspended_parent": "suspended",
        "agent_subagent": "active",  # direct state is active, parent suspended
    })
    v3 = engine3.evaluate(propose("agent_subagent"))
    print("\nverdict:")
    dump_verdict(v3)
    print("\ngovernance log:")
    dump_log(engine3)
    print("  (per arxiv 2605.08460 — Cai/Zhang/Hei, May 8 2026)")

    banner("Summary")
    print(f"  S1 active actor:     {v1.kind.value}  (expected PERMIT)")
    print(f"  S2 fined actor:      {v2.kind.value}  (expected FORBID)")
    print(f"  S3 subagent inherit: {v3.kind.value}  (expected FORBID)")

    ok = (
        v1.kind.value == "permit"
        and v2.kind.value == "forbid"
        and v3.kind.value == "forbid"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
