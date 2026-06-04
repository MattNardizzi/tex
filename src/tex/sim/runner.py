"""
runner.py — orchestrate a scenario end to end against a running Tex backend.

Flow:
  1. generate the estate (the population the backend is watching)
  2. ignite discovery and assert the inventory mapped ("mapping…")
  3. drive the action plan into the real /evaluate (the live governing)
  4. assert each outcome: verdict, sealed, proof round-trip (sampled)
  5. assert the voice is speaking and the chain is intact
  6. emit the ten-second report (+ JSON for the cockpit)

Dry-run (no backend) prints the estate and the planned action stream so the
generator and screenplay can be inspected offline.
"""

from __future__ import annotations

import sys
from collections import Counter

from tex.sim import scenarios
from tex.sim.behavior import golden_smoke_plan, plan_actions
from tex.sim.client import TexClient, TexClientError
from tex.sim.estate import generate_estate
from tex.sim.oracle import (
    check_chain_integrity,
    check_inventory,
    check_proof_roundtrip,
    check_sealed,
    check_verdict,
    check_voice,
)
from tex.sim.report import Report


def run(
    scenario_name: str,
    *,
    base_url: str = "http://localhost:8000",
    api_key: str | None = None,
    report_path: str | None = None,
    proof_sample: int = 20,
    dry_run: bool = False,
) -> Report:
    sc = scenarios.get(scenario_name)
    estate = generate_estate(
        seed=sc.seed, idp_agents=sc.idp_agents,
        shadow_agents=sc.shadow_agents, mcp_agents=sc.mcp_agents,
    )
    report = Report(scenario=sc.name, org=estate.org_name, tenant_id=estate.tenant_id,
                    seed=sc.seed, estate_summary=estate.summary())

    plan = golden_smoke_plan(estate) if sc.golden else plan_actions(
        estate, total_actions=sc.total_actions, seed=sc.seed, stochastic=sc.stochastic)

    if dry_run:
        print(report.console())
        print("\nPLANNED ACTION STREAM (first 24):")
        for p in plan[:24]:
            print(f"  [{p.seq:03d}] {p.intended_verdict:8s} {p.agent.department:11s} "
                  f"{p.agent.external_id[:34]:34s} :: {p.content[:54]}")
        print(f"  … {len(plan)} actions total")
        return report

    client = TexClient(base_url=base_url, api_key=api_key)

    # 0. liveness
    try:
        client.health()
    except TexClientError as e:
        print(f"backend not reachable at {base_url} ({e}). Is `uvicorn tex.main:app` up "
              f"with TEX_SANDBOX=1? Use --dry-run to inspect offline.", file=sys.stderr)
        raise SystemExit(2)

    # 1-2. ignite + inventory ("mapping…")
    try:
        status = client.discovery_status(estate.tenant_id)
        if not status.get("ignited"):
            client.ignite(estate.tenant_id)
    except TexClientError:
        pass  # surface route may differ; inventory check still runs
    report.add(check_inventory(client, estate_total(estate), len(estate.shadow_agents)))

    # 3-4. drive actions through the real PDP + assert
    vc: Counter[str] = Counter()
    proofs_done = 0
    for p in plan:
        payload = p.to_evaluate_payload(estate.tenant_id)
        try:
            resp = client.evaluate(payload)
        except TexClientError as e:
            from tex.sim.oracle import Check, FAIL
            report.add(Check(f"evaluate[{p.seq}]", FAIL, f"{e.status}: {e.body[:120]}"))
            continue
        vc[str(resp.get("verdict"))] += 1
        if sc.assert_verdicts:
            report.add(check_verdict(p, resp))
        report.add(check_sealed(p, resp))
        # Proof round-trips are the costliest check; sample them.
        if proofs_done < proof_sample and (sc.golden or p.intended_verdict != "PERMIT"):
            report.add(check_proof_roundtrip(client, p, resp))
            proofs_done += 1
    report.verdict_counts = dict(vc)

    # 5. voice + chain integrity
    report.add(check_voice(client))
    report.add(check_chain_integrity(client))

    from datetime import UTC, datetime
    report.finished_at = datetime.now(UTC).isoformat()
    if report_path:
        report.write_json(report_path)
    return report


def estate_total(estate) -> int:
    return len(estate.agents)
