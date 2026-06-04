"""
scenarios.py — the named tiers.

  smoke     — 12 agents, deterministic golden screenplay, every verdict path
              hit, fast regression net.
  reference — 200 agents (170 IdP + 30 shadow), Meridian Financial, realistic
              trickle. This is the tier the interface lives in: what "mapping…"
              maps on first run.
  soak      — 1,000 ramping toward 5,000, stochastic, for breaking the
              pipeline under cloud-native NHI-sprawl load.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    seed: int
    idp_agents: int
    shadow_agents: int
    mcp_agents: int
    total_actions: int
    stochastic: bool
    golden: bool          # use the fixed smoke screenplay
    assert_verdicts: bool # assert intended verdict (smoke) vs invariants only


SCENARIOS: dict[str, Scenario] = {
    "smoke": Scenario(
        name="smoke", seed=1, idp_agents=9, shadow_agents=3, mcp_agents=0,
        total_actions=12, stochastic=False, golden=True, assert_verdicts=True,
    ),
    "reference": Scenario(
        name="reference", seed=7, idp_agents=170, shadow_agents=30, mcp_agents=0,
        total_actions=400, stochastic=False, golden=False, assert_verdicts=True,
    ),
    "soak": Scenario(
        name="soak", seed=11, idp_agents=4500, shadow_agents=500, mcp_agents=40,
        total_actions=4000, stochastic=True, golden=False, assert_verdicts=False,
    ),
}


def get(name: str) -> Scenario:
    if name not in SCENARIOS:
        raise SystemExit(f"unknown scenario '{name}'. choose: {', '.join(SCENARIOS)}")
    return SCENARIOS[name]
