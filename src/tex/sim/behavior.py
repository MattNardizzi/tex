"""
behavior.py — the estate, alive.

Discovery answers *who exists*. This answers *what they do*, on a clock. Each
agent emits actions at a realistic cadence; each action is rendered from its
department's action profiles into an EvaluateRequestDTO and fed to the real
PDP. The verdict mix (mostly PERMIT, a steady trickle of ABSTAIN, the rare
FORBID) emerges from real recognizers over authored content — it is not
scripted into the surface.

Two modes:

  * deterministic (default) — a seeded screenplay. The same run produces the
    same action sequence, so "does ABSTAIN pop the way it should" is a
    repeatable assertion. Used by smoke and reference.

  * stochastic (soak) — Poisson-ish arrivals with per-agent jitter, different
    every run, for hunting breakage under messy load.

The driver yields PlannedAction records; the runner is what actually POSTs
them and hands the result to the oracle. Keeping planning and execution
separate means the same plan can be dry-run, replayed, or asserted.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterator

from tex.sim import actions as ACT
from tex.sim.estate import Estate, SimAgent


@dataclass(frozen=True, slots=True)
class PlannedAction:
    seq: int
    agent: SimAgent
    action_type: str
    content: str
    channel: str
    recipient: str | None
    intended_verdict: str
    profile: str

    def to_evaluate_payload(self, tenant_id: str) -> dict:
        """Render the exact EvaluateRequestDTO wire shape."""
        return {
            "request_id": str(uuid.uuid4()),
            "action_type": self.action_type,
            "content": self.content,
            "recipient": self.recipient,
            "channel": self.channel,
            "environment": "prod",
            "requested_at": datetime.now(UTC).isoformat(),
            "session_id": f"sim-{self.agent.external_id}",
            "metadata": {
                "sim": True,
                "sim_profile": self.profile,
                "sim_intended_verdict": self.intended_verdict,
                "agent_external_id": self.agent.external_id,
                "agent_department": self.agent.department,
                "agent_plane": self.agent.plane,
                "agent_risk": self.agent.risk_profile,
            },
            # The runtime-identity block turns the adjudication into a
            # controlled discovery signal too — exactly as a real agent SDK
            # would attach it.
            "agent_identity": {
                "external_agent_id": self.agent.external_id,
                "agent_name": self.agent.name,
                "tenant_id": tenant_id,
                "owner": self.agent.owner,
                "environment": "prod",
                "data_scopes": list(self.agent.scopes),
            },
        }

    def to_decide_payload(self, tenant_id: str) -> dict:
        """Render the DecideRequest wire shape for POST /v1/govern/decide — the
        live PEP path. It carries only what a real enforcement point observed:
        the action edge plus the agent handle (external id). The agent must
        already be sealed in the registry (discovery seals a birth at ignition);
        an unknown agent fails closed at the floor, which is the honest result."""
        return {
            "action_type": self.action_type,
            "content": self.content,
            "channel": self.channel,
            "environment": "prod",
            "recipient": self.recipient,
            "agent_external_id": self.agent.external_id,
            "session_id": f"sim-{self.agent.external_id}",
            "tenant_id": tenant_id,
        }


def plan_actions(
    estate: Estate,
    *,
    total_actions: int = 400,
    seed: int = 7,
    stochastic: bool = False,
    forbid_rate: float = 0.06,
    abstain_rate: float = 0.18,
) -> list[PlannedAction]:
    """
    Build an action plan over the estate.

    Verdict mix is steered by which action profile is chosen, biased by agent
    risk: high/critical and shadow agents are likelier to attempt the actions
    that draw ABSTAIN/FORBID. The exact rates are targets, not guarantees — the
    real PDP decides, and the oracle checks the real outcome.
    """
    rng = random.Random(seed)
    agents = list(estate.agents)
    # Weight agent selection by risk so risky agents act more (and more loudly).
    weights = [
        3.0 if a.is_shadow else (2.0 if a.risk_profile == "critical" else 1.4 if a.risk_profile == "high" else 1.0)
        for a in agents
    ]
    plan: list[PlannedAction] = []
    for seq in range(total_actions):
        agent = rng.choices(agents, weights=weights, k=1)[0]
        # Decide intended verdict class for this tick.
        roll = rng.random()
        risky = agent.is_shadow or agent.risk_profile in ("critical", "high")
        if risky and roll < forbid_rate:
            want = ACT.FORBID
        elif roll < forbid_rate + abstain_rate:
            want = ACT.ABSTAIN
        else:
            want = ACT.PERMIT

        # Choose a profile this agent plausibly performs that yields `want`.
        candidates = [
            t for t in ACT.TEMPLATES
            if t.intended_verdict == want and (t.profile in agent.action_profiles or want != ACT.PERMIT)
        ]
        if not candidates:
            candidates = [t for t in ACT.TEMPLATES if t.intended_verdict == ACT.PERMIT]
        template = rng.choice(candidates)
        rendered = ACT.render(template, rng)
        plan.append(
            PlannedAction(
                seq=seq,
                agent=agent,
                action_type=str(rendered["action_type"]),
                content=str(rendered["content"]),
                channel=str(rendered["channel"]),
                recipient=rendered["recipient"],  # type: ignore[arg-type]
                intended_verdict=str(rendered["intended_verdict"]),
                profile=str(rendered["profile"]),
            )
        )

    if stochastic:
        rng.shuffle(plan)
        plan = [PlannedAction(seq=i, **{k: getattr(p, k) for k in
                ("agent", "action_type", "content", "channel", "recipient", "intended_verdict", "profile")})
                for i, p in enumerate(plan)]
    return plan


def golden_smoke_plan(estate: Estate) -> list[PlannedAction]:
    """
    A tiny fixed screenplay that hits each verdict path exactly once per agent
    class, for the deterministic regression net. Order is stable.
    """
    rng = random.Random(1)
    picks = [
        ("controls_bypass_attempt", ACT.FORBID),
        ("payment_movement", ACT.FORBID),
        ("external_sharing", ACT.ABSTAIN),
        ("unauthorized_commitment", ACT.ABSTAIN),
        ("reconciliation_read", ACT.PERMIT),
        ("evidence_read", ACT.PERMIT),
        ("destructive_ops_attempt", ACT.FORBID),
        ("deploy_action", ACT.ABSTAIN),
        ("crm_read", ACT.PERMIT),
        ("pii_read", ACT.FORBID),
        ("customer_email", ACT.ABSTAIN),
        ("log_read", ACT.PERMIT),
    ]
    agents = list(estate.agents)
    plan: list[PlannedAction] = []
    for i, (profile, _want) in enumerate(picks):
        agent = agents[i % len(agents)]
        t = ACT._BY_PROFILE[profile][0]
        r = ACT.render(t, rng)
        plan.append(PlannedAction(
            seq=i, agent=agent, action_type=str(r["action_type"]), content=str(r["content"]),
            channel=str(r["channel"]), recipient=r["recipient"],  # type: ignore[arg-type]
            intended_verdict=str(r["intended_verdict"]), profile=str(r["profile"]),
        ))
    return plan
