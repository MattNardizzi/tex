"""
live.py — the estate, alive over wall-clock time.

The scenario runners (smoke / reference / soak) fire a fixed batch of actions
as fast as they can, assert exact verdicts, and exit. That answers "does the
pipeline produce the right verdict on this content right now." It does NOT
answer "does Tex hold up while it governs a living estate for a day or two" —
which is the question you stress-test against and finish the interface on.

This module is that long-running mode. It:

  1. ignites discovery so Tex maps the synthetic estate (the "mapping…" beat),
  2. optionally ONBOARDS the governed cohort the way a real operator would —
     promotes the IdP-discovered agents to a verified trust tier through the
     real PATCH /v1/agents route, while the shadow cohort stays UNVERIFIED,
  3. drives a wall-clock-paced stochastic action stream into the real
     /evaluate at a configurable arrival rate, for a configurable duration (or
     until Ctrl-C),
  4. prints a periodic heartbeat — uptime, decision count, live verdict mix,
     error rate, latency percentiles — and runs the chain-integrity / voice /
     seal invariants, surfacing any failure loudly.

Nothing here stamps a verdict or fakes maturation. The estate matures through
Tex's own state: the per-agent identity freshness penalty expires after an
hour of real time, and behavioral cold-start clears once an agent accumulates
enough sealed decisions. Over a long run you watch the verdict mix shift from
"holds almost everything" at ignition toward a realistic steady state — while
shadow and high-risk agents keep drawing ABSTAIN / FORBID.

  python -m tex.sim live reference --rate 1.5 --duration 2d
  python -m tex.sim live reference --onboard none   # stress the cold path
  python -m tex.sim live smoke --rate 5 --duration 10m --heartbeat 30
"""

from __future__ import annotations

import random
import signal
import statistics
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from tex.sim import actions as ACT
from tex.sim import scenarios
from tex.sim.behavior import PlannedAction
from tex.sim.client import TexClient, TexClientError
from tex.sim.estate import Estate, SimAgent, generate_estate
from tex.sim.oracle import check_chain_integrity, check_voice

# Trust tiers we are willing to promote a governed agent to. UNVERIFIED is the
# discovered-but-not-yet-trusted default; it is never an onboarding target.
_ONBOARD_TIERS = {"none", "standard", "trusted", "privileged"}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class LiveConfig:
    scenario: str = "reference"      # estate sizing only; verdicts are not asserted
    rate: float = 1.0                # mean actions/second across the whole estate
    duration_seconds: float | None = None   # None => run until Ctrl-C
    heartbeat_seconds: float = 60.0
    onboard: str = "standard"        # none | standard | trusted | privileged
    forbid_rate: float = 0.06        # target share of attempts that reach for FORBID content
    abstain_rate: float = 0.18       # target share that reach for ABSTAIN content
    seed: int = 7
    max_latency_samples: int = 2000  # bounded ring buffer for percentiles


def parse_duration(text: str | None) -> float | None:
    """'2d' -> 172800.0, '36h', '90m', '3600s', '3600' (seconds). None/'' => forever."""
    if not text:
        return None
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    unit = text[-1]
    if unit in units:
        value = float(text[:-1])
        return value * units[unit]
    return float(text)  # bare number => seconds


# --------------------------------------------------------------------------- #
# Live statistics (bounded, cheap to update every tick)
# --------------------------------------------------------------------------- #
@dataclass
class LiveStats:
    started_at: float = field(default_factory=time.monotonic)
    total: int = 0
    errors: int = 0
    verdicts: Counter = field(default_factory=Counter)
    sealed: int = 0
    unsealed: int = 0
    latencies_ms: deque = field(default_factory=lambda: deque(maxlen=2000))
    # since-last-heartbeat deltas
    _last_total: int = 0
    _last_errors: int = 0
    last_error_detail: str = ""

    def record(self, resp: dict, latency_ms: float) -> None:
        self.total += 1
        self.verdicts[str(resp.get("verdict"))] += 1
        if resp.get("decision_id") and resp.get("evidence_hash"):
            self.sealed += 1
        else:
            self.unsealed += 1
        self.latencies_ms.append(latency_ms)

    def record_error(self, detail: str) -> None:
        self.total += 1
        self.errors += 1
        self.last_error_detail = detail

    def _pct(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        k = max(0, min(len(ordered) - 1, int(round(p * (len(ordered) - 1)))))
        return ordered[k]

    def heartbeat_line(self) -> str:
        up = time.monotonic() - self.started_at
        d_total = self.total - self._last_total
        d_err = self.errors - self._last_errors
        self._last_total, self._last_errors = self.total, self.errors
        mix = "  ".join(f"{k[:3]}={self.verdicts[k]}" for k in ("PERMIT", "ABSTAIN", "FORBID")
                        if k in self.verdicts) or "—"
        rate = d_total / max(1e-9, self.heartbeat_window) if hasattr(self, "heartbeat_window") else 0.0
        return (f"  +{_hms(up)}  decisions={self.total} (+{d_total})  "
                f"mix[{mix}]  sealed={self.sealed}/{self.sealed + self.unsealed}  "
                f"errors={self.errors} (+{d_err})  "
                f"p50={self._pct(0.50):.0f}ms p95={self._pct(0.95):.0f}ms")

    def summary(self) -> dict[str, Any]:
        total_sealable = self.sealed + self.unsealed
        return {
            "uptime_seconds": round(time.monotonic() - self.started_at, 1),
            "total_decisions": self.total,
            "errors": self.errors,
            "verdict_mix": dict(self.verdicts),
            "sealed": self.sealed,
            "unsealed": self.unsealed,
            "seal_rate": round(self.sealed / total_sealable, 4) if total_sealable else None,
            "latency_p50_ms": round(self._pct(0.50), 1),
            "latency_p95_ms": round(self._pct(0.95), 1),
            "latency_p99_ms": round(self._pct(0.99), 1),
        }


def _hms(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


# --------------------------------------------------------------------------- #
# Action generation (one tick at a time — mirrors behavior.plan_actions logic)
# --------------------------------------------------------------------------- #
def _agent_weights(agents: list[SimAgent]) -> list[float]:
    return [
        3.0 if a.is_shadow else
        (2.0 if a.risk_profile == "critical" else
         1.4 if a.risk_profile == "high" else 1.0)
        for a in agents
    ]


def _next_action(estate: Estate, rng: random.Random, seq: int,
                 forbid_rate: float, abstain_rate: float,
                 agents: list[SimAgent], weights: list[float]) -> PlannedAction:
    agent = rng.choices(agents, weights=weights, k=1)[0]
    roll = rng.random()
    risky = agent.is_shadow or agent.risk_profile in ("critical", "high")
    if risky and roll < forbid_rate:
        want = ACT.FORBID
    elif roll < forbid_rate + abstain_rate:
        want = ACT.ABSTAIN
    else:
        want = ACT.PERMIT
    candidates = [
        t for t in ACT.TEMPLATES
        if t.intended_verdict == want and (t.profile in agent.action_profiles or want != ACT.PERMIT)
    ]
    if not candidates:
        candidates = [t for t in ACT.TEMPLATES if t.intended_verdict == ACT.PERMIT]
    template = rng.choice(candidates)
    rendered = ACT.render(template, rng)
    return PlannedAction(
        seq=seq, agent=agent,
        action_type=str(rendered["action_type"]), content=str(rendered["content"]),
        channel=str(rendered["channel"]), recipient=rendered["recipient"],  # type: ignore[arg-type]
        intended_verdict=str(rendered["intended_verdict"]), profile=str(rendered["profile"]),
    )


# --------------------------------------------------------------------------- #
# Onboarding — verify the governed cohort the way an operator would
# --------------------------------------------------------------------------- #
def _onboard_governed_cohort(client: TexClient, estate: Estate, tier: str) -> dict[str, int]:
    """
    Make the PERMIT path reachable from minute one by promoting the
    IdP-discovered (governed) agents to a verified trust tier through the real
    PATCH /v1/agents route. Shadow agents are deliberately left UNVERIFIED so
    Tex keeps holding them — which is the honest, watchable behavior, not a
    thing to paper over.

    An agent only appears in the registry once it has been adjudicated at
    least once (Tex auto-registers from the agent_identity block). So we send
    one warm-up evaluate per governed agent, then resolve external_id ->
    agent_id from the inventory and PATCH the trust tier.
    """
    tier = tier.lower()
    if tier == "none":
        return {"onboarded": 0, "warmups": 0, "skipped_shadow": len(estate.shadow_agents)}

    target = tier.upper()
    governed = list(estate.idp_agents)

    # 1. warm-up: one cheap adjudication per governed agent so it registers.
    warmups = 0
    for ag in governed:
        payload = {
            "request_id": _uuid(),
            "action_type": "read",
            "content": "Onboarding handshake: confirm agent registration.",
            "recipient": None,
            "channel": "internal",
            "environment": "prod",
            "session_id": f"sim-onboard-{ag.external_id}",
            "metadata": {"sim": True, "sim_onboarding": True,
                         "agent_external_id": ag.external_id},
            "agent_identity": {
                "external_agent_id": ag.external_id,
                "agent_name": ag.name,
                "tenant_id": estate.tenant_id,
                "owner": ag.owner,
                "environment": "prod",
                "data_scopes": list(ag.scopes),
            },
        }
        try:
            client.evaluate(payload)
            warmups += 1
        except TexClientError:
            pass

    # 2. resolve external_id -> agent_id from the inventory.
    id_by_external = _external_to_agent_id(client)

    # 3. promote the governed cohort; leave shadow untrusted.
    onboarded = 0
    for ag in governed:
        agent_id = id_by_external.get(ag.external_id)
        if not agent_id:
            continue
        try:
            client.update_agent(agent_id, {"trust_tier": target})
            onboarded += 1
        except TexClientError:
            pass

    return {"onboarded": onboarded, "warmups": warmups,
            "skipped_shadow": len(estate.shadow_agents), "tier": target}


def _external_to_agent_id(client: TexClient) -> dict[str, str]:
    """Map every agent's external id to its server agent_id, paging if needed."""
    out: dict[str, str] = {}
    try:
        payload = client.list_agents()
    except TexClientError:
        return out
    items = payload.get("agents") if isinstance(payload, dict) else payload
    for a in (items or []):
        meta = a.get("metadata") or {}
        ext = meta.get("external_agent_id") or meta.get("discovery_external_id")
        aid = a.get("agent_id")
        if ext and aid:
            out[str(ext)] = str(aid)
    return out


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# The run loop
# --------------------------------------------------------------------------- #
def run_live(config: LiveConfig, *, base_url: str = "http://localhost:8000",
             api_key: str | None = None, report_path: str | None = None) -> int:
    if config.onboard.lower() not in _ONBOARD_TIERS:
        print(f"--onboard must be one of {sorted(_ONBOARD_TIERS)}", file=sys.stderr)
        return 2

    sc = scenarios.get(config.scenario)
    estate = generate_estate(seed=sc.seed, idp_agents=sc.idp_agents,
                             shadow_agents=sc.shadow_agents, mcp_agents=sc.mcp_agents)
    client = TexClient(base_url=base_url, api_key=api_key)

    # 0. liveness
    try:
        client.health()
    except TexClientError as e:
        print(f"backend not reachable at {base_url} ({e}). Is `uvicorn tex.main:app` up "
              f"with TEX_SANDBOX=1?", file=sys.stderr)
        return 2

    dur = "until Ctrl-C" if config.duration_seconds is None else _hms(config.duration_seconds)
    print("=" * 72)
    print(f"  TEX SANDBOX — LIVE   ({estate.org_name})")
    print("=" * 72)
    print(f"  estate     : {len(estate.agents)} agents "
          f"({len(estate.idp_agents)} governed, {len(estate.shadow_agents)} shadow)  seed={sc.seed}")
    print(f"  drive      : ~{config.rate}/s, {dur}, heartbeat {int(config.heartbeat_seconds)}s")
    print(f"  onboard    : governed cohort -> {config.onboard.upper()}  (shadow stays UNVERIFIED)")
    print("-" * 72)

    # 1. ignite discovery (map the estate)
    try:
        status = client.discovery_status(estate.tenant_id)
        if not status.get("ignited"):
            client.ignite(estate.tenant_id)
            print("  discovery ignited — mapping the estate…")
    except TexClientError:
        pass

    # 2. onboard the governed cohort
    if config.onboard.lower() != "none":
        ob = _onboard_governed_cohort(client, estate, config.onboard)
        print(f"  onboarded  : {ob.get('onboarded', 0)} governed agents -> "
              f"{ob.get('tier', '')}  ({ob.get('warmups', 0)} registered, "
              f"{ob.get('skipped_shadow', 0)} shadow left untrusted)")
    print("-" * 72)
    print("  watching. heartbeats below; Ctrl-C for a clean stop + summary.\n")

    stats = LiveStats(latencies_ms=deque(maxlen=config.max_latency_samples))
    stats.heartbeat_window = config.heartbeat_seconds  # type: ignore[attr-defined]

    stop = {"flag": False}

    def _handle_sigint(signum, frame):  # noqa: ANN001
        stop["flag"] = True
        print("\n  stop requested — finishing in-flight tick…")

    signal.signal(signal.SIGINT, _handle_sigint)

    rng = random.Random(config.seed)
    agents = list(estate.agents)
    weights = _agent_weights(agents)
    mean_interval = 1.0 / config.rate if config.rate > 0 else 1.0

    start = time.monotonic()
    deadline = None if config.duration_seconds is None else start + config.duration_seconds
    next_heartbeat = start + config.heartbeat_seconds
    seq = 0
    health_fail = False

    while not stop["flag"]:
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            break

        # Poisson-ish arrival: exponential inter-arrival around the mean rate.
        interval = rng.expovariate(1.0 / mean_interval) if mean_interval > 0 else 0.0
        # sleep in small slices so Ctrl-C and heartbeats stay responsive
        wake = time.monotonic() + interval
        while time.monotonic() < wake and not stop["flag"]:
            time.sleep(min(0.25, max(0.0, wake - time.monotonic())))
        if stop["flag"]:
            break

        action = _next_action(estate, rng, seq, config.forbid_rate, config.abstain_rate, agents, weights)
        seq += 1
        payload = action.to_evaluate_payload(estate.tenant_id)
        t0 = time.monotonic()
        try:
            resp = client.evaluate(payload)
            stats.record(resp, (time.monotonic() - t0) * 1000.0)
        except TexClientError as e:
            stats.record_error(f"{e.status} {str(e.body)[:80]}")

        # heartbeat + invariants
        now = time.monotonic()
        if now >= next_heartbeat:
            print(stats.heartbeat_line())
            chain = check_chain_integrity(client)
            voice = check_voice(client)
            if chain.status == "FAIL" or voice.status == "FAIL":
                health_fail = True
                print(f"    !! invariant: chain={chain.status} ({chain.detail}) "
                      f"voice={voice.status} ({voice.detail})")
            if stats.unsealed and stats.sealed == 0:
                health_fail = True
                print(f"    !! invariant: {stats.unsealed} decisions returned with no seal")
            if stats.last_error_detail:
                print(f"    last error: {stats.last_error_detail}")
            next_heartbeat = now + config.heartbeat_seconds

    # final summary
    summary = stats.summary()
    print("\n" + "=" * 72)
    print(f"  TEX SANDBOX — LIVE  stopped after {_hms(summary['uptime_seconds'])}")
    print("-" * 72)
    print(f"  decisions  : {summary['total_decisions']}   errors: {summary['errors']}")
    print(f"  verdict mix: {summary['verdict_mix']}")
    print(f"  seal rate  : {summary['seal_rate']}  ({summary['sealed']} sealed, {summary['unsealed']} unsealed)")
    print(f"  latency    : p50 {summary['latency_p50_ms']}ms  "
          f"p95 {summary['latency_p95_ms']}ms  p99 {summary['latency_p99_ms']}ms")
    chain = check_chain_integrity(client)
    print(f"  chain      : {chain.status} — {chain.detail}")
    print("=" * 72)

    if report_path:
        import json
        with open(report_path, "w") as fh:
            json.dump({"finished_at": datetime.now(UTC).isoformat(),
                       "config": {"scenario": config.scenario, "rate": config.rate,
                                  "onboard": config.onboard,
                                  "duration_seconds": config.duration_seconds},
                       "summary": summary,
                       "chain": {"status": chain.status, "detail": chain.detail}}, fh, indent=2)
        print(f"  report -> {report_path}")

    # non-zero exit if an invariant broke or every request errored
    if health_fail or (stats.total > 0 and stats.errors == stats.total):
        return 1
    return 0
