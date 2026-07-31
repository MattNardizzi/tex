"""
Empirical Cournot-replication test.

Replicates the directional finding of arxiv 2601.11369 (Bracale Syrnikov
et al., 2026) — Institutional governance reduces collusion-tier across
runs of repeated multi-commodity Cournot competition — using
deterministic agent strategy stubs in place of LLM agents.

The paper reports mean collusion tier 3.10 (Ungoverned) vs 1.82
(Institutional), Cohen's d=1.28, severe-tier from 50% -> 5.6%.
We do NOT attempt to replicate the *magnitude* (impossible without
real LLM agents). We assert the *direction* — that the manifest-
declared escalation ladder, fed by the Oracle's tier classification,
mechanically lowers per-run tier by suspending firms whose
specialisation persists.

Cournot environment per Section 5.2:
  Two firms, two commodities (A, B)
  Linear inverse demand:  P_j = α - Q_j / β   with α=100, β=2
  Capacity:               κ = 100 per firm per round
  Costs:                  c_1 = 40, c_2 = 50  (asymmetric — Lin et al.
                          report 10/10 specialisation under (40,50)
                          vs (50,40))
  Horizon:                50 rounds (paper's T)

Agent strategies (deterministic stubs):
  * Collusion-prone (CollusiveAgent): firm 1 dumps capacity into
    commodity A, firm 2 into commodity B. Faithful proxy of the
    Lin et al. failure mode that the paper itself replicates.
  * Cournot-Nash baseline (NashAgent): each firm plays the closed-form
    NE quantities every round.
  * Compliance-aware (CompliantWhenSanctionedAgent): plays the
    collusive strategy when in state 'active', and falls back to the
    Nash strategy when sanctioned. Models the responsiveness the
    paper credits institutional governance with eliciting.

Reference
---------
arxiv 2601.11369 §5.2 / §5.3 / §6.3 / §7
"""

from __future__ import annotations

import math
import random
from datetime import UTC, datetime
from pathlib import Path

import pytest

import tex.ecosystem  # noqa: F401  prime ordering

from tex.ecosystem.state import EcosystemState
from tex.institutional import (
    SIGNAL_HIGH_HHI,
    SIGNAL_SPECIALISATION,
    GovernanceController,
    GovernanceGraph,
    GovernanceLog,
    GovernanceOracle,
    OracleSignal,
    collusion_tier,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
COURNOT_MANIFEST = FIXTURES_DIR / "cournot_market.yaml"


# ---------------------------------------------------------------------
# Environment parameters (paper §5.2)
# ---------------------------------------------------------------------


ALPHA: float = 100.0
BETA: float = 2.0
KAPPA: float = 100.0
COSTS: tuple[float, float] = (40.0, 50.0)
COMMODITIES: tuple[str, str] = ("A", "B")
HORIZON: int = 50


# ---------------------------------------------------------------------
# Closed-form Cournot–Nash for two-firm, two-commodity, linear demand,
# capacity κ.
# ---------------------------------------------------------------------


def cournot_nash_quantities(
    *,
    alpha: float = ALPHA,
    beta: float = BETA,
    kappa: float = KAPPA,
    costs: tuple[float, float] = COSTS,
) -> tuple[tuple[float, float], tuple[float, float]]:
    """
    Compute the two-firm, two-commodity Cournot–Nash quantities under
    linear inverse demand P_j = α - Q_j/β (per commodity, independent
    markets) with constant marginal costs c_i and per-firm aggregate
    capacity kappa.

    For independent commodity markets with constant MC, the unconstrained
    NE quantity for firm i in commodity j is (paper §5.2):

        q*_i,j = β · (α - 2·c_i + c_-i) / 3

    Both firms produce in both commodities (no specialisation under NE).
    If aggregate q*_i,1 + q*_i,2 exceeds kappa we scale proportionally;
    in this fixture (40,50) costs the unconstrained sum is 60 (firm 1)
    and 40 (firm 2), both well under κ=100.

    Returns (firm_1_quantities, firm_2_quantities) where each is
    (q_A, q_B).
    """
    c_low, c_high = costs[0], costs[1]
    # Firm 1 (low-cost) NE quantity per commodity:
    q1 = beta * (alpha - 2 * c_low + c_high) / 3.0
    # Firm 2 (high-cost) NE quantity per commodity:
    q2 = beta * (alpha - 2 * c_high + c_low) / 3.0
    # Same NE quantity in both commodities (symmetric demand)
    q1_a, q1_b = q1, q1
    q2_a, q2_b = q2, q2
    # Capacity scaling if needed.
    s1 = (q1_a + q1_b) / kappa if (q1_a + q1_b) > kappa else 1.0
    s2 = (q2_a + q2_b) / kappa if (q2_a + q2_b) > kappa else 1.0
    return ((q1_a / s1, q1_b / s1), (q2_a / s2, q2_b / s2))


def _market_clear(
    quantities: list[tuple[float, float]],
    *,
    alpha: float = ALPHA,
    beta: float = BETA,
) -> tuple[float, float]:
    """Clear the market and return per-commodity prices."""
    Q_A = sum(q[0] for q in quantities)
    Q_B = sum(q[1] for q in quantities)
    return (max(0.0, alpha - Q_A / beta), max(0.0, alpha - Q_B / beta))


# ---------------------------------------------------------------------
# Market-structure metrics (paper §5.3)
# ---------------------------------------------------------------------


def _hhi_for_commodity(shares: list[float]) -> float:
    """HHI = Σ s_i² where s_i is firm i's share for the commodity."""
    return sum(s * s for s in shares)


def _cv(values: list[float]) -> float:
    """Coefficient of variation (Eq. 4)."""
    n = len(values)
    if n == 0:
        return 0.0
    mu = sum(values) / n
    if mu == 0.0:
        return 0.0
    var = sum((v - mu) ** 2 for v in values) / n
    sd = math.sqrt(var)
    return sd / abs(mu)


def market_structure_metrics(
    history: list[list[tuple[float, float]]],
) -> tuple[float, float]:
    """
    Compute (CV_excess, HHI_excess) over the run.

    history: list (per round) of [(q_A, q_B) for firm 1, (q_A, q_B)
    for firm 2].

    Per paper §5.3:
      CV_i      = σ across commodities / μ across commodities (per firm)
      HHI_c     = Σ s_i² for commodity c (per round); we average over
                  rounds and take the mean across commodities.
      Excess    = (observed - Nash) / Nash   (Eq. 5/6)

    We report run-level *maximum across firms* of CV_excess (paper's
    primary headline number).
    """
    n_rounds = len(history)
    if n_rounds == 0:
        return (0.0, 0.0)

    # CV per firm across commodities, averaged across rounds.
    cv_per_firm: list[list[float]] = [[], []]
    for round_q in history:
        for i, (qA, qB) in enumerate(round_q):
            cv_per_firm[i].append(_cv([qA, qB]))
    cv_observed_max = max(
        sum(c) / len(c) if c else 0.0 for c in cv_per_firm
    )

    # HHI per commodity per round, averaged.
    hhi_per_commodity: list[list[float]] = [[], []]  # A, B
    for round_q in history:
        Q_A = sum(q[0] for q in round_q)
        Q_B = sum(q[1] for q in round_q)
        if Q_A > 0:
            shares_A = [q[0] / Q_A for q in round_q]
            hhi_per_commodity[0].append(_hhi_for_commodity(shares_A))
        if Q_B > 0:
            shares_B = [q[1] / Q_B for q in round_q]
            hhi_per_commodity[1].append(_hhi_for_commodity(shares_B))
    hhi_observed_max = max(
        sum(h) / len(h) if h else 0.0 for h in hhi_per_commodity
    )

    # Cournot–Nash baseline metrics
    nash_q1, nash_q2 = cournot_nash_quantities()
    cv_nash_max = max(_cv([nash_q1[0], nash_q1[1]]), _cv([nash_q2[0], nash_q2[1]]))
    Q_A_nash = nash_q1[0] + nash_q2[0]
    Q_B_nash = nash_q1[1] + nash_q2[1]
    hhi_nash_a = _hhi_for_commodity(
        [nash_q1[0] / Q_A_nash, nash_q2[0] / Q_A_nash]
    ) if Q_A_nash > 0 else 0.0
    hhi_nash_b = _hhi_for_commodity(
        [nash_q1[1] / Q_B_nash, nash_q2[1] / Q_B_nash]
    ) if Q_B_nash > 0 else 0.0
    hhi_nash_max = max(hhi_nash_a, hhi_nash_b)

    # Excess ratios (Eq. 5/6). Guard div-by-zero with a small epsilon.
    cv_excess = (
        (cv_observed_max - cv_nash_max) / cv_nash_max
        if cv_nash_max > 1e-9
        else cv_observed_max
    )
    hhi_excess = (
        (hhi_observed_max - hhi_nash_max) / hhi_nash_max
        if hhi_nash_max > 1e-9
        else hhi_observed_max
    )
    return (cv_excess, hhi_excess)


# ---------------------------------------------------------------------
# Deterministic agent strategies
# ---------------------------------------------------------------------


def collusive_strategy(
    *, firm_id: int, capacity: float = KAPPA, jitter_seed: int = 0
) -> tuple[float, float]:
    """
    Faithful proxy of the Lin et al. (2024) market-division failure
    mode: firm 1 dumps capacity into commodity A, firm 2 into commodity B.
    Produces high CV/HHI excess.

    A small reproducible jitter (a few %) keeps the run from being
    perfectly degenerate.
    """
    rng = random.Random(jitter_seed)
    if firm_id == 1:
        qA = capacity * (0.95 + rng.uniform(-0.02, 0.02))
        qB = capacity * (0.05 + rng.uniform(-0.02, 0.02))
    else:
        qA = capacity * (0.05 + rng.uniform(-0.02, 0.02))
        qB = capacity * (0.95 + rng.uniform(-0.02, 0.02))
    return (max(0.0, qA), max(0.0, qB))


def nash_strategy(*, firm_id: int) -> tuple[float, float]:
    """Plays closed-form Cournot–Nash quantities every round."""
    nash = cournot_nash_quantities()
    return nash[firm_id - 1]


def compliant_when_sanctioned_strategy(
    *,
    firm_id: int,
    institutional_state: str,
    capacity: float = KAPPA,
    jitter_seed: int = 0,
) -> tuple[float, float]:
    """
    Plays collusive when in 'active', falls back to Nash quantities
    otherwise. Suspended actors produce zero. This models the paper's
    central empirical finding: agents respond to *consequences*, not to
    declarative prohibitions.
    """
    if institutional_state == "suspended":
        return (0.0, 0.0)
    if institutional_state == "active":
        return collusive_strategy(
            firm_id=firm_id, capacity=capacity, jitter_seed=jitter_seed
        )
    # Warning / fined / credited -> Nash baseline
    return nash_strategy(firm_id=firm_id)


# ---------------------------------------------------------------------
# Run loops
# ---------------------------------------------------------------------


def run_ungoverned(
    *,
    horizon: int = HORIZON,
    seed: int = 0,
) -> tuple[float, float, int]:
    """
    Ungoverned run: collusive strategy applies on every round for both
    firms. Returns (CV_excess, HHI_excess, tier).
    """
    history: list[list[tuple[float, float]]] = []
    for t in range(horizon):
        q1 = collusive_strategy(firm_id=1, jitter_seed=seed + t)
        q2 = collusive_strategy(firm_id=2, jitter_seed=seed + t + 1000)
        history.append([q1, q2])
    cv_ex, hhi_ex = market_structure_metrics(history)
    return (cv_ex, hhi_ex, collusion_tier(cv_excess=cv_ex, hhi_excess=hhi_ex))


def _windowed_metrics(
    history: list[list[tuple[float, float]]],
    *,
    window: int = 5,
) -> tuple[float, float]:
    """
    Compute CV/HHI excess over the trailing ``window`` rounds.
    Used by the Oracle to fire signals on a rolling basis (paper uses
    a 30-round agent-side window; we use a tighter 5-round window for
    governance signals so escalation can take effect within the 50-round
    horizon).

    Returns (cv_excess, hhi_excess).
    """
    if not history:
        return (0.0, 0.0)
    tail = history[-window:]
    return market_structure_metrics(tail)


def run_governed(
    *,
    horizon: int = HORIZON,
    seed: int = 0,
) -> tuple[float, float, int, dict]:
    """
    Tex-governed run with the Cournot manifest.

    Returns (CV_excess, HHI_excess, tier, log_summary).

    Each round:
      1. Both firms propose quantities under their respective strategy
         (compliant_when_sanctioned).
      2. Markets clear; quantities recorded.
      3. Oracle observes the trailing-window CV/HHI excess for each
         firm and (if signals fire) opens a probable_violation case.
      4. Controller enforces by traversing the manifest. SANCTION
         decisions update the firm's institutional state, and the
         strategy reads the new state on the next round.
      5. Each round also emits a clean_round event for actors in
         'active' (records the lawful traversal of the no-op edge)
         and an expiry_tick event for non-active actors after the
         declared duration_rounds elapses.
    """
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    oracle = GovernanceOracle(
        graph=g,
        signals=(
            OracleSignal(SIGNAL_HIGH_HHI, "hhi_excess", threshold=0.50),
            OracleSignal(
                SIGNAL_SPECIALISATION, "cv_excess", threshold=0.75
            ),
        ),
        rule_id_for_signal={
            SIGNAL_HIGH_HHI: "P2_independent_decision",
            SIGNAL_SPECIALISATION: "P2_independent_decision",
        },
    )
    log = GovernanceLog(
        signing_key_id=f"cournot-replication-{seed}",
        manifest_semantic_sha256=g.manifest_semantic_sha256,
    )
    controller = GovernanceController(oracle=oracle, ledger=log)

    history: list[list[tuple[float, float]]] = []
    sanction_count = 0
    suspended_count = 0
    blocked_count = 0
    sanctioned_round_first: int | None = None

    # Track when each actor entered a non-active state (for expiry).
    state_entered_round: dict[str, int] = {}

    for t in range(horizon):
        s1 = controller.actor_state("firm_1")
        s2 = controller.actor_state("firm_2")

        q1 = compliant_when_sanctioned_strategy(
            firm_id=1, institutional_state=s1, jitter_seed=seed + t
        )
        q2 = compliant_when_sanctioned_strategy(
            firm_id=2, institutional_state=s2, jitter_seed=seed + t + 1000
        )
        history.append([q1, q2])

        # Compute trailing-window market-structure signals.
        cv_ex, hhi_ex = _windowed_metrics(history, window=5)

        # Build an EcosystemState that the Oracle can read.
        ec_state = EcosystemState(
            snapshot_at=datetime.now(UTC),
            state_hash=f"round_{t}",
            active_agent_ids=("firm_1", "firm_2"),
            active_tool_ids=(),
            active_capability_ids=(),
            active_governance_graph_id=g.graph_id,
            aggregate_drift_signals={
                "cv_excess": cv_ex,
                "hhi_excess": hhi_ex,
            },
        )

        # Per-actor observation + enforcement.
        for actor_id, prior_state in [("firm_1", s1), ("firm_2", s2)]:
            obs = oracle.observe_state(ec_state, actor_entity_id=actor_id)
            case = obs.pending_cases[0] if obs.pending_cases else None

            # If a case fires, request the appropriate event kind for
            # the actor's current state. The manifest has no edge from
            # 'suspended' under probable_violation, so we skip those.
            current = controller.actor_state(actor_id)
            if case is not None and current != "suspended":
                d = controller.enforce(
                    proposed_event_kind="probable_violation",
                    actor_entity_id=actor_id,
                    current_round=t,
                    case=case,
                )
                if d["decision"] == "SANCTION":
                    sanction_count += 1
                    if sanctioned_round_first is None:
                        sanctioned_round_first = t
                    if controller.actor_state(actor_id) == "suspended":
                        suspended_count += 1
                    state_entered_round[actor_id] = t
                elif d["decision"] == "BLOCKED":
                    blocked_count += 1

            # Time-driven restoration tick: if an actor has been in a
            # non-active state for >= declared duration, fire expiry_tick.
            cur = controller.actor_state(actor_id)
            entered = state_entered_round.get(actor_id, -10**9)
            duration = _duration_for(cur)
            if cur != "active" and t - entered >= duration:
                d = controller.enforce(
                    proposed_event_kind="expiry_tick",
                    actor_entity_id=actor_id,
                    current_round=t,
                )
                if d["decision"] == "REMEDIATE":
                    state_entered_round.pop(actor_id, None)

    cv_ex, hhi_ex = market_structure_metrics(history)
    summary = {
        "sanctions": sanction_count,
        "suspensions": suspended_count,
        "blocked": blocked_count,
        "first_sanction_round": sanctioned_round_first,
        "log_entries": len(log),
        "manifest_semantic_sha256": g.manifest_semantic_sha256,
    }
    return (
        cv_ex,
        hhi_ex,
        collusion_tier(cv_excess=cv_ex, hhi_excess=hhi_ex),
        summary,
    )


def _duration_for(state_id: str) -> int:
    """Map the actor's institutional state to its declared duration."""
    return {
        "warning": 5,
        "fined": 5,
        "suspended": 5,
        "credited": 3,
        "active": 0,
    }.get(state_id, 0)


# ---------------------------------------------------------------------
# Sanity tests on the environment
# ---------------------------------------------------------------------


class TestCournotEnvironment:
    def test_nash_quantities_are_positive_and_below_capacity(self) -> None:
        q1, q2 = cournot_nash_quantities()
        for q in (q1[0], q1[1], q2[0], q2[1]):
            assert q > 0
        assert q1[0] + q1[1] <= KAPPA + 1e-6
        assert q2[0] + q2[1] <= KAPPA + 1e-6

    def test_nash_low_cost_firm_produces_more(self) -> None:
        q1, q2 = cournot_nash_quantities()
        # Firm 1 has c=40, firm 2 has c=50 -> firm 1 produces more.
        assert q1[0] > q2[0]
        assert q1[1] > q2[1]

    def test_collusive_strategy_specialises(self) -> None:
        q1 = collusive_strategy(firm_id=1)
        q2 = collusive_strategy(firm_id=2)
        # Firm 1 dominates A; firm 2 dominates B.
        assert q1[0] > q1[1] * 5
        assert q2[1] > q2[0] * 5

    def test_market_clears_at_paper_parameters(self) -> None:
        q1 = collusive_strategy(firm_id=1)
        q2 = collusive_strategy(firm_id=2)
        pA, pB = _market_clear([q1, q2])
        assert pA > 0
        assert pB > 0


class TestMarketStructureMetrics:
    def test_nash_history_yields_zero_excess(self) -> None:
        """Pure Nash history should produce CV/HHI excess close to zero."""
        history = []
        for _ in range(HORIZON):
            history.append([nash_strategy(firm_id=1), nash_strategy(firm_id=2)])
        cv_ex, hhi_ex = market_structure_metrics(history)
        assert abs(cv_ex) < 1e-3
        assert abs(hhi_ex) < 1e-3

    def test_pure_collusive_history_has_high_excess(self) -> None:
        history = []
        for t in range(HORIZON):
            history.append([
                collusive_strategy(firm_id=1, jitter_seed=t),
                collusive_strategy(firm_id=2, jitter_seed=t + 1000),
            ])
        cv_ex, hhi_ex = market_structure_metrics(history)
        # Collusive specialisation (95/5 split) yields CV around 0.9.
        # The paper's LLM agents push this higher (~1.4) because they
        # discover even more extreme specialisations; deterministic
        # stubs at 95/5 give us a stable baseline.
        assert cv_ex > 0.7
        # And concentration well above Nash. Nash HHI = 0.5 (firms
        # split each market equally per commodity is FALSE for
        # asymmetric costs — actually Nash HHI is roughly
        # 0.6²+0.4² = 0.52 here; collusive (~0.95²+0.05²=0.91)
        # produces ~75% excess).
        assert hhi_ex > 0.2


# ---------------------------------------------------------------------
# Single-run sanity
# ---------------------------------------------------------------------


class TestSingleRun:
    def test_ungoverned_collusive_run_lands_in_high_tier(self) -> None:
        """
        Ungoverned + collusive strategy -> tier >= 3. The paper's LLM
        agents reach tier 4 in 50% of runs because they push to more
        extreme specialisation (close to 99/1); our deterministic 95/5
        stub reliably lands at tier 3 instead. Either is "strong
        collusion" by the Table 1 definition.
        """
        cv_ex, hhi_ex, tier = run_ungoverned(seed=0)
        assert tier >= 3
        assert cv_ex > 0.5
        assert hhi_ex > 0.5

    def test_governed_run_emits_log_entries(self) -> None:
        """Governance must actually fire under collusive pressure."""
        _cv, _hhi, _tier, summary = run_governed(seed=0)
        assert summary["log_entries"] > 0
        assert summary["sanctions"] > 0
        # First sanction should arrive within the trailing-window
        # warm-up period plus a small tolerance.
        assert summary["first_sanction_round"] is not None
        assert summary["first_sanction_round"] < 15

    def test_governed_run_carries_manifest_digest(self) -> None:
        _cv, _hhi, _tier, summary = run_governed(seed=0)
        assert len(summary["manifest_semantic_sha256"]) == 64


# ---------------------------------------------------------------------
# DIRECTIONAL REPLICATION — the headline assertion
# ---------------------------------------------------------------------


class TestDirectionalReplication:
    """
    Paired-runs comparison across N seeds. Asserts that the mean
    governed tier is *strictly less than* the mean ungoverned tier.

    This is the directional analogue of arxiv 2601.11369 Cohen's d=1.28
    result: institutional governance lowers per-run collusion-tier.
    We do NOT replicate magnitude — that requires real LLM agents.
    """

    def test_governed_mean_tier_strictly_less_than_ungoverned(self) -> None:
        N = 10
        ungoverned_tiers: list[int] = []
        governed_tiers: list[int] = []
        for seed in range(N):
            _cv_u, _hhi_u, t_u = run_ungoverned(seed=seed)
            _cv_g, _hhi_g, t_g, _ = run_governed(seed=seed)
            ungoverned_tiers.append(t_u)
            governed_tiers.append(t_g)

        u_mean = sum(ungoverned_tiers) / N
        g_mean = sum(governed_tiers) / N
        # Paper's headline: governed tier strictly below ungoverned.
        assert g_mean < u_mean, (
            f"governed mean tier ({g_mean}) was not strictly less than "
            f"ungoverned mean tier ({u_mean}); "
            f"ungoverned={ungoverned_tiers} governed={governed_tiers}"
        )
        # Paper also reports paired runs: 6/6 study labels improve.
        # Stricter: every paired run must NOT regress.
        for i, (t_u, t_g) in enumerate(zip(ungoverned_tiers, governed_tiers)):
            assert t_g <= t_u, (
                f"seed={i}: governed tier {t_g} > ungoverned tier {t_u} "
                f"(institution made things worse)"
            )

    def test_governed_severe_tier_share_strictly_below_ungoverned(
        self,
    ) -> None:
        """
        Paper Table 6: Tier >= 4 share drops from 50% to 5.6%.
        We assert directional: governed severe-tier share <= ungoverned.
        """
        N = 10
        u_severe = 0
        g_severe = 0
        for seed in range(N):
            _cu, _hu, t_u = run_ungoverned(seed=seed)
            _cg, _hg, t_g, _ = run_governed(seed=seed)
            if t_u >= 4:
                u_severe += 1
            if t_g >= 4:
                g_severe += 1
        assert g_severe <= u_severe, (
            f"governed severe-tier share {g_severe}/{N} not <= "
            f"ungoverned {u_severe}/{N}"
        )

    @pytest.mark.parametrize("seed", list(range(5)))
    def test_governed_manifest_digest_is_stable_across_seeds(
        self, seed: int
    ) -> None:
        """
        Different seeds must NOT produce different manifest digests —
        the manifest is the public regime, agents are private. This
        confirms the digest captures only governance content.
        """
        _cv, _hhi, _tier, summary = run_governed(seed=seed)
        # The digest is the same across all seeds.
        if seed > 0:
            _cv0, _hhi0, _t0, summary0 = run_governed(seed=0)
            assert (
                summary["manifest_semantic_sha256"]
                == summary0["manifest_semantic_sha256"]
            )
