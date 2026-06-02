"""
v2 — live model of normal (DirichletNormalLearner).

The learner must:
  * accumulate conjugate counts in place for descriptive volume dimensions,
  * expose them via as_model() so surprise calibrates to the shop,
  * NEVER let an accumulating "normal" erase the safety floors
    (identity / monitoring / evidence stay pinned to their safe-state base),
  * produce a stable, sealable snapshot so the evolution of normal is
    itself auditable evidence,
  * boot identical to v1 (history-warmed) on the first cycle, then go live.
"""

from __future__ import annotations

from tex.vigil.conjugate import gamma_surprise
from tex.vigil.dimensions import DimensionReading
from tex.vigil.learning import LEARNABLE_GAMMA, DirichletNormalLearner
from tex.vigil.normal import ModelOfNormal


def _gamma_reading(key: str, count: float, history: list | None = None) -> DimensionReading:
    return DimensionReading(
        key=key,
        kind="gamma",
        observation=(float(count), 1.0),
        history=list(history or []),
        slots={"count": int(count)},
    )


def _evidence_reading(intact: bool = True, length: int = 10) -> DimensionReading:
    return DimensionReading(
        key="evidence",
        kind="beta",
        observation=(1.0, 0.0) if intact else (0.0, 1.0),
        history=[("intact", length)],
        slots={"length": length, "intact": intact},
    )


def test_counts_accumulate_in_place() -> None:
    learner = DirichletNormalLearner()
    learner.observe(_gamma_reading("discovery", 5), tenant="t1")
    learner.observe(_gamma_reading("discovery", 7), tenant="t1")
    snap = learner.snapshot()["tenants"]["t1"]["discovery"]
    # Two cycles, counts 5 and 7 -> total 12 over 2 observations.
    assert snap["n"] == 2
    assert snap["total"] == 12.0
    assert snap["learned_mean"] == 6.0


def test_as_model_reflects_accumulated_counts() -> None:
    # A discovery count of 8 is surprising against the cold base (mean 2),
    # but after the shop is observed routinely doing ~8, it stops surprising.
    learner = DirichletNormalLearner()
    reading = _gamma_reading("discovery", 8)

    cold = learner.as_model(tenant="t1")
    cold_prior = cold.prior_for(reading)
    cold_posterior = cold_prior.gamma.update(8.0, 1.0)
    cold_surprise = gamma_surprise(cold_prior.gamma, cold_posterior)

    # Let the shop run at ~8 for a good while.
    for _ in range(30):
        learner.observe(_gamma_reading("discovery", 8), tenant="t1")

    warm = learner.as_model(tenant="t1")
    warm_prior = warm.prior_for(reading)
    warm_posterior = warm_prior.gamma.update(8.0, 1.0)
    warm_surprise = gamma_surprise(warm_prior.gamma, warm_posterior)

    assert warm_prior.warm is True
    # The learned prior's mean has moved toward 8...
    assert warm_prior.gamma.mean > cold_prior.gamma.mean
    assert abs(warm_prior.gamma.mean - 8.0) < 1.0
    # ...so the same observation is far less surprising than when cold.
    assert warm_surprise < cold_surprise


def test_safety_floor_survives_a_flood_of_normal() -> None:
    # Flood the learner with "5 ungoverned high-risk agents every cycle".
    # This must NOT become the new normal: identity stays pinned to its
    # safe-state base, so the alarm still fires.
    learner = DirichletNormalLearner()
    for _ in range(500):
        learner.observe(_gamma_reading("identity", 5), tenant="t1")
        learner.observe(_gamma_reading("monitoring", 5), tenant="t1")

    model = learner.as_model(tenant="t1")
    cold = ModelOfNormal()

    for key in ("identity", "monitoring"):
        r = _gamma_reading(key, 5)
        learned_prior = model.prior_for(r)
        base_prior = cold.prior_for(_gamma_reading(key, 5))
        # Pinned: the learned prior is exactly the fixed base, unmoved.
        assert learned_prior.gamma.shape == base_prior.gamma.shape
        assert learned_prior.gamma.rate == base_prior.gamma.rate
        assert learned_prior.warm is False
        # And the safety dimensions never enter the learned snapshot.
        assert key not in LEARNABLE_GAMMA

    # The flood left no identity/monitoring state at all (and since only
    # safety dimensions were observed, the tenant never enters the snapshot).
    t1 = learner.snapshot()["tenants"].get("t1", {})
    assert "identity" not in t1
    assert "monitoring" not in t1


def test_evidence_beta_does_not_learn() -> None:
    learner = DirichletNormalLearner()
    for _ in range(100):
        learner.observe(_evidence_reading(intact=True), tenant="t1")
    # Beta safety floor: nothing accumulated, prior equals v1's strong base.
    model = learner.as_model(tenant="t1")
    cold = ModelOfNormal()
    r = _evidence_reading(intact=True)
    assert model.prior_for(r).beta.alpha == cold.prior_for(r).beta.alpha
    assert model.prior_for(r).beta.beta == cold.prior_for(r).beta.beta
    assert "t1" not in learner.snapshot()["tenants"] or "evidence" not in learner.snapshot()["tenants"].get("t1", {})


def test_snapshot_stable_and_sealable() -> None:
    learner = DirichletNormalLearner()
    learner.observe(_gamma_reading("discovery", 3), tenant="t1")
    learner.observe(_gamma_reading("execution", 4), tenant="t1")

    s1 = learner.snapshot()
    s2 = learner.snapshot()
    assert s1 == s2  # stable
    assert learner.snapshot_sha256() == learner.snapshot_sha256()  # deterministic seal

    # Only learnable volume dimensions appear.
    dims = set(s1["tenants"]["t1"].keys())
    assert dims <= LEARNABLE_GAMMA
    assert "discovery" in dims and "execution" in dims


def test_boot_equals_v1_on_first_cycle() -> None:
    # Before any observation, as_model() must produce exactly v1's
    # history-warmed prior for a learnable dimension.
    learner = DirichletNormalLearner()
    reading = _gamma_reading("discovery", 2, history=[2, 3, 1, 2])
    learned = learner.as_model(tenant="t1").prior_for(reading)
    v1 = ModelOfNormal().prior_for(reading)
    assert learned.gamma.shape == v1.gamma.shape
    assert learned.gamma.rate == v1.gamma.rate
    assert learned.warm == v1.warm


def test_first_observe_warm_starts_from_history() -> None:
    # The first observe folds the reading's sealed history in, then this
    # cycle on top — so the learner boots already knowing the shop.
    learner = DirichletNormalLearner()
    learner.observe(_gamma_reading("discovery", 2, history=[10, 10, 10]), tenant="t1")
    snap = learner.snapshot()["tenants"]["t1"]["discovery"]
    # 3 history entries (10,10,10) + this cycle (2) = 4 obs, total 32.
    assert snap["n"] == 4
    assert snap["total"] == 32.0


def test_tenants_are_isolated() -> None:
    learner = DirichletNormalLearner()
    learner.observe(_gamma_reading("discovery", 9), tenant="t1")
    learner.observe(_gamma_reading("discovery", 1), tenant="t2")
    t1 = learner.snapshot()["tenants"]["t1"]["discovery"]
    t2 = learner.snapshot()["tenants"]["t2"]["discovery"]
    assert t1["total"] == 9.0
    assert t2["total"] == 1.0
