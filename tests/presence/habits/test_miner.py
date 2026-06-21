"""The miner: surfaces a real pattern, stays silent on noise, never inflates."""

from __future__ import annotations

from tex.presence.contract import PresenceTier
from tex.presence.habits.miner import HabitMiner, MinerConfig
from tex.presence.habits.types import OutcomeDimension

from .conftest import make_obs


def test_clean_pattern_surfaces_with_supporting_receipts():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    obs.append(make_obs("wire", "permit", "p0"))  # one minority record
    hyps = HabitMiner().mine(tenant="acme", outcomes=obs)
    assert len(hyps) == 1
    h = hyps[0]
    assert h.subject_key == "wire"
    assert h.dominant_outcome == "forbid"
    assert h.action.proposed_tier is PresenceTier.ABSTAIN
    assert h.confidence.k == 6 and h.confidence.n == 7
    # supporting = the FORBID records only (the receipts for "you forbid this"),
    # never the minority permit record.
    assert h.supporting_count() == 6
    pids = {r.record_id for r in h.supporting}
    assert pids == {f"rec-f{i}" for i in range(6)}
    assert "rec-p0" not in pids


def test_thin_history_surfaces_nothing():
    # 4 records < min_support(5) → eligible by nothing.
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(4)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_noisy_subject_surfaces_nothing():
    # 6 forbid / 5 permit → rate 0.55 < 0.8 → not a pattern.
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    obs += [make_obs("wire", "permit", f"p{i}") for i in range(5)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_borderline_four_of_five_surfaces_nothing():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(4)]
    obs.append(make_obs("wire", "permit", "p0"))
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_spurious_clean_pattern_among_noise_is_suppressed():
    """One genuinely clean 5/5 subject hidden among 19 noisy subjects must NOT
    surface — the multiplicity correction (family=20) is exactly the guard against
    a subject looking clean by chance."""
    obs = [make_obs("clean", "forbid", f"c{i}") for i in range(5)]
    for s in range(19):
        obs += [make_obs(f"noise{s}", "forbid", f"n{s}_{i}") for i in range(3)]
        obs += [make_obs(f"noise{s}", "permit", f"n{s}_p{i}") for i in range(2)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_strong_pattern_clears_even_in_a_large_family_with_enough_support():
    # 10/10 clean among 19 noisy subjects → the bar scales with evidence; surfaces.
    obs = [make_obs("clean", "forbid", f"c{i}") for i in range(10)]
    for s in range(19):
        obs += [make_obs(f"noise{s}", "forbid", f"n{s}_{i}") for i in range(3)]
        obs += [make_obs(f"noise{s}", "permit", f"n{s}_p{i}") for i in range(3)]
    hyps = HabitMiner().mine(tenant="acme", outcomes=obs)
    assert [h.subject_key for h in hyps] == ["clean"]


def test_non_cautionary_dominance_is_never_offered_as_a_rule():
    """"You PERMIT everything about X" is a real pattern but offering it as a rule
    would RAISE confidence — L3 must never do that. It surfaces nothing."""
    obs = [make_obs("safe_topic", "permit", f"a{i}") for i in range(8)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_abstain_governance_pattern_proposes_abstain_ceiling():
    obs = [make_obs("murky", "abstain", f"a{i}") for i in range(6)]
    hyps = HabitMiner().mine(tenant="acme", outcomes=obs)
    assert len(hyps) == 1
    assert hyps[0].action.proposed_tier is PresenceTier.ABSTAIN


def test_correction_tier_dimension_proposes_that_tier():
    obs = [
        make_obs("topic", "derived", f"d{i}", dimension=OutcomeDimension.CORRECTION_TIER)
        for i in range(6)
    ]
    hyps = HabitMiner().mine(tenant="acme", outcomes=obs)
    assert len(hyps) == 1
    assert hyps[0].dimension is OutcomeDimension.CORRECTION_TIER
    assert hyps[0].action.proposed_tier is PresenceTier.DERIVED


def test_idempotent_reseal_cannot_inflate_support():
    """The same physical record (same record_id) repeated must count ONCE — an
    idempotent re-seal cannot manufacture a pattern."""
    one = make_obs("wire", "forbid", "f0")
    obs = [one] * 8  # eight copies of ONE record
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_tier_dimension_is_not_mined_by_default():
    # A consistently-SEALED subject (the inflating direction) is ignored by default.
    obs = [make_obs("x", "sealed", f"s{i}", dimension=OutcomeDimension.TIER) for i in range(8)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_mining_is_deterministic_and_order_independent():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    a = HabitMiner().mine(tenant="acme", outcomes=obs)
    b = HabitMiner().mine(tenant="acme", outcomes=list(reversed(obs)))
    assert [h.hypothesis_id for h in a] == [h.hypothesis_id for h in b]


def test_config_can_tune_support_floor():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(4)]
    cfg = MinerConfig(min_support=3, min_confidence=0.4)
    hyps = HabitMiner(cfg).mine(tenant="acme", outcomes=obs)
    assert len(hyps) == 1  # a looser, explicit config can surface less evidence
