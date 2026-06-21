"""The red-team harness: the place a "noticed pattern" would let hallucination back
in. Every case must resolve to "surface nothing" or "tighten only" — never a false
pattern, never an inflating rule, never a fact the generator invented.
"""

from __future__ import annotations

import dataclasses

import pytest

from tex.presence.contract import PresenceTier
from tex.presence.habits.confirm import confirm_hypothesis
from tex.presence.habits.hooks import build_habit_surface
from tex.presence.habits.miner import HabitMiner
from tex.presence.habits.phrasing import render_hypothesis
from tex.presence.habits.types import HypothesisAction

from .conftest import make_obs


# --- 1. false-pattern attacks: noise must surface nothing ---------------------


def test_pure_noise_surfaces_nothing():
    """Many subjects, each a coin-flip of outcomes — no real habit anywhere."""
    obs = []
    for s in range(15):
        # alternating forbid/permit → ~50% each, never a strong pattern
        for i in range(6):
            obs.append(make_obs(f"subj{s}", "forbid" if i % 2 == 0 else "permit", f"s{s}_{i}"))
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_spurious_clean_subject_among_noise_is_suppressed_by_multiplicity():
    obs = [make_obs("lucky", "forbid", f"l{i}") for i in range(5)]
    for s in range(19):
        obs += [make_obs(f"n{s}", "forbid", f"n{s}_{i}") for i in range(3)]
        obs += [make_obs(f"n{s}", "permit", f"n{s}_p{i}") for i in range(2)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_reseal_flood_cannot_manufacture_a_pattern():
    """An adversary re-submitting ONE sealed record many times must not create a
    pattern — dedupe by record_id defeats it."""
    one = make_obs("wire", "forbid", "f0")
    assert HabitMiner().mine(tenant="acme", outcomes=[one] * 50) == ()


# --- 2. inflation attacks: a habit may only ever tighten ---------------------


def test_a_habit_action_cannot_propose_sealed():
    """Defence in depth #1: the action type itself refuses an inflating proposal."""
    with pytest.raises(ValueError):
        HypothesisAction(subject_key="x", proposed_tier=PresenceTier.SEALED, statement="nope")


def test_permit_flood_never_becomes_a_confidence_rule():
    """"You PERMIT everything about X" is real, but turning it into a rule would
    RAISE confidence. It must surface nothing."""
    obs = [make_obs("safe", "permit", f"p{i}") for i in range(10)]
    assert HabitMiner().mine(tenant="acme", outcomes=obs) == ()


def test_l2_refuses_an_inflating_correction_even_if_one_reaches_it(profile):
    """Defence in depth #2: even a hand-forged hypothesis that smuggles a SEALED
    tier past L3 is refused by L2's write-gate — nothing is written."""
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    h = HabitMiner().mine(tenant="acme", outcomes=obs)[0]
    # Forge an inflating action by going around the dataclass guard.
    forged_action = dataclasses.replace(h.action)
    object.__setattr__(forged_action, "proposed_tier", PresenceTier.SEALED)
    forged = dataclasses.replace(h, action=forged_action)
    with pytest.raises(ValueError):
        confirm_hypothesis(hypothesis=forged, profile=profile, operator="alice")
    assert profile.correction_calls == []  # nothing written


# --- 3. the generator is never the fact-source -------------------------------


def test_default_phrasing_contains_only_mined_numbers():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    h = HabitMiner().mine(tenant="acme", outcomes=obs)[0]
    text = render_hypothesis(h)
    # The counts spoken are the mined counts — no other number is introduced.
    assert "6" in text  # k == n == 6
    assert "100%" in text
    # No causal / intent language.
    low = text.casefold()
    for forbidden in ("you want", "because", "you intend", "you prefer"):
        assert forbidden not in low


def test_adversarial_phraser_cannot_alter_the_load_bearing_content(mem, profile):
    """An LLM phraser that fabricates extra prose can change ONLY the cosmetic
    ``phrasing`` — the structured hypothesis (counts + supporting receipts), which
    is what gets confirmed/sealed, is untouched."""
    from tex.domain.verdict import Verdict

    from .conftest import seal_governed

    class LyingPhraser:
        def phrase(self, hyp):
            return "I've noticed you ALWAYS forbid everything, 999/999, trust me."

    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=6)
    surface = build_habit_surface(memory=mem, profile=profile, phraser=LyingPhraser())
    h = next(x for x in surface.surface(tenant="acme") if x.subject_key == "wire")
    # The lie is confined to .phrasing; the receipts and counts are the real ones.
    assert h.confidence.k == 6 and h.confidence.n == 6
    assert h.supporting_count() == 6
    assert h.action.proposed_tier is PresenceTier.ABSTAIN
    # Confirming uses the structured fields, not the prose — the correction is correct.
    surface.confirm(hypothesis=h, operator="alice")
    assert profile.correction_calls[0]["corrected_tier"] is PresenceTier.ABSTAIN


# --- 4. cross-tenant leakage -------------------------------------------------


def test_one_tenants_records_never_enter_anothers_hypotheses(mem, profile):
    from tex.domain.verdict import Verdict

    from .conftest import seal_governed

    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=6)
    seal_governed(mem, tenant="globex", claim_id="wire", governance_verdict=Verdict.PERMIT, n=6)
    surface = build_habit_surface(memory=mem, profile=profile)
    # globex's records are all PERMIT → no cautionary habit; acme's are all FORBID.
    assert surface.surface(tenant="globex") == ()
    acme = surface.surface(tenant="acme")
    assert [h.subject_key for h in acme] == ["wire"]
