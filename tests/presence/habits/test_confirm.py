"""Confirm writes ONE L2 correction; not confirming writes nothing; nothing inflates."""

from __future__ import annotations

import pytest

from tex.presence.contract import PresenceTier
from tex.presence.habits.confirm import confirm_hypothesis, decline_hypothesis
from tex.presence.habits.miner import HabitMiner

from .conftest import make_obs


def _one_hypothesis():
    obs = [make_obs("wire", "forbid", f"f{i}") for i in range(6)]
    return HabitMiner().mine(tenant="acme", outcomes=obs)[0]


def test_confirm_writes_exactly_one_correction(profile):
    h = _one_hypothesis()
    receipt = confirm_hypothesis(hypothesis=h, profile=profile, operator="alice")
    assert len(profile.correction_calls) == 1
    call = profile.correction_calls[0]
    assert call["tenant"] == "acme"
    assert call["claim_id"] == "wire"
    assert call["corrected_tier"] is PresenceTier.ABSTAIN
    assert call["operator"] == "alice"
    assert receipt.profile_ref.store == "presence_profile"
    assert receipt.subject_key == "wire"


def test_confirm_passes_decision_id_through_for_l1_route(profile):
    h = _one_hypothesis()
    receipt = confirm_hypothesis(hypothesis=h, profile=profile, operator="alice", decision_id="dec-42")
    assert profile.correction_calls[0]["decision_id"] == "dec-42"
    assert receipt.decision_id == "dec-42"


def test_not_confirming_changes_nothing(profile):
    _one_hypothesis()  # mined, surfaced — but never confirmed
    assert profile.correction_calls == []
    assert profile.recall_profile(tenant="acme").facts == ()


def test_decline_writes_nothing(profile):
    h = _one_hypothesis()
    rec = decline_hypothesis(hypothesis=h, operator="alice")
    assert rec.subject_key == "wire"
    assert profile.correction_calls == []
    assert profile.recall_profile(tenant="acme").facts == ()


def test_confirm_requires_a_server_side_operator(profile):
    h = _one_hypothesis()
    with pytest.raises(ValueError):
        confirm_hypothesis(hypothesis=h, profile=profile, operator="")
    assert profile.correction_calls == []  # nothing written on refusal


def test_confirm_is_idempotent_in_the_store(profile):
    h = _one_hypothesis()
    confirm_hypothesis(hypothesis=h, profile=profile, operator="alice")
    confirm_hypothesis(hypothesis=h, profile=profile, operator="alice")
    # apply_correction is called twice, but the content-addressed fact dedupes.
    assert len(profile.correction_calls) == 2
    assert len(profile.recall_profile(tenant="acme").facts) == 1
