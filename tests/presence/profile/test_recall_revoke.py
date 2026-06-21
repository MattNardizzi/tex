"""recall_profile is citable; revoke is forget-by-avoidance (sound: a durable
failure RAISES rather than lying about success)."""

from __future__ import annotations

import pytest

from tex.presence.contract import PresenceTier
from tex.presence.profile import SealedProfileMemory

from .conftest import CountingMirror, RaisingMirror


def test_recall_returns_citable_active_facts(profile: SealedProfileMemory):
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="boundary",
    )
    facts = profile.recall_profile(tenant="acme")
    assert len(facts.facts) == 1
    fact = facts.facts[0]
    citable = fact.as_ref()
    assert citable.record_id == ref.record_id
    assert citable.record_hash == ref.record_hash
    assert citable.store == "presence_profile"
    # refs() helper is the same set.
    assert facts.refs() == (citable,)


def test_recall_lexical_query_filter(profile: SealedProfileMemory):
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="shadow agents worry me",
    )
    profile.apply_correction(
        tenant="acme", claim_id="permit_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="billing questions",
    )
    hits = profile.recall_profile(tenant="acme", query="shadow")
    assert len(hits.facts) == 1
    assert hits.facts[0].subject_key == "forbid_count"


def test_revoke_makes_fact_gone_and_uncitable(profile: SealedProfileMemory):
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    assert profile.revoke(tenant="acme", record_id=ref.record_id) is True
    assert profile.get(tenant="acme", record_id=ref.record_id) is None
    assert profile.recall_profile(tenant="acme").facts == ()


def test_revoke_absent_is_false_and_double_revoke_is_false(profile: SealedProfileMemory):
    assert profile.revoke(tenant="acme", record_id="pf-nope") is False
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    assert profile.revoke(tenant="acme", record_id=ref.record_id) is True
    assert profile.revoke(tenant="acme", record_id=ref.record_id) is False


def test_revoke_writes_through_durable_delete():
    mirror = CountingMirror(rowcount=1)
    profile = SealedProfileMemory(mirror=mirror)
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    assert mirror.upserts == [ref.record_id]  # write-through on write
    assert profile.revoke(tenant="acme", record_id=ref.record_id) is True
    assert mirror.deletes == [("acme", ref.record_id)]  # tenant-scoped delete


def test_revoke_raises_and_restores_on_durable_failure():
    # The one unrecoverable-lie risk, closed: a durable delete that RAISES must not
    # report success while a durable copy may survive.
    profile = SealedProfileMemory(mirror=RaisingMirror())
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    with pytest.raises(RuntimeError, match="postgres unreachable"):
        profile.revoke(tenant="acme", record_id=ref.record_id)
    # revoke did NOT lie: the fact is still present (re-inserted on failure).
    assert profile.get(tenant="acme", record_id=ref.record_id) is not None


def test_concurrent_revoke_returns_exactly_one_true():
    import threading

    profile = SealedProfileMemory(mirror=None)
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    n = 8
    results: list[bool] = []
    barrier = threading.Barrier(n)

    def worker() -> None:
        barrier.wait()
        results.append(profile.revoke(tenant="acme", record_id=ref.record_id))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    assert results.count(False) == n - 1


def test_remember_preference_is_recall_only(profile: SealedProfileMemory):
    from tex.presence.profile import ProfileFactKind

    ref = profile.remember_preference(
        tenant="acme", claim_id="forbid_count", statement="I always care about shadow agents",
        operator="ceo@acme.com",
    )
    fact = profile.get(tenant="acme", record_id=ref.record_id)
    assert fact.kind is ProfileFactKind.PREFERENCE
    assert fact.corrected_tier is None  # never influences a verdict
    # A preference with no text is refused.
    with pytest.raises(ValueError, match="non-empty statement"):
        profile.remember_preference(tenant="acme", claim_id="x", statement="  ", operator="ceo@acme.com")
