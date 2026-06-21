"""The write-gate: provenance validated BEFORE write + monotone-lowering DIRECTION.

A correction with no named operator, an *upward* (inflating) correction, or a
non-tightening transition writes NOTHING and raises — the frontier's named blind
spot ("validate provenance before write"), closed.
"""

from __future__ import annotations

import pytest

from tex.presence.contract import PresenceTier
from tex.presence.profile import ProfileFactKind, SealedProfileMemory


def test_correction_written_and_citable(profile: SealedProfileMemory):
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="don't speak my forbid count as sealed",
        original_tier=PresenceTier.SEALED,
    )
    assert ref.store == "presence_profile"
    assert ref.record_id.startswith("pf-")
    assert len(ref.record_hash) == 64
    assert ref.prior_link_witness is None  # content anchor, not a chain proof

    fact = profile.get(tenant="acme", record_id=ref.record_id)
    assert fact is not None
    assert fact.kind is ProfileFactKind.CORRECTION
    assert fact.corrected_tier is PresenceTier.ABSTAIN
    assert fact.operator == "ceo@acme.com"
    # The anchor re-verifies offline.
    assert profile.verify(fact) is True


def test_upward_correction_to_sealed_is_refused(profile: SealedProfileMemory):
    # An operator asserting confidence Tex cannot prove is the fabrication vector.
    with pytest.raises(ValueError, match="upward correction"):
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.SEALED,
            operator="ceo@acme.com",
        )
    # Nothing was written.
    assert profile.recall_profile(tenant="acme").facts == ()


def test_anonymous_correction_is_refused(profile: SealedProfileMemory):
    with pytest.raises(ValueError, match="non-empty operator"):
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
            operator="   ",
        )
    assert profile.recall_profile(tenant="acme").facts == ()


def test_empty_claim_id_is_refused(profile: SealedProfileMemory):
    with pytest.raises(ValueError, match="claim_id"):
        profile.apply_correction(
            tenant="acme", claim_id="  ", corrected_tier=PresenceTier.ABSTAIN,
            operator="ceo@acme.com",
        )


def test_non_tightening_transition_is_refused(profile: SealedProfileMemory):
    # DERIVED → DERIVED is not a tightening; there is nothing to correct downward.
    with pytest.raises(ValueError, match="must tighten"):
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.DERIVED,
            operator="ceo@acme.com", original_tier=PresenceTier.DERIVED,
        )
    # ABSTAIN original has nothing below it.
    with pytest.raises(ValueError, match="must tighten"):
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
            operator="ceo@acme.com", original_tier=PresenceTier.ABSTAIN,
        )


def test_empty_tenant_is_refused(profile: SealedProfileMemory):
    with pytest.raises(ValueError, match="non-empty tenant"):
        profile.apply_correction(
            tenant="  ", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
            operator="ceo@acme.com",
        )


def test_resealing_identical_correction_is_idempotent(profile: SealedProfileMemory):
    kwargs = dict(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="same",
    )
    ref1 = profile.apply_correction(**kwargs)
    ref2 = profile.apply_correction(**kwargs)
    assert ref1.record_id == ref2.record_id  # content-addressed → idempotent
    assert len(profile.recall_profile(tenant="acme").facts) == 1


def test_different_operator_yields_a_different_record(profile: SealedProfileMemory):
    # operator is part of the content anchor (provenance is load-bearing).
    ref1 = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="a@acme.com",
    )
    ref2 = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="b@acme.com",
    )
    assert ref1.record_id != ref2.record_id


def test_believed_value_is_stored_but_never_in_a_spoken_field(profile: SealedProfileMemory):
    # The typed number an operator believes is metadata only — it is recorded for
    # audit but lives in believed_value, never in any spoken/recomputed field.
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", believed_value="3",
    )
    fact = profile.get(tenant="acme", record_id=ref.record_id)
    assert fact.believed_value == "3"
    # It is NOT smuggled into the statement or any tier field.
    assert "3" not in fact.statement
