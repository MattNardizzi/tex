"""Strict per-tenant isolation: tenant A's corrections never recall, revoke, or
influence anything for tenant B. (Application-layer only — disclosed in the store
docstring; this proves the layer that DOES exist holds.)"""

from __future__ import annotations

from tex.presence.contract import PresenceTier
from tex.presence.profile import SealedProfileMemory, apply_corrections_to_verdicts

from .conftest import make_verdict


def test_recall_is_tenant_scoped(profile: SealedProfileMemory):
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="a@acme.com",
    )
    assert len(profile.recall_profile(tenant="acme").facts) == 1
    assert profile.recall_profile(tenant="globex").facts == ()


def test_correction_influence_is_tenant_scoped(profile: SealedProfileMemory):
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="a@acme.com",
    )
    v = make_verdict("forbid_count", tier=PresenceTier.SEALED)
    # acme's verdict is lowered; globex's identical verdict is untouched.
    assert apply_corrections_to_verdicts(tenant="acme", verdicts=(v,), profile=profile)[0].tier is PresenceTier.ABSTAIN
    assert apply_corrections_to_verdicts(tenant="globex", verdicts=(v,), profile=profile)[0].tier is PresenceTier.SEALED


def test_one_tenant_cannot_revoke_anothers_record(profile: SealedProfileMemory):
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="a@acme.com",
    )
    # globex cannot revoke acme's record even with the exact id.
    assert profile.revoke(tenant="globex", record_id=ref.record_id) is False
    assert profile.get(tenant="acme", record_id=ref.record_id) is not None


def test_one_tenant_cannot_get_anothers_record(profile: SealedProfileMemory):
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="a@acme.com",
    )
    assert profile.get(tenant="globex", record_id=ref.record_id) is None
