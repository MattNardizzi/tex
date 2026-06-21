"""Sources turn REAL sealed stores into observations — per tenant, re-verifiable."""

from __future__ import annotations

from tex.domain.verdict import Verdict
from tex.presence.contract import PresenceTier
from tex.presence.habits.miner import HabitMiner
from tex.presence.habits.sources import (
    CompositeHistorySource,
    ProfileCorrectionHistorySource,
    S5MemoryHistorySource,
)
from tex.presence.habits.types import OutcomeDimension

from .conftest import seal_governed


def test_s5_source_reads_governance_and_tier_from_real_records(mem):
    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=5)
    obs = S5MemoryHistorySource(mem).outcomes(tenant="acme")
    gov = [o for o in obs if o.dimension is OutcomeDimension.GOVERNANCE_VERDICT]
    tier = [o for o in obs if o.dimension is OutcomeDimension.TIER]
    assert len(gov) == 5 and all(o.outcome_value == "forbid" for o in gov)
    assert len(tier) == 5 and all(o.outcome_value == "sealed" for o in tier)
    # Every observation carries a real, re-verifiable receipt into presence memory.
    assert all(o.evidence.store == "presence_memory" for o in obs)
    assert all(o.evidence.record_hash for o in obs)


def test_s5_source_is_strictly_per_tenant(mem):
    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=5)
    assert S5MemoryHistorySource(mem).outcomes(tenant="other") == ()


def test_s5_source_respects_recall_cap_honestly(mem):
    # Seal 25 distinct records; the documented recall cap (20) bounds the window.
    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=25)
    gov = [
        o for o in S5MemoryHistorySource(mem).outcomes(tenant="acme")
        if o.dimension is OutcomeDimension.GOVERNANCE_VERDICT
    ]
    assert len(gov) == 20  # capped, not 25 — the honest window


def test_s5_source_end_to_end_into_miner(mem):
    seal_governed(mem, tenant="acme", claim_id="offshore_wire", governance_verdict=Verdict.FORBID, n=6)
    hyps = HabitMiner().mine_source(tenant="acme", source=S5MemoryHistorySource(mem))
    subjects = {h.subject_key for h in hyps}
    assert "offshore_wire" in subjects
    h = next(h for h in hyps if h.subject_key == "offshore_wire")
    assert h.action.proposed_tier is PresenceTier.ABSTAIN


def test_profile_correction_source_reads_corrections(profile):
    profile.apply_correction(tenant="acme", claim_id="topic", corrected_tier=PresenceTier.ABSTAIN,
                             operator="alice")
    obs = ProfileCorrectionHistorySource(profile).outcomes(tenant="acme")
    assert len(obs) == 1
    assert obs[0].dimension is OutcomeDimension.CORRECTION_TIER
    assert obs[0].outcome_value == "abstain"
    assert obs[0].evidence.store == "presence_profile"


def test_composite_source_skips_a_faulty_member(mem):
    class Boom:
        def outcomes(self, *, tenant):
            raise RuntimeError("boom")

    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=5)
    composite = CompositeHistorySource(Boom(), S5MemoryHistorySource(mem))
    obs = composite.outcomes(tenant="acme")
    assert any(o.outcome_value == "forbid" for o in obs)  # the good member still produced
