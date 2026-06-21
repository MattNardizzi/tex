"""The Definition of Done, exercised end to end against REAL stores.

  * a CLEAR pattern → "I've noticed…" with receipts → confirm → it influences the
    NEXT decision (via L2's monotone tier-ceiling fold, using the frozen contract's
    ``tighten``);
  * NOISE → nothing;
  * unconfirmed → nothing;
  * per-tenant isolation holds.
"""

from __future__ import annotations

from tex.domain.verdict import Verdict
from tex.presence.contract import (
    ClaimKind,
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
    tighten,
)
from tex.presence.habits.hooks import build_habit_surface

from .conftest import seal_governed


def _next_verdict_about(subject: str) -> PresenceVerdict:
    """A fresh, fully-grounded SEALED verdict the gate would emit for ``subject`` on
    the NEXT question — the thing a confirmed habit must be able to cap."""
    return PresenceVerdict(
        claim_id=subject,
        tier=PresenceTier.SEALED,
        evidence=(EvidenceRef(record_id="r", record_hash="h" * 64, store="decision_store"),),
        recomputed_value=1,
        reason="recomputed-from-rows",
    )


def _apply_ceiling(verdict: PresenceVerdict, ceiling: PresenceTier | None) -> PresenceVerdict:
    """L2's cap, by the spec: a verdict is capped at the ceiling via the FROZEN
    ``tighten`` (only ever lowers). For an ABSTAIN ceiling this is unambiguous."""
    if ceiling is None:
        return verdict
    capped = tighten(verdict.tier, ceiling)
    return verdict if capped is verdict.tier else PresenceVerdict(
        claim_id=verdict.claim_id, tier=capped, reason=verdict.reason
    )


def test_clear_pattern_surfaces_confirms_and_influences_next_decision(mem, profile):
    tenant = "acme"
    # 1. SEED a clear repeated pattern: every sealed decision about offshore wires
    #    was forbidden.
    seal_governed(mem, tenant=tenant, claim_id="offshore_wire",
                  governance_verdict=Verdict.FORBID, n=6)

    surface = build_habit_surface(memory=mem, profile=profile)

    # 2. Tex NOTICES and OFFERS — with the supporting sealed records + the phrasing.
    hyps = surface.surface(tenant=tenant)
    wire = [h for h in hyps if h.subject_key == "offshore_wire"]
    assert len(wire) == 1
    h = wire[0]
    assert h.dominant_outcome == "forbid"
    assert h.supporting_count() == 6
    assert all(r.store == "presence_memory" for r in h.supporting)  # real receipts
    assert h.phrasing.startswith("I've noticed")
    assert h.action.proposed_tier is PresenceTier.ABSTAIN

    # 3. Before confirmation: the next verdict about the subject is UNCHANGED.
    ceiling_before = profile.recall_profile(tenant=tenant).tier_ceiling("offshore_wire")
    assert ceiling_before is None
    assert _apply_ceiling(_next_verdict_about("offshore_wire"), ceiling_before).tier is PresenceTier.SEALED

    # 4. CONFIRM → one sealed L2 correction.
    receipt = surface.confirm(hypothesis=h, operator="alice")
    assert receipt.profile_ref.store == "presence_profile"

    # 5. The NEXT decision about the subject is now capped to ABSTAIN (deferred).
    ceiling_after = profile.recall_profile(tenant=tenant).tier_ceiling("offshore_wire")
    assert ceiling_after is PresenceTier.ABSTAIN
    capped = _apply_ceiling(_next_verdict_about("offshore_wire"), ceiling_after)
    assert capped.tier is PresenceTier.ABSTAIN
    assert not capped.supports_speech()


def test_noise_surfaces_no_hypothesis(mem, profile):
    tenant = "acme"
    # A spread of verdicts about distinct subjects + a mixed subject — no real habit.
    seal_governed(mem, tenant=tenant, claim_id="topic_a", governance_verdict=Verdict.FORBID, n=2)
    seal_governed(mem, tenant=tenant, claim_id="topic_b", governance_verdict=Verdict.PERMIT, n=2)
    seal_governed(mem, tenant=tenant, claim_id="mixed", governance_verdict=Verdict.FORBID, n=3)
    seal_governed(mem, tenant=tenant, claim_id="mixed", governance_verdict=Verdict.PERMIT, n=3)
    surface = build_habit_surface(memory=mem, profile=profile)
    assert surface.surface(tenant=tenant) == ()


def test_unconfirmed_hypothesis_changes_nothing(mem, profile):
    tenant = "acme"
    seal_governed(mem, tenant=tenant, claim_id="wire", governance_verdict=Verdict.FORBID, n=6)
    surface = build_habit_surface(memory=mem, profile=profile)
    hyps = surface.surface(tenant=tenant)
    assert hyps  # something was offered
    # ...but surfacing wrote nothing: no corrections, and the next verdict is unchanged.
    assert profile.correction_calls == []
    assert profile.recall_profile(tenant=tenant).tier_ceiling("wire") is None


def test_per_tenant_isolation_end_to_end(mem, profile):
    # acme has the pattern; globex does not share acme's records or its confirmation.
    seal_governed(mem, tenant="acme", claim_id="wire", governance_verdict=Verdict.FORBID, n=6)
    surface = build_habit_surface(memory=mem, profile=profile)

    assert surface.surface(tenant="globex") == ()  # globex has no history

    h = next(h for h in surface.surface(tenant="acme") if h.subject_key == "wire")
    surface.confirm(hypothesis=h, operator="alice")

    # acme is capped; globex is untouched.
    assert profile.recall_profile(tenant="acme").tier_ceiling("wire") is PresenceTier.ABSTAIN
    assert profile.recall_profile(tenant="globex").tier_ceiling("wire") is None
