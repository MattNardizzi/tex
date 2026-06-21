"""The Definition-of-Done cycle, driven through the REAL gate → fold → compose:

    correct a tier  →  sealed labeled record written + citable
                    →  influences the NEXT decision for that tenant (the claim is
                       stripped from the spoken answer)
                    →  revoke makes it gone and STOPS influencing (the answer is
                       spoken again).

Nothing here is mocked: the truth-gate recomputes ``forbid_count`` from the real
in-memory stores in ``populated_state`` (parent conftest), and ``build_envelope``
is the production composer. The only thing inserted is the orchestrator's one line,
``apply_profile_corrections``.
"""

from __future__ import annotations

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate.compose import build_envelope
from tex.presence.gate.gate import PresenceTruthGate
from tex.presence.profile import SealedProfileMemory, apply_profile_corrections

_ABSTAIN_TEXT = "I can't ground that, so I'm holding it for review."


def _spoken(state, profile, tenant="acme"):
    """Run gate → (profile fold) → compose, exactly as the wired orchestrator
    would, and return (spoken_text, overall_tier)."""
    gate = PresenceTruthGate()
    claim = PresenceClaim("forbid_count", "how many forbids were there", ClaimKind.AGGREGATE)
    detailed = gate.evaluate_detailed(
        request=state, tenant=tenant, draft="there were some forbids", claims=(claim,), facts=None,
    )
    detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed, profile=profile)
    envelope = build_envelope(detailed, templated_abstain=_ABSTAIN_TEXT)
    return envelope.spoken_text, envelope.overall_tier


def test_correct_then_revoke_full_cycle(populated_state):
    profile = SealedProfileMemory(mirror=None)

    # 1) Baseline: the gate grounds forbid_count=3 and SPEAKS it (SEALED).
    spoken0, tier0 = _spoken(populated_state, profile)
    assert tier0 is PresenceTier.SEALED
    assert "3" in spoken0 and spoken0 != _ABSTAIN_TEXT

    # 2) Operator corrects: "don't speak my forbid count as a sealed fact" → ABSTAIN.
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", original_tier=PresenceTier.SEALED,
        statement="don't speak my forbid count as sealed",
    )
    # Sealed labeled record written + citable.
    assert ref.store == "presence_profile"
    assert profile.recall_profile(tenant="acme").refs() == (ref,)

    # 3) It influences the NEXT decision: the claim is now stripped → templated ABSTAIN.
    spoken1, tier1 = _spoken(populated_state, profile)
    assert tier1 is PresenceTier.ABSTAIN
    assert spoken1 == _ABSTAIN_TEXT
    assert "3" not in spoken1

    # 4) Isolation: a DIFFERENT tenant is unaffected (still speaks the count).
    spoken_other, tier_other = _spoken(populated_state, profile, tenant="globex")
    assert tier_other is PresenceTier.SEALED and "3" in spoken_other

    # 5) Revoke makes it gone and STOPS influencing — the answer is spoken again.
    assert profile.revoke(tenant="acme", record_id=ref.record_id) is True
    spoken2, tier2 = _spoken(populated_state, profile)
    assert tier2 is PresenceTier.SEALED
    assert spoken2 == spoken0  # byte-identical to the pre-correction answer


def test_correction_only_suppresses_the_corrected_subject(populated_state):
    # Correcting forbid_count must not touch a permit_count claim in the same answer.
    profile = SealedProfileMemory(mirror=None)
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    gate = PresenceTruthGate()
    claims = (
        PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),
        PresenceClaim("permit_count", "how many permits", ClaimKind.AGGREGATE),
    )
    detailed = gate.evaluate_detailed(request=populated_state, tenant="acme", draft="", claims=claims, facts=None)
    detailed = apply_profile_corrections(tenant="acme", evaluations=detailed, profile=profile)
    by_id = {e.claim.claim_id: e.verdict.tier for e in detailed}
    assert by_id["forbid_count"] is PresenceTier.ABSTAIN   # corrected → suppressed
    assert by_id["permit_count"] is PresenceTier.SEALED    # untouched

    # The spoken answer still contains the permit count (2) but not a forbid count.
    envelope = build_envelope(detailed, templated_abstain=_ABSTAIN_TEXT)
    assert "2" in envelope.spoken_text
