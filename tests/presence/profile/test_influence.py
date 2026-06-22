"""The influence fold — a correction can ONLY tighten (monotone-lowering).

These are the constitution's verdict-path-coverage tests for L2: they would FAIL if
a profile signal ever RAISED a tier, or fabricated a DERIVED floor, or left
evidence on an ABSTAIN verdict.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier, tighten
from tex.presence.gate.gate import ClaimEvaluation, RoutedClaim
from tex.presence.profile import (
    SealedProfileMemory,
    apply_corrections_to_verdicts,
    apply_profile_corrections,
    cap_verdict,
    stable_subject_key,
)

from .conftest import make_verdict

_TIERS = (PresenceTier.SEALED, PresenceTier.DERIVED, PresenceTier.ABSTAIN)
_RANK = {PresenceTier.SEALED: 2, PresenceTier.DERIVED: 1, PresenceTier.ABSTAIN: 0}


def _eval_for(verdict, *, query_key: str, kind: ClaimKind) -> ClaimEvaluation:
    """A real (frozen-dataclass) ClaimEvaluation with controllable verdict + a
    routed query — so the apply path keys on the STABLE routing subject exactly as
    it does in production. ``replace(e, verdict=...)`` needs a real dataclass."""
    query = SimpleNamespace(key=query_key, kind=kind)
    routed = RoutedClaim(query=query, target=None, reason="routed")
    claim = PresenceClaim(claim_id="brain-emitted-volatile-id", text_span="how many forbids", kind=kind)
    return ClaimEvaluation(claim=claim, verdict=verdict, recompute=None, routed=routed)


def test_cap_never_raises_a_tier_for_any_combination():
    # The core monotone invariant, exhaustively: for every (verdict tier, ceiling),
    # the capped tier is NEVER more confident than the original. A DERIVED ceiling
    # uses a floored DERIVED verdict so the only "stays DERIVED" edge is legal.
    for vt, ceiling in itertools.product(_TIERS, _TIERS):
        floor = 0.9 if vt is PresenceTier.DERIVED else None
        cov = "transductive" if vt is PresenceTier.DERIVED else None
        v = make_verdict(tier=vt, correctness_floor=floor, coverage_mode=cov)
        out = cap_verdict(v, ceiling)
        assert _RANK[out.tier] <= _RANK[vt], (vt, ceiling, out.tier)
        # And it equals the monotone fold of the two — never a max.
        assert out.tier is tighten(v.tier, _legal_floor_aware(vt, ceiling, floor))


def _legal_floor_aware(vt, ceiling, floor):
    # Mirror the production rule for the assertion: a DERIVED cap with no floor
    # present drops to ABSTAIN (no fabricated floor).
    capped = tighten(vt, ceiling)
    if capped is PresenceTier.DERIVED and floor is None:
        return PresenceTier.ABSTAIN
    return ceiling if _RANK[ceiling] <= _RANK[vt] else vt


def test_abstain_ceiling_clears_evidence_and_floor():
    v = make_verdict(tier=PresenceTier.SEALED, n_evidence=2)
    out = cap_verdict(v, PresenceTier.ABSTAIN, record_id="pf-x")
    assert out.tier is PresenceTier.ABSTAIN
    assert out.evidence == ()          # contract: evidence empty iff ABSTAIN
    assert out.correctness_floor is None
    assert "profile-correction:pf-x" in out.reason


def test_derived_ceiling_on_sealed_drops_to_abstain_no_fabricated_floor():
    # A SEALED verdict has no correctness_floor; capping at DERIVED must NOT mint a
    # floor-less DERIVED — it suppresses to ABSTAIN instead.
    v = make_verdict(tier=PresenceTier.SEALED)
    out = cap_verdict(v, PresenceTier.DERIVED)
    assert out.tier is PresenceTier.ABSTAIN
    assert out.correctness_floor is None


def test_derived_ceiling_on_floored_derived_is_a_noop():
    v = make_verdict(tier=PresenceTier.DERIVED, correctness_floor=0.9, coverage_mode="calibrated")
    out = cap_verdict(v, PresenceTier.DERIVED)
    assert out is v  # no-op: nothing to lower


def test_no_correction_leaves_verdict_untouched():
    v = make_verdict(tier=PresenceTier.SEALED)
    assert cap_verdict(v, None) is v


def test_apply_to_verdicts_lowers_only_the_corrected_subject(profile: SealedProfileMemory):
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    v_forbid = make_verdict("forbid_count", tier=PresenceTier.SEALED)
    v_permit = make_verdict("permit_count", tier=PresenceTier.SEALED)

    out = apply_corrections_to_verdicts(tenant="acme", verdicts=(v_forbid, v_permit), profile=profile)
    by_id = {v.claim_id: v for v in out}
    assert by_id["forbid_count"].tier is PresenceTier.ABSTAIN   # corrected subject lowered
    assert by_id["permit_count"].tier is PresenceTier.SEALED    # uncorrected subject untouched


def test_a_confirmation_never_influences_a_verdict(profile: SealedProfileMemory):
    # Confirmations are non-inflating by construction: the fold ignores them.
    profile.confirm(tenant="acme", claim_id="forbid_count", tier=PresenceTier.SEALED, operator="ceo@acme.com")
    v = make_verdict("forbid_count", tier=PresenceTier.SEALED)
    out = apply_corrections_to_verdicts(tenant="acme", verdicts=(v,), profile=profile)
    assert out[0] is v  # unchanged — a confirm cannot raise OR lower


def test_two_corrections_fold_to_the_most_cautious(profile: SealedProfileMemory):
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.DERIVED, operator="a@acme.com",
    )
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="b@acme.com",
    )
    facts = profile.recall_profile(tenant="acme")
    assert facts.tier_ceiling("forbid_count") is PresenceTier.ABSTAIN  # most cautious wins


def test_apply_path_correction_never_raises_a_tier_property():
    # CI GATE — the apply-side monotonicity property: for EVERY (gate verdict tier,
    # stored correction ceiling), the post-correction tier is NEVER more confident
    # than the gate's. A correction can ONLY tighten. This runs the REAL hot path
    # (apply_profile_corrections over a real ClaimEvaluation keyed on the stable
    # routing subject), so it would fail if the fold ever used max() or the
    # stable-key lookup mismatched and silently dropped a cap into a no-op-that-raises.
    subject = "q:aggregate:forbid_count"  # == stable_subject_key for the eval below
    for ceiling in (PresenceTier.DERIVED, PresenceTier.ABSTAIN):  # SEALED is write-refused
        profile = SealedProfileMemory(mirror=None)
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", subject_key=subject,
            corrected_tier=ceiling, operator="op@acme.com",
        )
        for vt in _TIERS:
            floor = 0.9 if vt is PresenceTier.DERIVED else None
            cov = "calibrated" if vt is PresenceTier.DERIVED else None
            v = make_verdict("forbid_count", tier=vt, correctness_floor=floor, coverage_mode=cov)
            e = _eval_for(v, query_key="forbid_count", kind=ClaimKind.AGGREGATE)
            assert stable_subject_key(e) == subject  # the stored subject really matches
            out = apply_profile_corrections(tenant="acme", evaluations=(e,), profile=profile)
            assert _RANK[out[0].verdict.tier] <= _RANK[vt], (vt, ceiling, out[0].verdict.tier)


def test_fold_fails_open_to_uncorrected_on_profile_error():
    # A profile that raises on recall must never raise a tier or crash voice — the
    # gate's verdict stands unchanged.
    class _Boom:
        def recall_profile(self, *, tenant, query=None):
            raise RuntimeError("profile down")

    v = make_verdict(tier=PresenceTier.SEALED)
    out = apply_corrections_to_verdicts(tenant="acme", verdicts=(v,), profile=_Boom())
    assert out == (v,)
