"""The tier→prosody mapping and wire helpers.

These pin the cardinal honesty rule: prosody is a PURE FUNCTION of the monotone
verdict tier and nothing else, and the mapping itself can never invert confidence
(a more-cautious tier never yields a more-assured-sounding plan).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tex.presence.contract import (
    AnswerEnvelope,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
    ProsodyMapper,
    ProsodyPlan,
    ClaimKind,
)
from tex.presence.prosody import (
    DEFAULT_MAPPER,
    EpistemicProsodyMapper,
    elevenlabs_voice_settings,
    kokoro_speed,
    plan_from_token,
    prosody_param_for_envelope,
    prosody_param_for_tier,
    tier_from_token,
    tier_token,
)

# Confidence rank: higher == sounds more assured. terminal pitch maps
# falling(assured) > level > rising(uncertain).
_PITCH_RANK = {"falling": 2, "level": 1, "rising": 0}
_TIERS_DESC = [PresenceTier.SEALED, PresenceTier.DERIVED, PresenceTier.ABSTAIN]


def test_mapper_satisfies_protocol():
    assert isinstance(EpistemicProsodyMapper(), ProsodyMapper)
    assert isinstance(DEFAULT_MAPPER, ProsodyMapper)


@pytest.mark.parametrize("tier", list(PresenceTier))
def test_mapper_is_exactly_the_frozen_function(tier):
    # The mapper delegates to the frozen contract function — it does NOT invent a
    # second mapping that could drift from the verdict's meaning.
    assert DEFAULT_MAPPER.plan(tier) == ProsodyPlan.from_tier(tier)


@pytest.mark.parametrize("tier", list(PresenceTier))
def test_mapper_is_deterministic_and_pure(tier):
    # Same tier in ⇒ identical plan out, every time. There is no other input the
    # function can read (signature is tier-only), so prosody cannot be sourced
    # from text/draft/vibe.
    plans = {DEFAULT_MAPPER.plan(tier) for _ in range(50)}
    assert len(plans) == 1


def test_mapping_is_monotone_cannot_invert_confidence():
    # Across SEALED → DERIVED → ABSTAIN every dimension must move toward LESS
    # assured (or hold): rate non-increasing, pause non-decreasing, terminal pitch
    # non-increasing in assurance. This is what makes "the voice can never sound
    # more confident than the verdict" true at the mapping layer.
    plans = [ProsodyPlan.from_tier(t) for t in _TIERS_DESC]
    rates = [p.rate for p in plans]
    pauses = [p.lead_pause_ms for p in plans]
    pitch = [_PITCH_RANK[p.terminal_pitch] for p in plans]

    assert rates == sorted(rates, reverse=True) and len(set(rates)) == 3
    assert pauses == sorted(pauses) and len(set(pauses)) == 3
    assert pitch == sorted(pitch, reverse=True) and len(set(pitch)) == 3


def test_backend_knobs_preserve_tier_order():
    # The translators must not collapse/invert the order after clamping, and every
    # contract rate must sit INSIDE both backends' accepted ranges (kokoro
    # hard-ASSERTS [0.5,2.0] — out of range crashes, it does not clamp; EL is
    # [0.7,1.2]). Guards a future contract retune.
    plans = [ProsodyPlan.from_tier(t) for t in _TIERS_DESC]
    ks = [kokoro_speed(p) for p in plans]
    es = [elevenlabs_voice_settings(p)["speed"] for p in plans]
    assert ks == sorted(ks, reverse=True) and len(set(ks)) == 3
    assert es == sorted(es, reverse=True) and len(set(es)) == 3
    for p in plans:
        assert 0.5 <= p.rate <= 2.0   # kokoro hard-assert range
        assert 0.7 <= p.rate <= 1.2   # elevenlabs documented range


# --------------------------------------------------------------------------- wire tokens


@pytest.mark.parametrize("tier", list(PresenceTier))
def test_token_roundtrip(tier):
    assert tier_from_token(tier_token(tier)) is tier
    assert prosody_param_for_tier(tier) == tier.value
    assert plan_from_token(tier_token(tier)) == ProsodyPlan.from_tier(tier)


def test_token_is_case_and_space_tolerant():
    assert tier_from_token("  SEALED ") is PresenceTier.SEALED
    assert tier_from_token("Abstain") is PresenceTier.ABSTAIN


@pytest.mark.parametrize(
    "junk",
    ["", "   ", "confident", "sealed;rate=2", "SEALED\x00", "1.05", "rising", None],
)
def test_token_rejects_everything_but_a_tier(junk):
    # A caller cannot smuggle raw rate/pitch/pause through this seam: only the
    # three StrEnum values parse; everything else is None (→ caller renders the
    # fail-safe, never a hand-set assured plan).
    assert tier_from_token(junk) is None
    assert plan_from_token(junk) is None


# --------------------------------------------------------------------------- envelope hand-off


def _verdict(tier):
    return PresenceVerdict(claim_id=f"c-{tier.value}", tier=tier)


def test_param_for_envelope_tracks_the_monotone_fold_not_the_plan():
    # Build an envelope whose stored prosody_plan is deliberately INFLATED to
    # SEALED while the verdicts fold to ABSTAIN. The wire token must follow the
    # fold (ABSTAIN), never the inflated plan — and assert_supported must reject
    # the inflated envelope so it can never be spoken as-is.
    verdicts = (_verdict(PresenceTier.SEALED), _verdict(PresenceTier.ABSTAIN))
    claims = tuple(
        PresenceClaim(claim_id=v.claim_id, text_span="x", kind=ClaimKind.ENTITY)
        for v in verdicts
    )
    env = AnswerEnvelope(
        spoken_text="x",
        claims=claims,
        verdicts=verdicts,
        prosody_plan=ProsodyPlan.from_tier(PresenceTier.SEALED),  # inflated
    )
    assert env.overall_tier is PresenceTier.ABSTAIN
    assert prosody_param_for_envelope(env) == "abstain"
    with pytest.raises(ValueError):
        env.assert_supported()


def test_param_for_empty_envelope_is_abstain_never_neutral_confident():
    env = AnswerEnvelope(spoken_text="(nothing grounded)")
    assert env.overall_tier is PresenceTier.ABSTAIN
    assert prosody_param_for_envelope(env) == "abstain"


def test_param_for_none_envelope_is_none():
    # Presence not engaged ⇒ no token ⇒ client omits prosody ⇒ today's neutral
    # voice. Honest: no presence verdict, no epistemic prosody.
    assert prosody_param_for_envelope(None) is None


@pytest.mark.parametrize("tier", list(PresenceTier))
def test_param_for_uniform_envelope_matches_tier(tier):
    v = _verdict(tier)
    c = PresenceClaim(claim_id=v.claim_id, text_span="x", kind=ClaimKind.ENTITY)
    env = AnswerEnvelope(spoken_text="x", claims=(c,), verdicts=(v,)).with_bound_prosody()
    assert prosody_param_for_envelope(env) == tier.value
