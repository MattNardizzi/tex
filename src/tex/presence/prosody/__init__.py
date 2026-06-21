"""Tex Presence — epistemic prosody (Session 4).

The voice's *perceived* confidence, bound to the gate's *real* verdict. One
monotone :class:`~tex.presence.contract.PresenceTier` drives a pure
:class:`~tex.presence.contract.ProsodyPlan` (the frozen
:meth:`ProsodyPlan.from_tier`); this package translates that plan into the knobs
each TTS backend actually has — and into honest PCM post-processing for the cues
none of them expose — so an ABSTAIN audibly sounds uncertain (slower, rising
terminal, a lead pause) and a SEALED answer sounds assured (slightly faster,
falling terminal). It can NEVER sound more confident than the verdict, because
prosody is a pure function of the monotone tier and nothing else.

Public surface::

    from tex.presence.prosody import (
        EpistemicProsodyMapper,           # the ProsodyMapper protocol impl
        plan_from_token,                  # /v1/speak: token → ProsodyPlan
        prosody_param_for_envelope,       # orchestrator: /v1/ask envelope → token
        kokoro_speed, elevenlabs_voice_settings,   # generation-time backend knobs
        apply_prosody_to_wav,             # post-process: lead pause + terminal glide
    )

``tex.gateway.backends`` and ``tex.api.voice_routes`` wire these in; they never
re-derive prosody from anything other than the tier.
"""

from __future__ import annotations

from tex.presence.prosody.knobs import (
    apply_prosody_to_wav,
    describe,
    elevenlabs_voice_settings,
    kokoro_speed,
    lead_silence_pcm16,
)
from tex.presence.prosody.mapper import (
    DEFAULT_MAPPER,
    EpistemicProsodyMapper,
    plan_from_token,
    prosody_param_for_envelope,
    prosody_param_for_tier,
    tier_from_token,
    tier_token,
)

__all__ = [
    "EpistemicProsodyMapper",
    "DEFAULT_MAPPER",
    "tier_token",
    "tier_from_token",
    "plan_from_token",
    "prosody_param_for_tier",
    "prosody_param_for_envelope",
    "kokoro_speed",
    "elevenlabs_voice_settings",
    "lead_silence_pcm16",
    "apply_prosody_to_wav",
    "describe",
]
