"""Backend-knob translators + PCM post-processing.

Proves (1) the translators are pure functions of the plan, (2) the lead pause is
exact, content-independent silence, (3) the terminal-pitch glide is REAL DSP (the
tail's dominant frequency actually moves in the claimed direction), and (4) the
post-process fails CLOSED — a cautious tier never degrades toward a more-confident
render.
"""

from __future__ import annotations

import math
import struct
import wave
from io import BytesIO

import pytest

from tex.presence.contract import PresenceTier, ProsodyPlan
from tex.presence.prosody import (
    apply_prosody_to_wav,
    describe,
    elevenlabs_voice_settings,
    kokoro_speed,
    lead_silence_pcm16,
)

SR = 24000
F0 = 220.0


def _tone_wav(seconds=0.6, freq=F0, sample_rate=SR, nchannels=1, sampwidth=2):
    n = int(seconds * sample_rate)
    if sampwidth == 2:
        frame = lambda v: struct.pack("<h", int(v))  # noqa: E731
    else:  # 8-bit unsigned, only used for the "non-s16 degrade" test
        frame = lambda v: struct.pack("<B", int(128 + v / 256))  # noqa: E731
    mono = b"".join(frame(8000 * math.sin(2 * math.pi * freq * i / sample_rate)) for i in range(n))
    data = mono if nchannels == 1 else b"".join(mono[i:i + sampwidth] * nchannels for i in range(0, len(mono), sampwidth))
    buf = BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(sample_rate)
        w.writeframes(data)
    return buf.getvalue()


def _decode(wav_bytes):
    with wave.open(BytesIO(wav_bytes), "rb") as r:
        sr = r.getframerate()
        nframes = r.getnframes()
        frames = r.readframes(nframes)
    samples = list(struct.unpack("<%dh" % (len(frames) // 2), frames)) if frames else []
    return samples, sr


def _tail_freq(samples, sr, ms=60):
    seg = samples[-int(ms / 1000 * sr):]
    zc = sum(1 for a, b in zip(seg, seg[1:]) if (a >= 0) != (b >= 0))
    return (zc / 2) / (len(seg) / sr)


def _leading_zeros(samples):
    n = 0
    for v in samples:
        if v != 0:
            break
        n += 1
    return n


# --------------------------------------------------------------------------- purity


@pytest.mark.parametrize("tier", list(PresenceTier))
def test_knob_translators_are_pure_functions_of_the_plan(tier):
    plan = ProsodyPlan.from_tier(tier)
    # Identical plan ⇒ byte-identical knobs, regardless of how many times / in
    # what order we ask. No text, no draft, no global state is an input.
    assert {kokoro_speed(plan) for _ in range(20)} == {kokoro_speed(plan)}
    assert [elevenlabs_voice_settings(plan) for _ in range(5)].count(
        elevenlabs_voice_settings(plan)
    ) == 5
    assert lead_silence_pcm16(plan, SR) == lead_silence_pcm16(plan, SR)


def test_none_plan_is_neutral_passthrough():
    assert kokoro_speed(None) == 1.0
    assert elevenlabs_voice_settings(None) is None  # send no settings ⇒ today's behavior
    assert lead_silence_pcm16(None, SR) == b""
    wav = _tone_wav()
    assert apply_prosody_to_wav(wav, None) == wav  # exact passthrough


@pytest.mark.parametrize(
    "tier,expected_speed",
    [(PresenceTier.SEALED, 1.05), (PresenceTier.DERIVED, 0.98), (PresenceTier.ABSTAIN, 0.9)],
)
def test_kokoro_and_elevenlabs_speed_equal_the_tier_rate(tier, expected_speed):
    plan = ProsodyPlan.from_tier(tier)
    assert kokoro_speed(plan) == pytest.approx(expected_speed)
    assert elevenlabs_voice_settings(plan)["speed"] == pytest.approx(expected_speed)


def test_elevenlabs_voice_settings_only_speed_varies_by_tier():
    # Everything but speed is a PINNED constant across tiers ⇒ perceived
    # confidence can never drift from a mutable stored account setting.
    settings = [elevenlabs_voice_settings(ProsodyPlan.from_tier(t)) for t in PresenceTier]
    speeds = [s.pop("speed") for s in settings]
    assert len(set(speeds)) == 3                  # speed genuinely varies
    assert all(s == settings[0] for s in settings)  # the rest are identical constants
    # and the pinned constants are ElevenLabs' documented defaults
    assert settings[0] == {"stability": 0.5, "similarity_boost": 0.75,
                           "style": 0.0, "use_speaker_boost": True}


# --------------------------------------------------------------------------- lead pause


@pytest.mark.parametrize(
    "tier,ms", [(PresenceTier.SEALED, 0), (PresenceTier.DERIVED, 120), (PresenceTier.ABSTAIN, 280)],
)
def test_lead_silence_is_exact_and_content_independent(tier, ms):
    plan = ProsodyPlan.from_tier(tier)
    sil = lead_silence_pcm16(plan, SR)
    assert sil == b"\x00\x00" * round(ms / 1000 * SR)  # exact sample count, all zero
    # content-independence: the silence does not depend on any text/audio input.
    assert lead_silence_pcm16(plan, SR) == sil


# --------------------------------------------------------------------------- terminal glide (real DSP)


def test_terminal_pitch_glide_moves_tail_frequency_in_the_claimed_direction():
    base_samples, _ = _decode(_tone_wav())
    base_f = _tail_freq(base_samples, SR)

    sealed, _ = _decode(apply_prosody_to_wav(_tone_wav(), ProsodyPlan.from_tier(PresenceTier.SEALED)))
    derived, _ = _decode(apply_prosody_to_wav(_tone_wav(), ProsodyPlan.from_tier(PresenceTier.DERIVED)))
    abstain, _ = _decode(apply_prosody_to_wav(_tone_wav(), ProsodyPlan.from_tier(PresenceTier.ABSTAIN)))

    # SEALED = falling ⇒ tail pitch DOWN; ABSTAIN = rising ⇒ tail pitch UP;
    # DERIVED = level ⇒ tail pitch UNCHANGED (exact no-op glide).
    assert _tail_freq(sealed, SR) < base_f - 10
    assert _tail_freq(abstain, SR) > base_f + 10
    assert _tail_freq(derived, SR) == pytest.approx(base_f, abs=2.0)


def test_glide_starts_continuous_no_boundary_click():
    # The glide ramps from rate 1.0, so the body up to the final window is
    # untouched — no discontinuity is introduced before the window.
    plan = ProsodyPlan.from_tier(PresenceTier.SEALED)
    out, sr = _decode(apply_prosody_to_wav(_tone_wav(seconds=1.0), plan))
    # first ~700ms (before the 250ms glide window) equals the source tone exactly.
    src, _ = _decode(_tone_wav(seconds=1.0))
    keep = int(0.70 * sr)
    assert out[:keep] == src[:keep]


# --------------------------------------------------------------------------- fail-closed


def test_postprocess_failclosed_short_line_still_gets_lead_pause():
    # A sub-window ABSTAIN line: the terminal glide degrades to a no-op (window
    # too short) but the lead pause — cheap, content-independent — is STILL
    # applied. The cautious cue never fails open toward a more-confident render.
    plan = ProsodyPlan.from_tier(PresenceTier.ABSTAIN)
    tiny = _tone_wav(seconds=0.05)  # 50 ms < 250 ms glide window
    out, sr = _decode(apply_prosody_to_wav(tiny, plan))
    assert _leading_zeros(out) >= round(280 / 1000 * sr)


def test_postprocess_degrades_cleanly_on_non_mono_s16():
    # Not mono s16le ⇒ returned UNCHANGED (degrade, never corrupt). All Tex
    # backends emit mono s16le, so this is the defensive floor, not a live path.
    stereo = _tone_wav(nchannels=2)
    assert apply_prosody_to_wav(stereo, ProsodyPlan.from_tier(PresenceTier.ABSTAIN)) == stereo
    assert apply_prosody_to_wav(b"", ProsodyPlan.from_tier(PresenceTier.ABSTAIN)) == b""


def test_postprocess_output_is_valid_mono_s16_wav():
    out = apply_prosody_to_wav(_tone_wav(), ProsodyPlan.from_tier(PresenceTier.ABSTAIN))
    assert out[:4] == b"RIFF"
    with wave.open(BytesIO(out)) as r:
        assert r.getnchannels() == 1
        assert r.getsampwidth() == 2
        assert r.getframerate() == SR
        # lengthened by the lead pause (and the falling/rising tail), never shorter.
        assert r.getnframes() > len(_decode(_tone_wav())[0])


def test_describe_is_a_pure_summary():
    assert describe(None)["style"] == "neutral"
    d = describe(ProsodyPlan.from_tier(PresenceTier.ABSTAIN))
    assert d == {"tier": "abstain", "style": "uncertain", "rate": 0.9,
                 "terminal_pitch": "rising", "lead_pause_ms": 280}
