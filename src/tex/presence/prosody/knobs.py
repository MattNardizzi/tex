"""Translate a :class:`~tex.presence.contract.ProsodyPlan` into the concrete
knobs each TTS backend actually exposes — and into real PCM post-processing for
the cues no backend exposes.

Every function here takes a ``ProsodyPlan`` (or ``None``) and NOTHING else. A
plan is only ever produced by :meth:`ProsodyPlan.from_tier`, so by construction
no request text, model draft, or "vibe" can reach these knobs. ``None`` means
"no plan supplied" and yields the NEUTRAL knob (today's behavior, byte-for-byte),
which keeps the wiring purely additive.

Knob coverage, stated honestly (degrade cleanly where a backend lacks a knob):

  * ``rate``  → Kokoro ``create(speed=...)`` and ElevenLabs
    ``voice_settings.speed`` — a GENERATION-TIME knob, so it is applied inside the
    backend's synth call (you cannot change speech rate after rendering without a
    time-stretch that would also move pitch). Both backends honor it.
  * ``lead_pause_ms`` → real leading silence, prepended to the rendered PCM
    (:func:`lead_silence_pcm16`). Applies on every WAV/PCM path. DEGRADES on the
    ElevenLabs MP3 *stream* (you cannot splice silence into a live MP3 frame
    stream without re-encoding) — see ``tex.gateway.backends.synthesize_tts_stream``.
  * ``terminal_pitch`` → no TTS backend exposes a terminal-F0 contour knob, so
    this is a genuine (not faked) post-process: a smooth pitch GLIDE applied to
    the final window of the rendered PCM (:func:`apply_prosody_to_wav`). It is
    real signal processing — the tail's dominant frequency actually moves — and
    is verified by a zero-crossing test. ``"level"`` is an exact no-op. DEGRADES
    on the MP3 stream, same reason as the lead pause.

Evidence base for the DIRECTIONS (faster + falling == assured; slower + rising +
pause == uncertain), re-verified this session:
  * Goupil & Aucouturier, Nature Communications 12:861 (2021) — faster rate and a
    FALLING word-final contour read as confident/honest. NUANCE the design honors:
    it is the pitch CONTOUR direction (intonation), NOT the mean pitch LEVEL, that
    signals certainty (mean pitch was not a reliable predictor). Hence the
    terminal cue here is a CONTOUR glide, not a level shift.
  * Vromans, R. & Swerts, M., Risk Analysis 44(10):2496-2515 (2024),
    DOI 10.1111/risa.14319 — a RISING global intonation lowered perceived speaker
    confidence (large effect, partial-eta^2=0.82) and a filled/lead PAUSE lowered
    it further (partial-eta^2=0.42), the two being additive. (The frozen contract
    cites this as "Swerts, Risk Analysis 44(10), 2024"; the lead author is
    Vromans — corrected here, not in the frozen contract.)

stdlib only (``wave``/``struct``/``io``) so the dependency-free ``OfflineTTS``
path is never broken by importing this.
"""

from __future__ import annotations

import struct
import wave
from io import BytesIO

from tex.presence.contract import ProsodyPlan

__all__ = [
    "kokoro_speed",
    "elevenlabs_voice_settings",
    "lead_silence_pcm16",
    "apply_prosody_to_wav",
    "describe",
]

# Neutral / clamp envelopes. Our tier rates live in [0.9, 1.05], comfortably
# inside every backend's accepted range; the clamps are belt-and-braces so a
# future contract tweak can never drive a backend out of range.
_NEUTRAL_RATE = 1.0
# Kokoro (kokoro_onnx Kokoro.create) accepts a wide speed range; keep a sane
# guard rail. Higher == faster.
_KOKORO_MIN, _KOKORO_MAX = 0.5, 2.0
# ElevenLabs voice_settings.speed is documented in [0.7, 1.2] (verified against
# the ElevenLabs TTS docs this session — voice_settings.speed: number, default
# 1.0, range 0.7..1.2, honored by eleven_flash_v2_5; partial voice_settings is
# accepted). The non-speed fields are PINNED to ElevenLabs' documented defaults
# so perceived confidence is a pure function of the tier (via speed) and never
# drifts with the account's mutable stored voice settings.
_EL_SPEED_MIN, _EL_SPEED_MAX = 0.7, 1.2
_EL_PINNED_SETTINGS = {
    "stability": 0.5,
    "similarity_boost": 0.75,
    "style": 0.0,
    "use_speaker_boost": True,
}

# Terminal-pitch glide: a smooth ramp over the final window. The end-of-window
# instantaneous read rate (<1 stretches → lower pitch; >1 compresses → higher
# pitch). Magnitudes are fixed CONSTANTS per direction — a pure function of the
# tier-derived terminal_pitch string, never of any audio content.
_GLIDE_WINDOW_S = 0.25
_FALL_END_RATE = 0.85  # ~2.8 semitones down by the end of the window
_RISE_END_RATE = 1.15  # ~2.4 semitones up


def _clampf(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _clamp16(x: int) -> int:
    return -32768 if x < -32768 else 32767 if x > 32767 else x


def kokoro_speed(plan: ProsodyPlan | None) -> float:
    """Kokoro ``create(speed=...)`` for this plan. ``None`` → 1.0 (neutral)."""
    if plan is None:
        return _NEUTRAL_RATE
    return _clampf(plan.rate, _KOKORO_MIN, _KOKORO_MAX)


def elevenlabs_voice_settings(plan: ProsodyPlan | None) -> dict | None:
    """ElevenLabs ``voice_settings`` for this plan, or ``None`` to send no
    settings at all (preserving today's behavior — the account's stored voice
    defaults — exactly, for the param-absent path).

    When a plan IS supplied, ONLY ``speed`` varies by tier (the one field
    grounded in the rate-vs-certainty literature). The other fields are pinned to
    documented constants so two tiers can differ ONLY in speed and perceived
    confidence can never drift from a non-tier source (a mutable stored account
    setting). See :data:`_EL_PINNED_SETTINGS`."""
    if plan is None:
        return None
    return {"speed": _clampf(plan.rate, _EL_SPEED_MIN, _EL_SPEED_MAX), **_EL_PINNED_SETTINGS}


def lead_silence_pcm16(plan: ProsodyPlan | None, sample_rate: int) -> bytes:
    """``plan.lead_pause_ms`` of leading silence as mono s16le PCM. Empty for a
    ``None`` plan or a 0 ms pause (e.g. SEALED)."""
    if plan is None:
        return b""
    n = round(plan.lead_pause_ms / 1000.0 * sample_rate)
    return b"\x00\x00" * max(0, n)


def _glide_tail(samples: list[int], framerate: int, direction: str) -> list[int]:
    """Apply a smooth terminal-pitch glide to the final window of ``samples``.

    The glide's instantaneous read rate ramps from 1.0 (at the window start, so
    it is CONTINUOUS with the unshifted body — no click) to the per-direction end
    rate. Reading slower than 1.0 lengthens + lowers (falling); faster shortens +
    raises (rising). ``"level"`` (and anything unrecognized) is a no-op."""
    if direction == "falling":
        end_rate = _FALL_END_RATE
    elif direction == "rising":
        end_rate = _RISE_END_RATE
    else:
        return samples  # "level" / unknown → degrade to no glide

    n_total = len(samples)
    window = min(n_total, int(_GLIDE_WINDOW_S * framerate))
    if window < 8:  # too short to glide meaningfully
        return samples

    head = samples[: n_total - window]
    tail = samples[n_total - window :]
    n = len(tail)
    out: list[int] = []
    p = 0.0
    while p < n - 1:
        step = 1.0 + (end_rate - 1.0) * (p / (n - 1))  # ramp 1.0 → end_rate
        i = int(p)
        frac = p - i
        s = tail[i] + (tail[i + 1] - tail[i]) * frac
        out.append(_clamp16(int(round(s))))
        p += step
    return head + out


def apply_prosody_to_wav(wav_bytes: bytes, plan: ProsodyPlan | None) -> bytes:
    """Post-process a rendered mono s16le WAV with the cues that are NOT
    generation-time knobs: a terminal-pitch glide then a leading pause.

    Pure function of ``(wav_bytes, plan)``. A ``None`` plan, empty audio, or any
    non-mono / non-16-bit WAV is returned UNCHANGED — degrade, never corrupt
    (every Tex TTS backend emits mono s16le, so the transform runs on the real
    paths). Rate is NOT applied here; it is a generation-time backend knob."""
    if plan is None or not wav_bytes:
        return wav_bytes
    try:
        with wave.open(BytesIO(wav_bytes), "rb") as r:
            if r.getnchannels() != 1 or r.getsampwidth() != 2:
                return wav_bytes  # only shape mono s16le; otherwise leave intact
            framerate = r.getframerate()
            frames = r.readframes(r.getnframes())
    except (wave.Error, EOFError):
        return wav_bytes

    samples = list(struct.unpack("<%dh" % (len(frames) // 2), frames)) if frames else []
    samples = _glide_tail(samples, framerate, plan.terminal_pitch)
    body = struct.pack("<%dh" % len(samples), *samples) if samples else b""

    out = lead_silence_pcm16(plan, framerate) + body
    buf = BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(framerate)
        w.writeframes(out)
    return buf.getvalue()


def describe(plan: ProsodyPlan | None) -> dict:
    """A small, header/telemetry-friendly summary of the knobs a plan resolves to
    (no audio). Useful for the ``X-Tex-Voice-*`` headers and for tests."""
    if plan is None:
        return {"tier": None, "style": "neutral", "rate": _NEUTRAL_RATE,
                "terminal_pitch": "level", "lead_pause_ms": 0}
    return {
        "tier": plan.tier.value,
        "style": plan.style_label,
        "rate": plan.rate,
        "terminal_pitch": plan.terminal_pitch,
        "lead_pause_ms": plan.lead_pause_ms,
    }
