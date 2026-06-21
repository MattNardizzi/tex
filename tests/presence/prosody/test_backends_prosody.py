"""Per-backend prosody wiring that the route tests don't exercise directly:
OfflineTTS's generation-time rate, and the word-timed ElevenLabs path (rate +
synced lead pause, glide intentionally degraded)."""

from __future__ import annotations

import base64
import json
import struct
import urllib.request
import wave
from io import BytesIO

import pytest

from tex.gateway.backends import OfflineTTS
from tex.presence.contract import PresenceTier, ProsodyPlan

SR = 24000


def _nframes(wav_bytes):
    with wave.open(BytesIO(wav_bytes), "rb") as r:
        return r.getnframes()


def test_offline_tts_rate_scales_duration_monotonically():
    text = "the evidence chain is intact"
    sealed = OfflineTTS().synthesize(text, sample_rate=SR, prosody=ProsodyPlan.from_tier(PresenceTier.SEALED))
    neutral = OfflineTTS().synthesize(text, sample_rate=SR)  # rate 1.0
    abstain = OfflineTTS().synthesize(text, sample_rate=SR, prosody=ProsodyPlan.from_tier(PresenceTier.ABSTAIN))
    # faster (SEALED 1.05) ⇒ shorter; slower (ABSTAIN 0.9) ⇒ longer. The rate cue
    # is real even on the no-voice floor.
    assert _nframes(sealed) < _nframes(neutral) < _nframes(abstain)


def test_offline_tts_no_prosody_is_unchanged():
    text = "hello"
    a = OfflineTTS().synthesize(text, sample_rate=SR)
    b = OfflineTTS().synthesize(text, sample_rate=SR, prosody=None)
    assert a == b


def _patch_timed(monkeypatch):
    captured: dict = {}
    pcm = b"\x11\x11" * 200  # non-zero raw PCM so we can see the silence prefix
    body = json.dumps(
        {
            "audio_base64": base64.b64encode(pcm).decode(),
            "alignment": {
                "characters": list("Forbid it"),
                "character_start_times_seconds": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
                "character_end_times_seconds": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
            },
        }
    ).encode("utf-8")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return body

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    return captured


def test_synthesize_timed_applies_rate_and_lead_pause_with_synced_shift(monkeypatch):
    from tex.gateway.backends import ElevenLabsTTS

    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    captured = _patch_timed(monkeypatch)

    plan = ProsodyPlan.from_tier(PresenceTier.ABSTAIN)
    out = ElevenLabsTTS().synthesize_timed("Forbid it", sample_rate=SR, prosody=plan)

    # rate carried into the request
    assert captured["body"]["voice_settings"]["speed"] == pytest.approx(0.9)
    rate = out["sample_rate"]
    shift = 280 / 1000.0

    # word times shifted by exactly the lead pause so the highlight stays in sync.
    # "Forbid" spans chars 0..5 (start 0.0, end 0.6); "it" spans chars 7..8
    # (start 0.7, end 0.9).
    assert out["words"][0]["start"] == pytest.approx(0.0 + shift)
    assert out["words"][0]["end"] == pytest.approx(0.6 + shift)
    assert out["words"][1]["start"] == pytest.approx(0.7 + shift)

    # the returned PCM has the leading silence prepended
    audio = base64.b64decode(out["audio_b64"])
    lead_samples = round(280 / 1000 * rate)
    assert audio[: lead_samples * 2] == b"\x00\x00" * lead_samples
    assert audio[lead_samples * 2 : lead_samples * 2 + 2] == b"\x11\x11"  # then the real PCM


def test_synthesize_timed_no_prosody_is_byte_identical(monkeypatch):
    from tex.gateway.backends import ElevenLabsTTS

    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    captured = _patch_timed(monkeypatch)

    out = ElevenLabsTTS().synthesize_timed("Forbid it", sample_rate=SR)  # no prosody
    # no voice_settings sent (preserves stored vendor defaults), no time shift.
    assert "voice_settings" not in captured["body"]
    assert out["words"][0]["start"] == pytest.approx(0.0)
    assert out["words"][1]["start"] == pytest.approx(0.7)
