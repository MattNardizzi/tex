"""ElevenLabsTTS — Tex's cloud voice as VOCAL CORDS ONLY.

These tests are HERMETIC: they never touch the ElevenLabs network. They prove
the honest availability gate, the select/fallback discipline (the no-vendor
Kokoro/Offline fallbacks are never lost), the request CONSTRUCTION (the SOTA
``eleven_flash_v2_5`` model pinned explicitly, ``apply_text_normalization=off``
so the SEALED line is voiced verbatim, the Tex voice id, pcm@24k → WAV), and the
runtime fall-through that keeps Tex from ever going mute. The actual audio from
the live API is proven separately with a real key — it cannot be faked here, so
it isn't asserted here.
"""

from __future__ import annotations

import json
import urllib.request
import wave
from io import BytesIO

import pytest

from tex.gateway.backends import (
    ElevenLabsTTS,
    _chars_to_words,
    select_tts,
    synthesize_tts,
)

VOICE_ID = "8eWiU0Pinoj0ItwssWXL"


def test_available_gates_on_api_key(monkeypatch):
    el = ElevenLabsTTS()
    # No key → unavailable, and the name does NOT yet claim the vendor.
    assert el.available() is False
    assert el.name == "elevenlabs(seam)"
    # Key present → available, and the name names the cloud vendor exactly.
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    assert el.available() is True
    assert el.name == "elevenlabs"


def test_select_prefers_elevenlabs_only_with_key(monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    assert select_tts().name == "elevenlabs"
    # Without a key the vendor is NEVER in the path — a no-vendor backend is.
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)
    assert select_tts().name != "elevenlabs"
    assert select_tts().name in {"kokoro", "offline-tone(no-voice)"}


def test_synthesize_without_key_refuses_truthfully(monkeypatch):
    with pytest.raises(RuntimeError, match="ELEVENLABS_API_KEY"):
        ElevenLabsTTS().synthesize("hello", sample_rate=24000)


def test_request_is_sota_and_voices_the_sealed_text_verbatim(monkeypatch):
    """The outgoing request must pin flash_v2_5 EXPLICITLY, force normalization
    OFF, target the Tex voice id + pcm@24k, and carry the EXACT sealed text —
    then return a valid WAV wrapping the vendor PCM with no resample."""
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    captured: dict = {}
    fake_pcm = b"\x00\x00" * 2400  # 0.1s of 24 kHz mono s16le

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_pcm

    def _fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["method"] = request.get_method()
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    sealed = "Forbid. I cannot prove that, so I will not claim it."
    wav = ElevenLabsTTS().synthesize(sealed, sample_rate=24000)

    assert captured["method"] == "POST"
    assert VOICE_ID in captured["url"]
    assert "output_format=pcm_24000" in captured["url"]
    assert captured["headers"]["xi-api-key"] == "sk_test"
    assert captured["body"]["model_id"] == "eleven_flash_v2_5"  # pinned, not the default
    assert captured["body"]["apply_text_normalization"] == "off"  # sealed line, verbatim
    assert captured["body"]["text"] == sealed  # the vendor never re-authors the line

    assert wav[:4] == b"RIFF"
    with wave.open(BytesIO(wav)) as w:
        assert w.getframerate() == 24000
        assert w.getnchannels() == 1
        assert w.getsampwidth() == 2
        assert w.getnframes() == 2400  # the 24k path does NOT resample


def test_empty_text_returns_silent_wav_without_vendor_call(monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    calls = {"n": 0}

    def _explode(*a, **k):
        calls["n"] += 1
        raise AssertionError("must not call the vendor for empty text")

    monkeypatch.setattr(urllib.request, "urlopen", _explode)
    wav = ElevenLabsTTS().synthesize("   ", sample_rate=24000)
    assert wav[:4] == b"RIFF"
    assert calls["n"] == 0  # nothing sealed to say → no vendor call, no cost


def test_runtime_failure_falls_through_and_labels_honestly(monkeypatch):
    """A vendor outage must NOT mute Tex: synthesize_tts falls through to the next
    backend and returns the name of whoever ACTUALLY spoke — never 'elevenlabs'
    when ElevenLabs did not produce the audio."""
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")

    def _boom(self, text, *, sample_rate):
        raise RuntimeError("simulated ElevenLabs 503")

    monkeypatch.setattr(ElevenLabsTTS, "synthesize", _boom)

    audio, name = synthesize_tts("the evidence chain is intact", sample_rate=24000)
    assert audio[:4] == b"RIFF"
    assert name != "elevenlabs"
    assert name in {"kokoro", "offline-tone(no-voice)"}


def test_chars_to_words_rollup():
    """Per-character alignment rolls up into words whose start/end bound the
    spoken span — the basis for in-sync on-screen highlighting."""
    chars = list("Hi there")  # H i _ t h e r e
    starts = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]
    ends = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    words = _chars_to_words(chars, starts, ends)
    assert [w["text"] for w in words] == ["Hi", "there"]
    assert words[0]["start"] == 0.0 and words[0]["end"] == 0.2
    assert words[1]["start"] == 0.3 and words[1]["end"] == 0.8


def test_synthesize_timed_uses_with_timestamps_and_rolls_words(monkeypatch):
    """The word-timed path must hit the /with-timestamps endpoint with flash_v2_5
    pinned + normalization OFF, and roll the returned char timing into words."""
    import base64

    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    captured: dict = {}
    fake_pcm_b64 = base64.b64encode(b"\x00\x00" * 100).decode()
    body = json.dumps(
        {
            "audio_base64": fake_pcm_b64,
            "alignment": {
                "characters": list("Forbid it"),  # F o r b i d _ i t
                "character_start_times_seconds": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
                "character_end_times_seconds": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
            },
        }
    ).encode("utf-8")

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return body

    def _fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    out = ElevenLabsTTS().synthesize_timed("Forbid it", sample_rate=24000)

    assert "/with-timestamps" in captured["url"]
    assert "output_format=pcm_24000" in captured["url"]
    assert captured["body"]["model_id"] == "eleven_flash_v2_5"
    assert captured["body"]["apply_text_normalization"] == "off"
    assert out["backend"] == "elevenlabs"
    assert out["sample_rate"] == 24000
    assert out["audio_b64"] == fake_pcm_b64
    assert [w["text"] for w in out["words"]] == ["Forbid", "it"]
