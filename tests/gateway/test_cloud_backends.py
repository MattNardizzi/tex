"""June-2026 SOTA voice upgrade — cloud STT/TTS backends.

OpenAICloudSTT (gpt-4o-transcribe) and OpenAICloudTTS (gpt-4o-mini-tts) are the
smooth, SOTA cloud path. They preserve the grounding boundary (STT transcribes
into the deterministic /v1/ask; TTS voices an already-sealed line — never
end-to-end S2S). The openai SDK is optional and not installed in CI, so the live
transport is exercised with injected fakes; the honest availability gate and the
offline fallback are verified without keys.
"""

from __future__ import annotations

import tex.gateway.backends as be
from tex.gateway.backends import (
    OpenAICloudSTT,
    OpenAICloudTTS,
    select_stt,
    select_tts,
)


# --------------------------------------------------------------------------- honesty gate


def test_cloud_backends_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert OpenAICloudSTT().available() is False
    assert OpenAICloudTTS().available() is False
    # Name reads "(seam)" while not live, so the X-Tex-Voice-Backend header never
    # mislabels a fallback as the cloud vendor.
    assert OpenAICloudSTT().name.endswith("(seam)")
    assert OpenAICloudTTS().name.endswith("(seam)")


def test_cloud_backends_available_only_with_key_and_sdk(monkeypatch):
    monkeypatch.setattr(be, "_deps_present", lambda *m: True)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    assert OpenAICloudSTT().available() is True
    assert OpenAICloudSTT().name == "openai-transcribe"
    assert OpenAICloudTTS().available() is True
    assert OpenAICloudTTS().name == "openai-tts"

    # Key present but SDK missing → still unavailable (necessary AND sufficient).
    monkeypatch.setattr(be, "_deps_present", lambda *m: False)
    assert OpenAICloudSTT().available() is False
    assert OpenAICloudTTS().available() is False


def test_offline_fallback_when_nothing_configured(monkeypatch):
    for k in ("OPENAI_API_KEY", "ELEVENLABS_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(be, "_deps_present", lambda *m: False)
    assert select_stt().name == "offline-placeholder(no-asr)"
    assert select_tts().name == "offline-tone(no-voice)"


def test_selectors_prefer_cloud_when_keyed(monkeypatch):
    monkeypatch.setattr(be, "_deps_present", lambda *m: True)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)
    # STT: cloud transcription is first preference.
    assert select_stt().name == "openai-transcribe"
    # TTS: no ElevenLabs key → OpenAI cloud TTS is chosen over local Kokoro.
    assert select_tts().name == "openai-tts"


# --------------------------------------------------------------------------- live transport (faked)


class _FakeTranscriptions:
    def __init__(self, text):
        self._text = text
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        class _R:
            text = self._text

        return _R()


class _FakeSpeechResp:
    def __init__(self, pcm):
        self._pcm = pcm

    def read(self):
        return self._pcm


class _FakeSpeech:
    def __init__(self, pcm):
        self._pcm = pcm
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeSpeechResp(self._pcm)


class _FakeAudio:
    def __init__(self, *, text=None, pcm=None):
        self.transcriptions = _FakeTranscriptions(text or "")
        self.speech = _FakeSpeech(pcm or b"")


class _FakeOpenAI:
    def __init__(self, *, text=None, pcm=None):
        self.audio = _FakeAudio(text=text, pcm=pcm)


def test_cloud_stt_session_returns_real_transcript(monkeypatch):
    monkeypatch.setattr(be, "_deps_present", lambda *m: True)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    stt = OpenAICloudSTT()
    stt._client = _FakeOpenAI(text="what is the evidence chain status")

    session = stt.session(sample_rate=16000)
    interim = session.feed(b"\x00\x00" * 1600)
    assert interim is not None and interim.is_final is False  # neutral partial
    final = session.finish()
    assert final.is_final is True
    assert final.text == "what is the evidence chain status"
    # Uploaded a real WAV to gpt-4o-transcribe.
    call = stt._client.audio.transcriptions.calls[0]
    assert call["model"] == "gpt-4o-transcribe"


def test_cloud_tts_synthesizes_wav_for_sealed_text(monkeypatch):
    monkeypatch.setattr(be, "_deps_present", lambda *m: True)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    tts = OpenAICloudTTS()
    # 24 kHz native rate → no resample (keeps the test numpy-free).
    pcm = b"\x01\x02" * 240
    tts._client = _FakeOpenAI(pcm=pcm)

    wav = tts.synthesize("the action was permitted", sample_rate=24000)
    assert wav[:4] == b"RIFF"  # valid WAV container
    call = tts._client.audio.speech.calls[0]
    assert call["model"] == "gpt-4o-mini-tts"
    assert call["response_format"] == "pcm"
    assert call["input"] == "the action was permitted"


def test_cloud_tts_empty_text_is_silent_wav_no_vendor_call(monkeypatch):
    monkeypatch.setattr(be, "_deps_present", lambda *m: True)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    tts = OpenAICloudTTS()
    tts._client = _FakeOpenAI(pcm=b"should-not-be-used")
    wav = tts.synthesize("   ", sample_rate=24000)
    assert wav[:4] == b"RIFF"
    assert tts._client.audio.speech.calls == []  # no vendor call, no cost
