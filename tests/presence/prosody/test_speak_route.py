"""End-to-end ``/v1/speak`` + ``/v1/ask`` prosody wiring (hermetic).

These close the adversary's flagged monotonicity holes at the HTTP boundary:
  * a supplied prosody token routes to the full WAV post-process path (never the
    MP3 stream that strips the lead pause + terminal contour) — even when the
    ElevenLabs cloud voice is available;
  * a PRESENT-but-garbage token fails CLOSED to the most cautious (ABSTAIN) plan,
    while an ABSENT param keeps today's neutral voice;
  * the prosody cue is independent of the spoken text (a pure function of tier);
  * the AskResponse echoes the verdict tier so the client can thread it.
"""

from __future__ import annotations

import json
import struct
import wave
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

SR = 24000
F0 = 220.0


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("TEX_APP_ENV", "development")
    monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)  # no cloud voice
    # Force the deterministic 220 Hz OfflineTTS tone so the prosody assertions are
    # hermetic regardless of whether Kokoro/Whisper happen to be provisioned on
    # this machine: point Kokoro at an empty dir so its model files are "missing"
    # ⇒ available() is False ⇒ select_tts falls to OfflineTTS.
    monkeypatch.setenv("TEX_KOKORO_DIR", str(tmp_path / "no-kokoro"))
    from tex.main import create_app

    return TestClient(create_app())


def _decode(wav_bytes):
    assert wav_bytes[:4] == b"RIFF"
    with wave.open(BytesIO(wav_bytes), "rb") as r:
        sr = r.getframerate()
        frames = r.readframes(r.getnframes())
    return list(struct.unpack("<%dh" % (len(frames) // 2), frames)), sr


def _leading_zeros(samples):
    n = 0
    for v in samples:
        if v != 0:
            break
        n += 1
    return n


def _tail_freq(samples, sr, ms=60):
    seg = samples[-int(ms / 1000 * sr):]
    zc = sum(1 for a, b in zip(seg, seg[1:]) if (a >= 0) != (b >= 0))
    return (zc / 2) / (len(seg) / sr)


# --------------------------------------------------------------------------- routing


def test_abstain_routes_to_wav_with_lead_pause_and_rising_tail(client):
    r = client.get("/v1/speak", params={"text": "I cannot prove that", "prosody": "abstain"})
    assert r.status_code == 200
    # NOT the MP3 stream — the WAV post-process path, so the cues are real.
    assert r.headers["content-type"] == "audio/wav"
    assert r.headers["x-tex-voice-prosody"] == "uncertain"
    assert r.headers["x-tex-voice-prosody-tier"] == "abstain"
    samples, sr = _decode(r.content)
    assert _leading_zeros(samples) >= round(280 / 1000 * sr)   # the 280 ms lead pause
    assert _tail_freq(samples, sr) > F0 + 8                    # rising terminal


def test_sealed_sounds_assured_no_pause_falling_tail(client):
    r = client.get("/v1/speak", params={"text": "234 of 234 are governed", "prosody": "sealed"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "audio/wav"
    assert r.headers["x-tex-voice-prosody-tier"] == "sealed"
    samples, sr = _decode(r.content)
    assert _leading_zeros(samples) < 50          # no lead pause
    assert _tail_freq(samples, sr) < F0 - 8      # falling terminal


def test_garbled_token_fails_closed_to_abstain_never_confident(client):
    for junk in ("confident", "sealed;rate=2", "SEALED\x00", "1.05"):
        r = client.get("/v1/speak", params={"text": "hello", "prosody": junk})
        assert r.status_code == 200
        # present-but-unparseable ⇒ most cautious plan, never a confident default.
        assert r.headers["x-tex-voice-prosody-tier"] == "abstain"
        samples, sr = _decode(r.content)
        assert _leading_zeros(samples) >= round(280 / 1000 * sr)


def test_absent_param_keeps_neutral_voice(client):
    # No prosody param ⇒ today's path, no epistemic prosody (header says neutral,
    # no lead pause). Backward compatible / purely additive.
    r = client.get("/v1/speak", params={"text": "hello"})
    assert r.status_code == 200
    assert r.headers["x-tex-voice-prosody"] == "neutral"
    samples, _ = _decode(r.content)
    assert _leading_zeros(samples) < 50


def test_prosody_is_independent_of_text(client):
    # The SAME tier on two DIFFERENT texts yields the SAME prosody cue (lead pause
    # length). Text content cannot influence prosody — it is a pure function of
    # the tier.
    a = client.get("/v1/speak", params={"text": "x", "prosody": "abstain"})
    b = client.get("/v1/speak", params={"text": "a much longer uncertain sentence here", "prosody": "abstain"})
    sa, sra = _decode(a.content)
    sb, srb = _decode(b.content)
    # identical cue regardless of text length, and ≥ the 280 ms ABSTAIN lead pause.
    assert _leading_zeros(sa) == _leading_zeros(sb)
    assert _leading_zeros(sa) >= round(280 / 1000 * sra)
    assert sra == srb


# --------------------------------------------------------------------------- ElevenLabs cloud path still routes to WAV


def test_prosody_uses_wav_convert_not_mp3_stream_even_with_cloud_voice(client, monkeypatch):
    # With a key present, the param-less path would MP3-stream; but a prosody
    # request MUST take the WAV convert path so lead pause + contour are applied,
    # and the request must carry voice_settings.speed for the tier.
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    captured: dict = {}
    fake_pcm = b"".join(
        struct.pack("<h", int(8000 * __import__("math").sin(2 * 3.141592653589793 * F0 * i / SR)))
        for i in range(int(0.5 * SR))
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_pcm

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    r = client.get("/v1/speak", params={"text": "a sealed line", "prosody": "abstain"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "audio/wav"           # WAV path, not audio/mpeg
    assert "/stream" not in captured["url"]                   # convert endpoint, not stream
    assert "output_format=pcm_" in captured["url"]
    assert captured["body"]["voice_settings"]["speed"] == pytest.approx(0.9)  # ABSTAIN rate
    samples, sr = _decode(r.content)
    assert _leading_zeros(samples) >= round(280 / 1000 * sr)  # lead pause applied post-vendor


def test_stream_payload_carries_speed_for_defense_in_depth(monkeypatch):
    # synthesize_tts_stream is not used with prosody by the route, but if a direct
    # caller streams with a plan, the rate MUST be in the MP3 request (it carried
    # none before this change).
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test")
    from tex.gateway.backends import synthesize_tts_stream
    from tex.presence.contract import ProsodyPlan, PresenceTier

    captured: dict = {}

    class _StreamResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, _n=-1):
            if not captured.get("served"):
                captured["served"] = True
                return b"ID3mp3"
            return b""

        def close(self):
            pass

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _StreamResp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    plan = ProsodyPlan.from_tier(PresenceTier.SEALED)
    it, name, media = synthesize_tts_stream("hi", sample_rate=SR, prosody=plan)
    list(it)  # drain
    assert "/stream" in captured["url"]
    assert captured["body"]["voice_settings"]["speed"] == pytest.approx(1.05)


# --------------------------------------------------------------------------- AskResponse echo


def test_ask_response_exposes_prosody_field(client):
    # Presence not engaged by default ⇒ prosody is None (client omits it ⇒ neutral
    # voice). The field exists and defaults honestly; the non-None mapping is
    # unit-tested via prosody_param_for_envelope.
    r = client.post("/v1/ask", json={"transcript": "what is the evidence chain status"})
    assert r.status_code == 200
    body = r.json()
    assert "prosody" in body
    assert body["prosody"] is None
