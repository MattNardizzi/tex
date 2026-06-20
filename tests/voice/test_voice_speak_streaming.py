"""
Hermetic tests for the STREAMING ``/v1/speak`` path (the ② streaming-TTS change).

The ElevenLabs vendor branch is exercised WITHOUT a network by monkeypatching
``urllib.request.urlopen``. These guard the two doctrine-critical invariants the
review flagged as unprotected:

  (a) VERBATIM — the vendor receives the SEALED string only, with the model
      pinned (``eleven_flash_v2_5``) and ``apply_text_normalization: "off"``, so
      it cannot paraphrase or re-render digits/symbols Tex never sealed; and
  (b) NEVER MUTED — a pre-roll vendor failure FALLS THROUGH to the no-vendor
      path (Kokoro/offline WAV), while a mid-stream break only TRUNCATES (the
      text is already on glass) rather than erroring the client.
"""

from __future__ import annotations

import json
import urllib.error

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch) -> TestClient:
    monkeypatch.setenv("TEX_APP_ENV", "development")
    monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
    from tex.main import create_app

    return TestClient(create_app())


class _FakeStreamResp:
    """Mimics the urllib response ``ElevenLabsTTS.stream`` consumes: a context
    manager with ``read(n)`` yielding chunks then ``b""``. ``raise_after`` makes
    ``read`` raise once N chunks have been served (a mid-stream break)."""

    def __init__(self, chunks, *, raise_after=None):
        self._chunks = list(chunks)
        self._i = 0
        self._raise_after = raise_after
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()
        return False

    def read(self, _size=-1):
        if self._raise_after is not None and self._i >= self._raise_after:
            raise OSError("simulated mid-stream read failure")
        if self._i >= len(self._chunks):
            return b""
        chunk = self._chunks[self._i]
        self._i += 1
        return chunk

    def close(self):
        self.closed = True


def _patch_urlopen(monkeypatch, *, behavior):
    """Patch urllib.request.urlopen; capture the outgoing request for assertions."""
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return behavior(request)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return captured


def test_speak_streams_elevenlabs_mp3_verbatim(client, monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test_key")
    chunks = [b"ID3\x03mp3-chunk-one", b"mp3-chunk-two", b"mp3-chunk-three"]
    captured = _patch_urlopen(monkeypatch, behavior=lambda req: _FakeStreamResp(chunks))

    sealed = "234 of 234 high-risk agents are acting outside governance."
    resp = client.get("/v1/speak", params={"text": sealed})

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("audio/mpeg")
    assert resp.headers["x-tex-voice-backend"] == "elevenlabs"
    # body is EVERY chunk, including the pre-rolled first one.
    assert resp.content == b"".join(chunks)
    # DOCTRINE: the vendor got the sealed string verbatim, model pinned, no normalization.
    assert captured["body"]["text"] == sealed
    assert captured["body"]["model_id"] == "eleven_flash_v2_5"
    assert captured["body"]["apply_text_normalization"] == "off"
    assert "/stream" in captured["url"]


def test_speak_falls_through_to_no_vendor_on_preroll_failure(client, monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test_key")

    def boom(req):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", hdrs={}, fp=None)

    _patch_urlopen(monkeypatch, behavior=boom)

    resp = client.get("/v1/speak", params={"text": "the evidence chain is intact"})

    # NEVER MUTED: vendor 401 before the first byte → fall through to a real WAV
    # voice, and the header does NOT mislabel it as elevenlabs.
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "audio/wav"
    assert resp.content[:4] == b"RIFF"
    assert resp.headers["x-tex-voice-backend"] != "elevenlabs"


def test_speak_truncates_not_mutes_on_midstream_break(client, monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test_key")
    # first chunk pre-rolls OK, then read() raises → truncate, no error to client.
    _patch_urlopen(
        monkeypatch,
        behavior=lambda req: _FakeStreamResp([b"ID3-first-chunk"], raise_after=1),
    )

    resp = client.get("/v1/speak", params={"text": "a held decision"})

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("audio/mpeg")
    assert resp.headers["x-tex-voice-backend"] == "elevenlabs"
    assert resp.content == b"ID3-first-chunk"  # the one good chunk, then a clean stop


def test_speak_empty_text_makes_no_vendor_call(client, monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test_key")
    captured = _patch_urlopen(
        monkeypatch, behavior=lambda req: _FakeStreamResp([b"should-not-be-served"])
    )

    resp = client.get("/v1/speak", params={"text": "   "})

    assert resp.status_code == 200
    # Empty/whitespace sealed line → no vendor call (no cost), valid WAV.
    assert "url" not in captured
    assert resp.headers["content-type"] == "audio/wav"
    assert resp.content[:4] == b"RIFF"
