"""
The gateway speaks the exact wire protocol the client expects, end to end, with
the dependency-free offline backend — proving the protocol works with no GPU and
without importing any neural dependency. Also pins the token gate (close 4401)
and the production fail-closed posture of the grant.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import textwrap
import types

from tex.gateway import grant
from tex.gateway.backends import OfflineSTT, OfflineTTS, select_stt
from tex.gateway.voice_gateway import handle_connection


class _FakeWS:
    """A minimal stand-in for a websockets server connection."""

    def __init__(self, incoming: list, *, path: str = "/?token=x") -> None:
        self._incoming = list(incoming)
        self.sent: list[str] = []
        self.closed: tuple[int, str] | None = None
        self.request = types.SimpleNamespace(path=path)

    async def __aiter__(self):
        for m in self._incoming:
            yield m

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


def _run(coro):
    return asyncio.run(coro)


def test_offline_roundtrip_emits_partial_then_final() -> None:
    pcm = b"\x00\x01" * 160  # one 20ms-ish frame of fake 16k PCM
    incoming = [pcm] * 5 + [json.dumps({"type": "end"})]
    ws = _FakeWS(incoming)

    _run(handle_connection(ws, stt=OfflineSTT(canned_transcript="hello tex"), require_token=False))

    frames = [json.loads(s) for s in ws.sent]
    partials = [f for f in frames if f["type"] == "partial"]
    finals = [f for f in frames if f["type"] == "final"]
    assert len(partials) >= 1
    assert len(finals) == 1
    assert finals[0]["text"] == "hello tex"
    assert ws.closed is None  # a clean end is not an error close


def test_start_frame_sets_sample_rate() -> None:
    incoming = [json.dumps({"type": "start", "sample_rate": 16000}), b"\x00\x00" * 80,
                json.dumps({"type": "end"})]
    ws = _FakeWS(incoming)
    _run(handle_connection(ws, stt=OfflineSTT(canned_transcript="x"), require_token=False))
    finals = [json.loads(s) for s in ws.sent if json.loads(s)["type"] == "final"]
    assert finals and finals[0]["text"] == "x"


def test_release_without_end_still_finalizes() -> None:
    # Socket closes mid-stream (no {"type":"end"}). The client must never hang —
    # the gateway emits a final on teardown.
    ws = _FakeWS([b"\x00\x00" * 80])
    _run(handle_connection(ws, stt=OfflineSTT(canned_transcript="late"), require_token=False))
    finals = [json.loads(s) for s in ws.sent if json.loads(s)["type"] == "final"]
    assert finals and finals[0]["text"] == "late"


def test_invalid_token_is_closed_4401() -> None:
    ws = _FakeWS([b"\x00\x00"], path="/?token=garbage")
    _run(handle_connection(ws, stt=OfflineSTT(), require_token=True))
    assert ws.closed is not None
    assert ws.closed[0] == 4401
    assert ws.sent == []  # nothing transcribed for an unauthorized socket


def test_valid_dev_token_is_accepted(monkeypatch) -> None:
    monkeypatch.setenv("TEX_APP_ENV", "development")
    monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
    minted = grant.make_token("acme")
    assert minted is not None
    token, _exp = minted
    ws = _FakeWS([json.dumps({"type": "end"})], path=f"/?token={token}")
    _run(handle_connection(ws, stt=OfflineSTT(canned_transcript="ok"), require_token=True))
    finals = [json.loads(s) for s in ws.sent if json.loads(s)["type"] == "final"]
    assert finals and finals[0]["text"] == "ok"


def test_offline_path_imports_no_neural_dependency() -> None:
    # The offline gateway path must not, BY ITSELF, pull in a neural ASR/TTS
    # runtime (keep the no-GPU path light). Measured in a FRESH subprocess so a
    # legitimate neural test elsewhere in THIS pytest process — e.g. real Kokoro
    # TTS via /v1/speak, which loads onnxruntime on purpose — cannot pollute the
    # sys.modules check. The invariant and its teeth are unchanged: if running
    # the offline path imported onnxruntime/faster_whisper/nemo, this still fails.
    prog = textwrap.dedent(
        """
        import asyncio, json, sys, types
        from tex.gateway.backends import OfflineSTT
        from tex.gateway.voice_gateway import handle_connection

        class _WS:
            def __init__(self, msgs):
                self._m = list(msgs); self.sent = []; self.closed = None
                self.request = types.SimpleNamespace(path="/?token=x")
            async def __aiter__(self):
                for m in self._m:
                    yield m
            async def send(self, d):
                self.sent.append(d)
            async def close(self, code=1000, reason=""):
                self.closed = (code, reason)

        asyncio.run(handle_connection(
            _WS([b"\\x00\\x00", json.dumps({"type": "end"})]),
            stt=OfflineSTT(), require_token=False,
        ))
        loaded = [n for n in ("faster_whisper", "nemo_toolkit", "onnxruntime")
                  if n in sys.modules]
        print(",".join(loaded))
        sys.exit(1 if loaded else 0)
        """
    )
    # Inherit the parent env (carries PYTHONPATH=src) so the child imports tex.
    result = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"offline path imported a neural runtime: {result.stdout.strip()!r}\n{result.stderr}"
    )


def test_select_stt_falls_back_to_offline_when_unprovisioned(monkeypatch, tmp_path) -> None:
    # When no neural STT is provisioned (model files absent), the registry
    # honestly falls back to the OfflineSTT placeholder — regardless of whether
    # faster_whisper happens to be importable on the box. Force the unprovisioned
    # state with an empty model dir so this tests the FALLBACK LOGIC, not the
    # ambient machine. Still has teeth: if select_stt stopped falling back when
    # nothing real is available, this fails.
    monkeypatch.setenv("TEX_WHISPER_DIR", str(tmp_path))  # empty → WhisperSTT unavailable
    assert select_stt().name == OfflineSTT().name


def test_offline_tts_emits_a_valid_wav() -> None:
    wav = OfflineTTS().synthesize("hello", sample_rate=24000)
    assert wav[:4] == b"RIFF"
    assert wav[8:12] == b"WAVE"


def test_production_grant_fails_closed_without_secret(monkeypatch) -> None:
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    monkeypatch.delenv("TEX_VOICE_GATEWAY_SECRET", raising=False)
    assert grant.voice_secret() is None
    assert grant.make_token("acme") is None
    ok, _ = grant.verify_token("anything")
    assert ok is False
