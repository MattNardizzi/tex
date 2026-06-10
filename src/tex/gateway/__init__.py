"""
[Architecture: Cross-cutting (Voice infrastructure)] — Tex's self-hosted speech gateway.

The recognizer stream is a direct browser→gateway WebSocket: a serverless proxy
cannot hold a streaming socket, so the listen path needs a short-lived token
(minted server-side by ``GET /v1/voice/token``) and a gateway URL. The gateway
is Tex's OWN infrastructure, inside the same trust domain — audio never touches
a third party. This is the deliberate grounded cascade (STT → ``/v1/ask`` →
TTS), never an end-to-end speech-to-speech model: an S2S model generates its own
answers, which would put a free-running model in the speaking seat and break the
one thing that makes Tex a witness.

Maturity is labelled honestly per backend (``tex.gateway.backends``): only the
stdlib ``OfflineSTT``/``OfflineTTS`` run in this environment (they make the wire
protocol fully testable without a GPU); the neural backends (Parakeet,
faster-whisper, Kokoro, …) are real seams that refuse to register as live when
their model/GPU dependencies are absent.
"""

from __future__ import annotations

__all__: list[str] = []
