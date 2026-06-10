"""
[Architecture: Voice infrastructure] — the streaming recognizer WebSocket.

This is the standalone speech gateway: a direct browser→Tex WebSocket that
takes 16 kHz s16le PCM while the operator holds the gesture and returns interim
and final transcripts. It speaks EXACTLY the protocol the client
(``tex-systems/src/lib/texVoiceClient.js``) expects:

    client → gateway:  binary frames = raw little-endian 16-bit PCM
                       text frame {"type":"end"}     = end of utterance
                       (optional) {"type":"start","sample_rate":16000}
    gateway → client:  {"type":"partial","text": "..."}  (interim, while held)
                       {"type":"final","text": "..."}     (on end / close)

Auth: the connection must carry a ``?token=`` minted by ``GET /v1/voice/token``
(``tex.gateway.grant``); an invalid/expired token is closed with code 4401. In a
non-production env with no secret configured a dev token is accepted (see
``grant.voice_secret``). Push-to-talk deletes the hardest 2026 voice problem
(end-of-turn detection): the RELEASE is the end of turn, so there is no VAD
guessing whether you stopped.

The recognizer engine is a pluggable backend (``tex.gateway.backends``). In this
environment only the offline placeholder runs (it does not transcribe — it
returns a deterministic transcript so the wire is testable); the neural backends
are seams that activate when their model/GPU deps are present.

Run standalone:  ``python -m tex.gateway.voice_gateway``  (host/port from
``TEX_VOICE_GATEWAY_HOST`` / ``TEX_VOICE_GATEWAY_PORT``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any
from urllib.parse import parse_qs, urlparse

from tex.gateway.backends import STTBackend, select_stt
from tex.gateway.grant import is_production_like, verify_token

__all__ = ["handle_connection", "serve", "main"]

_logger = logging.getLogger(__name__)

# Emit at most one partial per this many PCM frames, to mimic a real recognizer's
# cadence rather than echo on every 20 ms chunk.
_PARTIAL_EVERY = 5


def _query_token(raw_path: str | None) -> str | None:
    if not raw_path:
        return None
    qs = parse_qs(urlparse(raw_path).query)
    vals = qs.get("token")
    return vals[0] if vals else None


def _connection_path(websocket: Any) -> str | None:
    # websockets >= 13 exposes the request on the server side; older builds put
    # the path on the connection directly. Be tolerant of both.
    req = getattr(websocket, "request", None)
    if req is not None and getattr(req, "path", None):
        return req.path
    return getattr(websocket, "path", None)


async def handle_connection(
    websocket: Any,
    *,
    stt: STTBackend | None = None,
    require_token: bool | None = None,
) -> None:
    """Serve one recognizer connection. Never raises out — a protocol error is a
    quiet close, mirroring the client's degrade-to-silence contract."""
    backend = stt or select_stt()
    enforce = is_production_like() if require_token is None else require_token

    token = _query_token(_connection_path(websocket))
    ok, _tenant = verify_token(token)
    if enforce and not ok:
        await websocket.close(code=4401, reason="invalid or missing voice token")
        return

    sample_rate = 16000
    session = backend.session(sample_rate=sample_rate)
    frame_count = 0
    final_sent = False

    try:
        async for message in websocket:
            if isinstance(message, (bytes, bytearray)):
                frame_count += 1
                partial = session.feed(bytes(message))
                if partial is not None and frame_count % _PARTIAL_EVERY == 0:
                    await websocket.send(json.dumps({"type": "partial", "text": partial.text}))
                continue

            # Text control frame.
            try:
                msg = json.loads(message)
            except (ValueError, TypeError):
                continue
            mtype = msg.get("type")
            if mtype == "start":
                sr = int(msg.get("sample_rate") or sample_rate)
                if sr != sample_rate:
                    sample_rate = sr
                    session = backend.session(sample_rate=sample_rate)
            elif mtype == "end":
                final = session.finish()
                await websocket.send(json.dumps({"type": "final", "text": final.text}))
                final_sent = True
                break
    except Exception as exc:  # noqa: BLE001 — never crash the gateway on one socket
        _logger.info("voice gateway: connection ended abnormally: %s", exc)
    finally:
        if not final_sent:
            # The socket closed without an explicit end (released mid-stream):
            # still emit whatever the recognizer has, so the client never hangs.
            try:
                final = session.finish()
                await websocket.send(json.dumps({"type": "final", "text": final.text}))
            except Exception:  # noqa: BLE001 — best-effort; the client already degrades to silence
                pass


async def serve(host: str | None = None, port: int | None = None) -> None:
    import websockets  # local import: the gateway process needs it; the API does not

    host = host or os.environ.get("TEX_VOICE_GATEWAY_HOST", "0.0.0.0")
    port = int(port or os.environ.get("TEX_VOICE_GATEWAY_PORT", "8765"))
    backend = select_stt()
    _logger.warning(
        "Tex voice gateway listening on ws://%s:%d (STT backend: %s)",
        host, port, backend.name,
    )

    async def _handler(websocket: Any) -> None:
        await handle_connection(websocket, stt=backend)

    async with websockets.serve(_handler, host, port):
        await asyncio.Future()  # run forever


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())


if __name__ == "__main__":  # pragma: no cover
    main()
