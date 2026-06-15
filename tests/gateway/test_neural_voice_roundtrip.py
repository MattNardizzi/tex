"""Integration: the REAL neural voice path, end to end, when provisioned.

Kokoro TTS speaks a phrase; faster-whisper STT transcribes it back. This proves
both neural backends are genuinely wired (not the placeholder tone / canned
transcript) and that the gateway PCM contract (16 kHz s16le) round-trips.

Skipped — never faked — when the models aren't provisioned (they are a ~340 MB +
~145 MB download, not committed to the repo). Provision with
``scripts/provision_kokoro.sh`` + ``scripts/provision_whisper.sh``.
"""

from __future__ import annotations

import io

import numpy as np
import pytest

from tex.gateway.backends import KokoroTTS, WhisperSTT

_KOKORO = KokoroTTS()
_WHISPER = WhisperSTT()

pytestmark = pytest.mark.skipif(
    not (_KOKORO.available() and _WHISPER.available()),
    reason="neural voice models not provisioned "
    "(scripts/provision_kokoro.sh + scripts/provision_whisper.sh)",
)


def _to_pcm16k(wav_bytes: bytes) -> bytes:
    import soundfile as sf

    data, sr = sf.read(io.BytesIO(wav_bytes))
    data = np.asarray(data, dtype=np.float32).reshape(-1)
    if sr != 16000:
        n = int(round(data.size * 16000 / sr))
        data = np.interp(
            np.linspace(0.0, 1.0, n, dtype=np.float64),
            np.linspace(0.0, 1.0, data.size, dtype=np.float64),
            data,
        ).astype(np.float32)
    return (np.clip(data, -1.0, 1.0) * 32767).astype(np.int16).tobytes()


def test_kokoro_to_whisper_roundtrip() -> None:
    phrase = "the quarterly audit found seventeen violations"
    pcm = _to_pcm16k(_KOKORO.synthesize(phrase, sample_rate=24000))

    session = _WHISPER.session(sample_rate=16000)
    chunk = 16000 * 2 // 5  # ~200 ms frames, as the client streams them
    for i in range(0, len(pcm), chunk):
        session.feed(pcm[i : i + chunk])
    final = session.finish()

    assert final.is_final
    text = final.text.lower()
    # Real ASR recovers the salient content (number + noun) — a transcription,
    # not the fixed OfflineSTT placeholder string.
    # ...neither of which appears in the canned OfflineSTT placeholder, so a pass
    # here can only mean genuine transcription.
    assert "seventeen" in text or "17" in text, f"number lost: {final.text!r}"
    assert "violation" in text, f"noun lost: {final.text!r}"
