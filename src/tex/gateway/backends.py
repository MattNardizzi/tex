"""
[Architecture: Voice infrastructure] — pluggable STT / TTS backends.

The gateway's wire protocol is fixed by the client (16 kHz s16le PCM in;
``{type:"partial"|"final"}`` JSON out; synthesized audio out). The *engine*
behind that protocol is swappable, and each engine declares honestly whether it
can actually run here.

Two ``typing.Protocol`` seams — ``STTBackend`` and ``TTSBackend`` — plus:

  * ``OfflineSTT`` / ``OfflineTTS`` — the REGISTERED DEFAULT, stdlib only
    (``wave``/``struct``/``hashlib``; no numpy/soundfile/torch needed). They make
    the protocol end-to-end testable with no GPU. CRITICAL HONESTY: ``OfflineSTT``
    does NOT transcribe speech — it returns a deterministic placeholder transcript
    so the loop is exercisable; it must never be deployed as a recognizer.
    ``OfflineTTS`` emits a valid but content-free WAV (a short low tone), not a
    spoken voice.

  * Neural seams (``ParakeetSTT``, ``WhisperSTT``, ``KokoroTTS``) — real upgrade
    points that lazy-import their deps inside ``start()``/``load()`` and refuse to
    register as live when the model/GPU dependency is absent. In THIS environment
    ``faster_whisper`` / ``onnxruntime`` / ``soundfile`` are not installed and
    there is no GPU (verified), so ``available()`` is False for all of them and
    ``select_*`` falls back to the offline backend — and SAYS SO (no silent cap).
"""

from __future__ import annotations

import importlib.util
import logging
import math
import struct
import wave
from dataclasses import dataclass
from io import BytesIO
from typing import Protocol, runtime_checkable

__all__ = [
    "Transcript",
    "STTSession",
    "STTBackend",
    "TTSBackend",
    "OfflineSTT",
    "OfflineTTS",
    "ParakeetSTT",
    "WhisperSTT",
    "KokoroTTS",
    "select_stt",
    "select_tts",
]

_logger = logging.getLogger(__name__)


def _deps_present(*modules: str) -> bool:
    return all(importlib.util.find_spec(m) is not None for m in modules)


@dataclass(frozen=True, slots=True)
class Transcript:
    text: str
    is_final: bool
    sample_rate: int


@runtime_checkable
class STTSession(Protocol):
    """One push-to-talk utterance. ``feed`` returns an interim partial (or None);
    ``finish`` returns the final transcript."""

    def feed(self, pcm: bytes) -> Transcript | None: ...
    def finish(self) -> Transcript: ...


@runtime_checkable
class STTBackend(Protocol):
    name: str
    requires: tuple[str, ...]

    def available(self) -> bool: ...
    def session(self, *, sample_rate: int) -> STTSession: ...


@runtime_checkable
class TTSBackend(Protocol):
    name: str
    requires: tuple[str, ...]

    def available(self) -> bool: ...
    def synthesize(self, text: str, *, sample_rate: int) -> bytes: ...


# --------------------------------------------------------------------------- offline (default)


class _OfflineSTTSession:
    """Counts audio, returns a DETERMINISTIC PLACEHOLDER — never real ASR."""

    def __init__(self, *, sample_rate: int, canned: str) -> None:
        self._sample_rate = sample_rate
        self._canned = canned
        self._bytes = 0

    def feed(self, pcm: bytes) -> Transcript | None:
        self._bytes += len(pcm)
        # A single interim "…" partial so the client's partial path is exercised
        # without implying recognition is happening.
        return Transcript(text="…", is_final=False, sample_rate=self._sample_rate)

    def finish(self) -> Transcript:
        return Transcript(text=self._canned, is_final=True, sample_rate=self._sample_rate)


class OfflineSTT:
    """Dependency-free STT placeholder. DOES NOT TRANSCRIBE. The final transcript
    is a fixed, configurable string so the wire protocol and the ``/v1/ask``
    grounding can be tested without a recognizer or a GPU."""

    name = "offline-placeholder(no-asr)"
    requires: tuple[str, ...] = ()

    def __init__(self, canned_transcript: str = "what is the evidence chain status") -> None:
        self._canned = canned_transcript

    def available(self) -> bool:
        return True

    def session(self, *, sample_rate: int) -> STTSession:
        return _OfflineSTTSession(sample_rate=sample_rate, canned=self._canned)


class OfflineTTS:
    """Dependency-free TTS placeholder. Emits a VALID but content-free WAV (a
    short, quiet sine tone whose length scales with the text) so the client's
    audio path plays real bytes — it is NOT a spoken voice. stdlib only."""

    name = "offline-tone(no-voice)"
    requires: tuple[str, ...] = ()

    def available(self) -> bool:
        return True

    def synthesize(self, text: str, *, sample_rate: int) -> bytes:
        # ~45 ms per character, clamped, at a low amplitude so it is audibly a
        # placeholder, not a claim to speech.
        seconds = max(0.25, min(6.0, 0.045 * max(1, len(text or ""))))
        n = int(seconds * sample_rate)
        amp = 1500  # quiet, well below int16 max
        freq = 220.0
        buf = BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sample_rate)
            frames = bytearray()
            for i in range(n):
                frames += struct.pack("<h", int(amp * math.sin(2 * math.pi * freq * i / sample_rate)))
            w.writeframes(bytes(frames))
        return buf.getvalue()


# --------------------------------------------------------------------------- neural seams (OFF here)


class ParakeetSTT:
    """NVIDIA Parakeet TDT streaming ASR seam (CC-BY-4.0 model). Lazy-imports its
    runtime; refuses to register as live without GPU + deps. NOT running here."""

    name = "parakeet-tdt(seam)"
    requires = ("torch", "nemo_toolkit")

    def available(self) -> bool:
        return _deps_present(*self.requires)

    def session(self, *, sample_rate: int) -> STTSession:  # pragma: no cover - seam
        raise RuntimeError(
            "ParakeetSTT is a labelled seam: requires "
            f"{self.requires} + a GPU, not installed in this environment."
        )


class WhisperSTT:
    """faster-whisper + LocalAgreement streaming seam. (Use LocalAgreement, NOT
    the PolyForm-NC SimulStreaming, to keep the path Apache/MIT-clean.) Lazy seam,
    OFF here — ``faster_whisper`` is not installed (verified)."""

    name = "faster-whisper(seam)"
    requires = ("faster_whisper",)

    def available(self) -> bool:
        return _deps_present(*self.requires)

    def session(self, *, sample_rate: int) -> STTSession:  # pragma: no cover - seam
        raise RuntimeError(
            "WhisperSTT is a labelled seam: requires faster_whisper, not installed."
        )


class KokoroTTS:
    """Kokoro (Apache-2.0) low-latency TTS seam. Lazy, OFF here — onnxruntime /
    soundfile not installed (verified)."""

    name = "kokoro(seam)"
    requires = ("onnxruntime", "soundfile")

    def available(self) -> bool:
        return _deps_present(*self.requires)

    def synthesize(self, text: str, *, sample_rate: int) -> bytes:  # pragma: no cover - seam
        raise RuntimeError(
            "KokoroTTS is a labelled seam: requires onnxruntime + soundfile, not installed."
        )


# --------------------------------------------------------------------------- selection


_STT_PREFERENCE: tuple[STTBackend, ...] = (ParakeetSTT(), WhisperSTT())
_TTS_PREFERENCE: tuple[TTSBackend, ...] = (KokoroTTS(),)


def select_stt() -> STTBackend:
    """The best available STT, falling back to the offline placeholder — and
    logging both the choice and every neural backend skipped (no silent cap)."""
    for backend in _STT_PREFERENCE:
        if backend.available():
            _logger.info("voice gateway: selected STT backend %s", backend.name)
            return backend
        _logger.info("voice gateway: STT backend %s unavailable (needs %s)", backend.name, backend.requires)
    _logger.warning(
        "voice gateway: NO neural STT available — falling back to %s. This does "
        "NOT transcribe speech; it is for protocol/integration testing only.",
        OfflineSTT().name,
    )
    return OfflineSTT()


def select_tts() -> TTSBackend:
    for backend in _TTS_PREFERENCE:
        if backend.available():
            _logger.info("voice gateway: selected TTS backend %s", backend.name)
            return backend
        _logger.info("voice gateway: TTS backend %s unavailable (needs %s)", backend.name, backend.requires)
    _logger.warning(
        "voice gateway: NO neural TTS available — falling back to %s (a tone, not a voice).",
        OfflineTTS().name,
    )
    return OfflineTTS()
