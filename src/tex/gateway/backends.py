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

  * Neural backends — lazy-import their deps inside the synth/session call and
    refuse to register as live unless their deps AND model files are present.
    ``KokoroTTS`` is now LIVE when provisioned: the ``kokoro_onnx`` wrapper plus
    the Kokoro-82M ONNX model on disk produce real 24 kHz speech (no GPU, no
    vendor in the audio path). ``WhisperSTT`` / ``ParakeetSTT`` remain seams here
    — ``faster_whisper`` / ``torch`` are not installed — so STT ``available()`` is
    False and ``select_stt`` still falls back to ``OfflineSTT`` and SAYS SO (no
    silent cap). Real STT (faster-whisper) is the next step, not yet wired.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import struct
import threading
import wave
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
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
    """Kokoro-82M (Apache-2.0) TTS, run locally via ONNX — REAL speech, with no
    cloud and no vendor in the audio path.

    Availability is honest. The ``kokoro_onnx`` wrapper (which transitively
    bundles its own phonemizer + a prebuilt espeak-ng, so NO system espeak-ng is
    required) must import alongside onnxruntime/soundfile, AND the two model
    files must exist on disk. onnxruntime+soundfile alone CANNOT turn text into
    speech, so they are necessary-but-not-sufficient: until everything is
    present this backend reports unavailable and ``select_tts`` falls back to the
    honest ``OfflineTTS`` tone. The model + voices are a one-time ~340 MB
    download into ``$TEX_KOKORO_DIR`` (default ``~/.cache/tex/kokoro``); see
    ``scripts/provision_kokoro.sh``.

    ``name`` reads exactly ``"kokoro"`` only once real audio can be produced, so
    the ``X-Tex-Voice-Backend`` header never labels a placeholder tone as kokoro.

    LICENSING NOTE: the wrapper is MIT and the Kokoro weights are Apache-2.0, but
    the bundled libespeak-ng shared library is GPLv3 (loaded at runtime for
    phonemization). Fine for an in-house service; flag it before redistributing.
    """

    requires = ("onnxruntime", "soundfile", "kokoro_onnx")
    VOICE = "af_heart"
    MODEL_FILE = "kokoro-v1.0.onnx"
    VOICES_FILE = "voices-v1.0.bin"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._kokoro = None  # cached ONNX session, built lazily on first synth

    @property
    def name(self) -> str:
        # Honest in both states: "(seam)" while unprovisioned (OfflineTTS is
        # selected anyway), exactly "kokoro" the moment real audio is possible.
        return "kokoro" if self.available() else "kokoro(seam)"

    @classmethod
    def _model_dir(cls) -> Path:
        return Path(
            os.environ.get("TEX_KOKORO_DIR", os.path.expanduser("~/.cache/tex/kokoro"))
        )

    @classmethod
    def _model_paths(cls) -> tuple[Path, Path]:
        d = cls._model_dir()
        return d / cls.MODEL_FILE, d / cls.VOICES_FILE

    def available(self) -> bool:
        # Deps importable AND both model files on disk — never True on just
        # onnxruntime+soundfile (those can't phonemize): the honesty gate.
        if not _deps_present(*self.requires):
            return False
        model_path, voices_path = self._model_paths()
        return model_path.is_file() and voices_path.is_file()

    def synthesize(self, text: str, *, sample_rate: int) -> bytes:
        """Real Kokoro-82M TTS → audio/wav bytes. Lazy-loads (and caches) the
        ONNX session on first call. Callers must gate on ``available()`` —
        ``select_tts`` does — so reaching here unavailable is a programming
        error, answered with a truthful refusal, never fabricated audio."""
        if not self.available():
            raise RuntimeError(
                "KokoroTTS.synthesize called while unavailable (missing "
                "kokoro_onnx/onnxruntime/soundfile or model files); use "
                "select_tts() so OfflineTTS handles the fallback."
            )

        import io

        import numpy as np
        import soundfile as sf

        kokoro = self._kokoro
        if kokoro is None:
            with self._lock:
                kokoro = self._kokoro
                if kokoro is None:
                    from kokoro_onnx import Kokoro

                    model_path, voices_path = self._model_paths()
                    kokoro = Kokoro(str(model_path), str(voices_path))
                    self._kokoro = kokoro

        samples, native_sr = kokoro.create(
            text, voice=self.VOICE, speed=1.0, lang="en-us"
        )
        samples = np.asarray(samples, dtype=np.float32).reshape(-1)  # mono, 1-D

        # Kokoro only emits 24 kHz. Honor the caller's rate honestly: resample
        # the signal rather than mislabel a 24 kHz clip with another rate (which
        # would shift pitch/duration). _SPEAK_SAMPLE_RATE is 24000, so the
        # common path is a no-op; the linear resample only runs off the 24 kHz
        # path and keeps pitch/duration truthful (quality < a polyphase filter).
        if samples.size and sample_rate != native_sr:
            n_out = int(round(samples.size * sample_rate / native_sr))
            if n_out > 0:
                x_old = np.linspace(0.0, 1.0, samples.size, dtype=np.float64)
                x_new = np.linspace(0.0, 1.0, n_out, dtype=np.float64)
                samples = np.interp(x_new, x_old, samples).astype(np.float32)
            out_sr = sample_rate
        else:
            out_sr = native_sr

        buf = io.BytesIO()
        sf.write(buf, samples, int(out_sr), format="WAV", subtype="PCM_16")
        return buf.getvalue()


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
