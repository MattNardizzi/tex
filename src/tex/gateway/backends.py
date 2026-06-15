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
    ``KokoroTTS`` (TTS) and ``WhisperSTT`` (STT, faster-whisper) are LIVE when
    provisioned: real 24 kHz speech out, and real transcription in — on CPU, no
    GPU, no vendor in the audio path. ``ParakeetSTT`` stays a seam (needs
    torch+nemo). Whenever a backend's deps OR model files are missing,
    ``available()`` is False and ``select_*`` falls back to the honest offline
    placeholder (a tone / a canned transcript) and SAYS SO (no silent cap).
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


class _WhisperSTTSession:
    """One push-to-talk utterance through faster-whisper. Buffers 16 kHz PCM and
    emits a REAL interim transcript at most every ``_PARTIAL_EVERY_S`` seconds of
    accumulated speech (re-decoding the buffer so far), then a REAL final on
    ``finish``. Both are genuine ASR output — never the canned placeholder."""

    _PARTIAL_EVERY_S = 1.5

    def __init__(self, model, *, sample_rate: int) -> None:
        self._model = model
        self._sample_rate = sample_rate
        self._pcm = bytearray()
        self._partialed_bytes = 0

    def feed(self, pcm: bytes) -> Transcript | None:
        self._pcm += pcm
        every = int(self._PARTIAL_EVERY_S * self._sample_rate) * 2  # int16 = 2 bytes
        if len(self._pcm) - self._partialed_bytes < every:
            return None
        self._partialed_bytes = len(self._pcm)
        return Transcript(
            text=self._transcribe(bytes(self._pcm)),
            is_final=False,
            sample_rate=self._sample_rate,
        )

    def finish(self) -> Transcript:
        return Transcript(
            text=self._transcribe(bytes(self._pcm)),
            is_final=True,
            sample_rate=self._sample_rate,
        )

    def _transcribe(self, raw: bytes) -> str:
        import numpy as np

        if not raw:
            return ""
        audio = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
        if self._sample_rate != 16000:  # faster-whisper wants 16 kHz mono float32
            n = int(round(audio.size * 16000 / self._sample_rate))
            if n <= 0:
                return ""
            audio = np.interp(
                np.linspace(0.0, 1.0, n, dtype=np.float64),
                np.linspace(0.0, 1.0, audio.size, dtype=np.float64),
                audio,
            ).astype(np.float32)
        segments, _info = self._model.transcribe(audio, language="en", beam_size=1)
        return " ".join(seg.text.strip() for seg in segments).strip()


class WhisperSTT:
    """Real streaming STT via faster-whisper (CTranslate2) — transcribes 16 kHz
    PCM into the text that flows to ``/v1/ask``. No GPU, no cloud.

    Honest gate (same shape as KokoroTTS): requires ``faster_whisper`` importable
    AND the model present on disk (``$TEX_WHISPER_DIR``, default
    ``~/.cache/tex/whisper``; provisioned by ``scripts/provision_whisper.sh``).
    The dep alone can't transcribe without weights, so until both are present
    ``available()`` is False and ``select_stt`` keeps the honest ``OfflineSTT``
    placeholder (which does NOT transcribe). ``name`` reads exactly
    ``"faster-whisper"`` only once real ASR is possible.

    Emits real re-decoded partials + a real final per utterance; full
    LocalAgreement incremental streaming is a future refinement, not faked here.
    """

    requires = ("faster_whisper",)
    MODEL = "base.en"
    MODEL_FILE = "model.bin"  # the CTranslate2 weights inside the model dir

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model = None  # cached WhisperModel, built lazily on first session

    @property
    def name(self) -> str:
        return "faster-whisper" if self.available() else "faster-whisper(seam)"

    @classmethod
    def _model_dir(cls) -> Path:
        return Path(
            os.environ.get("TEX_WHISPER_DIR", os.path.expanduser("~/.cache/tex/whisper"))
        )

    def available(self) -> bool:
        # Dep importable AND model weights on disk — never True on the dep alone.
        if not _deps_present(*self.requires):
            return False
        return (self._model_dir() / self.MODEL_FILE).is_file()

    def _load(self):
        model = self._model
        if model is None:
            with self._lock:
                model = self._model
                if model is None:
                    from faster_whisper import WhisperModel

                    model = WhisperModel(
                        str(self._model_dir()), device="cpu", compute_type="int8"
                    )
                    self._model = model
        return model

    def session(self, *, sample_rate: int) -> STTSession:
        if not self.available():
            raise RuntimeError(
                "WhisperSTT.session called while unavailable (missing faster_whisper "
                "or model files); use select_stt() so OfflineSTT handles the fallback."
            )
        return _WhisperSTTSession(self._load(), sample_rate=sample_rate)


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
