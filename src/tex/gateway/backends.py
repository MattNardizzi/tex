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
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # type-only; prosody helpers are imported lazily where used
    from tex.presence.contract import ProsodyPlan

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
    "ElevenLabsTTS",
    "select_stt",
    "select_tts",
    "synthesize_tts",
    "synthesize_tts_stream",
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
    def synthesize(self, text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> bytes: ...
    # ``prosody`` carries ONLY the GENERATION-TIME knob each backend has (speech
    # rate). The tier-derived cues that are not generation knobs — a lead pause
    # and the terminal-pitch glide — are applied once, post-synthesis, in
    # :func:`synthesize_tts` (so they are never double-applied). Backends that
    # lack a rate knob ignore ``prosody`` and degrade cleanly.


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

    def synthesize(self, text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> bytes:
        # ~45 ms per character, clamped, at a low amplitude so it is audibly a
        # placeholder, not a claim to speech. ``prosody`` (when supplied) scales
        # the tone's DURATION by the inverse of the speech rate — faster rate ⇒
        # shorter tone — so even the no-voice floor carries the rate cue. The
        # lead pause + terminal glide are added post-synthesis by synthesize_tts.
        rate = prosody.rate if prosody is not None else 1.0
        seconds = max(0.25, min(6.0, 0.045 * max(1, len(text or "")) / max(0.1, rate)))
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
    # The local-dev stand-in voice. Overridable via TEX_KOKORO_VOICE (mirrors
    # TEX_ELEVENLABS_VOICE for the cloud path) so the dev voice can be swapped
    # without code. Production speaks through ElevenLabs, not this — Kokoro is the
    # keyless fallback. Default kept neutral; 13 male / 15 female voices ship in
    # voices-v1.0.bin (am_*/bm_* male, af_*/bf_* female).
    VOICE = os.environ.get("TEX_KOKORO_VOICE", "af_heart")
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

    def synthesize(self, text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> bytes:
        """Real Kokoro-82M TTS → audio/wav bytes. Lazy-loads (and caches) the
        ONNX session on first call. Callers must gate on ``available()`` —
        ``select_tts`` does — so reaching here unavailable is a programming
        error, answered with a truthful refusal, never fabricated audio.

        ``prosody`` (when supplied) sets the GENERATION-TIME speech rate via
        Kokoro's ``create(speed=...)`` knob (clamped to Kokoro's accepted
        [0.5, 2.0] — it hard-asserts the range, so the clamp is load-bearing).
        The lead pause + terminal-pitch glide are applied post-synthesis by
        ``synthesize_tts``; this call only sets the rate."""
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

        from tex.presence.prosody import kokoro_speed  # lazy: keep gateway lean

        samples, native_sr = kokoro.create(
            text, voice=self.VOICE, speed=kokoro_speed(prosody), lang="en-us"
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


# --------------------------------------------------------------------------- elevenlabs (cloud vocal cords)


def _pcm_to_wav(pcm: bytes, sample_rate: int) -> bytes:
    """Wrap raw little-endian 16-bit MONO PCM in a WAV container (stdlib only)."""
    buf = BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(int(sample_rate))
        w.writeframes(pcm)
    return buf.getvalue()


def _resample_pcm16(pcm: bytes, *, src_rate: int, dst_rate: int) -> bytes:
    """Linear-resample mono s16le PCM from ``src_rate`` to ``dst_rate``. Honors
    the caller's rate honestly (keeps pitch/duration truthful) rather than
    mislabeling the sample rate; quality is below a polyphase filter. The common
    path NEVER resamples because ``_SPEAK_SAMPLE_RATE`` (24 kHz) is requested
    directly from the vendor."""
    if not pcm or src_rate == dst_rate:
        return pcm
    import numpy as np

    audio = np.frombuffer(pcm, dtype="<i2").astype(np.float32)
    n_out = int(round(audio.size * dst_rate / src_rate))
    if n_out <= 0:
        return b""
    resampled = np.interp(
        np.linspace(0.0, 1.0, n_out, dtype=np.float64),
        np.linspace(0.0, 1.0, audio.size, dtype=np.float64),
        audio,
    )
    return np.clip(np.round(resampled), -32768, 32767).astype("<i2").tobytes()


def _chars_to_words(
    chars: list[str],
    starts: list[float],
    ends: list[float],
) -> list[dict]:
    """Roll ElevenLabs CHARACTER-level alignment up into WORDS for in-sync
    on-screen highlighting. Splits on whitespace; each word carries the start
    time of its first character and the end time of its last (seconds). Keeps
    punctuation attached to its word, and reconstructs the exact spoken text so
    the highlight maps to the literal displayed line."""
    words: list[dict] = []
    cur = ""
    cur_start: float | None = None
    last_end: float | None = None
    for ch, s, e in zip(chars, starts, ends):
        if ch.isspace():
            if cur:
                words.append({"text": cur, "start": cur_start, "end": last_end})
                cur, cur_start, last_end = "", None, None
            continue
        if not cur:
            cur_start = s
        cur += ch
        last_end = e
    if cur:
        words.append({"text": cur, "start": cur_start, "end": last_end})
    return words


class ElevenLabsTTS:
    """ElevenLabs cloud TTS — Tex's signature voice — used as VOCAL CORDS ONLY.

    Unlike :class:`KokoroTTS` (local, no vendor) this sends text to ElevenLabs'
    servers to synthesize, so it is a VENDOR IN THE AUDIO PATH — labeled honestly:
    ``name`` reads exactly ``"elevenlabs"`` when live, so ``X-Tex-Voice-Backend``
    names the cloud vendor on every byte. It is invoked ONLY on a line Tex has
    ALREADY sealed in ``/v1/ask`` (a grounded answer, or an authored decline), so
    ElevenLabs never decides, generates, or paraphrases WHAT Tex says — it only
    voices bytes Tex authored.

    This uses the raw text-to-speech endpoint, NOT the ElevenLabs Agents /
    Conversational-AI product (which runs an LLM that would sit in the speaking
    seat — deliberately not used). The "speaks only the text sent, generates
    nothing" property is true by the endpoint's semantics; it is NOT a verbatim
    doc quote, so it is stated as such.

    Honest gate: ``available()`` is True only when ``ELEVENLABS_API_KEY`` is set —
    necessary (and, network/quota permitting, sufficient) to produce real speech.
    Without it the selectors fall back to the local :class:`KokoroTTS`, then the
    :class:`OfflineTTS` tone; a RUNTIME vendor failure also falls through (see
    :func:`synthesize_tts`). The no-vendor fallbacks are never removed.

    Synthesis pins the SOTA real-time model ``eleven_flash_v2_5`` EXPLICITLY (the
    convert endpoint otherwise defaults to the slower ``eleven_multilingual_v2``)
    and forces ``apply_text_normalization="off"`` so the vendor voices the SEALED
    string faithfully — it must not silently re-render digits/symbols into
    something Tex did not seal. Audio is requested as raw 16-bit PCM at the
    caller's rate and WAV-wrapped with no resample on the common 24 kHz path.

    Overridable per deploy: ``TEX_ELEVENLABS_VOICE`` (voice id),
    ``TEX_ELEVENLABS_MODEL`` (model id).
    """

    requires: tuple[str, ...] = ()  # stdlib urllib only — the live gate is the API key
    VOICE = "8eWiU0Pinoj0ItwssWXL"
    MODEL = "eleven_flash_v2_5"
    API_BASE = "https://api.elevenlabs.io"
    _SUPPORTED_PCM_RATES = (8000, 16000, 22050, 24000, 32000, 44100, 48000)
    _TIMEOUT_S = 30.0

    @property
    def name(self) -> str:
        # Honest in both states: exactly "elevenlabs" the moment a key is present
        # (so the vendor is named), "(seam)" while unconfigured (a fallback runs).
        return "elevenlabs" if self.available() else "elevenlabs(seam)"

    @classmethod
    def _voice(cls) -> str:
        return os.environ.get("TEX_ELEVENLABS_VOICE", cls.VOICE)

    @classmethod
    def _model(cls) -> str:
        return os.environ.get("TEX_ELEVENLABS_MODEL", cls.MODEL)

    @staticmethod
    def _api_key() -> str | None:
        key = (os.environ.get("ELEVENLABS_API_KEY") or "").strip()
        return key or None

    def available(self) -> bool:
        return self._api_key() is not None

    def synthesize(self, text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> bytes:
        """Real ElevenLabs speech for the EXACT sealed ``text`` → audio/wav bytes.
        Callers must gate on ``available()`` — the selectors do — so reaching here
        without a key is a programming error answered with a truthful refusal,
        never fabricated audio.

        ``prosody`` (when supplied) sets the GENERATION-TIME ``voice_settings``
        (only ``speed`` varies by tier; the rest are pinned constants). The lead
        pause + terminal-pitch glide are applied post-synthesis by
        ``synthesize_tts`` — ElevenLabs exposes no terminal-F0 knob, so that cue
        degrades to the WAV post-process here."""
        key = self._api_key()
        if key is None:
            raise RuntimeError(
                "ElevenLabsTTS.synthesize called while unavailable "
                "(ELEVENLABS_API_KEY not set); use synthesize_tts()/select_tts() "
                "so KokoroTTS/OfflineTTS handle the fallback."
            )
        if not (text or "").strip():
            # Nothing sealed to say → a valid, silent WAV (no vendor call, no cost).
            return _pcm_to_wav(b"", sample_rate)

        from tex.presence.prosody import elevenlabs_voice_settings  # lazy

        if sample_rate in self._SUPPORTED_PCM_RATES:
            req_rate, out_format = sample_rate, f"pcm_{sample_rate}"
        else:
            req_rate, out_format = 24000, "pcm_24000"

        pcm = self._post(
            path=f"/v1/text-to-speech/{self._voice()}?output_format={out_format}",
            key=key,
            text=text,
            voice_settings=elevenlabs_voice_settings(prosody),
        )
        if req_rate != sample_rate:
            pcm = _resample_pcm16(pcm, src_rate=req_rate, dst_rate=sample_rate)
        return _pcm_to_wav(pcm, sample_rate)

    def synthesize_timed(self, text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> dict:
        """Real ElevenLabs speech for the EXACT sealed ``text`` WITH per-word
        timing, for on-screen highlighting that tracks the voice. Returns
        ``{"backend","sample_rate","audio_b64","words"}`` where ``audio_b64`` is
        raw little-endian 16-bit mono PCM (base64) and ``words`` is
        ``[{text,start,end}]`` in seconds. Same honest gate as ``synthesize`` —
        callers must check ``available()`` first.

        Uses the documented ``/with-timestamps`` endpoint (single JSON response,
        not SSE — robust through the same-origin serverless proxy). The exact
        char→word rollup + the live request shape are verified by tests; the live
        ElevenLabs response is confirmed against a real key before production.

        ``prosody`` applies the rate (``voice_settings.speed``), the per-tier
        loudness gain (TIMING-SAFE — amplitude only, so it never desyncs the
        per-word timing), AND the lead pause (real leading silence + every word
        time shifted by the same offset, so the highlight stays in sync). HONEST
        DEGRADATION: the terminal-pitch glide is NOT applied on this path — it
        would desync per-word timing — so the word-timed surface carries the pace
        + loudness + pause cues but not the contour."""
        import base64
        import json

        key = self._api_key()
        if key is None:
            raise RuntimeError(
                "ElevenLabsTTS.synthesize_timed called while unavailable "
                "(ELEVENLABS_API_KEY not set)."
            )
        if not (text or "").strip():
            return {"backend": "elevenlabs", "sample_rate": sample_rate, "audio_b64": "", "words": []}

        from tex.presence.prosody import (  # lazy
            apply_intensity_pcm16,
            elevenlabs_voice_settings,
            lead_silence_pcm16,
        )

        rate = sample_rate if sample_rate in self._SUPPORTED_PCM_RATES else 24000
        raw = self._post(
            path=f"/v1/text-to-speech/{self._voice()}/with-timestamps?output_format=pcm_{rate}",
            key=key,
            text=text,
            voice_settings=elevenlabs_voice_settings(prosody),
        )
        data = json.loads(raw.decode("utf-8"))
        align = data.get("alignment") or {}
        words = _chars_to_words(
            align.get("characters") or [],
            align.get("character_start_times_seconds") or [],
            align.get("character_end_times_seconds") or [],
        )
        audio_b64 = data.get("audio_base64", "")

        # Per-tier loudness cue — timing-safe (amplitude only), applied to the
        # speech PCM BEFORE any lead silence so the silence stays exactly zero.
        if prosody is not None and audio_b64:
            audio_b64 = base64.b64encode(
                apply_intensity_pcm16(base64.b64decode(audio_b64), prosody)
            ).decode()

        if prosody is not None and prosody.lead_pause_ms > 0:
            # Prepend real leading silence to the raw PCM and shift every word
            # time by the same offset so the on-screen highlight stays aligned.
            lead = lead_silence_pcm16(prosody, rate)
            if lead and audio_b64:
                audio_b64 = base64.b64encode(lead + base64.b64decode(audio_b64)).decode()
            shift = prosody.lead_pause_ms / 1000.0
            words = [
                {
                    "text": w["text"],
                    "start": None if w["start"] is None else w["start"] + shift,
                    "end": None if w["end"] is None else w["end"] + shift,
                }
                for w in words
            ]

        return {
            "backend": "elevenlabs",
            "sample_rate": rate,
            "audio_b64": audio_b64,
            "words": words,
        }

    def stream(self, text: str, *, chunk_size: int = 4096, voice_settings: dict | None = None):
        """Stream the EXACT sealed ``text`` as MP3 chunks from ElevenLabs'
        ``/stream`` endpoint — the first audio bytes arrive in ~hundreds of ms
        instead of after the whole clip is generated (the ``synthesize`` convert
        path waits for the full body). A generator of raw MP3 bytes. Same honest
        gate + verbatim semantics as ``synthesize`` (flash_v2_5 pinned,
        normalization OFF, Tex's already-sealed string only — never generates).
        Raises BEFORE the first yield on a connect/auth/HTTP error, so a caller
        can fall back to the no-vendor path; a failure mid-stream simply truncates.

        ``voice_settings`` carries the GENERATION-TIME rate (``speed``) so even
        the low-latency MP3 path honors the tier's pace. HONEST DEGRADATION: the
        lead pause and terminal-pitch glide CANNOT be spliced into a live MP3
        frame stream, so they are NOT applied here — which is exactly why
        ``/v1/speak`` routes any prosody-bearing request to the full WAV
        post-process path instead of this stream."""
        import json
        import urllib.error
        import urllib.request

        key = self._api_key()
        if key is None:
            raise RuntimeError(
                "ElevenLabsTTS.stream called while unavailable (ELEVENLABS_API_KEY not set)."
            )
        if not (text or "").strip():
            return  # nothing sealed → empty stream, no vendor call, no cost
        body: dict = {
            "text": text,
            "model_id": self._model(),          # SOTA real-time; pinned
            "apply_text_normalization": "off",  # voice the SEALED string verbatim
        }
        if voice_settings is not None:
            body["voice_settings"] = voice_settings
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.API_BASE}/v1/text-to-speech/{self._voice()}/stream?output_format=mp3_44100_128",
            data=payload,
            method="POST",
            headers={
                "xi-api-key": key,
                "Content-Type": "application/json",
                "Accept": "audio/mpeg",
            },
        )
        try:
            resp = urllib.request.urlopen(request, timeout=self._TIMEOUT_S)
        except urllib.error.HTTPError as exc:
            detail = b""
            try:
                detail = exc.read()[:300]
            except Exception:  # pragma: no cover - defensive
                pass
            raise RuntimeError(
                f"ElevenLabs stream HTTP {exc.code} for voice {self._voice()}: {detail!r}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"ElevenLabs stream unreachable: {exc.reason}") from exc
        with resp:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def _post(self, *, path: str, key: str, text: str, voice_settings: dict | None = None) -> bytes:
        """POST the SEALED ``text`` to an ElevenLabs TTS endpoint (flash_v2_5
        pinned, normalization OFF) and return the raw response body. Shared by
        ``synthesize`` (audio bytes) and ``synthesize_timed`` (JSON).

        ``voice_settings`` (the tier-derived prosody knob, ``speed`` + pinned
        constants) is included ONLY when supplied — when ``None`` the payload is
        byte-identical to the pre-prosody request, so the no-prosody path never
        changes the vendor's stored voice defaults."""
        import json
        import urllib.error
        import urllib.request

        body: dict = {
            "text": text,
            "model_id": self._model(),          # SOTA real-time; pinned, never the default
            "apply_text_normalization": "off",  # voice the SEALED string verbatim
        }
        if voice_settings is not None:
            body["voice_settings"] = voice_settings
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.API_BASE}{path}",
            data=payload,
            method="POST",
            headers={"xi-api-key": key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._TIMEOUT_S) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:  # 4xx/5xx from ElevenLabs
            detail = b""
            try:
                detail = exc.read()[:300]
            except Exception:  # pragma: no cover - defensive
                pass
            raise RuntimeError(
                f"ElevenLabs TTS HTTP {exc.code} for voice {self._voice()}: {detail!r}"
            ) from exc
        except urllib.error.URLError as exc:  # network / DNS / timeout
            raise RuntimeError(f"ElevenLabs TTS unreachable: {exc.reason}") from exc


# --------------------------------------------------------------------------- selection


_STT_PREFERENCE: tuple[STTBackend, ...] = (ParakeetSTT(), WhisperSTT())
# ElevenLabs (cloud, Tex's signature voice) preferred when its key is present;
# local Kokoro is the no-vendor fallback; OfflineTTS the always-on floor.
_TTS_PREFERENCE: tuple[TTSBackend, ...] = (ElevenLabsTTS(), KokoroTTS())


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


def synthesize_tts(text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None) -> tuple[bytes, str]:
    """Synthesize ``text`` with the best available TTS, and — so Tex is NEVER
    muted by a vendor hiccup — fall THROUGH to the next backend on a RUNTIME
    failure (e.g. an ElevenLabs outage/timeout), ending at the always-available
    :class:`OfflineTTS`. Returns ``(wav_bytes, name)`` where ``name`` is the
    backend that ACTUALLY produced the audio, so ``X-Tex-Voice-Backend`` can never
    mislabel who spoke (a cloud vendor is named only when it truly voiced the
    line). Every skipped/failed backend is logged — no silent cap.

    ``prosody`` (a tier-derived :class:`~tex.presence.contract.ProsodyPlan`)
    threads the GENERATION-TIME rate into each backend's synth call, then applies
    the post-synthesis cues — leading pause + terminal-pitch glide — ONCE here via
    :func:`apply_prosody_to_wav`, so they are never double-applied and every
    backend's WAV gets the same honest treatment. ``prosody=None`` is byte-for-byte
    today's behavior (the call signature is identical, so existing test doubles
    that don't accept ``prosody`` keep working)."""
    failures: list[str] = []
    for backend in (*_TTS_PREFERENCE, OfflineTTS()):
        if not backend.available():
            continue
        try:
            if prosody is None:
                audio = backend.synthesize(text, sample_rate=sample_rate)
            else:
                audio = backend.synthesize(text, sample_rate=sample_rate, prosody=prosody)
        except Exception as exc:  # vendor / network / runtime failure → fall through
            _logger.warning(
                "voice gateway: TTS backend %s failed at synth (%r); falling through",
                backend.name, exc,
            )
            failures.append(f"{backend.name}: {exc!r}")
            continue
        if prosody is not None:
            # Post-synthesis, content-independent cues (lead pause + terminal
            # glide). Fail-CLOSED for the cautious tiers: the lead pause is pure
            # stdlib and is always applied; the glide degrades to a no-op only
            # when the window is too short — never toward a more-confident render.
            from tex.presence.prosody import apply_prosody_to_wav  # lazy
            audio = apply_prosody_to_wav(audio, prosody)
        if failures:
            _logger.warning(
                "voice gateway: spoke via fallback %s after %d failure(s): %s",
                backend.name, len(failures), "; ".join(failures),
            )
        return audio, backend.name
    # OfflineTTS is always available and never raises, so this is unreachable.
    raise RuntimeError(f"no TTS backend could synthesize; failures={failures}")


def synthesize_tts_stream(text: str, *, sample_rate: int, prosody: "ProsodyPlan | None" = None):
    """Streaming sibling of :func:`synthesize_tts`. Returns
    ``(iterator_of_bytes, backend_name, media_type)``.

    Prefers ElevenLabs' progressive MP3 stream — the first audio arrives in
    ~hundreds of ms instead of after the whole clip — and on ANY connect / auth /
    HTTP failure BEFORE the first byte falls THROUGH to the no-vendor path (the
    full Kokoro WAV / offline tone as a single chunk). So Tex is never muted by a
    vendor hiccup and the no-vendor fallbacks stay intact, exactly like
    :func:`synthesize_tts`. ``backend_name`` names who ACTUALLY produced the audio,
    so ``X-Tex-Voice-Backend`` is honest. Grounding is unchanged: this only voices
    a string the caller already sealed in ``/v1/ask`` — it never authors text.
    ``sample_rate`` applies ONLY to the no-vendor WAV fallback; the cloud path
    streams self-describing MP3 (``mp3_44100_128``) and ignores it.

    PROSODY ON THE STREAM IS PARTIAL BY NATURE: the rate (``voice_settings.speed``)
    is carried into the MP3 request, but the lead pause + terminal-pitch glide
    CANNOT be spliced into a live MP3 frame stream — so they DEGRADE on the cloud
    branch (the no-vendor fallback runs through :func:`synthesize_tts`, which DOES
    apply the full plan). Because that degradation could let a cautious tier sound
    at the confident default, ``/v1/speak`` does NOT send prosody here — it routes
    any prosody-bearing request to the full WAV path. ``prosody`` exists here for
    defense-in-depth so a direct streaming caller still gets an honest rate."""
    el = ElevenLabsTTS()
    if el.available():
        from tex.presence.prosody import elevenlabs_voice_settings  # lazy
        gen = el.stream(text, voice_settings=elevenlabs_voice_settings(prosody))
        try:
            first = next(gen)  # forces connect + first chunk; raises on vendor failure
        except StopIteration:
            pass  # empty/sealed-silent line → fall through to the no-vendor path
        except Exception as exc:  # connect/auth/HTTP before any audio → fall through
            _logger.warning(
                "voice gateway: ElevenLabs stream pre-roll failed (%r); falling through", exc
            )
        else:
            def _eleven_stream():
                try:
                    yield first
                    yield from gen
                except Exception as exc:  # rare mid-stream break → truncate, never mute
                    _logger.warning(
                        "voice gateway: ElevenLabs stream broke mid-clip (%r)", exc
                    )
                finally:
                    # Deterministically close the upstream ElevenLabs socket on a
                    # natural end, a mid-stream error, OR client abandonment /
                    # barge-in (when the response generator is closed) — don't lean
                    # on GC of ``with resp:`` to finalize the HTTPS connection.
                    gen.close()
            return _eleven_stream(), el.name, "audio/mpeg"
    # No vendor (or vendor failed pre-roll): the local no-vendor path, one chunk.
    # This path DOES apply the full plan (lead pause + glide) via synthesize_tts.
    audio, name = synthesize_tts(text, sample_rate=sample_rate, prosody=prosody)
    return iter([audio]), name, "audio/wav"
