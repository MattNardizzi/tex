#!/usr/bin/env bash
# Provision the local faster-whisper STT backend (real transcription for the
# voice gateway / the STT half of the grounded cascade).
#
# Installs the optional voice deps and downloads the Whisper model (CTranslate2,
# int8) into $TEX_WHISPER_DIR (default ~/.cache/tex/whisper). One-time, ~145 MB
# for base.en. After this, WhisperSTT.available() is True and select_stt()
# prefers it over the OfflineSTT canned placeholder. No GPU needed. Fully
# permissive licensing (faster-whisper + CTranslate2 + Whisper weights are MIT).
# Override the model with TEX_WHISPER_MODEL (e.g. small.en for more accuracy).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DIR="${TEX_WHISPER_DIR:-$HOME/.cache/tex/whisper}"
MODEL="${TEX_WHISPER_MODEL:-base.en}"

echo "==> Installing voice deps (faster-whisper)"
python3 -m pip install -r "$ROOT/requirements-voice.txt"

echo "==> Downloading Whisper model '$MODEL' into $DIR"
mkdir -p "$DIR"
python3 - "$MODEL" "$DIR" <<'PY'
import sys
try:
    from faster_whisper import download_model
except Exception:
    from faster_whisper.utils import download_model
model, out = sys.argv[1], sys.argv[2]
print("downloaded to:", download_model(model, output_dir=out))
PY

echo "==> Provisioned into $DIR"
ls -la "$DIR"

echo "==> Verifying WhisperSTT reports available and actually transcribes"
PYTHONPATH="$ROOT/src" python3 - <<'PY'
from tex.gateway.backends import WhisperSTT, select_stt
w = WhisperSTT()
assert w.available(), "WhisperSTT still unavailable after provisioning"
assert select_stt().name == "faster-whisper", "select_stt() did not prefer faster-whisper"
print(f"OK: WhisperSTT live; select_stt().name = {select_stt().name!r}")
PY
echo "==> Done. The voice gateway now returns a REAL transcript (not the placeholder)."
