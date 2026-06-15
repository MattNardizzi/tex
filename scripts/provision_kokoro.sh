#!/usr/bin/env bash
# Provision the local Kokoro-82M ONNX TTS backend (the real voice for /v1/speak).
#
# Installs the optional voice deps and downloads the model + voices files into
# $TEX_KOKORO_DIR (default ~/.cache/tex/kokoro). One-time, ~340 MB. After this,
# KokoroTTS.available() is True and select_tts() prefers it over the OfflineTTS
# placeholder tone. No GPU and no system espeak-ng needed (kokoro-onnx bundles a
# prebuilt espeak for phonemization). Idempotent: re-running re-verifies.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DIR="${TEX_KOKORO_DIR:-$HOME/.cache/tex/kokoro}"
BASE="https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0"
MODEL="kokoro-v1.0.onnx"   # ~310 MiB f32, Apache-2.0
VOICES="voices-v1.0.bin"   # ~27 MiB, 26 voice style vectors

echo "==> Installing voice deps (kokoro-onnx + onnxruntime + soundfile; bundled espeak)"
python3 -m pip install -r "$ROOT/requirements-voice.txt"

mkdir -p "$DIR"
for f in "$MODEL" "$VOICES"; do
  if [ -s "$DIR/$f" ]; then
    echo "==> have $f ($(du -h "$DIR/$f" | cut -f1))"
  else
    echo "==> downloading $f ..."
    curl -fL --retry 3 --retry-delay 2 -o "$DIR/$f" "$BASE/$f"
  fi
done

echo "==> Provisioned into $DIR"
ls -la "$DIR"

echo "==> Verifying KokoroTTS reports available and actually speaks"
PYTHONPATH="$ROOT/src" python3 - <<'PY'
from tex.gateway.backends import KokoroTTS, select_tts
k = KokoroTTS()
assert k.available(), "KokoroTTS still unavailable after provisioning"
assert select_tts().name == "kokoro", "select_tts() did not prefer kokoro"
wav = k.synthesize("Provisioning complete. The voice is live.", sample_rate=24000)
assert wav[:4] == b"RIFF" and len(wav) > 10000, "no real audio produced"
print(f"OK: KokoroTTS live; {len(wav)} wav bytes; select_tts().name = {select_tts().name!r}")
PY
echo "==> Done. /v1/speak now returns real Kokoro speech (X-Tex-Voice-Backend: kokoro)."
