"""Voice tests must never reach the ElevenLabs cloud by accident.

``ElevenLabsTTS.available()`` gates purely on ``ELEVENLABS_API_KEY``; if a real
key happens to be exported in the dev shell, the offline/local voice tests would
silently start making billed network calls. This autouse fixture deletes the key
by default so every voice test is hermetic and deterministic; the tests that
exercise the ElevenLabs backend set it explicitly (and stub the HTTP call).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _hermetic_elevenlabs(monkeypatch):
    monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)
