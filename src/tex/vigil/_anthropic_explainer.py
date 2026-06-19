"""
[Architecture: Cross-cutting (Vigil cognition)] — optional Anthropic transport
for the explanation layer.

Mirrors ``_openai_explainer.OpenAITextProvider`` so the vigil prose surface is
provider-symmetric with the semantic judge. Kept in its own module so nothing
in the vigil hot path hard-imports the Anthropic SDK. Construction is lazy and
every failure surfaces as an exception the Explainer catches and turns into the
deterministic floor. This provider does text generation only — it never sees
unsealed input, because the Explainer only ever hands it the sealed fact sheet,
and it is never on the ``/v1/ask`` (voice) path, which is deterministic.
"""

from __future__ import annotations

import os

__all__ = ["AnthropicTextProvider"]

# June-2026 SOTA default. Opus 4.8 is Anthropic's most capable available model
# (Fable 5 was disabled 2026-06-12 by US export-control directive).
_DEFAULT_MODEL = "claude-opus-4-8"
_DEFAULT_MAX_TOKENS = 1024


class AnthropicTextProvider:
    """Transport-only text generator over Anthropic's Messages API."""

    __slots__ = ("_api_key", "_model", "_timeout", "_max_tokens", "_client")

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 20.0,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._model = model or _DEFAULT_MODEL
        self._timeout = timeout_seconds
        self._max_tokens = max_tokens
        self._client = None

    @property
    def provider_name(self) -> str:
        return f"anthropic:{self._model}"

    def _get_client(self):
        if self._client is None:
            from anthropic import Anthropic  # local import; optional dependency

            if not self._api_key:
                raise RuntimeError("ANTHROPIC_API_KEY is not set")
            self._client = Anthropic(api_key=self._api_key, timeout=self._timeout)
        return self._client

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        client = self._get_client()
        # No sampling params (Opus 4.8 rejects temperature/top_p); thinking is
        # off by default, which is correct for a short grounded prose surface.
        response = client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        if getattr(response, "stop_reason", None) == "refusal":
            raise RuntimeError("Anthropic explainer declined the request")
        parts = [
            block.text
            for block in (getattr(response, "content", None) or [])
            if getattr(block, "type", None) == "text"
            and getattr(block, "text", None)
        ]
        text = "".join(parts).strip()
        if not text:
            raise RuntimeError("Anthropic explainer returned no text")
        return text
