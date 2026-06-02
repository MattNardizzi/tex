"""
[Architecture: Cross-cutting (Vigil cognition)] — optional OpenAI transport
for the explanation layer.

Kept in its own module so nothing in the vigil hot path hard-imports the
OpenAI SDK. Construction is lazy and every failure surfaces as an exception
the Explainer catches and turns into the deterministic floor. This provider
does text generation only — it never sees unsealed input, because the
Explainer only ever hands it the sealed fact sheet.
"""

from __future__ import annotations

import os

__all__ = ["OpenAITextProvider"]


class OpenAITextProvider:
    """Transport-only text generator over OpenAI's Responses API."""

    __slots__ = ("_api_key", "_model", "_timeout", "_client")

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 20.0,
    ) -> None:
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._model = model
        self._timeout = timeout_seconds
        self._client = None

    @property
    def provider_name(self) -> str:
        return f"openai:{self._model}"

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI  # local import; optional dependency

            if not self._api_key:
                raise RuntimeError("OPENAI_API_KEY is not set")
            self._client = OpenAI(api_key=self._api_key, timeout=self._timeout)
        return self._client

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        client = self._get_client()
        response = client.responses.create(
            model=self._model,
            instructions=system_prompt,
            input=user_prompt,
            temperature=0.2,
        )
        text = getattr(response, "output_text", None)
        if not text:
            raise RuntimeError("OpenAI explainer returned no text")
        return str(text)
