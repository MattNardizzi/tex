"""Anthropic (Claude) structured semantic provider.

A drop-in :class:`~tex.semantic.analyzer.StructuredSemanticProvider` parallel to
:class:`~tex.semantic.openai.OpenAIStructuredSemanticProvider`, so Tex's
schema-locked semantic layer — and the Presence brain — can run on Claude. Today
the only shipped provider is OpenAI; this makes the model swappable to Claude
without changing any caller.

Division of labour (per the provider protocol): **Tex owns prompt construction
and schema validation; the provider owns transport and model execution only.** So
``analyze`` returns the model's structured output as a ``Mapping[str, Any]`` — the
raw tool input — which the caller validates:

* the semantic layer coerces it into ``SemanticAnalysis``
  (``DefaultSemanticAnalyzer._coerce_provider_result``);
* the Presence brain parses it into ``(draft, claims)``.

Structured output is obtained via **forced tool use** (``tool_choice`` pins a
single tool), which guarantees a JSON object rather than free text. The tool's
``input_schema`` is intentionally permissive — the *system prompt* (owned by Tex)
defines the exact keys, and Tex validates downstream.

Honest notes:

* **Facts never live in weights.** Facts reach the model only through the prompt;
  nothing here fine-tunes or persists fact values. The model is a phrasing/parsing
  function over text it is handed each call.
* **Determinism.** On Opus 4.8 the ``temperature``/``top_p``/``top_k`` sampling
  parameters are removed (sending them is a 400), so this provider sets none and
  cannot pin a seed. Output is therefore not bit-reproducible — which is safe here
  precisely because the Presence gate re-verifies every claim against sealed
  evidence and never trusts the model's text.
* **Refusals.** A ``stop_reason == "refusal"`` is raised as ``SemanticProviderError``
  so the brain treats it as "uncertain → propose nothing" and the gate abstains.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Final

from tex.semantic.analyzer import SemanticProviderError

try:  # pragma: no cover - import guard for environments without the SDK
    import anthropic
    from anthropic import (
        Anthropic,
        APIConnectionError,
        APIStatusError,
        APITimeoutError,
        AuthenticationError,
        BadRequestError,
        RateLimitError,
    )
except ImportError as exc:  # pragma: no cover
    anthropic = None  # type: ignore[assignment]
    Anthropic = None  # type: ignore[assignment]
    APIConnectionError = Exception  # type: ignore[assignment]
    APIStatusError = Exception  # type: ignore[assignment]
    APITimeoutError = Exception  # type: ignore[assignment]
    AuthenticationError = Exception  # type: ignore[assignment]
    BadRequestError = Exception  # type: ignore[assignment]
    RateLimitError = Exception  # type: ignore[assignment]
    _ANTHROPIC_IMPORT_ERROR: ImportError | None = exc
else:  # pragma: no cover
    _ANTHROPIC_IMPORT_ERROR = None


# Opus 4.8 — the most capable Claude model (see the claude-api skill). Sampling
# params are removed on this tier; do not add temperature/top_p/top_k.
_DEFAULT_MODEL: Final[str] = "claude-opus-4-8"
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
_DEFAULT_MAX_RETRIES: Final[int] = 2
_DEFAULT_MAX_TOKENS: Final[int] = 4096
_DEFAULT_TOOL_NAME: Final[str] = "emit_structured_analysis"
_DEFAULT_TOOL_DESCRIPTION: Final[str] = (
    "Emit the single structured JSON object described by the system prompt. "
    "Populate exactly the keys the system prompt specifies and nothing else."
)
# Permissive object schema: the system prompt (Tex-owned) defines the keys; Tex
# validates the result. Forcing this tool guarantees a JSON object, not prose.
_TOOL_INPUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": True,
}


class AnthropicStructuredSemanticProvider:
    """Structured semantic provider for Tex backed by Claude (Messages API)."""

    __slots__ = (
        "_api_key",
        "_base_url",
        "_model",
        "_timeout_seconds",
        "_max_retries",
        "_max_tokens",
        "_tool_name",
        "_tool_description",
        "_tool_input_schema",
        "_client",
    )

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        base_url: str | None = None,
        tool_name: str = _DEFAULT_TOOL_NAME,
        tool_description: str = _DEFAULT_TOOL_DESCRIPTION,
        tool_input_schema: dict[str, Any] | None = None,
    ) -> None:
        self._api_key = self._normalize_optional(api_key) or os.getenv("ANTHROPIC_API_KEY")
        self._base_url = self._normalize_optional(base_url) or os.getenv("ANTHROPIC_BASE_URL")
        # ``model=None`` means "use this provider's default" — the
        # provider-neutral config contract (settings.semantic_model defaults to
        # None and each provider resolves its own June-2026 default). An
        # explicitly empty / whitespace model is still rejected.
        self._model = self._normalize_required(
            _DEFAULT_MODEL if model is None else model, field_name="model"
        )
        self._timeout_seconds = self._validate_timeout(timeout_seconds)
        self._max_retries = self._validate_max_retries(max_retries)
        self._max_tokens = self._validate_max_tokens(max_tokens)
        self._tool_name = self._normalize_required(tool_name, field_name="tool_name")
        self._tool_description = self._normalize_required(
            tool_description, field_name="tool_description"
        )
        self._tool_input_schema = dict(tool_input_schema or _TOOL_INPUT_SCHEMA)
        self._client: Any = None

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def analyze(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Run one schema-locked call; return the model's tool input as a dict.

        Raises:
            SemanticProviderError: on transport, refusal, or missing tool output.
        """
        instructions = self._normalize_required(system_prompt, field_name="system_prompt")
        request_prompt = self._normalize_required(user_prompt, field_name="user_prompt")
        client = self._get_client()

        try:
            response = client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=instructions,
                messages=[{"role": "user", "content": request_prompt}],
                tools=[
                    {
                        "name": self._tool_name,
                        "description": self._tool_description,
                        "input_schema": self._tool_input_schema,
                    }
                ],
                tool_choice={"type": "tool", "name": self._tool_name},
            )
        except APITimeoutError as exc:
            raise SemanticProviderError(
                f"Anthropic semantic request timed out after {self._timeout_seconds:.1f}s"
            ) from exc
        except RateLimitError as exc:
            raise SemanticProviderError("Anthropic semantic request was rate-limited") from exc
        except AuthenticationError as exc:
            raise SemanticProviderError("Anthropic semantic request failed authentication") from exc
        except APIConnectionError as exc:
            raise SemanticProviderError(
                "Anthropic semantic request failed due to connection error"
            ) from exc
        except BadRequestError as exc:
            raise SemanticProviderError(f"Anthropic semantic request was rejected: {exc}") from exc
        except APIStatusError as exc:
            raise SemanticProviderError(
                f"Anthropic semantic request returned an API error: {exc}"
            ) from exc
        except Exception as exc:  # pragma: no cover - defensive
            raise SemanticProviderError(
                f"unexpected Anthropic semantic provider failure: {type(exc).__name__}: {exc}"
            ) from exc

        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            detail = getattr(response, "stop_details", None)
            raise SemanticProviderError(
                f"Anthropic semantic provider refused the request (stop_details={detail!r})"
            )

        tool_input = self._extract_tool_input(response)
        if tool_input is None:
            raise SemanticProviderError(
                "Anthropic semantic provider returned no tool_use block "
                f"(stop_reason={stop_reason!r})"
            )
        return tool_input

    # ── internals ─────────────────────────────────────────────────────────────
    def _get_client(self) -> Any:
        if Anthropic is None:
            raise SemanticProviderError(
                "anthropic package is not installed. Install it before using "
                "AnthropicStructuredSemanticProvider."
            ) from _ANTHROPIC_IMPORT_ERROR
        if self._api_key is None:
            raise SemanticProviderError(
                "ANTHROPIC_API_KEY is not set and no api_key was provided"
            )
        if self._client is None:
            kwargs: dict[str, Any] = {
                "api_key": self._api_key,
                "timeout": self._timeout_seconds,
                "max_retries": self._max_retries,
            }
            if self._base_url is not None:
                kwargs["base_url"] = self._base_url
            self._client = Anthropic(**kwargs)
        return self._client

    def _extract_tool_input(self, response: object) -> dict[str, Any] | None:
        content = getattr(response, "content", None) or []
        for block in content:
            if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == self._tool_name:
                raw = getattr(block, "input", None)
                if isinstance(raw, dict):
                    return raw
                if hasattr(raw, "model_dump"):
                    dumped = raw.model_dump()
                    if isinstance(dumped, dict):
                        return dumped
        return None

    @staticmethod
    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_optional(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @classmethod
    def _normalize_required(cls, value: str, *, field_name: str) -> str:
        normalized = cls._normalize_optional(value)
        if normalized is None:
            raise ValueError(f"{field_name} must be a non-empty string")
        return normalized

    @staticmethod
    def _validate_timeout(value: float) -> float:
        if value <= 0:
            raise ValueError("timeout_seconds must be greater than 0")
        return float(value)

    @staticmethod
    def _validate_max_retries(value: int) -> int:
        if value < 0:
            raise ValueError("max_retries must be >= 0")
        return int(value)

    @staticmethod
    def _validate_max_tokens(value: int) -> int:
        if value <= 0:
            raise ValueError("max_tokens must be greater than 0")
        return int(value)
