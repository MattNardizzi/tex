from __future__ import annotations

import hashlib
import os
import time
from typing import Any
from typing import Final

from tex.semantic.analyzer import SemanticProviderError
from tex.semantic.schema import SemanticAnalysis, SemanticAnalysisParseTarget

try:
    import anthropic
    from anthropic import Anthropic
    from anthropic import APIConnectionError
    from anthropic import APITimeoutError
    from anthropic import BadRequestError
    from anthropic import RateLimitError
except ImportError as exc:  # pragma: no cover - import guard for environments without SDK
    anthropic = None  # type: ignore[assignment]
    Anthropic = None  # type: ignore[assignment]
    APIConnectionError = Exception  # type: ignore[assignment]
    APITimeoutError = Exception  # type: ignore[assignment]
    BadRequestError = Exception  # type: ignore[assignment]
    RateLimitError = Exception  # type: ignore[assignment]
    _ANTHROPIC_IMPORT_ERROR = exc
else:
    _ANTHROPIC_IMPORT_ERROR = None


# June-2026 SOTA default for the governance judge. Claude Opus 4.8
# (``claude-opus-4-8``) is Anthropic's most capable *available* model — Claude
# Fable 5 (`claude-fable-5`) was the launch-day top model but was disabled
# globally on 2026-06-12 by a US export-control directive, so Opus 4.8 is the
# correct default. To pin Fable 5 if/when it returns: TEX_SEMANTIC_MODEL=claude-fable-5.
_DEFAULT_MODEL: Final[str] = "claude-opus-4-8"
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
_DEFAULT_MAX_RETRIES: Final[int] = 2
# The slim parse target is bounded (per-dimension results + a <=2000-char
# summary), so a modest cap is ample. Opus 4.8 runs without extended thinking
# unless asked, so these are answer tokens only.
_DEFAULT_MAX_TOKENS: Final[int] = 4096


class AnthropicStructuredSemanticProvider:
    """
    Structured semantic provider for Tex over Anthropic's Messages API.

    Design goals mirror :class:`tex.semantic.openai.OpenAIStructuredSemanticProvider`
    exactly so the two providers are drop-in interchangeable behind
    ``TEX_SEMANTIC_PROVIDER``:
    - strict schema-bound output into SemanticAnalysis (via ``messages.parse``,
      which generates the JSON schema from ``SemanticAnalysisParseTarget`` and
      validates the result client-side against the pydantic model)
    - explicit failure surfaces for timeout/rate-limit/refusal/parse issues — a
      refusal or transport error becomes a ``SemanticProviderError`` so the
      analyzer falls back to its deterministic floor (the judge is a lowering-only
      signal; it must never fail open)
    - rich runtime metadata for audit and semantic evals
    - no prompt construction here; Tex already owns that boundary

    Synchronous to match Tex's existing ``StructuredSemanticProvider`` protocol.
    """

    __slots__ = (
        "_api_key",
        "_base_url",
        "_model",
        "_timeout_seconds",
        "_max_retries",
        "_max_tokens",
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
    ) -> None:
        self._api_key = self._normalize_optional_string(api_key) or os.getenv(
            "ANTHROPIC_API_KEY"
        )
        self._base_url = self._normalize_optional_string(base_url) or os.getenv(
            "ANTHROPIC_BASE_URL"
        )
        self._model = self._normalize_required_string(
            model or _DEFAULT_MODEL, field_name="model"
        )
        self._timeout_seconds = self._validate_timeout_seconds(timeout_seconds)
        self._max_retries = self._validate_max_retries(max_retries)
        self._max_tokens = self._validate_max_tokens(max_tokens)
        self._client: Anthropic | None = None

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
    ) -> SemanticAnalysis:
        """
        Executes one schema-locked semantic evaluation call.

        Returns:
            SemanticAnalysis

        Raises:
            SemanticProviderError: on transport, refusal, or schema/parse failure.
        """
        instructions = self._normalize_required_string(
            system_prompt,
            field_name="system_prompt",
        )
        request_prompt = self._normalize_required_string(
            user_prompt,
            field_name="user_prompt",
        )

        client = self._get_client()
        started_at = time.perf_counter()

        try:
            response = client.messages.parse(
                model=self._model,
                max_tokens=self._max_tokens,
                system=instructions,
                messages=[{"role": "user", "content": request_prompt}],
                output_format=SemanticAnalysisParseTarget,
                timeout=self._timeout_seconds,
            )
        except APITimeoutError as exc:
            raise SemanticProviderError(
                f"Anthropic semantic request timed out after {self._timeout_seconds:.1f}s"
            ) from exc
        except RateLimitError as exc:
            raise SemanticProviderError(
                "Anthropic semantic request was rate-limited"
            ) from exc
        except APIConnectionError as exc:
            raise SemanticProviderError(
                "Anthropic semantic request failed due to connection error"
            ) from exc
        except BadRequestError as exc:
            raise SemanticProviderError(
                f"Anthropic semantic request was rejected: {exc}"
            ) from exc
        except Exception as exc:
            raise SemanticProviderError(
                f"unexpected Anthropic semantic provider failure: {type(exc).__name__}: {exc}"
            ) from exc

        elapsed_ms = round((time.perf_counter() - started_at) * 1000.0, 3)

        # Safety classifiers (or a model refusal) surface as a 200 with
        # stop_reason == "refusal" and no parsed output. Treat it as a provider
        # failure so the analyzer drops to its deterministic floor — never as a
        # silent PERMIT.
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            raise SemanticProviderError(
                "Anthropic semantic provider declined the request (stop_reason=refusal)"
            )

        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            if stop_reason == "max_tokens":
                raise SemanticProviderError(
                    "Anthropic semantic provider hit max_tokens before producing "
                    "a parsed SemanticAnalysisParseTarget"
                )
            raise SemanticProviderError(
                "Anthropic semantic provider returned no parsed "
                f"SemanticAnalysisParseTarget (stop_reason={stop_reason!r})"
            )

        if not isinstance(parsed, SemanticAnalysisParseTarget):
            try:
                parsed = SemanticAnalysisParseTarget.model_validate(parsed)
            except Exception as exc:
                raise SemanticProviderError(
                    "Anthropic semantic provider returned a parsed object that "
                    "failed SemanticAnalysisParseTarget validation"
                ) from exc

        usage = getattr(response, "usage", None)

        anthropic_metadata = {
            "provider": "anthropic",
            "sdk_surface": "messages.parse",
            "response_id": getattr(response, "id", None)
            or getattr(response, "_request_id", None),
            "latency_ms": elapsed_ms,
            "stop_reason": stop_reason,
            "max_tokens": self._max_tokens,
            "timeout_seconds": self._timeout_seconds,
            "prompt_fingerprints": {
                "system_prompt_sha256": self._sha256_hex(instructions),
                "user_prompt_sha256": self._sha256_hex(request_prompt),
            },
            "usage": self._serialize_usage(usage),
        }

        return parsed.to_full_analysis(
            provider_name=self.provider_name,
            model_name=self._model,
            metadata={"anthropic": anthropic_metadata},
        )

    def _get_client(self) -> Anthropic:
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

    @staticmethod
    def _serialize_usage(usage: object) -> dict[str, Any] | None:
        if usage is None:
            return None

        if hasattr(usage, "model_dump"):
            try:
                dumped = usage.model_dump()
                if isinstance(dumped, dict):
                    return dumped
            except Exception:
                pass

        if isinstance(usage, dict):
            return usage

        result: dict[str, Any] = {}
        for field_name in (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        ):
            value = getattr(usage, field_name, None)
            if value is not None:
                result[field_name] = value

        return result or None

    @staticmethod
    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_optional_string(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @classmethod
    def _normalize_required_string(cls, value: str, *, field_name: str) -> str:
        normalized = cls._normalize_optional_string(value)
        if normalized is None:
            raise ValueError(f"{field_name} must be a non-empty string")
        return normalized

    @staticmethod
    def _validate_timeout_seconds(value: float) -> float:
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
