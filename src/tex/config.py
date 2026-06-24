from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SemanticProviderName = Literal["openai", "anthropic"]
SemanticReasoningEffort = Literal[
    "minimal",
    "low",
    "medium",
    "high",
    "none",
    "xhigh",
]

# TEE attestation operating mode. ``production`` means the attestation
# composer refuses dev-stub evidence and requires real Intel TDX quotes and
# NVIDIA H100/H200/B200/B300 attestation reports (Intel Trust Authority
# ``get_token_v2`` composite token, draft-ietf-rats-eat / Veraison EAR
# profile, April 2026 SDK). ``test`` is for local development only.
TeeAttestationMode = Literal["production", "test"]

# Non-production ``TEX_APP_ENV`` values. Anything outside this set is
# treated as production-like and the startup guard enforces hardened
# secrets and a non-``test`` TEE attestation mode.
_NON_PRODUCTION_APP_ENVS: frozenset[str] = frozenset(
    {"dev", "development", "test", "testing", "local"}
)


def is_production_env() -> bool:
    """True when ``TEX_APP_ENV`` names a production-like environment.

    The single, Settings-free source of truth for "are we in production?", so
    runtime seams (e.g. discovery connector building) can refuse synthetic data
    in production without constructing the full Settings object.
    """
    import os

    return (
        os.environ.get("TEX_APP_ENV", "development").strip().lower()
        not in _NON_PRODUCTION_APP_ENVS
    )


# Sentinel HMAC secret shipped in the repo. Real deployments MUST
# override ``TEX_EVIDENCE_SUMMARY_SECRET`` with a high-entropy value
# (>= 32 bytes from a CSPRNG). The startup guard refuses to boot when
# this default is still in place outside non-production environments.
_DEFAULT_EVIDENCE_SUMMARY_SECRET: str = "dev-only-change-me"


class Settings(BaseSettings):
    """
    Central runtime configuration for Tex.

    This keeps configuration explicit, typed, and environment-driven without
    leaking env lookups across the codebase.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    app_name: str = Field(default="tex", alias="TEX_APP_NAME")
    app_env: str = Field(default="development", alias="TEX_APP_ENV")
    debug: bool = Field(default=False, alias="TEX_DEBUG")

    host: str = Field(default="127.0.0.1", alias="TEX_HOST")
    port: int = Field(default=8000, alias="TEX_PORT")

    evidence_path: Path = Field(
        default=Path("data/evidence/evidence.jsonl"),
        alias="TEX_EVIDENCE_PATH",
    )

    semantic_provider: SemanticProviderName | None = Field(
        default=None,
        alias="TEX_SEMANTIC_PROVIDER",
    )
    allow_semantic_fallback: bool = Field(
        default=True,
        alias="TEX_ALLOW_SEMANTIC_FALLBACK",
    )
    # Provider-neutral: ``None`` means "use the configured provider's own
    # recommended June-2026 default" (OpenAI → ``gpt-5.5``; Anthropic →
    # ``claude-opus-4-8``). Set TEX_SEMANTIC_MODEL only to pin a specific model
    # (e.g. ``claude-fable-5`` once/if it is re-enabled, or ``gpt-5.5-pro``).
    semantic_model: str | None = Field(
        default=None,
        alias="TEX_SEMANTIC_MODEL",
    )
    semantic_timeout_seconds: float = Field(
        default=30.0,
        alias="TEX_SEMANTIC_TIMEOUT_SECONDS",
    )
    semantic_max_retries: int = Field(
        default=2,
        alias="TEX_SEMANTIC_MAX_RETRIES",
    )
    semantic_reasoning_effort: SemanticReasoningEffort = Field(
        default="minimal",
        alias="TEX_SEMANTIC_REASONING_EFFORT",
    )

    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_base_url: str | None = Field(default=None, alias="OPENAI_BASE_URL")
    openai_org_id: str | None = Field(default=None, alias="OPENAI_ORG_ID")
    openai_project_id: str | None = Field(default=None, alias="OPENAI_PROJECT_ID")

    # Anthropic transport for the semantic judge / vigil explainer when
    # TEX_SEMANTIC_PROVIDER='anthropic'. The judge is a lowering-only signal,
    # never the speaking seat (see voice/voice_ask.py), so binding a model here
    # cannot move a verdict toward release.
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_base_url: str | None = Field(default=None, alias="ANTHROPIC_BASE_URL")

    # ---- Production secrets / fail-closed guards -----------------------
    #
    # ``evidence_summary_secret`` is the HMAC-SHA-256 key used to sign
    # governance evidence-bundle manifests and agent evidence summaries.
    # Held as ``SecretStr`` so it never appears in ``repr()`` output,
    # exception tracebacks, or structured logs. The startup guard refuses
    # to boot in production-like environments when this remains the
    # in-repo sentinel value.
    evidence_summary_secret: SecretStr | None = Field(
        default=None,
        alias="TEX_EVIDENCE_SUMMARY_SECRET",
    )
    # ``tee_attestation_mode`` selects between hardware-attested operation
    # (production: requires real Intel TDX + NVIDIA H100/H200/B200/B300
    # attestation via the Intel Trust Authority ``get_token_v2`` composite
    # token) and a local-dev stub. The startup guard forbids ``test``
    # outside non-production environments.
    tee_attestation_mode: TeeAttestationMode = Field(
        default="production",
        alias="TEX_TEE_ATTESTATION_MODE",
    )

    @field_validator(
        "app_name",
        "app_env",
        "host",
        "semantic_model",
        "openai_api_key",
        "openai_base_url",
        "openai_org_id",
        "openai_project_id",
        "anthropic_api_key",
        "anthropic_base_url",
        mode="before",
    )
    @classmethod
    def _strip_optional_strings(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        return normalized or None

    @field_validator("semantic_provider", mode="before")
    @classmethod
    def _normalize_semantic_provider(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("TEX_SEMANTIC_PROVIDER must be a string when supplied")
        normalized = value.strip().lower()
        return normalized or None

    @field_validator("tee_attestation_mode", mode="before")
    @classmethod
    def _normalize_tee_attestation_mode(cls, value: object) -> object:
        # Accept ``Production``/``PRODUCTION``/``  test  `` etc. by
        # trimming and lowercasing. Empty values fall back to the
        # ``production`` default rather than failing closed at parse
        # time — the model_validator below is the policy gate.
        if value is None:
            return "production"
        if not isinstance(value, str):
            raise TypeError(
                "TEX_TEE_ATTESTATION_MODE must be a string when supplied"
            )
        normalized = value.strip().lower()
        return normalized or "production"

    @field_validator("semantic_timeout_seconds")
    @classmethod
    def _validate_semantic_timeout_seconds(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("TEX_SEMANTIC_TIMEOUT_SECONDS must be greater than 0")
        return value

    @field_validator("semantic_max_retries")
    @classmethod
    def _validate_semantic_max_retries(cls, value: int) -> int:
        if value < 0:
            raise ValueError("TEX_SEMANTIC_MAX_RETRIES must be >= 0")
        return value

    @field_validator("port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        if value <= 0 or value > 65535:
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("evidence_path", mode="before")
    @classmethod
    def _coerce_evidence_path(cls, value: object) -> object:
        if isinstance(value, Path):
            return value
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                raise ValueError("TEX_EVIDENCE_PATH cannot be blank")
            return Path(normalized)
        return value

    @property
    def semantic_provider_enabled(self) -> bool:
        return self.semantic_provider is not None

    @property
    def is_production_like(self) -> bool:
        """
        Return ``True`` when ``TEX_APP_ENV`` names a production-like
        environment (anything outside the explicit dev/test allow-list).

        Production-like environments must satisfy the fail-closed guards
        in :meth:`_validate_production_secrets`.
        """
        return self.app_env.strip().lower() not in _NON_PRODUCTION_APP_ENVS

    def get_evidence_summary_secret(self) -> str | None:
        """
        Return the raw HMAC secret string for the small set of call
        sites that need it (e.g. evidence-summary signing in
        ``tex.api.agent_routes`` and the governance snapshot store).

        Returns ``None`` when no secret has been configured. Callers
        outside non-production environments should never reach this
        ``None`` branch because :meth:`_validate_production_secrets`
        refuses to boot when the secret is missing or still the
        in-repo sentinel value.
        """
        if self.evidence_summary_secret is None:
            return None
        return self.evidence_summary_secret.get_secret_value()

    @model_validator(mode="after")
    def _validate_production_secrets(self) -> "Settings":
        """
        Fail-closed guard. Refuses to construct a Settings instance when
        the app is running in a production-like environment with unsafe
        defaults still in place.

        Two distinct guards are enforced here, both intentionally
        explicit so that operators get a clear remediation message
        instead of an opaque downstream signing failure or a stub-mode
        TEE quote silently flowing into an evidence bundle:

        1. ``TEX_EVIDENCE_SUMMARY_SECRET`` must be set to a real,
           non-sentinel value. The in-repo default
           (``dev-only-change-me``) and the empty string are rejected.
           The HMAC key signs every evidence-bundle manifest emitted
           under ``/v1/agents/governance/snapshots/...`` and every
           agent evidence summary — a weak key here breaks the
           cryptographic substrate that downstream regulator / insurer
           / auditor verifications rely on.

        2. ``TEX_TEE_ATTESTATION_MODE`` must not be ``test``. The TEE
           attestation composer (``tex.tee.attestation_client``,
           ``tex.evidence.tee_binding``) only emits real Intel TDX +
           NVIDIA H100/H200/B200/B300 evidence in ``production`` mode;
           the ``test`` mode is for local development only and is
           never an acceptable production posture.

        These checks intentionally do not run in dev / development /
        test / testing / local environments so that contributor
        ergonomics are unchanged.
        """
        if not self.is_production_like:
            return self

        secret_obj = self.evidence_summary_secret
        secret_value = (
            secret_obj.get_secret_value() if secret_obj is not None else None
        )
        if not secret_value or secret_value == _DEFAULT_EVIDENCE_SUMMARY_SECRET:
            raise ValueError(
                "TEX_EVIDENCE_SUMMARY_SECRET must be set to a real, "
                "non-default value when TEX_APP_ENV is "
                f"'{self.app_env}'. Generate a 32-byte secret "
                "(e.g. `python -c 'import secrets; "
                "print(secrets.token_urlsafe(32))'`) and set it in "
                "the deployment environment. The in-repo "
                "'dev-only-change-me' sentinel signs nothing of value "
                "and must never reach a production-like deployment."
            )

        if self.tee_attestation_mode == "test":
            raise ValueError(
                "TEX_TEE_ATTESTATION_MODE='test' is forbidden when "
                f"TEX_APP_ENV is '{self.app_env}'. The TEE attestation "
                "composer only emits real Intel TDX + NVIDIA H100/"
                "H200/B200/B300 evidence in 'production' mode "
                "(Intel Trust Authority get_token_v2 composite token). "
                "Set TEX_TEE_ATTESTATION_MODE=production or set "
                "TEX_APP_ENV to one of "
                f"{sorted(_NON_PRODUCTION_APP_ENVS)} for local "
                "development."
            )

        return self

    def validate_semantic_provider_configuration(self) -> None:
        """
        Fail loudly on bad semantic-provider wiring instead of silently
        degrading to heuristic fallback when the operator explicitly asked for
        a provider.
        """
        if self.semantic_provider is None:
            return

        if self.semantic_provider == "openai" and not self.openai_api_key:
            raise ValueError(
                "TEX_SEMANTIC_PROVIDER is set to 'openai' but OPENAI_API_KEY is missing."
            )

        if self.semantic_provider == "anthropic" and not self.anthropic_api_key:
            raise ValueError(
                "TEX_SEMANTIC_PROVIDER is set to 'anthropic' but ANTHROPIC_API_KEY is missing."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_semantic_provider_configuration()
    return settings