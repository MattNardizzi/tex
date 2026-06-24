"""June-2026 SOTA provider upgrade — semantic JUDGE.

Covers the provider-neutral config wiring that activates the Anthropic
structured provider (Opus 4.8) alongside OpenAI's default bump (gpt-5.5).

NOTE on the adopted Anthropic surface: V1 keeps the forced-TOOL structured
provider (``messages.create`` + ``tool_use``) that the presence brain depends
on (main.py / presence/brain). Its analyze() behaviour — schema-locked output,
refusal→provider-error, no-tool-block→error — is exercised in
``tests/semantic/test_anthropic_provider.py``. This file therefore tests only
the *wiring* the jun2026-sota pass added: the provider literal, the fail-closed
config validation, the provider-neutral model default, and the analyzer factory
dispatch. (The branch's alternate ``messages.parse``/``output_format`` surface
was intentionally not adopted, so its surface-specific tests are dropped.)
"""

from __future__ import annotations

import pytest

from tex.semantic.analyzer import SemanticProviderError  # noqa: F401 — re-exported contract


# --------------------------------------------------------------------------- Anthropic judge (honest-error + default model)


def test_anthropic_missing_sdk_is_honest_error(monkeypatch):
    # Default state: the anthropic SDK is not installed, so Anthropic is None.
    import tex.semantic.anthropic as mod

    if mod.Anthropic is not None:  # pragma: no cover - only if SDK is installed
        monkeypatch.setattr(mod, "Anthropic", None, raising=False)
    prov = mod.AnthropicStructuredSemanticProvider(api_key="test-key")
    with pytest.raises(SemanticProviderError, match="not installed"):
        prov.analyze(system_prompt="sys", user_prompt="user")


def test_anthropic_missing_key_is_honest_error(monkeypatch):
    import tex.semantic.anthropic as mod

    monkeypatch.setattr(mod, "Anthropic", object, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    prov = mod.AnthropicStructuredSemanticProvider(api_key=None)
    with pytest.raises(SemanticProviderError, match="ANTHROPIC_API_KEY"):
        prov.analyze(system_prompt="sys", user_prompt="user")


def test_anthropic_default_and_override_model():
    import tex.semantic.anthropic as mod

    # model=None (the provider-neutral config default) resolves to Opus 4.8.
    assert mod.AnthropicStructuredSemanticProvider().model_name == "claude-opus-4-8"
    assert (
        mod.AnthropicStructuredSemanticProvider(model=None).model_name
        == "claude-opus-4-8"
    )
    assert (
        mod.AnthropicStructuredSemanticProvider(model="claude-fable-5").model_name
        == "claude-fable-5"
    )


# --------------------------------------------------------------------------- OpenAI default bump


def test_openai_default_model_is_gpt_5_5():
    from tex.semantic.openai import OpenAIStructuredSemanticProvider

    # model=None must resolve to the June-2026 SOTA default, not the old mini.
    assert OpenAIStructuredSemanticProvider().model_name == "gpt-5.5"
    assert (
        OpenAIStructuredSemanticProvider(model="gpt-5.5-pro").model_name
        == "gpt-5.5-pro"
    )


# --------------------------------------------------------------------------- config wiring


def test_config_accepts_anthropic_provider_and_fails_closed_without_key():
    from tex.config import Settings

    s = Settings(_env_file=None, TEX_SEMANTIC_PROVIDER="anthropic")
    assert s.semantic_provider == "anthropic"
    assert s.semantic_model is None  # provider-neutral default
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        s.validate_semantic_provider_configuration()

    ok = Settings(
        _env_file=None,
        TEX_SEMANTIC_PROVIDER="anthropic",
        ANTHROPIC_API_KEY="k",
    )
    ok.validate_semantic_provider_configuration()  # no raise


def test_factory_builds_anthropic_provider(monkeypatch):
    import tex.semantic.analyzer as analyzer
    from tex.config import Settings

    fake_settings = Settings(
        _env_file=None, TEX_SEMANTIC_PROVIDER="anthropic", ANTHROPIC_API_KEY="k"
    )
    monkeypatch.setattr(analyzer, "get_settings", lambda: fake_settings)
    provider = analyzer._build_semantic_provider_from_settings()
    from tex.semantic.anthropic import AnthropicStructuredSemanticProvider

    assert isinstance(provider, AnthropicStructuredSemanticProvider)
    # The provider-neutral None model resolves to the Anthropic default.
    assert provider.model_name == "claude-opus-4-8"
