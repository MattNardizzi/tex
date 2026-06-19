"""June-2026 SOTA provider upgrade — semantic JUDGE.

Covers the Anthropic structured provider (Opus 4.8), the OpenAI default bump
(gpt-5.5), and the provider-neutral config wiring. The SDKs are optional and not
installed in CI, so the live transport is exercised with injected fakes; the
deterministic fallback and the grounding boundary are unchanged and unaffected.
"""

from __future__ import annotations

import pytest

from tex.domain.verdict import Verdict
from tex.semantic.analyzer import SemanticProviderError
from tex.semantic.schema import (
    SemanticAnalysisParseTarget,
    SemanticDimensionResult,
    SemanticVerdictRecommendation,
)


def _valid_parse_target() -> SemanticAnalysisParseTarget:
    dims = tuple(
        SemanticDimensionResult(
            dimension=d, score=0.1, confidence=0.9, summary="clear"
        )
        for d in (
            "policy_compliance",
            "data_leakage",
            "external_sharing",
            "unauthorized_commitment",
            "destructive_or_bypass",
        )
    )
    return SemanticAnalysisParseTarget(
        dimension_results=dims,
        recommended_verdict=SemanticVerdictRecommendation(
            verdict=Verdict.PERMIT, confidence=0.9, summary="permit"
        ),
        overall_confidence=0.9,
        evidence_sufficiency=0.8,
        rationale_quality=0.8,
        summary="all dimensions low risk",
        uncertainty_flags=(),
    )


class _FakeUsage:
    def model_dump(self):
        return {"input_tokens": 12, "output_tokens": 7}


class _FakeResp:
    def __init__(self, parsed, stop_reason="end_turn"):
        self.parsed_output = parsed
        self.stop_reason = stop_reason
        self.id = "msg_test"
        self.usage = _FakeUsage()


class _FakeMessages:
    def __init__(self, resp):
        self._resp = resp
        self.calls: list[dict] = []

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        return self._resp


class _FakeAnthropic:
    def __init__(self, resp):
        self.messages = _FakeMessages(resp)


# --------------------------------------------------------------------------- Anthropic judge


def _provider_with_fake(monkeypatch, resp):
    import tex.semantic.anthropic as mod

    # Make the SDK look present so _get_client doesn't short-circuit on import,
    # then inject the fake transport.
    monkeypatch.setattr(mod, "Anthropic", object, raising=False)
    prov = mod.AnthropicStructuredSemanticProvider(api_key="test-key")
    prov._client = _FakeAnthropic(resp)
    return prov


def test_anthropic_provider_returns_schema_locked_analysis(monkeypatch):
    prov = _provider_with_fake(monkeypatch, _FakeResp(_valid_parse_target()))
    result = prov.analyze(system_prompt="sys", user_prompt="user")

    assert result.provider_name == "anthropic"
    assert result.model_name == "claude-opus-4-8"
    assert result.recommended_verdict.verdict is Verdict.PERMIT
    assert "anthropic" in result.metadata
    assert result.metadata["anthropic"]["sdk_surface"] == "messages.parse"
    # The call was schema-locked to the slim parse target.
    call = prov._client.messages.calls[0]
    assert call["model"] == "claude-opus-4-8"
    assert call["output_format"] is SemanticAnalysisParseTarget


def test_anthropic_refusal_becomes_provider_error_not_permit(monkeypatch):
    # A safety-classifier refusal must NOT silently pass — it must surface as a
    # provider failure so the analyzer drops to the deterministic floor.
    prov = _provider_with_fake(monkeypatch, _FakeResp(None, stop_reason="refusal"))
    with pytest.raises(SemanticProviderError, match="declined"):
        prov.analyze(system_prompt="sys", user_prompt="user")


def test_anthropic_no_parsed_output_is_error(monkeypatch):
    prov = _provider_with_fake(monkeypatch, _FakeResp(None, stop_reason="end_turn"))
    with pytest.raises(SemanticProviderError, match="no parsed"):
        prov.analyze(system_prompt="sys", user_prompt="user")


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

    assert mod.AnthropicStructuredSemanticProvider().model_name == "claude-opus-4-8"
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
    assert provider.model_name == "claude-opus-4-8"
