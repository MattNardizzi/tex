"""AnthropicStructuredSemanticProvider: forced-tool structured output, refusal
handling, no sampling params, and clean failures — all without the SDK installed."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import tex.semantic.anthropic as anthropic_mod
from tex.semantic.analyzer import SemanticProviderError, StructuredSemanticProvider
from tex.semantic.anthropic import AnthropicStructuredSemanticProvider


def _provider(**kw):
    kw.setdefault("api_key", "test-key")
    return AnthropicStructuredSemanticProvider(**kw)


def _fake_client(response, *, capture: dict | None = None):
    def create(**kwargs):
        if capture is not None:
            capture.update(kwargs)
        return response
    return SimpleNamespace(messages=SimpleNamespace(create=create))


def _tool_use_response(tool_name, payload, *, stop_reason="tool_use"):
    block = SimpleNamespace(type="tool_use", name=tool_name, input=payload)
    return SimpleNamespace(stop_reason=stop_reason, content=[block], stop_details=None)


def test_conforms_to_structured_semantic_provider_protocol():
    assert isinstance(_provider(), StructuredSemanticProvider)


def test_default_model_is_opus_4_8():
    assert _provider().model_name == "claude-opus-4-8"
    assert _provider().provider_name == "anthropic"


def test_analyze_returns_tool_input_dict(monkeypatch):
    monkeypatch.setattr(anthropic_mod, "Anthropic", object)  # non-None sentinel
    prov = _provider()
    capture: dict = {}
    prov._client = _fake_client(
        _tool_use_response("emit_structured_analysis", {"draft": "hi", "claims": []}),
        capture=capture,
    )
    out = prov.analyze(system_prompt="sys", user_prompt="usr")
    assert out == {"draft": "hi", "claims": []}
    # Forced tool use; NO sampling params (removed on Opus 4.8 — would 400).
    assert capture["tool_choice"] == {"type": "tool", "name": "emit_structured_analysis"}
    assert "temperature" not in capture
    assert "top_p" not in capture
    assert "top_k" not in capture


def test_refusal_raises_semantic_provider_error(monkeypatch):
    monkeypatch.setattr(anthropic_mod, "Anthropic", object)
    prov = _provider()
    prov._client = _fake_client(
        SimpleNamespace(stop_reason="refusal", content=[], stop_details=SimpleNamespace(category="cyber"))
    )
    with pytest.raises(SemanticProviderError, match="refused"):
        prov.analyze(system_prompt="sys", user_prompt="usr")


def test_missing_tool_use_block_raises(monkeypatch):
    monkeypatch.setattr(anthropic_mod, "Anthropic", object)
    prov = _provider()
    text_block = SimpleNamespace(type="text", text="no tool here")
    prov._client = _fake_client(SimpleNamespace(stop_reason="end_turn", content=[text_block], stop_details=None))
    with pytest.raises(SemanticProviderError, match="no tool_use block"):
        prov.analyze(system_prompt="sys", user_prompt="usr")


def test_missing_sdk_raises_clear_error(monkeypatch):
    monkeypatch.setattr(anthropic_mod, "Anthropic", None)
    with pytest.raises(SemanticProviderError, match="not installed"):
        _provider().analyze(system_prompt="sys", user_prompt="usr")


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.setattr(anthropic_mod, "Anthropic", object)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    prov = AnthropicStructuredSemanticProvider(api_key=None)
    with pytest.raises(SemanticProviderError, match="ANTHROPIC_API_KEY"):
        prov.analyze(system_prompt="sys", user_prompt="usr")


def test_constructor_validates_inputs():
    with pytest.raises(ValueError):
        AnthropicStructuredSemanticProvider(api_key="k", max_tokens=0)
    with pytest.raises(ValueError):
        AnthropicStructuredSemanticProvider(api_key="k", timeout_seconds=0)
    with pytest.raises(ValueError):
        AnthropicStructuredSemanticProvider(api_key="k", model="  ")
