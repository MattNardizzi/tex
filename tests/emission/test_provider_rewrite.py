"""Tests for Approach B — provider request rewriting (provider-trusted)."""

from __future__ import annotations

import json

from tex.domain.agent import CapabilitySurface
from tex.emission.constraint import compile_constraint
from tex.emission.provider_rewrite import (
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENAI,
    detect_provider,
    rewrite_provider_request,
)


def _openai_body() -> dict:
    return {
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {"type": "function", "function": {"name": "send_email", "parameters": {"type": "object", "properties": {"to": {"type": "string"}}}}},
            {"type": "function", "function": {"name": "transfer_funds", "parameters": {"type": "object"}}},
        ],
        "tool_choice": "auto",
    }


def _anthropic_body() -> dict:
    return {
        "model": "claude-x",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            {"name": "send_email", "input_schema": {"type": "object", "properties": {"to": {"type": "string"}}}},
            {"name": "transfer_funds", "input_schema": {"type": "object"}},
        ],
        "tool_choice": {"type": "auto"},
    }


def _names_in(body: dict) -> str:
    """All text the provider could use to permit a call — for un-representability."""
    return json.dumps(body)


# --------------------------------------------------------------------------- #
# The core security property: a forbidden tool name is un-representable        #
# --------------------------------------------------------------------------- #


def test_openai_forbidden_tool_unrepresentable() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _openai_body()
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)

    names = [t["function"]["name"] for t in out["tools"]]
    assert names == ["send_email"]
    assert "transfer_funds" not in _names_in(out)
    # Input body is never mutated (pure).
    assert any(t["function"]["name"] == "transfer_funds" for t in body["tools"])


def test_openai_tool_choice_naming_forbidden_tool_fails_closed() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _openai_body()
    body["tool_choice"] = {"type": "function", "function": {"name": "transfer_funds"}}
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)
    # The forbidden specific choice is downgraded to "no tool", never honored.
    assert out["tool_choice"] == "none"
    assert "transfer_funds" not in _names_in(out)


def test_openai_all_tools_forbidden_collapses_to_none() -> None:
    surface = CapabilitySurface(allowed_tools=["only_this_one"])
    constraint = compile_constraint(surface)
    body = _openai_body()  # neither requested tool is allowed
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)
    assert out.get("tools", []) == []
    assert out["tool_choice"] == "none"


def test_anthropic_forbidden_tool_unrepresentable() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _anthropic_body()
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_ANTHROPIC)
    names = [t["name"] for t in out["tools"]]
    assert names == ["send_email"]
    assert "transfer_funds" not in _names_in(out)


def test_anthropic_forced_forbidden_tool_fails_closed() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _anthropic_body()
    body["tool_choice"] = {"type": "tool", "name": "transfer_funds"}
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_ANTHROPIC)
    assert out["tool_choice"] == {"type": "none"}
    assert "transfer_funds" not in _names_in(out)


# --------------------------------------------------------------------------- #
# The argument-shape constraint                                               #
# --------------------------------------------------------------------------- #


def test_openai_argument_shape_constraint_injects_pattern_default_not_strict() -> None:
    surface = CapabilitySurface(
        allowed_tools=["send_email"],
        allowed_recipient_domains=["corp.example.com"],
    )
    constraint = compile_constraint(
        surface, tool_value_fields={"send_email": {"to": "recipient"}}
    )
    out = rewrite_provider_request(_openai_body(), constraint, provider=PROVIDER_OPENAI)
    fn = out["tools"][0]["function"]
    # The recipient pattern is injected; the original type survives the merge.
    to_schema = fn["parameters"]["properties"]["to"]
    assert to_schema["type"] == "string"
    assert to_schema["pattern"] == constraint.value_regexes["recipient"]
    # Default does NOT force strict — that subset can break valid requests and may
    # not honor `pattern`. Honest: value enforcement is provider-dependent.
    assert "strict" not in fn


def test_openai_strict_structured_output_is_opt_in() -> None:
    surface = CapabilitySurface(
        allowed_tools=["send_email"],
        allowed_recipient_domains=["corp.example.com"],
    )
    constraint = compile_constraint(
        surface, tool_value_fields={"send_email": {"to": "recipient"}}
    )
    out = rewrite_provider_request(
        _openai_body(),
        constraint,
        provider=PROVIDER_OPENAI,
        strict_structured_output=True,
    )
    fn = out["tools"][0]["function"]
    assert fn["strict"] is True
    assert fn["parameters"]["additionalProperties"] is False


def test_anthropic_argument_shape_constraint_tightens_input_schema() -> None:
    surface = CapabilitySurface(
        allowed_tools=["send_email"],
        allowed_recipient_domains=["corp.example.com"],
    )
    constraint = compile_constraint(
        surface, tool_value_fields={"send_email": {"to": "recipient"}}
    )
    out = rewrite_provider_request(_anthropic_body(), constraint, provider=PROVIDER_ANTHROPIC)
    to_schema = out["tools"][0]["input_schema"]["properties"]["to"]
    assert to_schema["pattern"] == constraint.value_regexes["recipient"]


# --------------------------------------------------------------------------- #
# Honesty / passthrough                                                       #
# --------------------------------------------------------------------------- #


def test_unrestricted_surface_leaves_tools_intact() -> None:
    # No tool restriction declared -> the gate invents none.
    constraint = compile_constraint(CapabilitySurface())
    out = rewrite_provider_request(_openai_body(), constraint, provider=PROVIDER_OPENAI)
    names = sorted(t["function"]["name"] for t in out["tools"])
    assert names == ["send_email", "transfer_funds"]


def test_forbidden_name_strip_is_case_insensitive() -> None:
    # An attacker re-casing the name must not slip a forbidden tool back in.
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _openai_body()
    body["tools"].append(
        {"type": "function", "function": {"name": "Transfer_Funds", "parameters": {}}}
    )
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)
    names = [t["function"]["name"].casefold() for t in out["tools"]]
    assert names == ["send_email"]


def test_message_history_is_not_scrubbed() -> None:
    # Honesty: the rewrite constrains the NEXT emission's menu/choice, not the
    # historical transcript. A prior tool call recorded in messages is a fact,
    # not a new emission — locking this so the scope claim stays true.
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = _openai_body()
    body["messages"].append(
        {"role": "assistant", "tool_calls": [{"function": {"name": "transfer_funds"}}]}
    )
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)
    # History preserved; the tools MENU no longer offers transfer_funds.
    assert out["messages"][-1]["tool_calls"][0]["function"]["name"] == "transfer_funds"
    assert [t["function"]["name"] for t in out["tools"]] == ["send_email"]


def test_detect_provider() -> None:
    assert detect_provider(_openai_body()) == PROVIDER_OPENAI
    assert detect_provider(_anthropic_body()) == PROVIDER_ANTHROPIC
    assert detect_provider({"messages": []}) is None


def test_unknown_provider_returns_unchanged_copy() -> None:
    constraint = compile_constraint(CapabilitySurface(allowed_tools=["x"]))
    body = {"messages": [], "something": 1}
    out = rewrite_provider_request(body, constraint)
    assert out == body
    assert out is not body  # a copy, never the original


# --------------------------------------------------------------------------- #
# Fail-open regression: a forced tool_choice with NO tools array must still     #
# be narrowed (the bypass the merge review found).                             #
# --------------------------------------------------------------------------- #


def test_openai_forced_tool_choice_without_tools_array_is_blocked() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    # No `tools` array at all — only a forced choice naming a forbidden tool.
    body = {
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "function", "function": {"name": "transfer_funds"}},
    }
    assert detect_provider(body) == PROVIDER_OPENAI
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_OPENAI)
    assert out["tool_choice"] == "none"  # fail-closed, not passed through
    assert "transfer_funds" not in _names_in(out)


def test_anthropic_forced_tool_choice_without_tools_array_is_blocked() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    constraint = compile_constraint(surface)
    body = {
        "model": "claude-x",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "tool", "name": "transfer_funds"},
    }
    assert detect_provider(body) == PROVIDER_ANTHROPIC
    out = rewrite_provider_request(body, constraint, provider=PROVIDER_ANTHROPIC)
    assert out["tool_choice"] == {"type": "none"}
    assert "transfer_funds" not in _names_in(out)
