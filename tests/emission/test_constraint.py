"""Tests for the pure ``DecoderConstraint`` builder."""

from __future__ import annotations

import re

import pytest

from tex.domain.agent import CapabilitySurface
from tex.emission.constraint import DecoderConstraint, compile_constraint


def test_allowlist_normalized_sorted_deduped() -> None:
    surface = CapabilitySurface(allowed_tools=["Send_Email", "http_get", "SEND_EMAIL"])
    c = compile_constraint(surface)
    # Casefolded + de-duped (by the surface) and sorted (by the builder).
    assert c.allowed_tool_names == ("http_get", "send_email")
    assert c.constrains_tool_names is True
    assert c.is_tool_allowed("Send_Email") is True
    assert c.is_tool_allowed("transfer_funds") is False


def test_empty_allowlist_is_unrestricted_not_deny_all() -> None:
    # An empty allowed_tools means "no tool restriction declared" (the surface's
    # own semantics) — the gate must NOT invent a deny-all it was not asked for.
    surface = CapabilitySurface()
    c = compile_constraint(surface)
    assert c.constrains_tool_names is False
    assert c.surface_is_unrestricted is True
    assert c.is_tool_allowed("anything_at_all") is True


def test_digest_is_order_independent_and_change_sensitive() -> None:
    a = compile_constraint(CapabilitySurface(allowed_tools=["a", "b", "c"]))
    b = compile_constraint(CapabilitySurface(allowed_tools=["c", "a", "b"]))
    assert a.digest() == b.digest(), "allowlist is a set; order must not change H"

    c = compile_constraint(CapabilitySurface(allowed_tools=["a", "b"]))
    assert c.digest() != a.digest(), "removing a tool must change H"

    # A directly-built constraint with a different field also shifts the digest.
    d = DecoderConstraint(
        allowed_tool_names=("a", "b", "c"),
        constrains_tool_names=True,
        value_regexes={"recipient": "x"},
        constrains_values=True,
    )
    assert d.digest() != a.digest()


def test_recipient_value_regex_matches_surface_semantics() -> None:
    surface = CapabilitySurface(allowed_recipient_domains=["corp.example.com"])
    c = compile_constraint(surface)
    assert c.constrains_values is True
    pattern = c.value_regexes["recipient"]
    rx = re.compile(pattern)
    # Exact domain and sub-domains pass (mirrors permits_recipient).
    assert rx.match("alice@corp.example.com")
    assert rx.match("bob@us.corp.example.com")
    # An out-of-domain recipient does not — it is un-typeable, not just rejected.
    assert not rx.match("mallory@evil.com")
    # And the surface agrees, so the regex is faithful, not stricter/looser.
    assert surface.permits_recipient("alice@corp.example.com") is True
    assert surface.permits_recipient("mallory@evil.com") is False


def test_per_tool_schema_projection_only_for_allowed_tools() -> None:
    surface = CapabilitySurface(
        allowed_tools=["send_email"],
        allowed_recipient_domains=["corp.example.com"],
    )
    c = compile_constraint(
        surface,
        tool_value_fields={
            "send_email": {"to": "recipient"},
            # A forbidden tool: its schema must NOT be emitted (it is stripped
            # wholesale, so shaping its args is moot).
            "transfer_funds": {"to": "recipient"},
        },
    )
    assert set(c.per_tool_json_schema) == {"send_email"}
    field_schema = c.per_tool_json_schema["send_email"]["properties"]["to"]
    assert field_schema["type"] == "string"
    assert field_schema["pattern"] == c.value_regexes["recipient"]


def test_unknown_value_role_fails_loud() -> None:
    surface = CapabilitySurface(allowed_tools=["x"])
    with pytest.raises(ValueError, match="unknown value role"):
        compile_constraint(surface, tool_value_fields={"x": {"f": "not_a_role"}})


def test_known_role_without_domains_emits_no_vacuous_pattern() -> None:
    # 'recipient' is a known role, but with no domains declared there is nothing
    # to constrain — emit no (vacuously-true) pattern rather than a fake one.
    surface = CapabilitySurface(allowed_tools=["send_email"])
    c = compile_constraint(surface, tool_value_fields={"send_email": {"to": "recipient"}})
    assert c.per_tool_json_schema == {}
    assert c.constrains_values is False
