"""Tests for Approach A — vLLM guided-decoding mapping + fail-closed policy."""

from __future__ import annotations

from tex.domain.agent import CapabilitySurface
from tex.emission.constraint import compile_constraint
from tex.emission.vllm_mapping import (
    refuse_unconstrained_request,
    to_vllm_guided,
    vllm_serving_policy,
)


def test_tool_name_allowlist_maps_to_guided_choice_and_enum() -> None:
    constraint = compile_constraint(CapabilitySurface(allowed_tools=["a", "b"]))
    g = to_vllm_guided(constraint)
    assert g.guided_choice == ("a", "b")
    # The full-tool-call schema pins name to the allowlist enum — no other name
    # is representable at the sampler.
    assert g.guided_json is not None
    assert g.guided_json["properties"]["name"]["enum"] == ["a", "b"]
    assert g.extra_body == {"guided_json": g.guided_json}
    # Newer-vLLM unified form carries the same schema.
    assert g.structured_outputs == {"json": g.guided_json}


def test_unconstrained_surface_maps_to_no_guided_params() -> None:
    g = to_vllm_guided(compile_constraint(CapabilitySurface()))
    assert g.guided_choice is None
    assert g.guided_json is None
    assert g.extra_body == {}


def test_per_tool_argument_schema_becomes_conditional() -> None:
    surface = CapabilitySurface(
        allowed_tools=["send_email"],
        allowed_recipient_domains=["corp.example.com"],
    )
    constraint = compile_constraint(
        surface, tool_value_fields={"send_email": {"to": "recipient"}}
    )
    g = to_vllm_guided(constraint)
    conds = g.guided_json["allOf"]
    assert len(conds) == 1
    cond = conds[0]
    assert cond["if"]["properties"]["name"]["const"] == "send_email"
    to_schema = cond["then"]["properties"]["arguments"]["properties"]["to"]
    assert to_schema["pattern"] == constraint.value_regexes["recipient"]


# --------------------------------------------------------------------------- #
# Fail-closed serving policy                                                  #
# --------------------------------------------------------------------------- #


def test_no_surface_refuses_to_serve_fail_closed() -> None:
    decision = vllm_serving_policy(None)
    assert decision.serve is False
    assert decision.must_be_constrained is True
    assert "fail-closed" in decision.reason


def test_no_surface_explicit_opt_out_serves_unconstrained() -> None:
    decision = vllm_serving_policy(None, require_surface=False)
    assert decision.serve is True
    assert decision.constrained is False


def test_restricting_surface_serves_constrained_with_mandatory_params() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    decision = vllm_serving_policy(surface)
    assert decision.serve is True
    assert decision.must_be_constrained is True
    assert decision.constrained is True
    assert "guided_json" in decision.guided_extra_body
    assert decision.constraint_digest == compile_constraint(surface).digest()


def test_unrestricted_surface_serves_but_records_no_mask() -> None:
    decision = vllm_serving_policy(CapabilitySurface())
    assert decision.serve is True
    assert decision.must_be_constrained is False
    assert decision.constrained is False
    assert "unrestricted" in decision.reason


def test_refuse_unconstrained_request_enforces_mandatory_params() -> None:
    surface = CapabilitySurface(allowed_tools=["send_email"])
    decision = vllm_serving_policy(surface)

    # A request that drops the mandated guided params is refused.
    assert refuse_unconstrained_request(decision, {}) is not None
    assert refuse_unconstrained_request(decision, None) is not None
    # An altered constraint is refused.
    assert (
        refuse_unconstrained_request(decision, {"guided_json": {"tampered": True}})
        is not None
    )
    # The exact mandated params pass.
    assert refuse_unconstrained_request(decision, decision.guided_extra_body) is None


def test_refuse_is_noop_when_no_constraint_mandated() -> None:
    decision = vllm_serving_policy(CapabilitySurface())
    assert refuse_unconstrained_request(decision, {}) is None
