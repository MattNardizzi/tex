"""
Approach A — map a ``DecoderConstraint`` to vLLM guided-decoding engine params.

This is the *true unrepresentability* tier: when Tex hosts the decoder (vLLM /
SGLang / TGI behind an OpenAI-compatible endpoint), the constraint becomes a mask
on the **actual logits** before sampling, so a forbidden tool name reaches
probability exactly zero — no model cooperation, deterministic, replayable. This
module ships the *mapping* + the *fail-closed serving policy*; the serving shim
that calls vLLM is a deliberate follow-up (named in the SUMMARY), not claimed here.

vLLM param surface (grounded 2026-06-19, web)
---------------------------------------------
vLLM's OpenAI-compatible server takes ``guided_choice`` / ``guided_regex`` /
``guided_json`` as **extra request fields** (passed via the OpenAI client's
``extra_body``), GA since vLLM 0.8.5. NEWER vLLM versions DEPRECATE the
``guided_*`` fields in favor of a unified ``structured_outputs`` object. This
module emits the widely-deployed ``guided_*`` form as primary and ALSO emits the
``structured_outputs`` form, so the mapping works against both server generations.
Source: docs.vllm.ai structured_outputs; Red Hat Developer "Structured outputs in
vLLM" (2025-06). Labeled accordingly — the *tool-name* mask is ``production`` on
vLLM; the *value-level* ``pattern`` constraints are ``research-early`` (tokenizer
edge cases).

Fail-closed policy (the load-bearing security choice)
-----------------------------------------------------
A Tex-hosted governed decoder must not serve a request that drops the constraint.
:func:`vllm_serving_policy` refuses to serve when no capability surface can be
resolved (``require_surface=True``, the default) and, when a *restricting* surface
is present, marks the compiled guided params as MANDATORY.
:func:`refuse_unconstrained_request` is the enforcement check a serving shim calls
to reject a request that fails to carry them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tex.domain.agent import CapabilitySurface
from tex.emission.constraint import DecoderConstraint, compile_constraint


@dataclass(frozen=True, slots=True)
class VllmGuidedParams:
    """The guided-decoding params a ``DecoderConstraint`` maps to.

    ``guided_choice`` is the name-only lever (use when the decode step *is* the
    tool-name selection). ``guided_json`` is the general full-tool-call lever: a
    schema pinning ``name`` to the allowlist enum and ``arguments`` to the
    per-tool schema. ``extra_body`` is the ready-to-send dict for the OpenAI
    client against a vLLM server; ``structured_outputs`` is the newer
    (non-deprecated) form of the same constraint.
    """

    guided_choice: tuple[str, ...] | None
    guided_json: dict[str, Any] | None
    extra_body: dict[str, Any]
    structured_outputs: dict[str, Any] | None
    constrains_tool_names: bool
    constrains_values: bool
    notes: tuple[str, ...] = ()


def to_vllm_guided(constraint: DecoderConstraint) -> VllmGuidedParams:
    """Map a ``DecoderConstraint`` to vLLM guided-decoding params. Pure.

    When the constraint imposes a tool-name allowlist, ``guided_json`` pins
    ``name`` to an ``enum`` of the allowed names (true unrepresentability of any
    other name) and, where per-tool schemas exist, binds ``arguments`` to the
    matching schema via JSON-Schema ``allOf``/``if``-``then`` (name → args
    dependency). ``guided_choice`` carries the same allowlist for the name-only
    decode path. When the constraint imposes nothing decoder-expressible,
    ``extra_body`` is empty and the flags say so honestly.
    """
    notes: list[str] = []
    guided_choice: tuple[str, ...] | None = None
    guided_json: dict[str, Any] | None = None

    if constraint.constrains_tool_names:
        guided_choice = constraint.allowed_tool_names
        guided_json = _build_tool_call_schema(constraint)
        notes.append(
            "tool-name allowlist mapped to guided_json.name.enum (production mask)"
        )
    elif constraint.per_tool_json_schema:
        # No name allowlist, but argument schemas to enforce on whatever tools run.
        guided_json = _build_tool_call_schema(constraint)
        notes.append("no name allowlist; argument schema only (research-early)")

    if constraint.constrains_values:
        notes.append(
            "value-level regex/pattern constraints are research-early "
            "(tokenizer soundness must be fuzzed at the actuator)"
        )

    extra_body: dict[str, Any] = {}
    structured_outputs: dict[str, Any] | None = None
    if guided_json is not None:
        extra_body = {"guided_json": guided_json}
        # Newer vLLM (guided_* deprecated): the unified form of the same schema.
        structured_outputs = {"json": guided_json}

    return VllmGuidedParams(
        guided_choice=guided_choice,
        guided_json=guided_json,
        extra_body=extra_body,
        structured_outputs=structured_outputs,
        constrains_tool_names=constraint.constrains_tool_names,
        constrains_values=constraint.constrains_values,
        notes=tuple(notes),
    )


def _build_tool_call_schema(constraint: DecoderConstraint) -> dict[str, Any]:
    """A JSON schema for a single tool call: ``{name, arguments}``.

    ``name`` is pinned to the allowlist enum when one exists. ``arguments`` is
    bound per-tool via ``allOf`` of ``if name==X then arguments matches schemaX``,
    which is the sound way to express the name→args dependency in JSON Schema.
    """
    name_schema: dict[str, Any] = {"type": "string"}
    if constraint.constrains_tool_names:
        name_schema["enum"] = list(constraint.allowed_tool_names)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": name_schema,
            "arguments": {"type": "object"},
        },
        "required": ["name", "arguments"],
        "additionalProperties": False,
    }

    conditionals: list[dict[str, Any]] = []
    for tool_name, arg_schema in sorted(constraint.per_tool_json_schema.items()):
        conditionals.append(
            {
                "if": {"properties": {"name": {"const": tool_name}}},
                "then": {"properties": {"arguments": arg_schema}},
            }
        )
    if conditionals:
        schema["allOf"] = conditionals
    return schema


# --------------------------------------------------------------------------- #
# Fail-closed serving policy                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ServingDecision:
    """Whether a Tex-hosted decoder may serve, and under what mandatory params.

    ``serve`` False is a refusal (fail-closed). ``must_be_constrained`` marks that
    a restricting surface is present, so serving WITHOUT ``guided_extra_body`` is a
    policy violation (see :func:`refuse_unconstrained_request`). ``constrained``
    records whether a decoder-expressible mask was actually produced — honestly
    False for a declared-open surface, so the proof never overclaims a mask.
    """

    serve: bool
    must_be_constrained: bool
    constrained: bool
    reason: str
    guided_extra_body: dict[str, Any] = field(default_factory=dict)
    constraint: DecoderConstraint | None = None
    constraint_digest: str | None = None
    maturity: str = "research_solid"


def vllm_serving_policy(
    surface: CapabilitySurface | None,
    *,
    require_surface: bool = True,
    tool_value_fields: dict[str, dict[str, str]] | None = None,
) -> ServingDecision:
    """Decide whether a Tex-hosted decoder may serve this turn — fail-closed.

    * ``surface is None`` and ``require_surface`` (default): **REFUSE** — a
      governed decoder cannot serve un-constrained when it cannot resolve the
      agent's surface. This is the "refuse to serve un-constrained when a surface
      regime is in force" floor.
    * ``surface is None`` and not ``require_surface``: serve un-constrained — an
      EXPLICIT operator opt-out (e.g. an ungoverned dev endpoint), recorded as
      ``constrained=False`` so it is never mistaken for a mask.
    * restricting surface present (tool or value constraint): **SERVE, constrained**
      — ``guided_extra_body`` is mandatory.
    * surface present but fully unrestricted, or restricted only in dimensions the
      decoder cannot express (action types / channels — those stay the PDP's job):
      serve, ``constrained=False``, said plainly.
    """
    if surface is None:
        if require_surface:
            return ServingDecision(
                serve=False,
                must_be_constrained=True,
                constrained=False,
                reason="no-capability-surface-resolved:fail-closed",
            )
        return ServingDecision(
            serve=True,
            must_be_constrained=False,
            constrained=False,
            reason="no-surface:explicit-operator-opt-out",
        )

    constraint = compile_constraint(surface, tool_value_fields=tool_value_fields)
    if constraint.constrains_tool_names or constraint.constrains_values:
        guided = to_vllm_guided(constraint)
        return ServingDecision(
            serve=True,
            must_be_constrained=True,
            constrained=True,
            reason="surface-present:decoder-constrained",
            guided_extra_body=guided.extra_body,
            constraint=constraint,
            constraint_digest=constraint.digest(),
        )
    if surface.is_unrestricted:
        return ServingDecision(
            serve=True,
            must_be_constrained=False,
            constrained=False,
            reason="surface-present:declared-unrestricted",
            constraint=constraint,
            constraint_digest=constraint.digest(),
        )
    return ServingDecision(
        serve=True,
        must_be_constrained=False,
        constrained=False,
        reason="surface-present:no-decoder-expressible-constraint",
        constraint=constraint,
        constraint_digest=constraint.digest(),
    )


def refuse_unconstrained_request(
    decision: ServingDecision, request_extra_body: dict[str, Any] | None
) -> str | None:
    """The enforcement check: refuse a request that drops a mandated constraint.

    Returns a refusal reason string when ``decision.must_be_constrained`` but the
    actual ``request_extra_body`` does not carry the mandated guided params, else
    ``None`` (request may proceed). This is what makes "refuse to serve
    un-constrained" a runtime check, not merely advice: a serving shim calls it
    after assembling the outbound request and fails closed on a non-None result.
    """
    if not decision.must_be_constrained:
        return None
    if not decision.serve:
        return decision.reason
    body = request_extra_body or {}
    required = decision.guided_extra_body or {}
    for key, value in required.items():
        if body.get(key) != value:
            return f"unconstrained-request:missing-or-altered:{key}"
    return None
