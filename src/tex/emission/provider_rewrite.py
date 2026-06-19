"""
Approach B — re-assert the allowlist by rewriting the provider's request.

Tex sits as the proxy and rewrites the chat/completions request *before* it
reaches a hosted LLM provider (OpenAI / Anthropic shapes): forbidden tools are
stripped from the ``tools`` array, ``tool_choice`` is narrowed to the permitted
subset (fail-closed — a forbidden specific choice is downgraded to "no tool"),
and each surviving tool's argument schema is tightened from the constraint. The
provider's *own* constrained decoder then enforces; the agent cannot re-add a
tool Tex stripped, **provided it cannot reach the provider except through Tex**.

MATURITY LABEL — ``provider-trusted``, NOT ``Tex-enforced`` unrepresentability.
This is "the provider says it masks the request we control," which is strictly
stronger than cooperation-dependent guardrails (the *request the provider
executes is Tex-controlled*) but weaker than Approach A (``vllm_mapping``), where
Tex owns the sampler and the forbidden tokens reach probability exactly zero. The
tool-name strip is the high-confidence floor; the value-level ``pattern`` shaping
is ``research-early`` and its enforcement is provider-dependent.

Pure: never mutates ``body``; returns a new dict. No I/O.
"""

from __future__ import annotations

import copy
from typing import Any

from tex.emission.constraint import DecoderConstraint

# Provider request dialects this rewrite understands.
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"


def detect_provider(body: dict[str, Any]) -> str | None:
    """Best-effort detection of the request dialect from the body shape.

    OpenAI chat/completions nests each tool under a ``function`` key and uses a
    ``tool_choice`` of ``"auto"|"none"|"required"|{"type":"function",...}``.
    Anthropic Messages carries flat ``{"name", "input_schema"}`` tools and a
    ``tool_choice`` dict of ``{"type":"auto"|"any"|"tool"|"none", ...}``. Returns
    ``None`` when neither shape is recognizable — the caller then leaves the body
    untouched rather than guessing (fail-safe: no silent mis-rewrite).
    """
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        for t in tools:
            if isinstance(t, dict):
                if "function" in t:
                    return PROVIDER_OPENAI
                if "input_schema" in t:
                    return PROVIDER_ANTHROPIC
    # Fall back to tool_choice shape.
    choice = body.get("tool_choice")
    if isinstance(choice, dict):
        if choice.get("type") == "function":
            return PROVIDER_OPENAI
        if choice.get("type") in ("auto", "any", "tool", "none"):
            return PROVIDER_ANTHROPIC
    # Anthropic Messages always carries max_tokens; OpenAI does not require it.
    if "max_tokens" in body and "messages" in body and "tools" in body:
        return PROVIDER_ANTHROPIC
    return None


def rewrite_provider_request(
    body: dict[str, Any],
    constraint: DecoderConstraint,
    *,
    provider: str | None = None,
    strict_structured_output: bool = False,
) -> dict[str, Any]:
    """Return a copy of ``body`` with the allowlist re-asserted for ``provider``.

    Steps (each a no-op when the constraint does not call for it):
      1. Strip every tool whose name is not in ``constraint`` from ``tools`` — the
         RELIABLE floor (``production``, provider-independent for the menu).
      2. Narrow ``tool_choice``: a specific choice naming a now-forbidden tool is
         downgraded to "no tool may be called" (fail-closed); "must call a tool"
         with an empty permitted set likewise collapses to "no tool".
      3. Tighten each surviving tool's argument schema from
         ``per_tool_json_schema`` (inject the value ``pattern``).

    ``strict_structured_output`` (default False) is the structured-output lever:
    when True, OpenAI function tools are marked ``strict`` with
    ``additionalProperties: false`` so the provider's structured-output engine
    enforces the schema. It is OPT-IN and ``research-early`` on purpose — OpenAI's
    strict subset has historically rejected ``pattern``/``format`` and requires
    every property in ``required``, so forcing it can break an otherwise-valid
    request and may not enforce the value regex anyway. Whether ``pattern`` is
    honored is PROVIDER-DEPENDENT; the dependable guarantee here is the tool-name
    strip, not the value shape. (Anthropic always validates tool input against
    ``input_schema``, so its tightening needs no flag.)

    When ``constraint.constrains_tool_names`` is False the surface declared no
    tool restriction and the ``tools`` array is left intact — this gate does not
    invent a restriction the operator did not declare. Value-shape tightening
    still applies to whatever tools are present.

    Honest scope: this rewrites the tools MENU and the tool CHOICE for the next
    emission. It deliberately does NOT scrub prior ``messages`` history — a past
    tool call recorded in the transcript is a historical fact, not a new
    emission, and un-representability is a property of what the provider may
    NEWLY call.

    ``provider`` may be forced; otherwise it is detected. An unrecognized dialect
    returns ``body`` unchanged (a copy) — Tex does not mutate a request it cannot
    reason about.
    """
    out = copy.deepcopy(body)
    prov = provider or detect_provider(out)
    if prov == PROVIDER_OPENAI:
        return _rewrite_openai(out, constraint, strict_structured_output)
    if prov == PROVIDER_ANTHROPIC:
        return _rewrite_anthropic(out, constraint)
    return out


# --------------------------------------------------------------------------- #
# OpenAI chat/completions                                                      #
# --------------------------------------------------------------------------- #


def _openai_tool_name(tool: Any) -> str:
    if isinstance(tool, dict):
        fn = tool.get("function")
        if isinstance(fn, dict):
            return str(fn.get("name", ""))
    return ""


def _rewrite_openai(
    body: dict[str, Any], constraint: DecoderConstraint, strict: bool
) -> dict[str, Any]:
    tools = body.get("tools")
    if isinstance(tools, list):
        if constraint.constrains_tool_names:
            kept = [t for t in tools if constraint.is_tool_allowed(_openai_tool_name(t))]
        else:
            kept = list(tools)
        kept = [_tighten_openai_tool(t, constraint, strict) for t in kept]
        body["tools"] = kept
        body["tool_choice"] = _narrow_openai_tool_choice(
            body.get("tool_choice"), kept, constraint
        )
        if not kept:
            # No permitted tool remains — remove the (now empty) array so the
            # provider treats the turn as text-only, and pin tool_choice to none.
            body.pop("tools", None)
            body["tool_choice"] = "none"
    elif constraint.constrains_tool_names:
        # No usable `tools` array (missing or non-list), but a detected OpenAI
        # request can still carry a FORCED `tool_choice` naming a forbidden tool.
        # Narrow it fail-closed (kept=[]): a forbidden specific choice — or a
        # "required"/"auto" with no permitted menu — collapses to "none".
        body["tool_choice"] = _narrow_openai_tool_choice(
            body.get("tool_choice"), [], constraint
        )
    return body


def _tighten_openai_tool(tool: Any, constraint: DecoderConstraint, strict: bool) -> Any:
    if not isinstance(tool, dict):
        return tool
    name = _openai_tool_name(tool).strip().casefold()
    overlay = constraint.per_tool_json_schema.get(name)
    if not overlay:
        return tool
    fn = dict(tool.get("function", {}))
    params = _merge_schema(fn.get("parameters"), overlay)
    fn["parameters"] = params
    if strict:
        # OPT-IN structured-outputs-for-tools. Honest caveat: OpenAI's strict
        # subset has historically rejected ``pattern`` and requires every property
        # in ``required`` — enabling this is the caller's assertion that their
        # provider + schema are strict-compatible. Default off keeps the request
        # valid and the value ``pattern`` best-effort (provider-dependent).
        fn["strict"] = True
        params.setdefault("additionalProperties", False)
    new_tool = dict(tool)
    new_tool["function"] = fn
    return new_tool


def _narrow_openai_tool_choice(
    choice: Any, kept_tools: list[Any], constraint: DecoderConstraint
) -> Any:
    if not constraint.constrains_tool_names:
        return choice if choice is not None else "auto"
    if isinstance(choice, dict) and choice.get("type") == "function":
        named = str(choice.get("function", {}).get("name", ""))
        if not constraint.is_tool_allowed(named):
            # A specific forbidden choice — fail closed to "no tool".
            return "none"
        return choice
    if choice in ("required", "auto", "none", None):
        if not kept_tools:
            return "none"
        return choice if choice is not None else "auto"
    return choice


# --------------------------------------------------------------------------- #
# Anthropic Messages                                                           #
# --------------------------------------------------------------------------- #


def _anthropic_tool_name(tool: Any) -> str:
    if isinstance(tool, dict):
        return str(tool.get("name", ""))
    return ""


def _rewrite_anthropic(body: dict[str, Any], constraint: DecoderConstraint) -> dict[str, Any]:
    tools = body.get("tools")
    if isinstance(tools, list):
        if constraint.constrains_tool_names:
            kept = [
                t for t in tools if constraint.is_tool_allowed(_anthropic_tool_name(t))
            ]
        else:
            kept = list(tools)
        kept = [_tighten_anthropic_tool(t, constraint) for t in kept]
        body["tools"] = kept
        body["tool_choice"] = _narrow_anthropic_tool_choice(
            body.get("tool_choice"), kept, constraint
        )
        if not kept:
            body["tools"] = []
            body["tool_choice"] = {"type": "none"}
    elif constraint.constrains_tool_names:
        # Symmetric fail-closed for a detected Anthropic request with no usable
        # tools array but a forced tool_choice (e.g. {"type":"tool","name":X}).
        body["tool_choice"] = _narrow_anthropic_tool_choice(
            body.get("tool_choice"), [], constraint
        )
    return body


def _tighten_anthropic_tool(tool: Any, constraint: DecoderConstraint) -> Any:
    if not isinstance(tool, dict):
        return tool
    name = _anthropic_tool_name(tool).strip().casefold()
    overlay = constraint.per_tool_json_schema.get(name)
    if not overlay:
        return tool
    new_tool = dict(tool)
    # Anthropic always validates tool input against ``input_schema``, so
    # tightening it is the enforcement lever (no separate "strict" flag).
    new_tool["input_schema"] = _merge_schema(tool.get("input_schema"), overlay)
    return new_tool


def _narrow_anthropic_tool_choice(
    choice: Any, kept_tools: list[Any], constraint: DecoderConstraint
) -> Any:
    if not constraint.constrains_tool_names:
        return choice
    if isinstance(choice, dict) and choice.get("type") == "tool":
        named = str(choice.get("name", ""))
        if not constraint.is_tool_allowed(named):
            return {"type": "none"}
        return choice
    if isinstance(choice, dict) and choice.get("type") == "any" and not kept_tools:
        return {"type": "none"}
    return choice


# --------------------------------------------------------------------------- #
# Shared                                                                       #
# --------------------------------------------------------------------------- #


def _merge_schema(existing: Any, overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge constraint ``overlay`` (the tightening) onto an ``existing`` schema.

    Property-level merge: each property in ``overlay.properties`` is layered onto
    the existing property (so a ``pattern`` is *added*, the original ``type`` and
    ``description`` survive). The overlay is the constraint, so on a direct key
    clash within a property the overlay wins — a tightening must not be silently
    overridden by the model's looser claim.
    """
    base: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    base.setdefault("type", "object")
    base_props = dict(base.get("properties") or {})
    for field_name, field_schema in (overlay.get("properties") or {}).items():
        merged_field = dict(base_props.get(field_name) or {})
        merged_field.update(field_schema)
        base_props[field_name] = merged_field
    base["properties"] = base_props
    return base
