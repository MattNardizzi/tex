"""
Layer 2 - native-shape gateway adapter routes.

Each adapter exposes a route that accepts the *native* webhook payload of
a specific gateway and translates it into Tex's canonical guardrail
request internally. This means a customer integrating Tex with their
existing gateway can paste the gateway-native URL directly into their
config without having to learn Tex's canonical shape.

Architecture:

    Customer's gateway
       |
       | (sends gateway-native payload)
       v
    /v1/guardrail/<gateway>      <-- this module
       |
       | (translates to canonical)
       v
    Canonical evaluation logic
       |
       v
    Tex engine

Each adapter is intentionally small (a translator + a delegate call) so
that fixing or extending one gateway's quirks never touches engine code.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.guardrail import (
    GuardrailFormat,
    GuardrailMessage,
    GuardrailStage,
    GuardrailToolCall,
    GuardrailWebhookRequest,
    _build_response,
    _get_evaluate_action_command,
    _RENDERERS,
    _to_evaluation_request,
)


router = APIRouter(prefix="/v1/guardrail", tags=["guardrail-adapters"])


# --------------------------------------------------------------------------- #
# Shared evaluation helper                                                    #
# --------------------------------------------------------------------------- #


def _evaluate(
    canonical: GuardrailWebhookRequest,
    *,
    request: Request,
    principal: TexPrincipal,
) -> Any:
    """Run a canonical guardrail request through the engine and return the
    canonical response object. Adapters then project this into their
    gateway-specific shape."""
    try:
        domain_request = _to_evaluation_request(canonical, principal=principal)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    command = _get_evaluate_action_command(request)

    try:
        result = command.execute(domain_request)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return _build_response(
        result=result,
        request_id=domain_request.request_id,
        source=canonical.source,
    )


def _extract_chat_payload(body: dict[str, Any]) -> tuple[
    tuple[GuardrailMessage, ...] | None,
    str | None,
    str | None,
]:
    """
    Pull a chat payload out of an arbitrary gateway-shaped body. Returns
    (messages, prompt, response). Each is None when not present.

    Recognized shapes:
      - {"messages": [{"role": ..., "content": ...}, ...]}
      - {"prompt": "...", "response": "..."}
      - {"input": "...", "output": "..."} (alt naming)
      - {"text": "..."} (single string)
    """
    messages_raw = body.get("messages")
    messages: tuple[GuardrailMessage, ...] | None = None
    if isinstance(messages_raw, list) and messages_raw:
        validated = []
        for item in messages_raw:
            if isinstance(item, dict):
                validated.append(GuardrailMessage.model_validate(item))
        messages = tuple(validated) if validated else None

    def _pick(*keys: str) -> str | None:
        for key in keys:
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return None

    prompt = _pick("prompt", "input", "user_prompt")
    response = _pick("response", "output", "completion", "text")

    return messages, prompt, response


# --------------------------------------------------------------------------- #
# Portkey adapter                                                             #
# --------------------------------------------------------------------------- #


class PortkeyWebhookBody(BaseModel):
    """
    Portkey 'Bring Your Own Guardrail' inbound shape.

    Portkey sends the prompt/response under flexible field names; we accept
    the common ones and forward gateway metadata into evidence.

    Reference: https://portkey.ai/docs/product/guardrails/bring-your-own-guardrails
    """

    model_config = ConfigDict(extra="allow")

    # Stage hint - Portkey distinguishes input vs output guardrails by
    # which stage hook the customer attached to. We let callers pass the
    # hint explicitly, default to pre_call.
    stage: str | None = None


@router.post("/portkey", summary="Portkey BYO-Guardrail webhook")
def adapter_portkey(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """Portkey-native adapter. Accepts Portkey's BYO-Guardrail webhook payload
    and returns the {verdict, data} shape Portkey expects."""
    messages, prompt, response = _extract_chat_payload(body)
    stage_value = (body.get("stage") or "pre_call").strip().lower()
    stage = (
        GuardrailStage.POST_CALL
        if stage_value in ("post_call", "output", "after")
        else GuardrailStage.PRE_CALL
    )

    canonical = GuardrailWebhookRequest(
        stage=stage,
        messages=messages,
        prompt=prompt,
        response=response,
        content=body.get("content") if isinstance(body.get("content"), str) else None,
        metadata={"portkey_raw": _safe_subset(body)},
        source="portkey",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.PORTKEY](response_obj)


# --------------------------------------------------------------------------- #
# LiteLLM adapter                                                             #
# --------------------------------------------------------------------------- #


@router.post("/litellm", summary="LiteLLM Generic Guardrail webhook")
def adapter_litellm(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """LiteLLM-native adapter. LiteLLM's generic guardrail spec sends the
    full chat-completions request or response under standard keys."""
    messages, prompt, response = _extract_chat_payload(body)
    # LiteLLM's `mode` field can be "pre_call", "post_call", or "during_call".
    mode = (body.get("mode") or "pre_call").strip().lower()
    stage = (
        GuardrailStage.POST_CALL
        if mode == "post_call"
        else GuardrailStage.PRE_CALL
    )

    canonical = GuardrailWebhookRequest(
        stage=stage,
        messages=messages,
        prompt=prompt,
        response=response,
        metadata={"litellm_raw": _safe_subset(body)},
        source="litellm",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.LITELLM](response_obj)


# --------------------------------------------------------------------------- #
# Cloudflare AI Gateway adapter                                               #
# --------------------------------------------------------------------------- #


@router.post("/cloudflare", summary="Cloudflare AI Gateway guardrail webhook")
def adapter_cloudflare(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """Cloudflare AI Gateway adapter. Cloudflare proxies to model providers
    and can call out to a guardrail webhook before/after model calls."""
    messages, prompt, response = _extract_chat_payload(body)

    canonical = GuardrailWebhookRequest(
        stage=GuardrailStage.POST_CALL if response else GuardrailStage.PRE_CALL,
        messages=messages,
        prompt=prompt,
        response=response,
        metadata={"cloudflare_raw": _safe_subset(body)},
        source="cloudflare",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.CLOUDFLARE](response_obj)


# --------------------------------------------------------------------------- #
# Solo.io / Gloo AI Gateway adapter                                           #
# --------------------------------------------------------------------------- #


@router.post("/solo", summary="Solo.io / Gloo AI Gateway guardrail webhook")
def adapter_solo(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """Solo.io / Gloo AI Gateway adapter. Their guardrail webhook spec sends
    structured input or output content for inspection."""
    messages, prompt, response = _extract_chat_payload(body)
    direction = (body.get("direction") or "request").strip().lower()
    stage = (
        GuardrailStage.POST_CALL
        if direction in ("response", "output", "post")
        else GuardrailStage.PRE_CALL
    )

    canonical = GuardrailWebhookRequest(
        stage=stage,
        messages=messages,
        prompt=prompt,
        response=response,
        metadata={"solo_raw": _safe_subset(body)},
        source="solo",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.SOLO](response_obj)


# --------------------------------------------------------------------------- #
# TrueFoundry AI Gateway adapter                                              #
# --------------------------------------------------------------------------- #


@router.post("/truefoundry", summary="TrueFoundry AI Gateway guardrail webhook")
def adapter_truefoundry(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """TrueFoundry AI Gateway adapter. Their guardrail provider spec
    supports llm_input, llm_output, mcp_tool_pre_invoke, and
    mcp_tool_post_invoke hooks."""
    hook = (body.get("hook") or "llm_input").strip().lower()

    if hook in ("mcp_tool_pre_invoke", "mcp_tool_post_invoke"):
        tool_call = _extract_tool_call(body)
        canonical = GuardrailWebhookRequest(
            stage=GuardrailStage.TOOL_INVOCATION,
            tool_call=tool_call,
            metadata={"truefoundry_raw": _safe_subset(body)},
            source="truefoundry",
        )
    else:
        messages, prompt, response = _extract_chat_payload(body)
        stage = (
            GuardrailStage.POST_CALL
            if hook == "llm_output"
            else GuardrailStage.PRE_CALL
        )
        canonical = GuardrailWebhookRequest(
            stage=stage,
            messages=messages,
            prompt=prompt,
            response=response,
            metadata={"truefoundry_raw": _safe_subset(body)},
            source="truefoundry",
        )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.TRUEFOUNDRY](response_obj)


# --------------------------------------------------------------------------- #
# Bedrock-compatible adapter                                                  #
# --------------------------------------------------------------------------- #


@router.post("/bedrock", summary="AWS Bedrock-style Guardrails webhook")
def adapter_bedrock(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """Bedrock-compatible adapter. Lets AWS-shop customers swap out (or
    sit alongside) Bedrock Guardrails by pointing their gateway at this
    URL."""
    messages, prompt, response = _extract_chat_payload(body)

    canonical = GuardrailWebhookRequest(
        stage=GuardrailStage.POST_CALL if response else GuardrailStage.PRE_CALL,
        messages=messages,
        prompt=prompt,
        response=response,
        metadata={"bedrock_raw": _safe_subset(body)},
        source="bedrock",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return _RENDERERS[GuardrailFormat.BEDROCK](response_obj)


# --------------------------------------------------------------------------- #
# Microsoft Copilot Studio external guardrails (Layer 3 stub)                 #
# --------------------------------------------------------------------------- #


@router.post(
    "/copilot-studio",
    summary="Microsoft Copilot Studio external guardrails webhook",
)
def adapter_copilot_studio(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """Microsoft Copilot Studio external-guardrails adapter.

    Copilot Studio's external guardrails API sends a request envelope with
    the agent's pending response and conversation context. This adapter
    forwards content into Tex and returns a Copilot-Studio-shaped verdict.
    """
    messages, prompt, response = _extract_chat_payload(body)
    canonical = GuardrailWebhookRequest(
        stage=GuardrailStage.POST_CALL if response else GuardrailStage.PRE_CALL,
        messages=messages,
        prompt=prompt,
        response=response,
        metadata={"copilot_studio_raw": _safe_subset(body)},
        source="copilot_studio",
    )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return {
        "decision": "block" if not response_obj.allowed else "allow",
        "rationale": response_obj.reason,
        "categories": [f.short_code for f in response_obj.asi_findings],
        "tex_decision_id": str(response_obj.decision_id),
    }


# --------------------------------------------------------------------------- #
# OpenAI AgentKit runtime guardrail (Layer 3 stub)                            #
# --------------------------------------------------------------------------- #


@router.post(
    "/agentkit",
    summary="OpenAI AgentKit runtime guardrail webhook",
)
def adapter_agentkit(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """OpenAI AgentKit runtime guardrail adapter.

    AgentKit invokes registered runtime guardrails before tool calls and
    after model responses. This adapter handles both shapes.
    """
    tool_call = _extract_tool_call(body)
    if tool_call is not None:
        canonical = GuardrailWebhookRequest(
            stage=GuardrailStage.TOOL_INVOCATION,
            tool_call=tool_call,
            metadata={"agentkit_raw": _safe_subset(body)},
            source="agentkit",
        )
    else:
        messages, prompt, response = _extract_chat_payload(body)
        canonical = GuardrailWebhookRequest(
            stage=GuardrailStage.POST_CALL if response else GuardrailStage.PRE_CALL,
            messages=messages,
            prompt=prompt,
            response=response,
            metadata={"agentkit_raw": _safe_subset(body)},
            source="agentkit",
        )

    response_obj = _evaluate(canonical, request=request, principal=principal)
    return {
        "allow": response_obj.allowed,
        "verdict": response_obj.verdict.value,
        "score": response_obj.score,
        "message": response_obj.reason,
        "tex_decision_id": str(response_obj.decision_id),
    }


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _extract_tool_call(body: dict[str, Any]) -> GuardrailToolCall | None:
    """Pull a tool/MCP invocation out of an arbitrary gateway-shaped body."""
    tool = body.get("tool_call") or body.get("tool") or body.get("invocation")
    if not isinstance(tool, dict):
        return None
    name = tool.get("name") or tool.get("tool_name")
    if not isinstance(name, str) or not name.strip():
        return None
    arguments = tool.get("arguments") or tool.get("args") or tool.get("parameters") or {}
    if not isinstance(arguments, dict):
        arguments = {}
    server = tool.get("server") or tool.get("mcp_server")
    if not isinstance(server, str):
        server = None
    return GuardrailToolCall(name=name, arguments=arguments, server=server)


_SAFE_KEYS_LIMIT = 20
_SAFE_VALUE_LEN = 500


def _safe_subset(body: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, JSON-safe snapshot of a gateway body for evidence
    metadata. We don't want raw prompts in metadata (they're already in
    content), but session/trace IDs are useful for correlation."""
    safe: dict[str, Any] = {}
    interesting = (
        "session_id",
        "trace_id",
        "request_id",
        "user",
        "user_id",
        "model",
        "provider",
        "deployment",
        "tenant",
        "tenant_id",
        "workspace",
        "workspace_id",
        "hook",
        "mode",
        "stage",
        "direction",
    )
    for key in interesting:
        value = body.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            safe[key] = (
                value[:_SAFE_VALUE_LEN] if isinstance(value, str) else value
            )
        if len(safe) >= _SAFE_KEYS_LIMIT:
            break
    return safe


def build_adapter_router() -> APIRouter:
    """Convenience constructor mirroring tex.api.guardrail.build_guardrail_router."""
    return router


__all__ = [
    "build_adapter_router",
    "router",
]
