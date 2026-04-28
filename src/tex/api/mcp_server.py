"""
Layer 4 - MCP server interface for Tex.

Exposes Tex's evaluation capability as an MCP (Model Context Protocol)
server so any MCP-aware client (Claude Desktop, Cursor, AgentKit,
Copilot Studio, Bifrost, Portkey, custom LangChain/CrewAI agents) can
register Tex as a guardrail tool with one config line:

    {
      "mcpServers": {
        "tex": { "url": "https://api.tex.io/mcp" }
      }
    }

This module implements the MCP HTTP-transport surface (the JSON-RPC 2.0
flavor used by the streamable HTTP transport). It deliberately avoids
adding a third-party MCP SDK dependency — the protocol is small enough
that a clean, typed implementation in ~200 lines is more auditable than
a vendored library, and it keeps your dependency surface tight.

The server exposes a single tool: `evaluate_action`. Calling it produces
the same Tex decision the canonical webhook produces, in the same engine,
under the same evidence chain.

Reference: https://modelcontextprotocol.io/specification/
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.guardrail import (
    GuardrailMessage,
    GuardrailStage,
    GuardrailToolCall,
    GuardrailWebhookRequest,
    _build_response,
    _get_evaluate_action_command,
    _to_evaluation_request,
)


router = APIRouter(prefix="/mcp", tags=["mcp"])


# --------------------------------------------------------------------------- #
# JSON-RPC 2.0 envelope types                                                 #
# --------------------------------------------------------------------------- #


class JsonRpcRequest(BaseModel):
    """A single MCP-over-JSON-RPC request envelope."""

    model_config = ConfigDict(extra="allow")

    jsonrpc: str = Field(default="2.0")
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcError(BaseModel):
    """Standard JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="forbid")

    code: int
    message: str
    data: dict[str, Any] | None = None


# Standard JSON-RPC 2.0 error codes.
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


def _ok(rpc_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _err(rpc_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": JsonRpcError(code=code, message=message, data=data).model_dump(
            exclude_none=True,
        ),
    }


# --------------------------------------------------------------------------- #
# Tool catalog                                                                #
# --------------------------------------------------------------------------- #


_TOOL_NAME = "evaluate_action"

_TOOL_SCHEMA: dict[str, Any] = {
    "name": _TOOL_NAME,
    "description": (
        "Evaluate an AI agent action through Tex. Returns a verdict "
        "(PERMIT / ABSTAIN / FORBID), risk score, OWASP ASI 2026 findings, "
        "and a decision_id for evidence-bundle retrieval. Surface-agnostic: "
        "evaluate emails, API calls, database writes, Slack messages, "
        "deployments, tool invocations, or any other agent outbound action."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "stage": {
                "type": "string",
                "enum": ["pre_call", "post_call", "tool_invocation"],
                "default": "pre_call",
                "description": "When the evaluation is being requested.",
            },
            "content": {
                "type": "string",
                "description": "Direct content to evaluate.",
            },
            "messages": {
                "type": "array",
                "description": "Chat-style payload (OpenAI/Anthropic shape).",
                "items": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["role"],
                },
            },
            "prompt": {"type": "string"},
            "response": {"type": "string"},
            "tool_call": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"},
                    "server": {"type": "string"},
                },
                "required": ["name"],
            },
            "action_type": {"type": "string"},
            "channel": {"type": "string"},
            "environment": {"type": "string"},
            "recipient": {"type": "string"},
            "policy_id": {"type": "string"},
            "metadata": {"type": "object"},
        },
        "additionalProperties": False,
    },
}


_SERVER_INFO: dict[str, Any] = {
    "name": "tex-guardrail",
    "version": "1.0.0",
    "vendor": "VortexBlack",
    "description": (
        "Tex - the gate between AI and the real world. Evaluates AI agent "
        "actions, returns three-way verdicts (PERMIT/ABSTAIN/FORBID), and "
        "produces hash-chained, audit-grade evidence."
    ),
}


# --------------------------------------------------------------------------- #
# Method handlers                                                             #
# --------------------------------------------------------------------------- #


def _handle_initialize(rpc_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    """MCP `initialize` - capability negotiation handshake."""
    return _ok(rpc_id, {
        "protocolVersion": "2025-06-18",
        "serverInfo": _SERVER_INFO,
        "capabilities": {
            "tools": {"listChanged": False},
        },
    })


def _handle_tools_list(rpc_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    """MCP `tools/list` - return the tool catalog."""
    return _ok(rpc_id, {"tools": [_TOOL_SCHEMA]})


def _handle_tools_call(
    *,
    rpc_id: Any,
    params: dict[str, Any],
    request: Request,
    principal: TexPrincipal,
) -> dict[str, Any]:
    """MCP `tools/call` - dispatch the named tool against Tex."""
    name = params.get("name")
    if name != _TOOL_NAME:
        return _err(rpc_id, _METHOD_NOT_FOUND, f"unknown tool: {name!r}")

    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _err(rpc_id, _INVALID_PARAMS, "arguments must be an object")

    # Translate MCP arguments into the canonical guardrail request.
    try:
        messages_raw = arguments.get("messages")
        messages: tuple[GuardrailMessage, ...] | None = None
        if isinstance(messages_raw, list) and messages_raw:
            messages = tuple(
                GuardrailMessage.model_validate(m) for m in messages_raw if isinstance(m, dict)
            ) or None

        tool_call_raw = arguments.get("tool_call")
        tool_call: GuardrailToolCall | None = None
        if isinstance(tool_call_raw, dict):
            tool_call = GuardrailToolCall.model_validate(tool_call_raw)

        stage_raw = (arguments.get("stage") or "pre_call").strip().lower()
        try:
            stage = GuardrailStage(stage_raw)
        except ValueError:
            stage = GuardrailStage.PRE_CALL

        canonical = GuardrailWebhookRequest(
            stage=stage,
            content=arguments.get("content"),
            messages=messages,
            prompt=arguments.get("prompt"),
            response=arguments.get("response"),
            tool_call=tool_call,
            action_type=arguments.get("action_type"),
            channel=arguments.get("channel"),
            environment=arguments.get("environment"),
            recipient=arguments.get("recipient"),
            policy_id=arguments.get("policy_id"),
            metadata=arguments.get("metadata") or {},
            source="mcp",
        )
    except Exception as exc:
        return _err(rpc_id, _INVALID_PARAMS, f"invalid arguments: {exc}")

    try:
        domain_request = _to_evaluation_request(canonical, principal=principal)
    except ValueError as exc:
        return _err(rpc_id, _INVALID_PARAMS, str(exc))

    command = _get_evaluate_action_command(request)

    try:
        result = command.execute(domain_request)
    except Exception as exc:
        return _err(rpc_id, _INTERNAL_ERROR, f"evaluation failed: {exc}")

    response = _build_response(
        result=result,
        request_id=domain_request.request_id,
        source="mcp",
    )

    # MCP tools/call returns a content array. We supply one structured block
    # plus a human-readable text block so MCP clients that show tool output
    # to the user have something readable.
    structured = {
        "verdict": response.verdict.value,
        "allowed": response.allowed,
        "score": response.score,
        "confidence": response.confidence,
        "reason": response.reason,
        "decision_id": str(response.decision_id),
        "policy_version": response.policy_version,
        "asi_findings": [
            {
                "short_code": f.short_code,
                "title": f.title,
                "severity": f.severity,
                "verdict_influence": f.verdict_influence.value,
            }
            for f in response.asi_findings
        ],
    }
    text_summary = (
        f"Tex verdict: {response.verdict.value} "
        f"(score={response.score:.2f}, confidence={response.confidence:.2f}). "
        f"{response.reason}"
    )

    return _ok(rpc_id, {
        "content": [
            {"type": "text", "text": text_summary},
        ],
        "structuredContent": structured,
        "isError": not response.allowed,
    })


# --------------------------------------------------------------------------- #
# HTTP transport                                                              #
# --------------------------------------------------------------------------- #


@router.post("", summary="MCP server endpoint (JSON-RPC 2.0)")
def mcp_dispatch(
    request: Request,
    body: dict[str, Any],
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """
    Single MCP dispatch endpoint. Accepts a JSON-RPC 2.0 request, routes
    by method name, and returns a JSON-RPC 2.0 response.

    Supported methods:
      - initialize            : capability handshake
      - tools/list            : enumerate Tex's MCP tools
      - tools/call            : execute a tool (Tex evaluation)
      - ping                  : liveness check
    """
    try:
        rpc = JsonRpcRequest.model_validate(body)
    except Exception as exc:
        return _err(None, _INVALID_REQUEST, f"invalid JSON-RPC request: {exc}")

    method = rpc.method
    rpc_id = rpc.id

    if method == "initialize":
        return _handle_initialize(rpc_id, rpc.params)
    if method == "tools/list":
        return _handle_tools_list(rpc_id, rpc.params)
    if method == "tools/call":
        return _handle_tools_call(
            rpc_id=rpc_id,
            params=rpc.params,
            request=request,
            principal=principal,
        )
    if method == "ping":
        return _ok(rpc_id, {})
    if method == "notifications/initialized":
        # Notification: no response required, but return a minimal ack.
        return _ok(rpc_id, {})

    return _err(rpc_id, _METHOD_NOT_FOUND, f"method not found: {method!r}")


@router.get("", summary="MCP server discovery")
def mcp_discovery() -> dict[str, Any]:
    """GET handler returns server info so a discovery probe (browser hit,
    health check, registry crawler) sees something useful."""
    return {
        "server": _SERVER_INFO,
        "transport": "http+json-rpc-2.0",
        "tools": [_TOOL_NAME],
        "endpoints": {
            "rpc": "POST /mcp",
            "discovery": "GET /mcp",
        },
    }


def build_mcp_router() -> APIRouter:
    """Convenience constructor."""
    return router


__all__ = [
    "build_mcp_router",
    "router",
]
