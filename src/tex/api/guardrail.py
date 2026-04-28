"""
Canonical guardrail webhook surface for Tex.

This module is the single integration point that every external gateway,
agent platform, and SDK adapter delegates to. It exists so that:

- Tex's existing /evaluate route stays the strict, typed, internal contract.
- Every third-party gateway (Portkey, LiteLLM, Cloudflare AI Gateway, Solo.io
  Gloo, TrueFoundry, Bedrock-style guardrails, Microsoft Copilot Studio
  external guardrails, OpenAI AgentKit runtime guardrails, etc.) can plug
  into Tex by sending a webhook to *one* canonical endpoint.
- Each gateway's response-shape quirk is handled by a tiny render function
  here, not by a parallel evaluation pipeline.

Design properties:

1. The canonical request shape is a superset of what every gateway sends.
   Optional fields cover the union of: prompt-style payloads, message-array
   payloads, raw content payloads, tool/MCP invocation payloads.
2. The endpoint never invents an EvaluationRequest the engine wouldn't
   accept. It normalizes inputs, fills sensible defaults, and delegates to
   the existing EvaluateActionCommand.
3. The output renderer is selected by `format` (query param) or
   `X-Tex-Format` header. Default is `canonical`. Each renderer is a pure
   function over the internal EvaluateActionResult.
4. No new persistence. No new evaluation logic. Pure adapter.

Non-goals:
- Authentication. That belongs in middleware shared with the rest of the
  API surface.
- Asynchronous evaluation. Callers that need fire-and-forget can use the
  existing /evaluate route or a future /evaluate/async route.
- Rate limiting and tenancy. Those live in the eventual platform layer,
  not in this adapter.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.api.auth import TexPrincipal, authenticate_request
from tex.commands.evaluate_action import EvaluateActionCommand
from tex.domain.asi_finding import ASIFinding, ASIVerdictInfluence
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

# Sentinel defaults. Every gateway webhook contract eventually has to
# produce action_type / channel / environment; when callers omit them
# (which they will, because most gateways don't carry that taxonomy),
# Tex falls back to these.
_DEFAULT_ACTION_TYPE: Final[str] = "agent_action"
_DEFAULT_CHANNEL: Final[str] = "unspecified"
_DEFAULT_ENVIRONMENT: Final[str] = "production"
_DEFAULT_STAGE: Final[str] = "pre_call"

# Cap on synthesized content length so an upstream gateway flooding the
# webhook with a huge transcript can't push the engine into its 50k limit
# at the EvaluationRequest boundary. We mirror that limit here so we fail
# loudly rather than silently truncating.
_MAX_SYNTHESIZED_CONTENT_LENGTH: Final[int] = 50_000


class GuardrailStage(str, Enum):
    """
    The hook point at which the gateway is invoking Tex.

    Every modern AI gateway and platform exposes this distinction in some
    form (input vs output, pre_call vs post_call, prompt vs response,
    pre_invoke vs post_invoke). Tex normalizes them onto these three.
    """

    PRE_CALL = "pre_call"          # input guardrail: before LLM/tool execution
    POST_CALL = "post_call"        # output guardrail: after LLM/tool execution
    TOOL_INVOCATION = "tool_invocation"  # MCP / tool-call interception


class GuardrailFormat(str, Enum):
    """
    Response shape selector. Each gateway expects a slightly different
    response contract; rather than fragment the codebase across N routes,
    one canonical endpoint renders the chosen shape.
    """

    CANONICAL = "canonical"        # Tex-native shape; full detail
    PORTKEY = "portkey"            # {verdict: bool, data: {...}}
    LITELLM = "litellm"            # raise-on-fail style; passthrough payload on success
    CLOUDFLARE = "cloudflare"      # {action: "block"|"allow", reason, score}
    SOLO = "solo"                  # Gloo AI Gateway webhook spec
    TRUEFOUNDRY = "truefoundry"    # {verdict, severity, message}
    BEDROCK = "bedrock"            # AWS Bedrock Guardrails-compatible shape


# --------------------------------------------------------------------------- #
# Inbound payload                                                             #
# --------------------------------------------------------------------------- #


class GuardrailMessage(BaseModel):
    """One message in a chat-style payload (OpenAI / Anthropic / Bedrock shape)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    role: str = Field(min_length=1, max_length=50)
    content: str = Field(default="", max_length=_MAX_SYNTHESIZED_CONTENT_LENGTH)

    @field_validator("role", mode="before")
    @classmethod
    def _normalize_role(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise TypeError("role must be a string")
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("role must not be blank")
        return normalized

    @field_validator("content", mode="before")
    @classmethod
    def _normalize_content(cls, value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        # Some providers send content as a list of parts (OpenAI vision shape).
        # Flatten conservatively to text only; non-text parts are summarized.
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str) and text.strip():
                        parts.append(text)
                    else:
                        kind = item.get("type", "non_text_part")
                        parts.append(f"[{kind}]")
            return "\n".join(parts)
        raise TypeError("content must be a string or a list of parts")


class GuardrailToolCall(BaseModel):
    """One tool / MCP invocation that the gateway is asking Tex to evaluate."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str = Field(min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    server: str | None = Field(default=None, max_length=200)

    @field_validator("name", mode="before")
    @classmethod
    def _normalize_name(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise TypeError("name must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized

    @field_validator("arguments", mode="before")
    @classmethod
    def _normalize_arguments(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("arguments must be a dictionary")
        return dict(value)

    @field_validator("server", mode="before")
    @classmethod
    def _normalize_server(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("server must be a string")
        normalized = value.strip()
        return normalized or None


class GuardrailWebhookRequest(BaseModel):
    """
    Canonical guardrail webhook payload.

    This shape is a superset of what real gateways send. Adapters for
    specific gateways translate their native request into this object
    before calling into Tex.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    # Stage of the hook (input vs output vs tool-invocation).
    stage: GuardrailStage = Field(default=GuardrailStage.PRE_CALL)

    # Content can be supplied any of three ways:
    #   - direct `content` string (Cloudflare, Solo.io, simple webhooks)
    #   - `messages` array (OpenAI / Anthropic chat-completions style)
    #   - `prompt` + `response` pair (post-call evaluation)
    # The endpoint resolves whichever is present into a single content blob.
    content: str | None = Field(default=None, max_length=_MAX_SYNTHESIZED_CONTENT_LENGTH)
    messages: tuple[GuardrailMessage, ...] | None = Field(default=None)
    prompt: str | None = Field(default=None, max_length=_MAX_SYNTHESIZED_CONTENT_LENGTH)
    response: str | None = Field(default=None, max_length=_MAX_SYNTHESIZED_CONTENT_LENGTH)

    # Tool / MCP invocation context, when relevant.
    tool_call: GuardrailToolCall | None = Field(default=None)

    # Tex-native fields. All optional so that gateway webhooks don't have
    # to know Tex's internal taxonomy. When omitted, sensible defaults are
    # applied so the engine receives a valid EvaluationRequest.
    action_type: str | None = Field(default=None, max_length=100)
    channel: str | None = Field(default=None, max_length=50)
    environment: str | None = Field(default=None, max_length=50)
    recipient: str | None = Field(default=None, max_length=500)
    policy_id: str | None = Field(default=None, max_length=100)

    # Caller-supplied metadata. Tex does not interpret arbitrary keys; the
    # whole dict is forwarded into evidence so audit consumers can correlate
    # with the gateway's own session/trace IDs.
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Optional caller-supplied identifiers. If absent, Tex generates them.
    request_id: UUID | None = Field(default=None)
    session_id: str | None = Field(default=None, max_length=200)
    user_id: str | None = Field(default=None, max_length=200)

    # Identifies which gateway / platform is invoking Tex. Surfaced into
    # evidence so post-hoc auditors can see the call chain.
    source: str | None = Field(default=None, max_length=100)

    @field_validator(
        "content",
        "prompt",
        "response",
        mode="before",
    )
    @classmethod
    def _normalize_optional_string(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("text fields must be strings")
        normalized = value.strip()
        return normalized or None

    @field_validator(
        "action_type",
        "channel",
        "environment",
        "recipient",
        "policy_id",
        "session_id",
        "user_id",
        "source",
        mode="before",
    )
    @classmethod
    def _normalize_short_string(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("identifier fields must be strings")
        normalized = value.strip()
        return normalized or None

    @field_validator("metadata", mode="before")
    @classmethod
    def _normalize_metadata(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("metadata must be a dictionary")
        return dict(value)

    @model_validator(mode="after")
    def _require_some_content(self) -> "GuardrailWebhookRequest":
        # A guardrail request must carry *something* to evaluate. We allow
        # any of: content, messages, prompt, response, or a tool_call with
        # arguments. Empty payloads are rejected so the engine isn't asked
        # to evaluate nothing.
        has_text = any([
            self.content,
            self.messages,
            self.prompt,
            self.response,
        ])
        has_tool = self.tool_call is not None
        if not (has_text or has_tool):
            raise ValueError(
                "guardrail request must include at least one of: content, "
                "messages, prompt, response, or tool_call."
            )
        return self


# --------------------------------------------------------------------------- #
# Outbound payload (canonical)                                                #
# --------------------------------------------------------------------------- #


class GuardrailASIFindingDTO(BaseModel):
    """Compact ASI finding view for guardrail consumers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    short_code: str
    title: str
    severity: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict_influence: ASIVerdictInfluence
    counterfactual: str | None = None


class GuardrailWebhookResponse(BaseModel):
    """
    Canonical guardrail webhook response.

    Carries enough information for any gateway-specific renderer to project
    out the shape that gateway expects, plus the full Tex decision_id so a
    consumer can later retrieve the signed evidence bundle.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Pass / no-pass for gateways that only consume a boolean.
    allowed: bool

    # Tex-native three-way verdict.
    verdict: Verdict

    # Calibrated risk score in [0, 1]. Higher means more likely to be unsafe.
    score: float = Field(ge=0.0, le=1.0)

    # Tex's confidence in the verdict in [0, 1].
    confidence: float = Field(ge=0.0, le=1.0)

    # Short human-readable summary suitable for inline UX strings.
    reason: str

    # Full structured reasons from the engine. Useful for debugging.
    reasons: tuple[str, ...] = Field(default_factory=tuple)

    # Uncertainty flags raised by the routing layer.
    uncertainty_flags: tuple[str, ...] = Field(default_factory=tuple)

    # Compact ASI findings. The full Decision record carries the complete
    # finding objects with evidence trails.
    asi_findings: tuple[GuardrailASIFindingDTO, ...] = Field(default_factory=tuple)

    # Identifiers for follow-up.
    decision_id: UUID
    request_id: UUID
    policy_version: str
    evaluated_at: datetime

    # Echoes any source label the caller provided so multi-gateway
    # deployments can disambiguate downstream.
    source: str | None = None


# --------------------------------------------------------------------------- #
# Renderers                                                                   #
# --------------------------------------------------------------------------- #


def _render_canonical(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """Default Tex shape. Full detail. Used when no gateway is specified."""
    return payload.model_dump(mode="json")


def _render_portkey(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    Portkey 'Bring Your Own Guardrail' shape: {verdict: bool, data: {...}}

    Reference: https://portkey.ai/docs/product/guardrails/bring-your-own-guardrails
    """
    return {
        "verdict": payload.allowed,
        "data": {
            "reason": payload.reason,
            "score": payload.score,
            "tex_verdict": payload.verdict.value,
            "tex_decision_id": str(payload.decision_id),
            "tex_request_id": str(payload.request_id),
            "asi_findings": [
                {
                    "code": finding.short_code,
                    "title": finding.title,
                    "severity": finding.severity,
                    "verdict_influence": finding.verdict_influence.value,
                }
                for finding in payload.asi_findings
            ],
        },
    }


def _render_litellm(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    LiteLLM Generic Guardrail API shape.

    LiteLLM expects either a passthrough success or a structured failure.
    Tex's three-way verdict is collapsed: PERMIT -> action='ALLOW',
    ABSTAIN -> action='REVIEW' (LiteLLM treats this as block-with-context),
    FORBID -> action='BLOCK'.

    Reference: https://docs.litellm.ai/docs/proxy/guardrails/quick_start
    """
    if payload.verdict is Verdict.PERMIT:
        action = "ALLOW"
    elif payload.verdict is Verdict.ABSTAIN:
        action = "REVIEW"
    else:
        action = "BLOCK"
    return {
        "action": action,
        "score": payload.score,
        "message": payload.reason,
        "metadata": {
            "tex_decision_id": str(payload.decision_id),
            "tex_request_id": str(payload.request_id),
            "tex_verdict": payload.verdict.value,
            "tex_confidence": payload.confidence,
            "tex_policy_version": payload.policy_version,
        },
    }


def _render_cloudflare(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    Cloudflare AI Gateway-style guardrail shape.

    Reference: https://developers.cloudflare.com/ai-gateway/features/guardrails/
    """
    return {
        "action": "allow" if payload.allowed else "block",
        "reason": payload.reason,
        "score": payload.score,
        "categories": [finding.short_code for finding in payload.asi_findings],
        "tex_decision_id": str(payload.decision_id),
    }


def _render_solo(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    Solo.io / Gloo AI Gateway Guardrail Webhook API shape.

    Reference: https://docs.solo.io/gateway/main/ai/guardrail-api/
    """
    return {
        "action": "PASS" if payload.allowed else "REJECT",
        "reason": payload.reason,
        "modified": False,  # Tex does not rewrite content; it adjudicates.
        "metadata": {
            "tex_decision_id": str(payload.decision_id),
            "tex_verdict": payload.verdict.value,
            "tex_score": payload.score,
            "asi_codes": [finding.short_code for finding in payload.asi_findings],
        },
    }


def _render_truefoundry(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    TrueFoundry-style guardrail provider shape.

    Reference: https://www.truefoundry.com/docs/ai-gateway/code-safety-linter
    """
    severity = "high" if payload.score >= 0.75 else "medium" if payload.score >= 0.4 else "low"
    return {
        "verdict": "pass" if payload.allowed else "fail",
        "severity": severity,
        "message": payload.reason,
        "evidence": {
            "tex_decision_id": str(payload.decision_id),
            "tex_verdict": payload.verdict.value,
            "tex_score": payload.score,
            "tex_confidence": payload.confidence,
            "asi_findings": [
                {"code": f.short_code, "title": f.title, "severity": f.severity}
                for f in payload.asi_findings
            ],
        },
    }


def _render_bedrock(payload: GuardrailWebhookResponse) -> dict[str, Any]:
    """
    AWS Bedrock Guardrails-compatible shape, suitable for callers that
    were already integrating with Bedrock and want Tex as a drop-in
    replacement (or sidecar) for content moderation.
    """
    # Bedrock returns "GUARDRAIL_INTERVENED" when content is blocked, or
    # "NONE" when it's allowed. We add Tex extensions in `assessments`.
    intervened = not payload.allowed
    return {
        "action": "GUARDRAIL_INTERVENED" if intervened else "NONE",
        "outputs": [{"text": payload.reason}] if intervened else [],
        "assessments": [
            {
                "tex": {
                    "verdict": payload.verdict.value,
                    "score": payload.score,
                    "confidence": payload.confidence,
                    "decision_id": str(payload.decision_id),
                    "asi_findings": [
                        {
                            "code": f.short_code,
                            "severity": f.severity,
                            "verdict_influence": f.verdict_influence.value,
                        }
                        for f in payload.asi_findings
                    ],
                },
            },
        ],
    }


_RENDERERS: Final[dict[GuardrailFormat, Any]] = {
    GuardrailFormat.CANONICAL: _render_canonical,
    GuardrailFormat.PORTKEY: _render_portkey,
    GuardrailFormat.LITELLM: _render_litellm,
    GuardrailFormat.CLOUDFLARE: _render_cloudflare,
    GuardrailFormat.SOLO: _render_solo,
    GuardrailFormat.TRUEFOUNDRY: _render_truefoundry,
    GuardrailFormat.BEDROCK: _render_bedrock,
}


# --------------------------------------------------------------------------- #
# Synthesis: gateway payload -> EvaluationRequest                             #
# --------------------------------------------------------------------------- #


def _synthesize_content(req: GuardrailWebhookRequest) -> str:
    """
    Resolve the various ways a gateway might supply content into a single
    string suitable for Tex's content-evaluation pipeline.
    """
    # Most specific source wins. Direct `content` is treated as authoritative
    # when present.
    if req.content:
        return req.content

    # Post-call evaluations typically supply prompt + response. We keep both
    # because Tex's specialists and semantic layer benefit from seeing the
    # request that produced the response.
    if req.prompt or req.response:
        chunks: list[str] = []
        if req.prompt:
            chunks.append(f"[PROMPT]\n{req.prompt}")
        if req.response:
            chunks.append(f"[RESPONSE]\n{req.response}")
        return "\n\n".join(chunks)

    # Chat-message arrays (OpenAI / Anthropic / Bedrock shape).
    if req.messages:
        rendered: list[str] = []
        for msg in req.messages:
            if not msg.content:
                continue
            rendered.append(f"[{msg.role.upper()}]\n{msg.content}")
        if rendered:
            return "\n\n".join(rendered)

    # Tool / MCP invocation. Render the call shape so the engine can
    # evaluate intent and arguments.
    if req.tool_call:
        tc = req.tool_call
        argument_lines = "\n".join(f"  {k}: {v!r}" for k, v in tc.arguments.items())
        server_line = f" (server: {tc.server})" if tc.server else ""
        return (
            f"[TOOL_CALL]\n"
            f"name: {tc.name}{server_line}\n"
            f"arguments:\n{argument_lines or '  (none)'}"
        )

    # Defensive: model_validator already rejected this case, but keep an
    # explicit error so future code changes don't silently fall through.
    raise ValueError("guardrail request had no resolvable content")


def _synthesize_action_type(req: GuardrailWebhookRequest) -> str:
    """
    Pick a Tex action_type when the caller didn't specify one.

    The mapping is intentionally coarse. Adapters can override by setting
    `action_type` explicitly on the canonical request before calling.
    """
    if req.action_type:
        return req.action_type
    if req.tool_call is not None:
        return "tool_invocation"
    if req.stage is GuardrailStage.POST_CALL or req.response:
        return "llm_response"
    if req.messages or req.prompt:
        return "llm_request"
    return _DEFAULT_ACTION_TYPE


def _synthesize_metadata(req: GuardrailWebhookRequest) -> dict[str, Any]:
    """Merge gateway-supplied metadata with structured guardrail context."""
    merged: dict[str, Any] = dict(req.metadata)
    merged.setdefault("guardrail", {
        "stage": req.stage.value,
        "source": req.source,
        "session_id": req.session_id,
        "user_id": req.user_id,
        "tool_call": (
            {
                "name": req.tool_call.name,
                "server": req.tool_call.server,
                "argument_keys": sorted(req.tool_call.arguments.keys()),
            }
            if req.tool_call
            else None
        ),
    })
    return merged


def _to_evaluation_request(
    req: GuardrailWebhookRequest,
    *,
    principal: "TexPrincipal | None" = None,
) -> EvaluationRequest:
    """Translate a canonical guardrail payload into a Tex EvaluationRequest."""
    content = _synthesize_content(req)
    if len(content) > _MAX_SYNTHESIZED_CONTENT_LENGTH:
        raise ValueError(
            "synthesized guardrail content exceeded the maximum length of "
            f"{_MAX_SYNTHESIZED_CONTENT_LENGTH} characters"
        )

    metadata = _synthesize_metadata(req)
    if principal is not None and not principal.is_anonymous:
        metadata["tex_auth"] = {
            "tenant": principal.tenant,
            "api_key_fingerprint": principal.api_key_fingerprint,
        }

    payload: dict[str, Any] = {
        "request_id": req.request_id or uuid4(),
        "action_type": _synthesize_action_type(req),
        "content": content,
        "recipient": req.recipient,
        "channel": req.channel or _DEFAULT_CHANNEL,
        "environment": req.environment or _DEFAULT_ENVIRONMENT,
        "metadata": metadata,
        "policy_id": req.policy_id,
        "requested_at": datetime.now(UTC),
    }
    return EvaluationRequest(**payload)


# --------------------------------------------------------------------------- #
# Result -> canonical response                                                #
# --------------------------------------------------------------------------- #


def _project_asi_findings(
    findings: tuple[ASIFinding, ...],
) -> tuple[GuardrailASIFindingDTO, ...]:
    return tuple(
        GuardrailASIFindingDTO(
            short_code=f.short_code,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            verdict_influence=f.verdict_influence,
            counterfactual=f.counterfactual,
        )
        for f in findings
    )


def _summarize_reason(
    *,
    verdict: Verdict,
    reasons: tuple[str, ...],
    asi_findings: tuple[ASIFinding, ...],
) -> str:
    """
    Build a one-line reason for inline gateway UX.

    Prefer a decisive ASI finding's title when one exists; fall back to
    the first engine reason; final fallback names the verdict.
    """
    decisive = next((f for f in asi_findings if f.is_decisive), None)
    if decisive is not None:
        return f"{decisive.short_code}: {decisive.title}"
    if reasons:
        return reasons[0]
    return {
        Verdict.PERMIT: "permitted",
        Verdict.ABSTAIN: "escalate to human review",
        Verdict.FORBID: "blocked by policy",
    }[verdict]


def _build_response(
    *,
    result: Any,  # EvaluateActionResult; typed loosely to avoid a hard import cycle
    request_id: UUID,
    source: str | None,
) -> GuardrailWebhookResponse:
    """Project an EvaluateActionResult into the canonical guardrail response."""
    # The internal result shape is documented in
    # tex.commands.evaluate_action.EvaluateActionResult. We mirror the
    # projection that EvaluateResponseDTO.from_command_result already does
    # but only pull the fields the guardrail surface needs.
    decision = getattr(result, "decision")
    verdict: Verdict = decision.verdict
    asi_findings: tuple[ASIFinding, ...] = tuple(decision.asi_findings)
    reasons: tuple[str, ...] = tuple(decision.reasons)
    uncertainty_flags: tuple[str, ...] = tuple(decision.uncertainty_flags)

    return GuardrailWebhookResponse(
        allowed=verdict is Verdict.PERMIT,
        verdict=verdict,
        score=float(decision.final_score),
        confidence=float(decision.confidence),
        reason=_summarize_reason(
            verdict=verdict,
            reasons=reasons,
            asi_findings=asi_findings,
        ),
        reasons=reasons,
        uncertainty_flags=uncertainty_flags,
        asi_findings=_project_asi_findings(asi_findings),
        decision_id=decision.decision_id,
        request_id=request_id,
        policy_version=str(decision.policy_version),
        evaluated_at=decision.decided_at,
        source=source,
    )


# --------------------------------------------------------------------------- #
# Format selection                                                            #
# --------------------------------------------------------------------------- #


def _resolve_format(
    *,
    query_format: str | None,
    header_format: str | None,
) -> GuardrailFormat:
    """
    Select an output format. Header wins over query, and unknown values
    raise 400 rather than silently falling back so misconfiguration is
    surfaced loudly during integration.
    """
    chosen = (header_format or query_format or GuardrailFormat.CANONICAL.value).strip().lower()
    try:
        return GuardrailFormat(chosen)
    except ValueError as exc:
        valid = ", ".join(sorted(f.value for f in GuardrailFormat))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported guardrail format '{chosen}'. Expected one of: {valid}.",
        ) from exc


# --------------------------------------------------------------------------- #
# Router                                                                      #
# --------------------------------------------------------------------------- #


router = APIRouter(prefix="/v1/guardrail", tags=["guardrail"])


@router.post(
    "",
    summary="Canonical guardrail webhook (gateway-agnostic)",
)
def guardrail_evaluate(
    payload: GuardrailWebhookRequest,
    request: Request,
    format: str | None = Query(default=None, description="Response shape selector."),
    x_tex_format: str | None = Header(default=None, alias="X-Tex-Format"),
    principal: TexPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    """
    Evaluate one guardrail webhook call through Tex.

    This endpoint is the single integration point that gateway adapters
    (Portkey, LiteLLM, Cloudflare, Solo.io, TrueFoundry, Bedrock-style,
    Microsoft Copilot Studio external guardrails, AgentKit runtime
    guardrails, MCP servers, and SDKs) all delegate to.

    Behavior:
    1. Authenticate the request when API keys are configured.
    2. Normalize the gateway-supplied payload into an EvaluationRequest.
    3. Delegate to the existing EvaluateActionCommand. No new evaluation
       logic; this is a pure adapter.
    4. Render the result in the format requested by the caller.

    The full Tex decision is always durable in the decision store and
    evidence chain regardless of which output format is rendered. Auditors
    can hit /decisions/{decision_id}/evidence-bundle to retrieve the
    signed bundle.
    """
    chosen_format = _resolve_format(query_format=format, header_format=x_tex_format)

    try:
        domain_request = _to_evaluation_request(payload, principal=principal)
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

    canonical_response = _build_response(
        result=result,
        request_id=domain_request.request_id,
        source=payload.source,
    )

    renderer = _RENDERERS[chosen_format]
    return renderer(canonical_response)


@router.get(
    "/formats",
    summary="List supported guardrail response formats",
)
def list_guardrail_formats() -> dict[str, Any]:
    """Return the set of response shapes this Tex deployment can render."""
    return {
        "formats": sorted(f.value for f in GuardrailFormat),
        "default": GuardrailFormat.CANONICAL.value,
    }


# --------------------------------------------------------------------------- #
# App-state plumbing (mirrors tex.api.routes pattern)                         #
# --------------------------------------------------------------------------- #


def _get_evaluate_action_command(request: Request) -> EvaluateActionCommand:
    command = getattr(request.app.state, "evaluate_action_command", None)
    if command is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="evaluate_action_command is not wired on app.state.",
        )
    if not isinstance(command, EvaluateActionCommand):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="evaluate_action_command on app.state has the wrong type.",
        )
    return command


def build_guardrail_router() -> APIRouter:
    """Convenience constructor mirroring build_api_router() in tex.api.routes."""
    return router


__all__ = [
    "GuardrailFormat",
    "GuardrailMessage",
    "GuardrailStage",
    "GuardrailToolCall",
    "GuardrailWebhookRequest",
    "GuardrailWebhookResponse",
    "GuardrailASIFindingDTO",
    "build_guardrail_router",
    "router",
]
