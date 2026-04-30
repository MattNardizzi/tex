"""
V12 — enforcement-layer tests.

Five guarantees the gate makes; each has dedicated tests:

1. FORBID always blocks the wrapped action.
2. PERMIT always passes through transparently.
3. ABSTAIN behavior follows the configured policy (BLOCK / ALLOW / REVIEW).
4. Transport failures fail closed by default; fail-open is operator-explicit.
5. Every gated execution emits exactly one GateEvent; observer failures
   are suppressed and never break enforcement.

Plus integration coverage for:

- decorator form (`@tex_gated`) — shape and behavior
- async gate (`TexGateAsync`) — same five guarantees on the async path
- DirectCommandTransport against the real EvaluateActionCommand
- HttpClientTransport using a fake httpx-compatible client
- MCP middleware adapter
- CrewAI duck-typed adapter (CrewAI itself is not installed in test)
- HTTP enforcement proxy: refuses on FORBID, forwards on PERMIT,
  surfaces evidence on refusal
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.verdict import Verdict
from tex.enforcement import (
    AbstainPolicy,
    DirectCommandTransport,
    GateConfig,
    HttpClientTransport,
    TexAbstainError,
    TexForbiddenError,
    TexGate,
    TexGateAsync,
    TexUnavailableError,
    tex_gated,
)
from tex.enforcement.adapters import (
    make_crewai_tex_tool,
    make_mcp_tool_middleware,
)
from tex.enforcement.events import CollectingObserver, GateEvent
from tex.enforcement.proxy import (
    UpstreamForwarder,
    build_enforcement_proxy,
    default_content_extractor,
)
from tex.enforcement.transport import CallableTransport, TransportResult
from tex.main import build_runtime


# --------------------------------------------------------------------------- #
# Helpers — synthetic responses + transports                                  #
# --------------------------------------------------------------------------- #


def _make_response(verdict: Verdict, *, score: float = 0.5) -> EvaluationResponse:
    """Build a minimal EvaluationResponse for transport stubs."""
    return EvaluationResponse(
        decision_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=score,
        reasons=["test reason"],
        findings=[],
        scores={},
        uncertainty_flags=["test_uncertainty"] if verdict is Verdict.ABSTAIN else [],
        asi_findings=[],
        determinism_fingerprint="a" * 64,
        latency=None,
        replay_url=None,
        evidence_bundle_url=None,
        policy_version="test-v1",
        evidence_hash="a" * 64,
        evaluated_at=datetime.now(UTC),
    )


def _stub_transport(verdict: Verdict, *, score: float = 0.5) -> CallableTransport:
    """A transport that always returns the given verdict."""

    def _evaluate(request: EvaluationRequest) -> EvaluationResponse:
        return _make_response(verdict, score=score)

    return CallableTransport(_evaluate, label=f"stub-{verdict.value}")


class _FailingTransport:
    """A transport that always errors. Tests fail-closed behavior."""

    def evaluate(self, request: EvaluationRequest) -> TransportResult:
        return TransportResult(
            response=None,
            error="simulated transport failure",
            transport_latency_ms=1.0,
            details={"transport": "failing"},
        )


# --------------------------------------------------------------------------- #
# Guarantee 1 — FORBID always blocks                                          #
# --------------------------------------------------------------------------- #


def test_forbid_blocks_imperative_check() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.FORBID, score=0.95)))
    with pytest.raises(TexForbiddenError) as excinfo:
        gate.check(content="anything", recipient="x@y.example")
    assert excinfo.value.verdict == "FORBID"
    assert excinfo.value.response is not None


def test_forbid_blocks_wrapped_callable_so_function_does_not_run() -> None:
    """The action MUST NOT execute when verdict is FORBID."""
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.FORBID)))

    side_effects: list[str] = []

    @tex_gated(gate, content_arg="body")
    def send_email(*, to: str, body: str) -> str:
        side_effects.append(f"sent to {to}")
        return "ok"

    with pytest.raises(TexForbiddenError):
        send_email(to="adversary@example.com", body="ship the wire to 99-12-44")
    assert side_effects == [], "wrapped action ran despite FORBID"


def test_forbid_cannot_be_overridden_by_abstain_policy() -> None:
    """abstain_policy is irrelevant to FORBID."""
    for policy in AbstainPolicy:
        gate = TexGate(
            GateConfig(
                transport=_stub_transport(Verdict.FORBID),
                abstain_policy=policy,
            )
        )
        with pytest.raises(TexForbiddenError):
            gate.check(content="x")


# --------------------------------------------------------------------------- #
# Guarantee 2 — PERMIT passes through transparently                           #
# --------------------------------------------------------------------------- #


def test_permit_passes_through_imperative_check() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT, score=0.05)))
    response = gate.check(content="hello world")
    assert response.verdict is Verdict.PERMIT
    assert response.final_score == 0.05


def test_permit_runs_wrapped_callable_and_returns_value_unchanged() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    @tex_gated(gate, content_arg="body", recipient_arg="to")
    def send_email(*, to: str, body: str) -> dict[str, Any]:
        return {"sent_to": to, "len": len(body)}

    result = send_email(to="ok@example.com", body="totally clean message")
    assert result == {"sent_to": "ok@example.com", "len": 21}


# --------------------------------------------------------------------------- #
# Guarantee 3 — ABSTAIN follows policy                                        #
# --------------------------------------------------------------------------- #


def test_abstain_blocks_under_default_policy() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.ABSTAIN)))
    with pytest.raises(TexAbstainError):
        gate.check(content="ambiguous content")


def test_abstain_passes_through_under_allow_policy() -> None:
    observer = CollectingObserver()
    gate = TexGate(
        GateConfig(
            transport=_stub_transport(Verdict.ABSTAIN),
            abstain_policy=AbstainPolicy.ALLOW,
            observer=observer,
        )
    )
    response = gate.check(content="ambiguous content")
    assert response.verdict is Verdict.ABSTAIN
    # Critical: the wrapped callable would have executed; the gate
    # records this in the audit trail.
    assert observer.events[-1].outcome == "executed"
    assert observer.events[-1].details.get("abstain_overridden") is True


def test_abstain_routes_to_review_under_review_policy() -> None:
    observer = CollectingObserver()
    gate = TexGate(
        GateConfig(
            transport=_stub_transport(Verdict.ABSTAIN),
            abstain_policy=AbstainPolicy.REVIEW,
            observer=observer,
        )
    )
    with pytest.raises(TexAbstainError) as excinfo:
        gate.check(content="needs human review")
    assert excinfo.value.details["abstain_policy"] == "REVIEW"
    assert observer.events[-1].outcome == "reviewed"


# --------------------------------------------------------------------------- #
# Guarantee 4 — fail-closed by default                                        #
# --------------------------------------------------------------------------- #


def test_transport_failure_fails_closed_by_default() -> None:
    gate = TexGate(GateConfig(transport=_FailingTransport()))

    side_effects: list[str] = []

    @tex_gated(gate, content_arg="body")
    def send_email(*, body: str) -> str:
        side_effects.append("sent")
        return "ok"

    with pytest.raises(TexUnavailableError):
        send_email(body="anything")
    assert side_effects == [], "wrapped action ran despite Tex being unavailable"


def test_transport_failure_can_fail_open_when_explicit() -> None:
    """fail_closed=False is operator-explicit, never default."""
    observer = CollectingObserver()
    gate = TexGate(
        GateConfig(
            transport=_FailingTransport(),
            fail_closed=False,
            observer=observer,
        )
    )
    response = gate.check(content="anything")
    # Synthetic ABSTAIN — fail-open does NOT mean PERMIT.
    assert response.verdict is Verdict.ABSTAIN
    assert "tex_unavailable" in response.uncertainty_flags
    # The audit event should still record what happened.
    assert observer.events[-1].verdict == "UNAVAILABLE"
    assert observer.events[-1].outcome == "executed"


# --------------------------------------------------------------------------- #
# Guarantee 5 — every gated execution emits exactly one GateEvent             #
# --------------------------------------------------------------------------- #


def test_observer_called_once_per_check() -> None:
    observer = CollectingObserver()
    gate = TexGate(
        GateConfig(
            transport=_stub_transport(Verdict.PERMIT),
            observer=observer,
        )
    )
    for _ in range(5):
        gate.check(content="some content")
    assert len(observer.events) == 5
    for event in observer.events:
        assert isinstance(event, GateEvent)
        assert event.verdict == "PERMIT"
        assert event.outcome == "executed"
        assert event.gate_latency_ms >= 0.0


def test_observer_failure_does_not_break_gate() -> None:
    """A buggy observer must never break enforcement."""

    def buggy_observer(event: GateEvent) -> None:
        raise RuntimeError("observer is broken")

    gate = TexGate(
        GateConfig(
            transport=_stub_transport(Verdict.PERMIT),
            observer=buggy_observer,
        )
    )
    # Should NOT raise — the gate suppresses observer failures.
    response = gate.check(content="anything")
    assert response.verdict is Verdict.PERMIT


def test_observer_records_event_on_blocked_action() -> None:
    observer = CollectingObserver()
    gate = TexGate(
        GateConfig(
            transport=_stub_transport(Verdict.FORBID),
            observer=observer,
        )
    )
    with pytest.raises(TexForbiddenError):
        gate.check(content="anything", recipient="x@y.example")
    assert len(observer.events) == 1
    event = observer.events[0]
    assert event.verdict == "FORBID"
    assert event.outcome == "blocked"


# --------------------------------------------------------------------------- #
# Decorator shape                                                             #
# --------------------------------------------------------------------------- #


def test_decorator_preserves_function_metadata() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    @tex_gated(gate, content_arg="body")
    def send_email(*, to: str, body: str) -> str:
        """Send an email."""
        return f"to={to}"

    assert send_email.__name__ == "send_email"
    assert send_email.__doc__ == "Send an email."


def test_decorator_raises_typeerror_when_content_arg_missing() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    @tex_gated(gate, content_arg="body")
    def send_email(*, body: str) -> str:
        return "ok"

    with pytest.raises(TypeError, match="requires keyword argument 'body'"):
        send_email()  # type: ignore[call-arg]


# --------------------------------------------------------------------------- #
# Async gate                                                                  #
# --------------------------------------------------------------------------- #


def test_async_gate_blocks_on_forbid() -> None:
    gate = TexGateAsync(GateConfig(transport=_stub_transport(Verdict.FORBID)))

    async def run() -> None:
        with pytest.raises(TexForbiddenError):
            await gate.check(content="anything")

    asyncio.run(run())


def test_async_gate_runs_wrapped_coroutine_only_on_permit() -> None:
    gate = TexGateAsync(GateConfig(transport=_stub_transport(Verdict.PERMIT)))
    side_effects: list[str] = []

    async def send(*, body: str) -> str:
        side_effects.append("sent")
        return "ok"

    gated = gate.wrap(send, content_arg="body")

    async def run() -> None:
        result = await gated(body="hi")
        assert result == "ok"

    asyncio.run(run())
    assert side_effects == ["sent"]


def test_async_gate_does_not_run_wrapped_coroutine_on_forbid() -> None:
    gate = TexGateAsync(GateConfig(transport=_stub_transport(Verdict.FORBID)))
    side_effects: list[str] = []

    async def send(*, body: str) -> str:
        side_effects.append("sent")
        return "ok"

    gated = gate.wrap(send, content_arg="body")

    async def run() -> None:
        with pytest.raises(TexForbiddenError):
            await gated(body="bad")

    asyncio.run(run())
    assert side_effects == [], "async wrapped coroutine ran despite FORBID"


# --------------------------------------------------------------------------- #
# Direct command transport (real Tex)                                         #
# --------------------------------------------------------------------------- #


def test_direct_command_transport_against_real_tex() -> None:
    """End-to-end: the gate calls real Tex through the in-process command."""
    runtime = build_runtime(evidence_path="/tmp/tex-v12-direct.jsonl")
    transport = DirectCommandTransport(runtime.evaluate_action_command)
    gate = TexGate(GateConfig(transport=transport))

    response = gate.check(
        content="Friendly, totally clean outbound message about scheduling.",
        action_type="send_email",
        channel="email",
        environment="production",
        recipient="prospect@target.example",
    )
    # We don't assert verdict because real Tex makes the call; we
    # assert the gate produced a response with a real fingerprint.
    assert response.determinism_fingerprint is not None
    assert len(response.determinism_fingerprint) == 64


# --------------------------------------------------------------------------- #
# HTTP client transport                                                       #
# --------------------------------------------------------------------------- #


class _FakeHttpResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = "fake"

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeHttpClient:
    """Minimal httpx-compatible double for testing the HTTP transport."""

    def __init__(self, response: _FakeHttpResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any],
        timeout: float,
        headers: dict[str, str],
    ) -> _FakeHttpResponse:
        self.calls.append(
            {"url": url, "json": json, "timeout": timeout, "headers": dict(headers)}
        )
        return self._response


def test_http_transport_parses_permit_response() -> None:
    response_payload = _make_response(Verdict.PERMIT).model_dump(mode="json")
    fake_http = _FakeHttpClient(_FakeHttpResponse(200, response_payload))
    transport = HttpClientTransport(
        client=fake_http,
        url="https://tex.example/evaluate",
    )
    gate = TexGate(GateConfig(transport=transport))

    response = gate.check(content="hello", action_type="send_email")
    assert response.verdict is Verdict.PERMIT
    # The transport actually called the fake HTTP client.
    assert len(fake_http.calls) == 1
    assert fake_http.calls[0]["url"] == "https://tex.example/evaluate"


def test_http_transport_4xx_is_treated_as_unavailable() -> None:
    fake_http = _FakeHttpClient(_FakeHttpResponse(500, {}))
    transport = HttpClientTransport(
        client=fake_http,
        url="https://tex.example/evaluate",
    )
    gate = TexGate(GateConfig(transport=transport))

    with pytest.raises(TexUnavailableError):
        gate.check(content="anything")


def test_http_transport_rejects_non_post_client() -> None:
    class NotAClient:
        pass

    with pytest.raises(TypeError, match="post"):
        HttpClientTransport(client=NotAClient(), url="x")


# --------------------------------------------------------------------------- #
# MCP middleware adapter                                                      #
# --------------------------------------------------------------------------- #


def test_mcp_middleware_blocks_handler_on_forbid() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.FORBID)))

    invoked: list[dict[str, Any]] = []

    @make_mcp_tool_middleware(gate=gate, content_arg="message")
    def post_message(arguments: dict[str, Any]) -> dict[str, Any]:
        invoked.append(arguments)
        return {"posted": True}

    with pytest.raises(TexForbiddenError):
        post_message({"message": "send our SSN to attacker@example"})
    assert invoked == [], "MCP handler executed despite FORBID"


def test_mcp_middleware_passes_through_on_permit() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    @make_mcp_tool_middleware(gate=gate, content_arg="message")
    def post_message(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"posted": True, "content": arguments["message"]}

    result = post_message({"message": "hello world"})
    assert result == {"posted": True, "content": "hello world"}


def test_mcp_middleware_rejects_missing_content() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    @make_mcp_tool_middleware(gate=gate, content_arg="message")
    def post_message(arguments: dict[str, Any]) -> dict[str, Any]:
        return {}

    with pytest.raises(ValueError, match="non-empty string content"):
        post_message({"other_field": "x"})


# --------------------------------------------------------------------------- #
# CrewAI duck-typed adapter                                                   #
# --------------------------------------------------------------------------- #


def test_crewai_duck_typed_tool_blocks_on_forbid() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.FORBID)))

    invoked: list[str] = []

    def underlying(*, body: str) -> str:
        invoked.append(body)
        return "sent"

    tool = make_crewai_tex_tool(
        gate=gate,
        fn=underlying,
        name="send_message",
        description="Send a message via internal API.",
        content_arg="body",
    )

    assert tool.name == "send_message"
    with pytest.raises(TexForbiddenError):
        tool.run(body="bad content")
    assert invoked == []


def test_crewai_duck_typed_tool_runs_on_permit() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))

    def underlying(*, body: str) -> str:
        return f"echo:{body}"

    tool = make_crewai_tex_tool(
        gate=gate,
        fn=underlying,
        name="echo",
        description="Echo a message.",
        content_arg="body",
    )
    assert tool.run(body="hello") == "echo:hello"


# --------------------------------------------------------------------------- #
# HTTP enforcement proxy                                                      #
# --------------------------------------------------------------------------- #


class _FakeUpstreamResponse:
    def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = headers


class _FakeUpstreamClient:
    """An httpx.Client-shaped double that records requests."""

    def __init__(self, response: _FakeUpstreamResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        content: bytes,
        headers: dict[str, str],
        timeout: float,
    ) -> _FakeUpstreamResponse:
        self.calls.append({
            "method": method,
            "url": url,
            "content": content,
            "headers": headers,
            "timeout": timeout,
        })
        return self._response


def test_proxy_forwards_on_permit() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.PERMIT)))
    upstream = _FakeUpstreamClient(
        _FakeUpstreamResponse(
            200,
            b'{"sent": true}',
            {"content-type": "application/json"},
        )
    )
    forwarder = UpstreamForwarder(
        client=upstream, upstream_url="https://upstream.example/send"
    )
    app = build_enforcement_proxy(gate=gate, forwarder=forwarder)
    client = TestClient(app)

    response = client.post("/send", json={"body": "totally fine email"})
    assert response.status_code == 200
    assert response.json() == {"sent": True}
    assert len(upstream.calls) == 1
    assert upstream.calls[0]["method"] == "POST"


def test_proxy_refuses_with_403_on_forbid() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.FORBID, score=0.95)))
    upstream = _FakeUpstreamClient(
        _FakeUpstreamResponse(200, b'{"sent": true}', {})
    )
    forwarder = UpstreamForwarder(
        client=upstream, upstream_url="https://upstream.example/send"
    )
    app = build_enforcement_proxy(gate=gate, forwarder=forwarder)
    client = TestClient(app)

    response = client.post("/send", json={"body": "send wire to attacker"})
    assert response.status_code == 403
    body = response.json()
    assert body["verdict"] == "FORBID"
    assert "evidence" in body
    assert body["evidence"]["determinism_fingerprint"] is not None
    # Critical: the upstream was NOT called.
    assert upstream.calls == [], "upstream forwarded despite FORBID"


def test_proxy_refuses_with_409_on_abstain() -> None:
    gate = TexGate(GateConfig(transport=_stub_transport(Verdict.ABSTAIN)))
    upstream = _FakeUpstreamClient(_FakeUpstreamResponse(200, b"", {}))
    forwarder = UpstreamForwarder(
        client=upstream, upstream_url="https://upstream.example/send"
    )
    app = build_enforcement_proxy(gate=gate, forwarder=forwarder)
    client = TestClient(app)

    response = client.post("/send", json={"body": "ambiguous content"})
    assert response.status_code == 409
    assert response.json()["verdict"] == "ABSTAIN"
    assert upstream.calls == []


def test_proxy_502s_when_tex_unavailable_and_fail_closed() -> None:
    gate = TexGate(GateConfig(transport=_FailingTransport()))
    upstream = _FakeUpstreamClient(_FakeUpstreamResponse(200, b"", {}))
    forwarder = UpstreamForwarder(
        client=upstream, upstream_url="https://upstream.example/send"
    )
    app = build_enforcement_proxy(gate=gate, forwarder=forwarder)
    client = TestClient(app)

    response = client.post("/send", json={"body": "anything"})
    assert response.status_code == 502
    assert response.json()["verdict"] == "UNAVAILABLE"
    assert upstream.calls == []


def test_default_content_extractor_finds_common_fields() -> None:
    body = b'{"to": "x@y.com", "body": "hello"}'
    content, recipient = default_content_extractor(body)
    assert content == "hello"
    assert recipient == "x@y.com"


def test_default_content_extractor_falls_back_to_full_body() -> None:
    body = b"not json at all"
    content, recipient = default_content_extractor(body)
    assert content == "not json at all"
    assert recipient is None


# --------------------------------------------------------------------------- #
# Backwards compatibility: enforcement is purely additive                     #
# --------------------------------------------------------------------------- #


def test_enforcement_module_does_not_alter_existing_runtime() -> None:
    """
    Importing tex.enforcement should not change anything about how
    the existing runtime behaves. V12 is purely additive.
    """
    runtime_a = build_runtime(evidence_path="/tmp/tex-v12-noop-a.jsonl")
    import tex.enforcement  # noqa: F401 — explicit import for the test

    runtime_b = build_runtime(evidence_path="/tmp/tex-v12-noop-b.jsonl")

    assert type(runtime_a.pdp) is type(runtime_b.pdp)
    assert type(runtime_a.evaluate_action_command) is type(
        runtime_b.evaluate_action_command
    )
    # Both should still accept the same EvaluationRequest shape.
    req = EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content="basic content",
        channel="email",
        environment="production",
    )
    runtime_a.evaluate_action_command.execute(req)
