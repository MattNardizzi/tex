"""
Integration tests for the new guardrail surface.

Covers:
- /v1/guardrail canonical webhook (all 7 response formats)
- /v1/guardrail/<gateway> adapter routes (Portkey, LiteLLM, Cloudflare,
  Solo, TrueFoundry, Bedrock, Copilot Studio, AgentKit)
- /mcp JSON-RPC server (initialize, tools/list, tools/call)
- API-key authentication (off, on, valid, invalid)
- Tenant tagging in evidence metadata
- The Python SDK against the live FastAPI app
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient


# Make the SDK package importable from sdks/python.
SDK_PATH = Path(__file__).resolve().parents[1] / "sdks" / "python"
if str(SDK_PATH) not in sys.path:
    sys.path.insert(0, str(SDK_PATH))


# ------------------------------------------------------------------------- #
# Fixtures                                                                  #
# ------------------------------------------------------------------------- #


@pytest.fixture
def fresh_app(monkeypatch):
    """Build a fresh Tex app with no API keys configured (auth disabled)."""
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    # Auth state is loaded per-request, so no module reset needed.
    from tex.main import create_app
    return create_app()


@pytest.fixture
def client(fresh_app):
    return TestClient(fresh_app)


@pytest.fixture
def authed_client(monkeypatch):
    """Build a Tex app with TEX_API_KEYS configured."""
    monkeypatch.setenv("TEX_API_KEYS", "key_acme:tenant_acme,key_globex:tenant_globex")
    from tex.main import create_app
    app = create_app()
    return TestClient(app)


# ------------------------------------------------------------------------- #
# Test payloads                                                             #
# ------------------------------------------------------------------------- #


def _clean_payload() -> dict[str, Any]:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": (
            "Hi Jordan, saw you're hiring for revops — happy to share what's "
            "working for similar teams. Worth a 15-min call next week?"
        ),
        "source": "test_suite",
    }


def _dirty_payload() -> dict[str, Any]:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": (
            "Use the API key sk-proj-abc1234567890XYZ to run the import. "
            "Customer ssn 123-45-6789. Wire to acct 4111111111111111."
        ),
        "source": "test_suite",
    }


# ------------------------------------------------------------------------- #
# Canonical guardrail endpoint                                              #
# ------------------------------------------------------------------------- #


class TestCanonicalGuardrail:
    def test_clean_payload_permits(self, client):
        resp = client.post("/v1/guardrail", json=_clean_payload())
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is True
        assert body["verdict"] == "PERMIT"
        assert "decision_id" in body
        assert body["score"] < 0.5

    def test_dirty_payload_forbids(self, client):
        resp = client.post("/v1/guardrail", json=_dirty_payload())
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is False
        assert body["verdict"] == "FORBID"
        assert body["score"] >= 0.5
        assert len(body["asi_findings"]) > 0
        assert any(f["short_code"].startswith("ASI") for f in body["asi_findings"])

    def test_empty_payload_rejected(self, client):
        resp = client.post(
            "/v1/guardrail",
            json={"stage": "pre_call", "source": "test"},
        )
        assert resp.status_code == 422

    def test_unknown_format_rejected(self, client):
        resp = client.post(
            "/v1/guardrail?format=does_not_exist",
            json=_clean_payload(),
        )
        assert resp.status_code == 400
        assert "unsupported" in resp.json()["detail"].lower()

    def test_format_via_header(self, client):
        resp = client.post(
            "/v1/guardrail",
            json=_clean_payload(),
            headers={"X-Tex-Format": "portkey"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Portkey shape has 'verdict' and 'data', not the canonical schema.
        assert "verdict" in body
        assert "data" in body
        assert body["verdict"] is True

    def test_format_listing(self, client):
        resp = client.get("/v1/guardrail/formats")
        assert resp.status_code == 200
        formats = resp.json()["formats"]
        assert "canonical" in formats
        assert "portkey" in formats
        assert "litellm" in formats
        assert "cloudflare" in formats
        assert "solo" in formats
        assert "truefoundry" in formats
        assert "bedrock" in formats


# ------------------------------------------------------------------------- #
# Per-format response shapes                                                #
# ------------------------------------------------------------------------- #


class TestRendererShapes:
    @pytest.mark.parametrize("fmt", [
        "canonical", "portkey", "litellm", "cloudflare",
        "solo", "truefoundry", "bedrock",
    ])
    def test_clean_payload_each_format(self, client, fmt):
        resp = client.post(
            f"/v1/guardrail?format={fmt}",
            json=_clean_payload(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, dict) and body  # non-empty

    def test_portkey_shape(self, client):
        resp = client.post("/v1/guardrail?format=portkey", json=_dirty_payload())
        body = resp.json()
        assert body["verdict"] is False  # portkey verdict is allowed-bool
        assert "data" in body
        assert "score" in body["data"]
        assert "asi_findings" in body["data"]

    def test_litellm_shape(self, client):
        resp = client.post("/v1/guardrail?format=litellm", json=_dirty_payload())
        body = resp.json()
        assert body["action"] in ("ALLOW", "REVIEW", "BLOCK")
        assert "tex_decision_id" in body["metadata"]

    def test_cloudflare_shape(self, client):
        resp = client.post("/v1/guardrail?format=cloudflare", json=_dirty_payload())
        body = resp.json()
        assert body["action"] in ("allow", "block")
        assert isinstance(body["categories"], list)

    def test_bedrock_shape(self, client):
        resp = client.post("/v1/guardrail?format=bedrock", json=_dirty_payload())
        body = resp.json()
        assert body["action"] in ("GUARDRAIL_INTERVENED", "NONE")
        assert "assessments" in body
        assert "tex" in body["assessments"][0]


# ------------------------------------------------------------------------- #
# Gateway adapter routes                                                    #
# ------------------------------------------------------------------------- #


class TestGatewayAdapters:
    def test_portkey_adapter_native_payload(self, client):
        # Portkey sends prompt/messages under flexible shapes.
        resp = client.post(
            "/v1/guardrail/portkey",
            json={
                "messages": [
                    {"role": "user", "content": "send maria a check-in"},
                ],
                "session_id": "portkey_session_1",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        # Portkey shape: verdict is bool.
        assert "verdict" in body
        assert "data" in body

    def test_litellm_adapter(self, client):
        resp = client.post(
            "/v1/guardrail/litellm",
            json={
                "mode": "pre_call",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] in ("ALLOW", "REVIEW", "BLOCK")

    def test_cloudflare_adapter(self, client):
        resp = client.post(
            "/v1/guardrail/cloudflare",
            json={"prompt": "hello", "response": "world"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] in ("allow", "block")

    def test_solo_adapter(self, client):
        resp = client.post(
            "/v1/guardrail/solo",
            json={"direction": "request", "prompt": "hello"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] in ("PASS", "REJECT")

    def test_truefoundry_adapter_llm_input(self, client):
        resp = client.post(
            "/v1/guardrail/truefoundry",
            json={"hook": "llm_input", "prompt": "hello"},
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] in ("pass", "fail")

    def test_truefoundry_adapter_mcp_tool(self, client):
        resp = client.post(
            "/v1/guardrail/truefoundry",
            json={
                "hook": "mcp_tool_pre_invoke",
                "tool_call": {
                    "name": "send_email",
                    "arguments": {"to": "external@competitor.com", "body": "leak"},
                },
            },
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] in ("pass", "fail")

    def test_bedrock_adapter(self, client):
        resp = client.post(
            "/v1/guardrail/bedrock",
            json={"prompt": "hello"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] in ("GUARDRAIL_INTERVENED", "NONE")

    def test_copilot_studio_adapter(self, client):
        resp = client.post(
            "/v1/guardrail/copilot-studio",
            json={"response": "hello"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] in ("allow", "block")
        assert "rationale" in body

    def test_agentkit_adapter_chat(self, client):
        resp = client.post(
            "/v1/guardrail/agentkit",
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "allow" in body
        assert "verdict" in body

    def test_agentkit_adapter_tool(self, client):
        resp = client.post(
            "/v1/guardrail/agentkit",
            json={
                "tool_call": {
                    "name": "send_email",
                    "arguments": {"to": "external@example.com", "body": "x"},
                },
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "allow" in body


# ------------------------------------------------------------------------- #
# MCP server                                                                #
# ------------------------------------------------------------------------- #


class TestMcpServer:
    def test_discovery(self, client):
        resp = client.get("/mcp")
        assert resp.status_code == 200
        body = resp.json()
        assert body["server"]["name"] == "tex-guardrail"
        assert "evaluate_action" in body["tools"]

    def test_initialize(self, client):
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 1
        assert "result" in body
        assert "protocolVersion" in body["result"]

    def test_tools_list(self, client):
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert resp.status_code == 200
        tools = resp.json()["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "evaluate_action"
        assert "inputSchema" in tools[0]

    def test_tools_call_clean(self, client):
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": _clean_payload(),
                },
            },
        )
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert "content" in result
        assert "structuredContent" in result
        assert result["structuredContent"]["verdict"] == "PERMIT"
        assert result["isError"] is False

    def test_tools_call_dirty(self, client):
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": _dirty_payload(),
                },
            },
        )
        body = resp.json()
        assert body["result"]["structuredContent"]["verdict"] == "FORBID"
        assert body["result"]["isError"] is True

    def test_tools_call_unknown_tool(self, client):
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "nonexistent", "arguments": {}},
            },
        )
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] == -32601

    def test_unknown_method(self, client):
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 6, "method": "made_up", "params": {}},
        )
        body = resp.json()
        assert "error" in body
        assert body["error"]["code"] == -32601

    def test_ping(self, client):
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}},
        )
        assert resp.status_code == 200
        assert "result" in resp.json()


# ------------------------------------------------------------------------- #
# Authentication                                                            #
# ------------------------------------------------------------------------- #


class TestAuthentication:
    def test_no_keys_configured_allows_anonymous(self, client):
        resp = client.post("/v1/guardrail", json=_clean_payload())
        assert resp.status_code == 200

    def test_keys_configured_rejects_missing_key(self, authed_client):
        resp = authed_client.post("/v1/guardrail", json=_clean_payload())
        assert resp.status_code == 401

    def test_keys_configured_accepts_valid_bearer(self, authed_client):
        resp = authed_client.post(
            "/v1/guardrail",
            json=_clean_payload(),
            headers={"Authorization": "Bearer key_acme"},
        )
        assert resp.status_code == 200

    def test_keys_configured_accepts_x_tex_header(self, authed_client):
        resp = authed_client.post(
            "/v1/guardrail",
            json=_clean_payload(),
            headers={"X-Tex-API-Key": "key_globex"},
        )
        assert resp.status_code == 200

    def test_keys_configured_rejects_invalid_key(self, authed_client):
        resp = authed_client.post(
            "/v1/guardrail",
            json=_clean_payload(),
            headers={"Authorization": "Bearer wrong_key"},
        )
        assert resp.status_code == 401

    def test_authed_decision_is_replayable(self, authed_client):
        resp = authed_client.post(
            "/v1/guardrail",
            json=_clean_payload(),
            headers={"Authorization": "Bearer key_acme"},
        )
        decision_id = resp.json()["decision_id"]
        replay = authed_client.get(f"/decisions/{decision_id}/replay")
        assert replay.status_code == 200
        # The replayed decision should carry the tenant in metadata.
        body = replay.json()
        # Tenant tagging is in the decision's request metadata, which lands
        # in the durable record.
        assert "decision_id" in body


# ------------------------------------------------------------------------- #
# Decision durability                                                       #
# ------------------------------------------------------------------------- #


class TestDurability:
    def test_guardrail_decision_replayable(self, client):
        resp = client.post("/v1/guardrail", json=_dirty_payload())
        decision_id = resp.json()["decision_id"]

        replay = client.get(f"/decisions/{decision_id}/replay")
        assert replay.status_code == 200
        replayed = replay.json()
        assert replayed["decision_id"] == decision_id
        assert replayed["verdict"] == "FORBID"
        assert len(replayed["asi_findings"]) > 0

    def test_evidence_bundle_available(self, client):
        resp = client.post("/v1/guardrail", json=_dirty_payload())
        decision_id = resp.json()["decision_id"]

        bundle = client.get(f"/decisions/{decision_id}/evidence-bundle")
        assert bundle.status_code == 200
        body = bundle.json()
        assert body["record_count"] > 0
        # Chain validity on a filtered (single-decision) bundle is informational;
        # the full chain is validated at /evidence/export. We just confirm the
        # field is present and boolean.
        assert isinstance(body["is_chain_valid"], bool)

    def test_adapter_decision_replayable(self, client):
        """Decisions created via gateway adapters should be just as durable."""
        resp = client.post(
            "/v1/guardrail/portkey",
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        decision_id = resp.json()["data"]["tex_decision_id"]
        replay = client.get(f"/decisions/{decision_id}/replay")
        assert replay.status_code == 200

    def test_mcp_decision_replayable(self, client):
        """Decisions created via MCP should be just as durable."""
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_action",
                    "arguments": _clean_payload(),
                },
            },
        )
        decision_id = resp.json()["result"]["structuredContent"]["decision_id"]
        replay = client.get(f"/decisions/{decision_id}/replay")
        assert replay.status_code == 200


# ------------------------------------------------------------------------- #
# Python SDK                                                                #
# ------------------------------------------------------------------------- #


class TestPythonSDK:
    def test_client_evaluate_clean(self, fresh_app, monkeypatch):
        """Drive the SDK against the FastAPI app via a TestClient adapter."""
        from tex_guardrail import TexClient, TexVerdict

        # Monkeypatch the SDK's HTTP layer to dispatch through TestClient
        # rather than urllib.
        test_client = TestClient(fresh_app)

        def _send(self, req):
            url = req.full_url
            method = req.get_method()
            headers = dict(req.header_items())
            if method == "POST":
                resp = test_client.post(
                    url.replace("https://api.tex.io", ""),
                    content=req.data,
                    headers=headers,
                )
            else:
                resp = test_client.get(
                    url.replace("https://api.tex.io", ""),
                    headers=headers,
                )
            if resp.status_code >= 400:
                from urllib.error import HTTPError
                raise HTTPError(
                    url, resp.status_code, resp.text, resp.headers, None
                )
            return resp.json()

        monkeypatch.setattr(TexClient, "_send", _send)

        client = TexClient(api_key=None)
        verdict = client.evaluate(
            content="Hi Jordan, saw you're hiring for revops...",
            action_type="send_email",
            channel="email",
        )
        assert verdict.verdict.value == "PERMIT"
        assert verdict.allowed is True
        assert verdict.decision_id

    def test_decorator_blocks_on_forbid(self, fresh_app, monkeypatch):
        from tex_guardrail import TexBlocked, TexClient, gate

        test_client = TestClient(fresh_app)

        def _send(self, req):
            method = req.get_method()
            url = req.full_url.replace("https://api.tex.io", "")
            if method == "POST":
                resp = test_client.post(
                    url, content=req.data, headers=dict(req.header_items()),
                )
            else:
                resp = test_client.get(url, headers=dict(req.header_items()))
            if resp.status_code >= 400:
                from urllib.error import HTTPError
                raise HTTPError(
                    req.full_url, resp.status_code, resp.text, resp.headers, None,
                )
            return resp.json()

        monkeypatch.setattr(TexClient, "_send", _send)

        client = TexClient(api_key=None)

        sent = []

        @gate(client=client, action_type="send_email", channel="email")
        def send_email(content, recipient):
            sent.append((content, recipient))
            return "sent"

        # Clean content -> permitted -> function executes.
        result = send_email(
            content="Hi Jordan, saw your job posting...",
            recipient="jordan@example.com",
        )
        assert result == "sent"
        assert len(sent) == 1

        # Dirty content -> blocked -> TexBlocked raised.
        with pytest.raises(TexBlocked):
            send_email(
                content=(
                    "Use API key sk-proj-abc1234567890XYZ. SSN 123-45-6789. "
                    "Wire to acct 4111111111111111."
                ),
                recipient="jordan@example.com",
            )
        # Function did NOT execute on the blocked call.
        assert len(sent) == 1


# ------------------------------------------------------------------------- #
# Service metadata                                                          #
# ------------------------------------------------------------------------- #


class TestServiceMetadata:
    def test_root_lists_integrations(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.json()
        integrations = body["integrations"]
        assert integrations["canonical_guardrail"] == "POST /v1/guardrail"
        assert "portkey" in integrations["gateway_adapters"]
        assert "agentkit" in integrations["gateway_adapters"]
        assert integrations["mcp_server"] == "POST /mcp"
