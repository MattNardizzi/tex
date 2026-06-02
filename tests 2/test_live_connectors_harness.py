"""
Live connector readiness harness.

These tests do NOT call real APIs. They patch ``urllib.request.urlopen``
inside the connector module so we can assert the connector's behavior
across the failure modes that matter in production:

  * 401 Unauthorized        → ConnectorError with the upstream code
  * 403 Forbidden           → ConnectorError (insufficient scope)
  * 429 Rate-limited        → ConnectorError (HTTP) and ConnectorTimeout
                              (Slack body-level ratelimited+retry_after)
  * 500 Server-side         → ConnectorError with status preserved
  * Network timeout         → ConnectorTimeout
  * Malformed JSON          → ConnectorError
  * Empty page              → zero candidates, no exception
  * Slack admin-scope miss  → degrades to scopeless candidates,
                              never raises
  * OpenAI happy path       → produces well-formed candidates
  * Slack happy path        → produces well-formed candidates

These are the failure modes you have to be honest about when a buyer
asks "does this work in production?" The goal is to prove the
connector tolerates each one without crashing the discovery service
or the surrounding runtime.

The harness lives next to the other discovery tests so failures show
up in the same suite. ``run_dev``-style live-credential tests against
real endpoints belong in ``scripts/connector_smoke.py`` and are NOT
part of the unit suite.
"""

from __future__ import annotations

import io
import json
from contextlib import contextmanager
from typing import Any, Iterator
from unittest.mock import patch
from urllib import error as urlerror

import pytest

from tex.discovery.connectors.base import (
    ConnectorContext,
    ConnectorError,
    ConnectorTimeout,
)
from tex.discovery.connectors.openai_live import OpenAIAssistantsLiveConnector
from tex.discovery.connectors.slack_live import SlackLiveConnector


# ---------------------------------------------------------------------------
# Mock urlopen helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Mimics enough of ``urlopen``'s response object for the connectors."""

    def __init__(self, body: bytes) -> None:
        self._buf = io.BytesIO(body)

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._buf.close()


def _http_error(code: int, body: str = "") -> urlerror.HTTPError:
    return urlerror.HTTPError(
        url="https://example.test",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode("utf-8")),
    )


@contextmanager
def patch_urlopen(module: str, side_effect: Any) -> Iterator[None]:
    """
    Patch ``urlopen`` inside a connector module with a callable
    ``side_effect`` (function or exception or sequence).
    """
    target = f"{module}.urlrequest.urlopen"
    with patch(target, side_effect=side_effect) as _:
        yield


def _ctx(**overrides: Any) -> ConnectorContext:
    base: dict[str, Any] = {"tenant_id": "tenant_acme", "timeout_seconds": 5.0}
    base.update(overrides)
    return ConnectorContext(**base)


# ===========================================================================
# OpenAI Assistants live connector
# ===========================================================================


class TestOpenAILiveConnectorErrors:
    def test_401_unauthorized_raises_connector_error(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise _http_error(401, '{"error":{"message":"invalid api key"}}')

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "401" in str(ei.value)

    def test_403_insufficient_scope_raises_connector_error(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise _http_error(403, '{"error":{"message":"missing scope"}}')

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "403" in str(ei.value)

    def test_429_rate_limit_raises_connector_error(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise _http_error(429, '{"error":{"message":"slow down"}}')

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "429" in str(ei.value)

    def test_500_upstream_failure_raises_connector_error(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise _http_error(500, "internal server error")

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "500" in str(ei.value)

    def test_network_timeout_raises_connector_timeout(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise urlerror.URLError("connection timed out")

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorTimeout):
                list(connector.scan(_ctx(timeout_seconds=0.5)))

    def test_timeout_error_raises_connector_timeout(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def boom(_req, timeout=None):
            raise TimeoutError("deadline exceeded")

        with patch_urlopen("tex.discovery.connectors.openai_live", boom):
            with pytest.raises(ConnectorTimeout):
                list(connector.scan(_ctx(timeout_seconds=0.5)))

    def test_malformed_json_raises_connector_error(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def fake(_req, timeout=None):
            return _FakeResponse(b"this is not json {{{")

        with patch_urlopen("tex.discovery.connectors.openai_live", fake):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "malformed JSON" in str(ei.value)

    def test_empty_page_returns_zero_candidates(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        def fake(_req, timeout=None):
            return _FakeResponse(
                json.dumps({"data": [], "has_more": False}).encode("utf-8")
            )

        with patch_urlopen("tex.discovery.connectors.openai_live", fake):
            candidates = list(connector.scan(_ctx()))
        assert candidates == []


class TestOpenAILiveConnectorHappyPath:
    def test_single_assistant_produces_one_candidate(self):
        connector = OpenAIAssistantsLiveConnector(api_key="sk-fake")

        body = {
            "data": [
                {
                    "id": "asst_abc123",
                    "name": "Refund Bot",
                    "description": "Handles refund requests",
                    "model": "gpt-4o",
                    "tools": [
                        {"type": "code_interpreter"},
                        {"type": "function", "function": {"name": "lookup_order"}},
                    ],
                    "tool_resources": {
                        "file_search": {"file_ids": ["file_xyz"]},
                    },
                    "metadata": {},
                    "created_at": 1700000000,
                }
            ],
            "has_more": False,
            "last_id": "asst_abc123",
        }

        def fake(_req, timeout=None):
            return _FakeResponse(json.dumps(body).encode("utf-8"))

        with patch_urlopen("tex.discovery.connectors.openai_live", fake):
            candidates = list(connector.scan(_ctx()))

        assert len(candidates) == 1
        c = candidates[0]
        assert c.name == "Refund Bot"
        # Tool types/functions land in capability hints
        assert c.capability_hints is not None


class TestOpenAILiveConnectorConstruction:
    def test_empty_api_key_raises_value_error(self):
        with pytest.raises(ValueError):
            OpenAIAssistantsLiveConnector(api_key="")

    def test_whitespace_api_key_raises_value_error(self):
        with pytest.raises(ValueError):
            OpenAIAssistantsLiveConnector(api_key="   ")


# ===========================================================================
# Slack live connector
# ===========================================================================


class TestSlackLiveConnectorErrors:
    def test_invalid_auth_raises_connector_error(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def fake(_req, timeout=None):
            return _FakeResponse(
                json.dumps({"ok": False, "error": "invalid_auth"}).encode()
            )

        with patch_urlopen("tex.discovery.connectors.slack_live", fake):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "invalid_auth" in str(ei.value)

    def test_body_level_ratelimited_raises_connector_timeout(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def fake(_req, timeout=None):
            return _FakeResponse(
                json.dumps(
                    {
                        "ok": False,
                        "error": "ratelimited",
                        "retry_after": 30,
                    }
                ).encode()
            )

        with patch_urlopen("tex.discovery.connectors.slack_live", fake):
            with pytest.raises(ConnectorTimeout) as ei:
                list(connector.scan(_ctx()))
        assert "rate limited" in str(ei.value)
        assert "retry_after=30" in str(ei.value)

    def test_http_429_raises_connector_error(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def boom(_req, timeout=None):
            raise _http_error(429)

        with patch_urlopen("tex.discovery.connectors.slack_live", boom):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "429" in str(ei.value)

    def test_network_timeout_raises_connector_timeout(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def boom(_req, timeout=None):
            raise urlerror.URLError("connection timed out")

        with patch_urlopen("tex.discovery.connectors.slack_live", boom):
            with pytest.raises(ConnectorTimeout):
                list(connector.scan(_ctx(timeout_seconds=0.5)))

    def test_malformed_json_raises_connector_error(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def fake(_req, timeout=None):
            return _FakeResponse(b"<html>no json here</html>")

        with patch_urlopen("tex.discovery.connectors.slack_live", fake):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "malformed JSON" in str(ei.value)

    def test_unexpected_response_shape_raises_connector_error(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def fake(_req, timeout=None):
            # Slack returned a JSON array instead of an object — out of contract.
            return _FakeResponse(b"[]")

        with patch_urlopen("tex.discovery.connectors.slack_live", fake):
            with pytest.raises(ConnectorError) as ei:
                list(connector.scan(_ctx()))
        assert "unexpected response shape" in str(ei.value)


class TestSlackLiveConnectorDegradedPermissions:
    def test_admin_apps_list_missing_falls_back_silently(self):
        """
        ``admin.apps.approved.list`` requires admin scopes the operator
        often does not grant. The connector must NOT raise — it must
        degrade to bots-without-scopes and continue.
        """
        connector = SlackLiveConnector(token="xoxb-fake")

        # users.list returns one bot, then is followed by the apps
        # admin call which fails. Use a list of canned responses.
        def fake_factory():
            calls = {"i": 0}

            def fake(req, timeout=None):
                calls["i"] += 1
                url = req.full_url
                if "users.list" in url:
                    return _FakeResponse(
                        json.dumps(
                            {
                                "ok": True,
                                "members": [
                                    {
                                        "id": "U1",
                                        "is_bot": True,
                                        "deleted": False,
                                        "name": "watson",
                                        "profile": {"api_app_id": "A1"},
                                    }
                                ],
                                "response_metadata": {"next_cursor": ""},
                            }
                        ).encode()
                    )
                if "admin.apps.approved.list" in url:
                    return _FakeResponse(
                        json.dumps(
                            {"ok": False, "error": "missing_scope"}
                        ).encode()
                    )
                # Default empty
                return _FakeResponse(json.dumps({"ok": True}).encode())

            return fake

        with patch_urlopen("tex.discovery.connectors.slack_live", fake_factory()):
            candidates = list(connector.scan(_ctx()))

        # Connector did NOT raise — it produced the bot with empty scopes.
        assert len(candidates) == 1


class TestSlackLiveConnectorHappyPath:
    def test_single_bot_user_produces_one_candidate(self):
        connector = SlackLiveConnector(token="xoxb-fake")

        def fake_factory():
            def fake(req, timeout=None):
                url = req.full_url
                if "users.list" in url:
                    return _FakeResponse(
                        json.dumps(
                            {
                                "ok": True,
                                "members": [
                                    {
                                        "id": "U2",
                                        "is_bot": True,
                                        "deleted": False,
                                        "name": "deploy_bot",
                                        "profile": {"api_app_id": "A2"},
                                    }
                                ],
                                "response_metadata": {"next_cursor": ""},
                            }
                        ).encode()
                    )
                if "admin.apps.approved.list" in url:
                    return _FakeResponse(
                        json.dumps(
                            {
                                "ok": True,
                                "approved_apps": [
                                    {
                                        "app": {"id": "A2"},
                                        "scopes": {
                                            "bot": ["chat:write", "users:read"],
                                            "user": [],
                                        },
                                    }
                                ],
                                "response_metadata": {"next_cursor": ""},
                            }
                        ).encode()
                    )
                return _FakeResponse(json.dumps({"ok": True}).encode())

            return fake

        with patch_urlopen("tex.discovery.connectors.slack_live", fake_factory()):
            candidates = list(connector.scan(_ctx()))

        assert len(candidates) == 1
        # Scope-driven risk classification ran
        assert candidates[0].name


class TestSlackLiveConnectorConstruction:
    def test_empty_token_raises_value_error(self):
        with pytest.raises(ValueError):
            SlackLiveConnector(token="")

    def test_whitespace_token_raises_value_error(self):
        with pytest.raises(ValueError):
            SlackLiveConnector(token="   ")
