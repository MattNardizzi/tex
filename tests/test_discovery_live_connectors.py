"""
Tests for the live discovery connectors (OpenAI Assistants + Slack).

The live connectors hit real HTTP APIs using ``urllib.request``.
These tests do not contact any network — they monkey-patch
``urllib.request.urlopen`` to return canned responses shaped like the
real APIs. That gives us coverage of:

- HTTP request construction (path, query, headers)
- pagination
- error handling (HTTP 4xx/5xx, timeouts, malformed JSON)
- candidate-shape parity with the mock connectors

The point of having both mock AND live connectors is that the *shape*
of the CandidateAgent each emits is identical. These tests assert
that explicitly so the rest of the discovery pipeline does not have
to care which connector flavour produced a candidate.
"""

from __future__ import annotations

import io
import json
from typing import Any
from urllib import error as urlerror

import pytest

from tex.discovery.connectors import (
    ConnectorContext,
    ConnectorError,
    OpenAIAssistantsLiveConnector,
    SlackLiveConnector,
)
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource


def _ctx(tenant: str = "acme") -> ConnectorContext:
    return ConnectorContext(tenant_id=tenant, timeout_seconds=5.0)


class _FakeResponse:
    """urlopen() returns an object with .read() and acts as a context manager."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# OpenAI Assistants Live Connector
# ---------------------------------------------------------------------------


class TestOpenAIAssistantsLiveConnector:
    def _install_responses(
        self, monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, Any]]
    ) -> list[Any]:
        """
        Patch urlopen to return ``pages`` in sequence. Returns a list
        of captured Request objects so tests can assert URL/headers.
        """
        captured: list[Any] = []
        page_iter = iter(pages)

        def fake_urlopen(req: Any, timeout: float | None = None) -> _FakeResponse:
            captured.append(req)
            try:
                payload = next(page_iter)
            except StopIteration:
                payload = {"data": [], "has_more": False}
            return _FakeResponse(json.dumps(payload).encode("utf-8"))

        monkeypatch.setattr(
            "tex.discovery.connectors.openai_live.urlrequest.urlopen",
            fake_urlopen,
        )
        return captured

    def test_construction_requires_api_key(self) -> None:
        with pytest.raises(ValueError):
            OpenAIAssistantsLiveConnector(api_key="")
        with pytest.raises(ValueError):
            OpenAIAssistantsLiveConnector(api_key="   ")

    def test_basic_assistant_emits_candidate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._install_responses(
            monkeypatch,
            [
                {
                    "data": [
                        {
                            "id": "asst_001",
                            "name": "Support Assistant",
                            "model": "gpt-4o",
                            "tools": [{"type": "file_search"}],
                            "created_at": 1_700_000_000,
                            "metadata": {"owner": "ops@acme.com"},
                        }
                    ],
                    "has_more": False,
                }
            ],
        )

        c = OpenAIAssistantsLiveConnector(api_key="sk-test-123")
        cands = list(c.scan(_ctx()))

        assert len(cands) == 1
        cand = cands[0]
        assert cand.source is DiscoverySource.OPENAI
        assert cand.external_id == "asst_001"
        assert cand.name == "Support Assistant"
        assert cand.model_provider_hint == "openai"
        assert cand.model_name_hint == "gpt-4o"
        assert cand.evidence["live"] is True

        # Assert the request was constructed correctly.
        req = captured[0]
        assert req.full_url.startswith("https://api.openai.com/v1/assistants")
        # Bearer auth header.
        auth_header = req.get_header("Authorization")
        assert auth_header == "Bearer sk-test-123"
        # Beta assistants v2 header.
        beta_header = req.get_header("Openai-beta")
        assert beta_header == "assistants=v2"

    def test_optional_org_and_project_headers_are_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._install_responses(
            monkeypatch,
            [{"data": [], "has_more": False}],
        )
        c = OpenAIAssistantsLiveConnector(
            api_key="sk-test",
            organization="org-abc",
            project="proj-xyz",
        )
        list(c.scan(_ctx()))

        req = captured[0]
        assert req.get_header("Openai-organization") == "org-abc"
        assert req.get_header("Openai-project") == "proj-xyz"

    def test_critical_risk_when_code_interp_plus_function(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_responses(
            monkeypatch,
            [
                {
                    "data": [
                        {
                            "id": "asst_002",
                            "name": "Power Agent",
                            "model": "gpt-4o",
                            "tools": [
                                {"type": "code_interpreter"},
                                {"type": "function", "function": {"name": "exec_sql"}},
                            ],
                            "created_at": 1_700_000_000,
                        }
                    ],
                    "has_more": False,
                }
            ],
        )
        c = OpenAIAssistantsLiveConnector(api_key="sk-test")
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True

    def test_pagination_follows_after_cursor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._install_responses(
            monkeypatch,
            [
                {
                    "data": [
                        {
                            "id": "asst_p1",
                            "name": "Page1",
                            "model": "gpt-4o",
                            "tools": [],
                            "created_at": 1_700_000_000,
                        }
                    ],
                    "has_more": True,
                    "last_id": "asst_p1",
                },
                {
                    "data": [
                        {
                            "id": "asst_p2",
                            "name": "Page2",
                            "model": "gpt-4o",
                            "tools": [],
                            "created_at": 1_700_000_000,
                        }
                    ],
                    "has_more": False,
                },
            ],
        )
        c = OpenAIAssistantsLiveConnector(api_key="sk-test")
        cands = list(c.scan(_ctx()))
        assert [x.external_id for x in cands] == ["asst_p1", "asst_p2"]
        assert "after=asst_p1" in captured[1].full_url

    def test_http_error_raises_connector_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raise_http_error(*_: Any, **__: Any) -> None:
            raise urlerror.HTTPError(
                url="https://api.openai.com/v1/assistants",
                code=401,
                msg="Unauthorized",
                hdrs=None,
                fp=io.BytesIO(b'{"error": "invalid_api_key"}'),
            )

        monkeypatch.setattr(
            "tex.discovery.connectors.openai_live.urlrequest.urlopen",
            raise_http_error,
        )
        c = OpenAIAssistantsLiveConnector(api_key="sk-bad")
        with pytest.raises(ConnectorError):
            list(c.scan(_ctx()))

    def test_malformed_json_raises_connector_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_urlopen(*_: Any, **__: Any) -> _FakeResponse:
            return _FakeResponse(b"not json")

        monkeypatch.setattr(
            "tex.discovery.connectors.openai_live.urlrequest.urlopen",
            fake_urlopen,
        )
        c = OpenAIAssistantsLiveConnector(api_key="sk-test")
        with pytest.raises(ConnectorError):
            list(c.scan(_ctx()))


# ---------------------------------------------------------------------------
# Slack Live Connector
# ---------------------------------------------------------------------------


class TestSlackLiveConnector:
    def _install_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        responses_by_path: dict[str, list[dict[str, Any]]],
    ) -> list[Any]:
        captured: list[Any] = []
        # mutable iterator per-path
        iters = {k: iter(v) for k, v in responses_by_path.items()}

        def fake_urlopen(req: Any, timeout: float | None = None) -> _FakeResponse:
            captured.append(req)
            url = req.full_url
            for path, it in iters.items():
                if path in url:
                    try:
                        payload = next(it)
                    except StopIteration:
                        payload = {"ok": False, "error": "no_more_pages"}
                    return _FakeResponse(json.dumps(payload).encode("utf-8"))
            return _FakeResponse(
                json.dumps({"ok": False, "error": "unmocked_path"}).encode("utf-8")
            )

        monkeypatch.setattr(
            "tex.discovery.connectors.slack_live.urlrequest.urlopen",
            fake_urlopen,
        )
        return captured

    def test_construction_requires_token(self) -> None:
        with pytest.raises(ValueError):
            SlackLiveConnector(token="")
        with pytest.raises(ValueError):
            SlackLiveConnector(token="   ")

    def test_basic_bot_with_no_admin_scopes_degrades_gracefully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # users.list returns one bot. apps.approved.list returns
        # missing_scope (admin token not present). The connector
        # should still emit one candidate, with empty scopes.
        self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_BOT_1",
                                "name": "support-bot",
                                "real_name": "Support Bot",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {
                                    "api_app_id": "A_APP_1",
                                    "real_name": "Support Bot",
                                },
                                "updated": 1_700_000_000,
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
                "/admin.apps.approved.list": [
                    {"ok": False, "error": "missing_scope"},
                ],
            },
        )
        c = SlackLiveConnector(token="xoxb-test")
        cands = list(c.scan(_ctx()))
        assert len(cands) == 1
        cand = cands[0]
        assert cand.source is DiscoverySource.SLACK
        assert cand.external_id == "U_BOT_1"
        # No scopes → LOW band
        assert cand.risk_band is DiscoveryRiskBand.LOW
        assert cand.evidence["live"] is True

    def test_admin_scope_app_yields_critical(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_BOT_2",
                                "name": "admin-bot",
                                "real_name": "Admin Bot",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {"api_app_id": "A_ADMIN"},
                                "updated": 1_700_000_000,
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
                "/admin.apps.approved.list": [
                    {
                        "ok": True,
                        "approved_apps": [
                            {
                                "app": {"id": "A_ADMIN"},
                                "scopes": {
                                    "bot": ["admin", "chat:write"],
                                    "user": [],
                                },
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
            },
        )
        c = SlackLiveConnector(token="xoxp-test")
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True

    def test_write_plus_sensitive_read_yields_high(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_BOT_3",
                                "name": "ai-bot",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {"api_app_id": "A_AI"},
                                "updated": 1_700_000_000,
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
                "/admin.apps.approved.list": [
                    {
                        "ok": True,
                        "approved_apps": [
                            {
                                "app": {"id": "A_AI"},
                                "scopes": {
                                    "bot": ["chat:write", "channels:history"],
                                    "user": [],
                                },
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
            },
        )
        c = SlackLiveConnector(token="xoxp-test")
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.HIGH

    def test_deleted_bots_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_GONE",
                                "is_bot": True,
                                "deleted": True,
                                "team_id": "T1",
                            },
                            {
                                "id": "U_LIVE",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {"api_app_id": "A1"},
                                "updated": 1_700_000_000,
                            },
                        ],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
                "/admin.apps.approved.list": [
                    {"ok": False, "error": "missing_scope"},
                ],
            },
        )
        c = SlackLiveConnector(token="xoxp-test")
        cands = list(c.scan(_ctx()))
        assert [x.external_id for x in cands] == ["U_LIVE"]

    def test_users_list_pagination(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_PAGE_1",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {},
                                "updated": 1_700_000_000,
                            }
                        ],
                        "response_metadata": {"next_cursor": "abc"},
                    },
                    {
                        "ok": True,
                        "members": [
                            {
                                "id": "U_PAGE_2",
                                "is_bot": True,
                                "team_id": "T1",
                                "profile": {},
                                "updated": 1_700_000_000,
                            }
                        ],
                        "response_metadata": {"next_cursor": ""},
                    },
                ],
                "/admin.apps.approved.list": [
                    {"ok": False, "error": "missing_scope"},
                ],
            },
        )
        c = SlackLiveConnector(token="xoxp-test")
        cands = list(c.scan(_ctx()))
        assert [x.external_id for x in cands] == ["U_PAGE_1", "U_PAGE_2"]
        # Second users.list call should carry the cursor.
        users_calls = [r for r in captured if "/users.list" in r.full_url]
        assert any("cursor=abc" in r.full_url for r in users_calls)

    def test_ratelimit_response_raises_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tex.discovery.connectors import ConnectorTimeout

        def fake_urlopen(*_: Any, **__: Any) -> _FakeResponse:
            return _FakeResponse(
                json.dumps(
                    {"ok": False, "error": "ratelimited", "retry_after": 30}
                ).encode("utf-8")
            )

        monkeypatch.setattr(
            "tex.discovery.connectors.slack_live.urlrequest.urlopen",
            fake_urlopen,
        )
        c = SlackLiveConnector(token="xoxp-test")
        with pytest.raises(ConnectorTimeout):
            list(c.scan(_ctx()))

    def test_team_id_propagates_to_query(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._install_responses(
            monkeypatch,
            {
                "/users.list": [
                    {
                        "ok": True,
                        "members": [],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
                "/admin.apps.approved.list": [
                    {
                        "ok": True,
                        "approved_apps": [],
                        "response_metadata": {"next_cursor": ""},
                    }
                ],
            },
        )
        c = SlackLiveConnector(token="xoxp-test", team_id="T_TARGET")
        list(c.scan(_ctx()))
        assert any("team_id=T_TARGET" in r.full_url for r in captured)
