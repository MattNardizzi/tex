"""
Wave-0 credibility floor — no anonymous-all-scopes default in production.

Before this change, a deployment that set neither ``TEX_REQUIRE_AUTH`` nor
``TEX_API_KEYS`` ran wide open: the anonymous principal held every scope —
*regardless of environment*. The fix makes the keyless anonymous fallback
reachable ONLY in a non-production ``TEX_APP_ENV``. In a production-like
environment (or with ``TEX_REQUIRE_AUTH=1``), a missing key configuration
fails closed (401) instead of granting everything.

Dev/test default to ``TEX_APP_ENV=development``, so the existing keyless
behaviour is unchanged for the suite; these tests set ``TEX_APP_ENV`` /
``TEX_REQUIRE_AUTH`` explicitly to exercise the production posture at the
auth entry point.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from tex.api.auth import _is_production_like, authenticate_request


def _request(headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw})


class TestIsProductionLike:
    @pytest.mark.parametrize("env", ["development", "dev", "test", "testing", "local", "DEV"])
    def test_non_production_envs(self, monkeypatch, env):
        monkeypatch.setenv("TEX_APP_ENV", env)
        assert _is_production_like() is False

    def test_unset_defaults_to_dev(self, monkeypatch):
        monkeypatch.delenv("TEX_APP_ENV", raising=False)
        assert _is_production_like() is False

    @pytest.mark.parametrize("env", ["production", "prod", "staging", "anything-else"])
    def test_production_like_envs(self, monkeypatch, env):
        monkeypatch.setenv("TEX_APP_ENV", env)
        assert _is_production_like() is True


class TestAnonymousFallbackGatedByEnv:
    def test_dev_no_keys_is_anonymous_all_scopes(self, monkeypatch):
        # Non-production default: keyless passthrough is preserved.
        monkeypatch.delenv("TEX_API_KEYS", raising=False)
        monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("TEX_APP_ENV", "development")
        principal = authenticate_request(_request())
        assert principal.is_anonymous
        assert principal.has_scope("decision:write")  # anonymous == every scope (dev only)

    def test_production_no_keys_is_401(self, monkeypatch):
        # Production-like env with no keys → fail closed, NOT anonymous-open.
        monkeypatch.delenv("TEX_API_KEYS", raising=False)
        monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("TEX_APP_ENV", "production")
        with pytest.raises(HTTPException) as exc:
            authenticate_request(_request())
        assert exc.value.status_code == 401

    def test_require_auth_no_keys_is_401_even_in_dev(self, monkeypatch):
        # Explicit enforce also fails closed regardless of environment.
        monkeypatch.delenv("TEX_API_KEYS", raising=False)
        monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
        monkeypatch.setenv("TEX_APP_ENV", "development")
        with pytest.raises(HTTPException) as exc:
            authenticate_request(_request())
        assert exc.value.status_code == 401

    def test_production_with_valid_key_authenticates(self, monkeypatch):
        # Properly configured production: a valid key works; a missing one 401s.
        monkeypatch.setenv("TEX_APP_ENV", "production")
        monkeypatch.setenv("TEX_API_KEYS", "k1:tenant_a:decision:read")
        principal = authenticate_request(_request({"Authorization": "Bearer k1"}))
        assert not principal.is_anonymous
        assert principal.tenant == "tenant_a"
        with pytest.raises(HTTPException) as exc:
            authenticate_request(_request())
        assert exc.value.status_code == 401
