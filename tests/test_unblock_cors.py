"""
Wave-0 credibility floor — CORS lockdown.

The old config (`allow_origins=["*"]` + `allow_credentials=True`) made
Starlette *reflect the caller's Origin* and set
`Access-Control-Allow-Credentials: true`, i.e. any site could make
credentialed cross-origin calls. These tests pin the closed posture at
two levels:

* unit: ``resolve_cors_policy`` never returns wildcard-with-credentials;
* integration: the live app does not reflect an arbitrary attacker
  origin with credentials, but does honour a configured allowlist.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.api.cors import resolve_cors_policy

_EVIL = "https://evil.example"
_APP = "https://app.example.com"


# --------------------------------------------------------------------------- #
# Unit: the invariant — wildcard ⇒ no credentials                             #
# --------------------------------------------------------------------------- #


class TestResolvePolicy:
    def test_unset_defaults_to_localhost_with_credentials(self) -> None:
        origins, creds = resolve_cors_policy(raw_env="")
        assert origins == ["http://localhost:3000", "http://127.0.0.1:3000"]
        assert creds is True
        assert "*" not in origins  # the whole point

    def test_wildcard_forces_credentials_off(self) -> None:
        origins, creds = resolve_cors_policy(raw_env="*")
        assert origins == ["*"]
        assert creds is False

    def test_wildcard_plus_explicit_collapses_to_safe_wildcard(self) -> None:
        origins, creds = resolve_cors_policy(raw_env="https://a.example,*")
        assert origins == ["*"]
        assert creds is False

    def test_explicit_allowlist_keeps_credentials(self) -> None:
        origins, creds = resolve_cors_policy(raw_env="https://a.example, https://b.example")
        assert origins == ["https://a.example", "https://b.example"]
        assert creds is True

    def test_never_wildcard_with_credentials(self) -> None:
        # Property check across representative inputs.
        for raw in ("", "*", "https://x,*", "*,https://x", "https://x", "https://x,https://y"):
            origins, creds = resolve_cors_policy(raw_env=raw)
            assert not ("*" in origins and creds), raw


# --------------------------------------------------------------------------- #
# Integration: observable response headers                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def app_factory(monkeypatch):
    def _build(cors_env: str | None):
        if cors_env is None:
            monkeypatch.delenv("TEX_CORS_ALLOW_ORIGINS", raising=False)
        else:
            monkeypatch.setenv("TEX_CORS_ALLOW_ORIGINS", cors_env)
        # Keyless so a plain GET succeeds; CORS headers are added regardless.
        monkeypatch.delenv("TEX_API_KEYS", raising=False)
        from tex.main import create_app

        return TestClient(create_app())

    return _build


class TestCorsHeaders:
    def test_default_does_not_reflect_attacker_origin(self, app_factory) -> None:
        client = app_factory(None)
        r = client.get("/v1/tee/status", headers={"Origin": _EVIL})
        # The dangerous behaviour is ACAO echoing the attacker origin. It must
        # NOT appear; at most a literal "*" (which the default policy also
        # never emits, since the default is a localhost allowlist).
        assert r.headers.get("access-control-allow-origin") != _EVIL

    def test_default_honours_localhost_with_credentials(self, app_factory) -> None:
        client = app_factory(None)
        r = client.get("/v1/tee/status", headers={"Origin": "http://localhost:3000"})
        assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert r.headers.get("access-control-allow-credentials") == "true"

    def test_explicit_allowlist_echoes_only_listed_origin(self, app_factory) -> None:
        client = app_factory(_APP)
        ok = client.get("/v1/tee/status", headers={"Origin": _APP})
        assert ok.headers.get("access-control-allow-origin") == _APP
        assert ok.headers.get("access-control-allow-credentials") == "true"

        bad = client.get("/v1/tee/status", headers={"Origin": _EVIL})
        assert bad.headers.get("access-control-allow-origin") != _EVIL

    def test_wildcard_mode_has_no_credentials(self, app_factory) -> None:
        client = app_factory("*")
        r = client.get("/v1/tee/status", headers={"Origin": _EVIL})
        # Safe wildcard: literal "*", and crucially NO credentials header,
        # so the reflect-with-credentials hole cannot occur.
        assert r.headers.get("access-control-allow-origin") == "*"
        assert r.headers.get("access-control-allow-credentials") is None
