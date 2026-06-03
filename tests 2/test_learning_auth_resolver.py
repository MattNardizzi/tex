"""Tests for the learning-layer auth-context actor resolver."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException, Request

from tex.api.learning_routes import _resolve_actor


def _request_with(*, principal=None, headers: dict[str, str] | None = None) -> Request:
    """
    Build a minimal Starlette Request for resolver tests.

    The resolver only touches request.state.principal and request.headers,
    so a trimmed-down ASGI scope is enough.
    """
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/test",
        "headers": [
            (k.lower().encode(), v.encode())
            for k, v in (headers or {}).items()
        ],
        "query_string": b"",
    }
    request = Request(scope)
    if principal is not None:
        request.state.principal = principal
    return request


def test_principal_string_resolves() -> None:
    request = _request_with(principal="matthew@vortexblack.com")
    actor = _resolve_actor(request, body_value=None, field_name="approver")
    assert actor == "matthew@vortexblack.com"


def test_principal_object_with_username_resolves() -> None:
    class P:
        username = "matt"

    request = _request_with(principal=P())
    actor = _resolve_actor(request, body_value=None, field_name="approver")
    assert actor == "matt"


def test_header_resolves_when_no_principal() -> None:
    request = _request_with(headers={"X-Tex-Approver": "auditor-1"})
    actor = _resolve_actor(request, body_value=None, field_name="approver")
    assert actor == "auditor-1"


def test_body_value_used_only_when_no_auth_context() -> None:
    request = _request_with()
    actor = _resolve_actor(
        request, body_value="local-dev-user", field_name="approver"
    )
    assert actor == "local-dev-user"


def test_principal_wins_over_body_when_equal() -> None:
    request = _request_with(principal="matt")
    actor = _resolve_actor(request, body_value="matt", field_name="approver")
    assert actor == "matt"


def test_spoofing_attempt_rejected() -> None:
    """Body-supplied identity that disagrees with auth context is a 409."""
    request = _request_with(principal="matt")
    with pytest.raises(HTTPException) as ei:
        _resolve_actor(request, body_value="someone-else", field_name="approver")
    assert ei.value.status_code == 409
    assert "approver" in ei.value.detail


def test_missing_identity_raises_401() -> None:
    request = _request_with()
    with pytest.raises(HTTPException) as ei:
        _resolve_actor(request, body_value=None, field_name="approver")
    assert ei.value.status_code == 401


def test_blank_strings_treated_as_missing() -> None:
    request = _request_with(headers={"X-Tex-Approver": "   "})
    with pytest.raises(HTTPException) as ei:
        _resolve_actor(request, body_value="   ", field_name="approver")
    assert ei.value.status_code == 401


def test_header_takes_precedence_over_body() -> None:
    request = _request_with(headers={"X-Tex-Approver": "header-user"})
    # Body supplies a *different* value — header wins (and we 409 because
    # they disagree).
    with pytest.raises(HTTPException) as ei:
        _resolve_actor(
            request, body_value="body-user", field_name="approver"
        )
    assert ei.value.status_code == 409


def test_principal_takes_precedence_over_header() -> None:
    request = _request_with(
        principal="from-principal",
        headers={"X-Tex-Approver": "from-header"},
    )
    # When they disagree we don't raise — the resolver currently treats
    # principal as the canonical source and the header is ignored when
    # principal is present. (The body-vs-auth check still applies.)
    actor = _resolve_actor(request, body_value=None, field_name="approver")
    assert actor == "from-principal"
