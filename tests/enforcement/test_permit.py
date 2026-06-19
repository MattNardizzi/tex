"""Unit tests for the permit signer (``tex.enforcement.permit``).

The permit is the egress proof: a short-lived, single-use HMAC authorization
bound to the EXACT action — principal, audience, action_type, and a digest of
the committed argument bytes. These tests pin the properties the proxy relies
on: a permit minted for one call cannot be forged, replayed to different
content, redirected to a different audience, or used after expiry; and minting
fails closed in production with no secret.
"""

from __future__ import annotations

import base64
import json
from uuid import uuid4

import pytest

from tex.enforcement import permit


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    # A fixed, hermetic secret so mint/verify agree across the test (the dev
    # ephemeral secret would also work, but pin it for determinism).
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "test-secret-please-rotate")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    yield


def _mint(content=b"BODY", recipient="api.host", action="http_post", ttl=30, now=None):
    return permit.mint(
        decision_id=uuid4(),
        tenant="acme",
        action_type=action,
        agent_id="agent-1",
        recipient=recipient,
        content=content,
        ttl_seconds=ttl,
        now=now,
    )


def test_happy_path_verifies():
    m = _mint()
    v = permit.verify(
        m.token,
        expected_content_digest=permit.content_digest(b"BODY"),
        expected_audience="api.host",
        expected_action_type="http_post",
    )
    assert v.ok and v.reason == "ok"
    assert v.claims["aid"] == "agent-1"


def test_forged_signature_rejected():
    m = _mint()
    body, _, sig = m.token.partition(".")
    forged = f"{body}.{'A' * len(sig)}"
    v = permit.verify(forged)
    assert not v.ok and "signature" in v.reason


def test_tampered_claims_rejected():
    # Flip the audience claim but keep the original signature: the signature
    # covers the original body, so verification fails closed. An attacker cannot
    # re-sign without the secret.
    m = _mint(recipient="api.host")
    body, _, sig = m.token.partition(".")
    claims = json.loads(permit._b64url_decode(body))
    claims["aud"] = "evil.host"
    tampered = f"{permit._canonical(claims)}.{sig}"
    v = permit.verify(tampered)
    assert not v.ok and "signature" in v.reason


def test_replay_to_different_content_rejected():
    # Permit minted to release "transfer $100"; an attacker replays the same
    # token to push different bytes. The fresh digest mismatch is the defence.
    m = _mint(content=b"transfer $100")
    v = permit.verify(
        m.token,
        expected_content_digest=permit.content_digest(b"transfer $1000000"),
        expected_audience="api.host",
    )
    assert not v.ok and "content digest" in v.reason


def test_audience_mismatch_rejected():
    m = _mint(recipient="api.host")
    v = permit.verify(
        m.token,
        expected_content_digest=permit.content_digest(b"BODY"),
        expected_audience="evil.host",
    )
    assert not v.ok and "audience" in v.reason


def test_action_type_mismatch_rejected():
    m = _mint(action="http_post")
    v = permit.verify(m.token, expected_action_type="http_delete")
    assert not v.ok and "action_type" in v.reason


def test_expired_permit_rejected():
    m = _mint(ttl=1, now=1000.0)  # expires at t=1001
    v = permit.verify(m.token, now=2000.0)
    assert not v.ok and v.reason == "expired"


def test_not_yet_expired_permit_verifies_at_mint_time():
    m = _mint(ttl=30, now=1000.0)
    v = permit.verify(
        m.token,
        now=1005.0,
        expected_content_digest=permit.content_digest(b"BODY"),
        expected_audience="api.host",
    )
    assert v.ok


def test_malformed_token_rejected():
    assert not permit.verify(None).ok
    assert not permit.verify("").ok
    assert not permit.verify("no-dot-here").ok


def test_unsupported_version_rejected():
    # Re-sign a bumped-version claim set with the REAL secret so the signature
    # passes; the version gate must still reject it.
    m = _mint()
    claims = json.loads(permit._b64url_decode(m.token.partition(".")[0]))
    claims["v"] = 999
    body = permit._canonical(claims)
    sig = permit._sign(permit.permit_secret(), body)
    v = permit.verify(f"{body}.{sig}")
    assert not v.ok and "version" in v.reason


def test_content_digest_binds_exact_bytes():
    assert permit.content_digest(b"a") != permit.content_digest(b"b")
    assert permit.content_digest("a") == permit.content_digest(b"a")
    assert permit.content_digest(None) is None


def test_metadata_carries_binding_claims():
    m = _mint(content=b"X", recipient="api.host", action="http_post")
    md = m.metadata
    assert md["agent_id"] == "agent-1"
    assert md["audience"] == "api.host"
    assert md["action_type"] == "http_post"
    assert md["content_digest"] == permit.content_digest(b"X")


def test_production_no_secret_fails_closed(monkeypatch):
    # Remove the fixture's secret and force a production-like env.
    monkeypatch.delenv("TEX_PERMIT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    assert permit.is_production_like() is True
    assert permit.permit_secret() is None
    assert (
        permit.mint(
            decision_id=uuid4(),
            tenant="acme",
            action_type="x",
            recipient="h",
            content=b"b",
        )
        is None
    )
    assert not permit.verify("anything.anything").ok


def test_precomputed_digest_equivalent_to_content(monkeypatch):
    digest = permit.content_digest(b"BODY")
    m = permit.mint(
        decision_id=uuid4(),
        tenant="acme",
        action_type="http_post",
        recipient="api.host",
        content_sha256=digest,
    )
    v = permit.verify(m.token, expected_content_digest=digest, expected_audience="api.host")
    assert v.ok
