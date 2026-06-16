"""
End-to-end HTTP tests for the voice surface through the real FastAPI app:
``/v1/voice/token`` mints a grant, ``/v1/ask`` answers grounded in the sealed
decision store (and the spoken count matches the store exactly), ``/v1/speak``
streams audio, and — the doctrine fix — ``/v1/ask`` requires ``evidence:read``
on a keyed backend while ``/v1/voice/token`` needs only ``decision:read``.
"""

from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict


def _decision(verdict: Verdict) -> Decision:
    content = uuid4().hex
    return Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.5,
        action_type="send_email",
        channel="email",
        environment="production",
        content_excerpt=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        policy_version="test-1",
        evidence_hash="e" * 64,
    )


@pytest.fixture
def client(monkeypatch) -> TestClient:
    monkeypatch.setenv("TEX_APP_ENV", "development")
    monkeypatch.delenv("TEX_REQUIRE_AUTH", raising=False)
    from tex.main import create_app

    return TestClient(create_app())


def test_voice_token_mints_grant(client: TestClient) -> None:
    resp = client.get("/v1/voice/token")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ws_url"].startswith("ws")
    assert body["token"] and "." in body["token"]
    assert isinstance(body["expires_at"], int)


def test_ask_speaks_the_sealed_count(client: TestClient) -> None:
    store = client.app.state.decision_store
    for _ in range(2):
        store.save(_decision(Verdict.FORBID))
    forbidden = sum(1 for d in store.list_recent(limit=500) if d.verdict is Verdict.FORBID)

    resp = client.post("/v1/ask", json={"transcript": "how many actions were forbidden"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == f"{forbidden} actions were forbidden in the recent window."
    assert body["attestation"]["verdict"] == "PERMIT"
    assert body["attestation"]["anchor_sha256"]
    assert body["object"] is None


def test_ask_abstains_when_ungroundable(client: TestClient) -> None:
    resp = client.post("/v1/ask", json={"transcript": "qwerty zxcv nonsense"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["attestation"]["verdict"] == "ABSTAIN"
    assert body["object"] is None


def test_speak_streams_wav_audio(client: TestClient) -> None:
    resp = client.get("/v1/speak", params={"text": "the evidence chain is intact"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "audio/wav"
    assert resp.content[:4] == b"RIFF"


def test_speak_timed_503_without_elevenlabs_key(client: TestClient) -> None:
    # Word-timed voice is ElevenLabs-only. With no key (hermetic conftest) the
    # route must 503 cleanly — NOT 500 — so the client falls back to plain
    # /v1/speak (real voice, no highlight). Purely additive, never a regression.
    resp = client.get("/v1/speak/timed", params={"text": "the evidence chain is intact"})
    assert resp.status_code == 503


def test_ask_requires_evidence_read_scope(monkeypatch) -> None:
    # Keyed, fail-closed backend: a key with ONLY decision:read must be 403'd on
    # /v1/ask (it returns sealed evidence_hash anchors) but allowed on
    # /v1/voice/token (decision:read suffices). This is the doctrine fix.
    # TEX_REQUIRE_AUTH=1 forces keyed auth + production-like grant posture
    # WITHOUT TEX_APP_ENV=production (which would trip unrelated startup secret
    # guards); auth and the grant both treat REQUIRE_AUTH=1 as production-like.
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    monkeypatch.setenv("TEX_API_KEYS", "k_read:acme:decision:read")
    monkeypatch.setenv("TEX_VOICE_GATEWAY_SECRET", "test-secret")
    from tex.config import get_settings

    get_settings.cache_clear()
    from tex.main import create_app

    c = TestClient(create_app())
    headers = {"Authorization": "Bearer k_read"}

    # decision:read alone → token OK
    assert c.get("/v1/voice/token", headers=headers).status_code == 200
    # decision:read alone → ask FORBIDDEN (needs evidence:read)
    r = c.post("/v1/ask", json={"transcript": "how many forbidden"}, headers=headers)
    assert r.status_code == 403
    assert "evidence:read" in r.json()["detail"]
    # no key at all → 401 (fail closed in production)
    assert c.post("/v1/ask", json={"transcript": "x"}).status_code == 401
    get_settings.cache_clear()


def test_ask_allows_key_with_both_scopes(monkeypatch) -> None:
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    monkeypatch.setenv("TEX_API_KEYS", "k_full:acme:decision:read+evidence:read")
    monkeypatch.setenv("TEX_VOICE_GATEWAY_SECRET", "test-secret")
    from tex.config import get_settings

    get_settings.cache_clear()
    from tex.main import create_app

    c = TestClient(create_app())
    r = c.post(
        "/v1/ask",
        json={"transcript": "how many forbidden"},
        headers={"Authorization": "Bearer k_full"},
    )
    assert r.status_code == 200
    get_settings.cache_clear()
