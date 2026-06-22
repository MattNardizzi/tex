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


# ----------------------------------------- presence envelope on the wire (S1 brain + S2 gate)


class _FakeBrain:
    """A GroundedBrain stub: proposes a fixed (draft, claims) so the truth-gate
    runs without a live model. Mirrors tests/presence/test_seam.py._FakeBrain."""

    def __init__(self, draft, claims):
        self._draft, self._claims = draft, claims

    def propose(self, *, question, tenant, facts, tools):
        return self._draft, self._claims


def test_ask_serializes_presence_envelope_when_brain_engaged(client: TestClient) -> None:
    # With a GroundedBrain on app.state, /v1/ask now CARRIES the presence envelope
    # the glass renders: a real credibility tier + per-claim, reachable evidence.
    from tex.presence.contract import ClaimKind, PresenceClaim

    store = client.app.state.decision_store
    for _ in range(3):
        store.save(_decision(Verdict.FORBID))

    client.app.state.presence_brain = _FakeBrain(
        "how many forbids",
        (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),),
    )

    resp = client.post(
        "/v1/ask", json={"transcript": "how many forbidden actions were there"}
    )
    assert resp.status_code == 200
    body = resp.json()

    # Legacy fields untouched — presence WRAPS, never replaces.
    assert body["answer"]
    assert body["attestation"]["verdict"]

    pres = body["presence"]
    assert pres is not None, "presence envelope must be on the wire when a brain is engaged"
    assert pres["overall_tier"] == "sealed"
    assert pres["spoken_text"]
    # Prosody is serialized whole (carried, not yet heard) so the S4 merge needs no
    # shape change here.
    assert pres["prosody_plan"]["tier"] == "sealed"

    # Per-claim render data the UI (presence.js normClaims/normEvidence) reads.
    assert pres["claims"], "claims drive the evidence chips"
    claim0 = pres["claims"][0]
    assert claim0["text"]                       # presence.js reads claim.text
    assert claim0["evidence"] and claim0["evidence"]["value"]  # a reachable handle

    verdict0 = pres["verdicts"][0]
    assert verdict0["tier"] == "sealed"
    assert verdict0["evidence"], "a SEALED verdict must carry the rows it was checked against"
    assert verdict0["evidence"][0]["sha256"]    # normEvidence reads .sha256
    assert isinstance(verdict0["recomputed_value"], int)  # the GATE's count, not the model's
    # Sealing is OFF by default → no attestation yet (S3 wires it under TEX_SEAL_DECISIONS=1).
    assert verdict0["attestation"] is None


class _GroundedBrain:
    """Reads the grounded fact sheet (brain_facts) and drafts the canonical phrase
    for a named key, keying the claim by its claim_id — exactly what the real
    prompt now instructs the model to do. Proves the grounded sheet reaches the
    brain THROUGH the live /v1/ask route."""

    def __init__(self, key):
        self._key = key

    def propose(self, *, question, tenant, facts, tools):
        from tex.presence.contract import ClaimKind, PresenceClaim

        rows = facts.get("recomputable_facts", []) if isinstance(facts, dict) else []
        fact = next((r for r in rows if r.get("claim_id") == self._key), None)
        if fact is None:
            return ("", ())
        draft = fact["phrase"]
        return (draft, (PresenceClaim(self._key, draft, ClaimKind.AGGREGATE),))


def test_ask_grounds_the_brain_and_seals_agent_count(client: TestClient) -> None:
    # Slice-1 fix through the real route: a grounded brain handed the gate's OWN
    # agent_count seals it and speaks the real number — instead of guessing a
    # number the gate disproves and abstaining on everything (the over-abstain bug).
    from tex.domain.agent import AgentIdentity

    reg = client.app.state.agent_registry
    reg.save(AgentIdentity(name="alpha", owner="acme", tenant_id="acme"))
    reg.save(AgentIdentity(name="beta", owner="acme", tenant_id="acme"))

    client.app.state.presence_brain = _GroundedBrain("agent_count")

    resp = client.post("/v1/ask", json={"transcript": "how many agents are in my directory?"})
    assert resp.status_code == 200
    pres = resp.json()["presence"]
    assert pres is not None, "a grounded brain should engage presence"
    assert pres["overall_tier"] == "sealed"
    assert "2" in pres["spoken_text"]
    assert pres["verdicts"][0]["recomputed_value"] == 2


def test_ask_presence_is_null_without_a_brain(client: TestClient) -> None:
    # The default app configures no GroundedBrain → presence stays null and the
    # legacy response is unchanged. The dormant-by-default guarantee.
    for _ in range(2):
        client.app.state.decision_store.save(_decision(Verdict.FORBID))
    resp = client.post(
        "/v1/ask", json={"transcript": "how many forbidden actions were there"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["presence"] is None
    assert body["answer"]  # the deterministic answer still stands on its own


def test_ask_presence_abstains_honestly(client: TestClient) -> None:
    # A brain that proposes a claim the gate cannot ground must surface an HONEST
    # ABSTAIN: tier "abstain", and NO claim/verdict presented as grounded.
    from tex.presence.contract import ClaimKind, PresenceClaim

    client.app.state.presence_brain = _FakeBrain(
        "zzqq",
        (PresenceClaim("definitely_not_a_query", "zzqq", ClaimKind.AGGREGATE),),
    )
    resp = client.post(
        "/v1/ask", json={"transcript": "how many forbidden actions were there"}
    )
    assert resp.status_code == 200
    pres = resp.json()["presence"]
    assert pres is not None
    assert pres["overall_tier"] == "abstain"
    assert pres["claims"] == []
    assert pres["verdicts"] == []


def test_ask_attaches_attestation_when_attestor_enabled(client: TestClient) -> None:
    # Wiring proof: an enabled attestor on app.state flows brain → gate →
    # build_envelope → apply_attestation, and the signed binding is serialized onto
    # the verdict for the proof glass. (The real crypto/forgery resistance is
    # covered by tests/presence/attest; this asserts the INTEGRATION carries it.)
    # A stub keeps the test hermetic — no signing key is minted.
    from tex.presence.contract import Attestation, ClaimKind, PresenceClaim, PresenceTier

    store = client.app.state.decision_store
    for _ in range(3):
        store.save(_decision(Verdict.FORBID))

    client.app.state.presence_brain = _FakeBrain(
        "how many forbids",
        (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),),
    )

    class _StubAttestor:
        enabled = True

        def attest(self, *, claim, verdict):
            if verdict.tier is PresenceTier.ABSTAIN:
                return None
            return Attestation(
                algorithm="ecdsa-p256",
                signed_digest_sha256="a" * 64,
                signature_b64="c2lnbmF0dXJl",
                is_post_quantum=False,
                key_id="presence-attest-key-v1",
            )

    client.app.state.presence_attestor = _StubAttestor()

    resp = client.post(
        "/v1/ask", json={"transcript": "how many forbidden actions were there"}
    )
    assert resp.status_code == 200
    v0 = resp.json()["presence"]["verdicts"][0]
    att = v0["attestation"]
    assert att is not None, "an enabled attestor must attach a signed binding to the verdict"
    assert att["algorithm"] == "ecdsa-p256"
    assert att["is_post_quantum"] is False
    assert att["signed_digest_sha256"] and att["signature_b64"]
    assert att["key_id"] == "presence-attest-key-v1"
