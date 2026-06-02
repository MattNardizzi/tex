"""
Tests for streaming and async evaluation endpoints.

Covers:
- POST /v1/guardrail/async (fire-and-forget submission + 202)
- GET /v1/guardrail/async/{id} (polling)
- POST /v1/guardrail/stream (SSE progressive)
- POST /v1/guardrail/stream/chunk (token-stream evaluation)
- TTL store eviction behavior
"""

from __future__ import annotations

import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def fresh_app(monkeypatch):
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    from tex.main import create_app
    return create_app()


@pytest.fixture
def client(fresh_app):
    return TestClient(fresh_app)


def _clean() -> dict:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "content": "Hi Jordan, following up on our chat last week.",
        "source": "stream_test",
    }


def _dirty() -> dict:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "content": (
            "Use the API key sk-proj-abc1234567890XYZ. SSN 123-45-6789. "
            "Wire to acct 4111111111111111."
        ),
        "source": "stream_test",
    }


# ------------------------------------------------------------------------- #
# Async submission + polling                                                #
# ------------------------------------------------------------------------- #


class TestAsyncMode:
    def test_submit_returns_202(self, client):
        resp = client.post("/v1/guardrail/async", json=_clean())
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "accepted"
        assert "decision_id" in body
        assert body["poll_url"].endswith(body["decision_id"])
        # The note must explicitly disclaim the use case for safety.
        assert "observability-only" in body["note"].lower()

    def test_poll_after_submit_succeeds(self, client):
        submit = client.post("/v1/guardrail/async", json=_clean())
        decision_id = submit.json()["decision_id"]

        # Background tasks complete after the response in TestClient.
        # Poll until status flips to complete (with a short timeout).
        deadline = time.time() + 5.0
        result = None
        while time.time() < deadline:
            poll = client.get(f"/v1/guardrail/async/{decision_id}")
            assert poll.status_code == 200
            result = poll.json()
            if result["status"] == "complete":
                break
            time.sleep(0.05)

        assert result is not None
        assert result["status"] == "complete"
        assert result["result"] is not None
        assert result["result"]["verdict"] in ("PERMIT", "ABSTAIN", "FORBID")
        assert result["completed_at"] is not None

    def test_poll_unknown_decision_404s(self, client):
        resp = client.get(f"/v1/guardrail/async/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_async_dirty_payload_records_forbid(self, client):
        submit = client.post("/v1/guardrail/async", json=_dirty())
        decision_id = submit.json()["decision_id"]

        deadline = time.time() + 5.0
        result = None
        while time.time() < deadline:
            poll = client.get(f"/v1/guardrail/async/{decision_id}")
            result = poll.json()
            if result["status"] == "complete":
                break
            time.sleep(0.05)

        assert result["status"] == "complete"
        assert result["result"]["verdict"] == "FORBID"

    def test_async_invalid_payload_rejected_at_submit(self, client):
        # Empty payload should be rejected before queueing.
        resp = client.post(
            "/v1/guardrail/async",
            json={"stage": "pre_call", "source": "test"},
        )
        assert resp.status_code in (400, 422)


# ------------------------------------------------------------------------- #
# SSE progressive endpoint                                                  #
# ------------------------------------------------------------------------- #


class TestSSEStream:
    def _parse_sse(self, body: str) -> list[dict]:
        """Parse an SSE response body into a list of {event, data} frames."""
        frames = []
        current_event = None
        for line in body.split("\n"):
            line = line.rstrip("\r")
            if line.startswith("event:"):
                current_event = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data = line[len("data:"):].strip()
                frames.append({
                    "event": current_event,
                    "data": json.loads(data) if data else None,
                })
                current_event = None
        return frames

    def test_stream_returns_event_stream_content_type(self, client):
        resp = client.post("/v1/guardrail/stream", json=_clean())
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")

    def test_stream_emits_started_verdict_done(self, client):
        resp = client.post("/v1/guardrail/stream", json=_clean())
        frames = self._parse_sse(resp.text)
        events = [f["event"] for f in frames]
        assert "started" in events
        assert "verdict" in events
        assert "done" in events
        # Order: started must come before verdict, verdict before done.
        assert events.index("started") < events.index("verdict")
        assert events.index("verdict") < events.index("done")

    def test_stream_verdict_frame_contains_canonical_shape(self, client):
        resp = client.post("/v1/guardrail/stream", json=_clean())
        frames = self._parse_sse(resp.text)
        verdict_frames = [f for f in frames if f["event"] == "verdict"]
        assert len(verdict_frames) == 1
        verdict = verdict_frames[0]["data"]
        # Canonical shape required keys.
        assert "verdict" in verdict
        assert "allowed" in verdict
        assert "score" in verdict
        assert "decision_id" in verdict
        assert verdict["verdict"] in ("PERMIT", "ABSTAIN", "FORBID")

    def test_stream_dirty_emits_forbid(self, client):
        resp = client.post("/v1/guardrail/stream", json=_dirty())
        frames = self._parse_sse(resp.text)
        verdict = next(f["data"] for f in frames if f["event"] == "verdict")
        assert verdict["verdict"] == "FORBID"
        assert verdict["allowed"] is False

    def test_stream_done_carries_elapsed_ms(self, client):
        resp = client.post("/v1/guardrail/stream", json=_clean())
        frames = self._parse_sse(resp.text)
        done = next(f["data"] for f in frames if f["event"] == "done")
        assert done["ok"] is True
        assert "elapsed_ms" in done
        assert isinstance(done["elapsed_ms"], (int, float))

    def test_stream_decision_is_durable(self, client):
        """SSE-evaluated decisions should be replayable like sync ones."""
        resp = client.post("/v1/guardrail/stream", json=_dirty())
        frames = self._parse_sse(resp.text)
        verdict = next(f["data"] for f in frames if f["event"] == "verdict")
        decision_id = verdict["decision_id"]
        replay = client.get(f"/decisions/{decision_id}/replay")
        assert replay.status_code == 200


# ------------------------------------------------------------------------- #
# Token-stream chunk endpoint                                               #
# ------------------------------------------------------------------------- #


class TestStreamChunk:
    def test_first_chunk_returns_baseline_verdict(self, client):
        session_id = str(uuid.uuid4())
        resp = client.post(
            "/v1/guardrail/stream/chunk",
            json={
                "session_id": session_id,
                "chunk": "Hi Jordan,",
                "action_type": "llm_response",
                "channel": "chat",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session_id
        assert body["chunk_index"] == 1
        assert body["cumulative_chars"] == len("Hi Jordan,")
        # First chunk always evaluates so the customer has a baseline.
        assert body["re_evaluated"] is True
        assert body["verdict"] in ("PERMIT", "ABSTAIN", "FORBID")

    def test_subsequent_small_chunks_skip_reeval(self, client):
        session_id = str(uuid.uuid4())
        # Seed the session.
        client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": "Hi Jordan,"},
        )
        # A small follow-up chunk under the threshold should not re-evaluate.
        resp = client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": " just"},
        )
        body = resp.json()
        assert body["chunk_index"] == 2
        # Threshold is 80 chars; we sent ~16 cumulative so no re-eval.
        assert body["re_evaluated"] is False

    def test_large_cumulative_triggers_reeval(self, client):
        session_id = str(uuid.uuid4())
        # First chunk seeds session AND counts as a re-eval (baseline).
        client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": "Hello there. "},
        )
        # Send a very large second chunk to exceed the threshold.
        big_chunk = "Some additional context. " * 10  # ~250 chars
        resp = client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": big_chunk},
        )
        assert resp.json()["re_evaluated"] is True

    def test_dirty_chunk_flips_verdict_to_forbid(self, client):
        session_id = str(uuid.uuid4())
        # Clean opener.
        client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": "Hi Jordan, following up. "},
        )
        # Then a chunk with secret + PII that should flip the verdict.
        dirty_chunk = (
            "Use API key sk-proj-abc1234567890XYZ. "
            "Customer SSN 123-45-6789. "
            "Wire to acct 4111111111111111. "
        ) * 2  # repeat to exceed re-eval threshold
        resp = client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": dirty_chunk, "is_final": True},
        )
        body = resp.json()
        assert body["re_evaluated"] is True
        assert body["verdict"] == "FORBID"
        assert body["allowed"] is False

    def test_is_final_clears_session(self, client):
        session_id = str(uuid.uuid4())
        # Submit final chunk.
        client.post(
            "/v1/guardrail/stream/chunk",
            json={
                "session_id": session_id,
                "chunk": "complete content here",
                "is_final": True,
            },
        )
        # Sending another chunk for the same session_id should start fresh
        # (chunk_index 1, not 2) because is_final cleared the session.
        resp = client.post(
            "/v1/guardrail/stream/chunk",
            json={"session_id": session_id, "chunk": "fresh start"},
        )
        body = resp.json()
        assert body["chunk_index"] == 1


# ------------------------------------------------------------------------- #
# TTL store behavior                                                        #
# ------------------------------------------------------------------------- #


class TestTTLStore:
    def test_put_and_get(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore(default_ttl_seconds=60)
        store.put("k1", {"value": 1})
        assert store.get("k1") == {"value": 1}

    def test_missing_key_returns_none(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore()
        assert store.get("nope") is None

    def test_expired_entries_evict(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore(default_ttl_seconds=0)  # immediate expiry
        store.put("k", "v")
        # Force a tick past the expiry boundary.
        time.sleep(0.01)
        assert store.get("k") is None

    def test_max_entries_bounded(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore(default_ttl_seconds=60, max_entries=3)
        for i in range(5):
            store.put(f"k{i}", i)
            time.sleep(0.001)  # ensure ordering
        # After 5 puts with max_entries=3, only last 3 should remain.
        assert len(store) <= 3

    def test_update_refreshes_value_and_ttl(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore(default_ttl_seconds=60)
        store.put("k", {"v": 1})
        ok = store.update("k", {"v": 2})
        assert ok is True
        assert store.get("k") == {"v": 2}

    def test_update_returns_false_on_missing_key(self):
        from tex.api.runtime_store import TTLStore
        store = TTLStore(default_ttl_seconds=60)
        assert store.update("missing", "x") is False


# ------------------------------------------------------------------------- #
# Service metadata reflects new endpoints                                   #
# ------------------------------------------------------------------------- #


class TestServiceMetadataStreaming:
    def test_root_lists_streaming_and_async(self, client):
        resp = client.get("/")
        body = resp.json()
        integrations = body["integrations"]
        assert "streaming" in integrations
        assert integrations["streaming"]["sse_progressive"] == "POST /v1/guardrail/stream"
        assert integrations["streaming"]["token_chunk"] == "POST /v1/guardrail/stream/chunk"
        assert "async" in integrations
        assert integrations["async"]["submit"] == "POST /v1/guardrail/async"
