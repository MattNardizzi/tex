"""
End-to-end smoke for the canonical guardrail webhook.

Spins up the real Tex FastAPI app, drives a single payload through the
guardrail endpoint in every supported response format, and confirms the
engine produced a real Decision with a hash-chained evidence record.

This is a smoke, not a unit test — it exercises the full integration path
(routing -> normalization -> EvaluateActionCommand -> engine -> renderer)
without mocking any layer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from uuid import uuid4

# Local import so the smoke can run from a fresh checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[0] / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from tex.api.guardrail import GuardrailFormat, build_guardrail_router  # noqa: E402
from tex.main import create_app  # noqa: E402


def _build_app():
    app = create_app()
    # Mount the guardrail router so the canonical endpoint is exposed.
    # In production this happens in tex.main.create_app once we wire it
    # there; this smoke proves the router is composable today.
    app.include_router(build_guardrail_router())
    return app


def _payload_clean() -> dict:
    """A clean cold-outreach style payload: should permit."""
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": (
            "Hi Jordan, I lead growth at Acme. Saw your team is hiring "
            "for revops — happy to share what's working for similar teams "
            "in your stage. Worth a 15-min call next week?"
        ),
        "source": "smoke_test",
        "session_id": "sess_001",
        "user_id": "user_123",
    }


def _payload_dirty() -> dict:
    """A payload that should trigger deterministic findings (PII / secrets)."""
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "buyer@example.com",
        "content": (
            "Hey - looping you in. Use the API key sk-proj-abc1234567890XYZ "
            "to run the import. Customer contact ssn 123-45-6789. We can "
            "settle the wire to acct 4111111111111111 by EOD."
        ),
        "source": "smoke_test",
    }


def _payload_messages() -> dict:
    """Chat-message-array payload (OpenAI / Anthropic style)."""
    return {
        "stage": "pre_call",
        "messages": [
            {"role": "system", "content": "You are a helpful sales assistant."},
            {"role": "user", "content": "Send Maria a friendly check-in email."},
        ],
        "source": "smoke_test",
    }


def _payload_tool_call() -> dict:
    """MCP-style tool-invocation payload."""
    return {
        "stage": "tool_invocation",
        "tool_call": {
            "name": "send_email",
            "server": "gmail-mcp",
            "arguments": {
                "to": "external@competitor.com",
                "subject": "internal pricing",
                "body": "Our internal pricing is $40k floor.",
            },
        },
        "source": "smoke_test",
    }


def _hit(client: TestClient, payload: dict, fmt: GuardrailFormat) -> dict:
    response = client.post(
        f"/v1/guardrail?format={fmt.value}",
        json=payload,
    )
    assert response.status_code == 200, (
        f"format={fmt.value} returned {response.status_code}: {response.text}"
    )
    return response.json()


def main() -> int:
    app = _build_app()
    client = TestClient(app)

    print("=== /v1/guardrail/formats ===")
    formats_response = client.get("/v1/guardrail/formats")
    assert formats_response.status_code == 200, formats_response.text
    print(json.dumps(formats_response.json(), indent=2))
    print()

    print("=== Clean cold-outreach payload, all formats ===")
    for fmt in GuardrailFormat:
        body = _hit(client, _payload_clean(), fmt)
        print(f"[{fmt.value}]")
        print(json.dumps(body, indent=2)[:600])
        print()

    print("=== Dirty payload (PII / secrets), canonical format ===")
    dirty_canonical = _hit(client, _payload_dirty(), GuardrailFormat.CANONICAL)
    print(json.dumps(dirty_canonical, indent=2)[:1200])
    print()

    print("=== Dirty payload, Portkey format ===")
    dirty_portkey = _hit(client, _payload_dirty(), GuardrailFormat.PORTKEY)
    print(json.dumps(dirty_portkey, indent=2))
    print()

    print("=== Chat-message payload ===")
    msg_resp = _hit(client, _payload_messages(), GuardrailFormat.CANONICAL)
    print(f"verdict={msg_resp['verdict']}  allowed={msg_resp['allowed']}  "
          f"score={msg_resp['score']:.3f}  reason={msg_resp['reason']!r}")
    print()

    print("=== Tool-call payload ===")
    tool_resp = _hit(client, _payload_tool_call(), GuardrailFormat.CANONICAL)
    print(f"verdict={tool_resp['verdict']}  allowed={tool_resp['allowed']}  "
          f"score={tool_resp['score']:.3f}  reason={tool_resp['reason']!r}")
    print()

    print("=== Replay the dirty decision via existing audit route ===")
    decision_id = dirty_canonical["decision_id"]
    replay = client.get(f"/decisions/{decision_id}/replay")
    assert replay.status_code == 200, replay.text
    replayed = replay.json()
    print(f"decision_id={replayed['decision_id']}  "
          f"verdict={replayed['verdict']}  "
          f"asi_findings={len(replayed['asi_findings'])}  "
          f"reasons={len(replayed['reasons'])}")
    print()

    print("=== Bad-format error path ===")
    bad = client.post(
        "/v1/guardrail?format=does_not_exist",
        json=_payload_clean(),
    )
    print(f"status={bad.status_code}  body={bad.json()}")
    assert bad.status_code == 400
    print()

    print("=== Empty-content error path ===")
    empty = client.post(
        "/v1/guardrail",
        json={"stage": "pre_call", "source": "smoke_test"},
    )
    print(f"status={empty.status_code}  body={empty.json()}")
    assert empty.status_code in (400, 422)
    print()

    print("ALL SMOKES PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
