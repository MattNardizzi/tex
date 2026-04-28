# tex-guardrail

Official Python SDK for [Tex](https://texaegis.com) — the gate between AI and the real world.

## Installation

```bash
pip install tex-guardrail
```

## Quick start

```python
from tex_guardrail import TexClient

tex = TexClient(api_key="your-api-key", base_url="https://api.tex.io")

verdict = tex.evaluate(
    content="Hi Jordan, saw you're hiring for revops...",
    action_type="send_email",
    channel="email",
    recipient="jordan@example.com",
)

print(verdict.verdict)        # PERMIT, ABSTAIN, or FORBID
print(verdict.score)          # 0.0–1.0 risk score
print(verdict.reason)         # human-readable summary
print(verdict.decision_id)    # for evidence-bundle retrieval

if verdict.allowed:
    send_email(...)
elif verdict.is_abstain:
    send_to_human_review_queue(...)
else:
    log_block(...)
```

## Decorator pattern

Wrap any function whose outbound action you want gated:

```python
from tex_guardrail import TexClient, gate

tex = TexClient(api_key="your-api-key")

@gate(client=tex, action_type="send_email", channel="email")
def send_outbound_email(content: str, recipient: str) -> None:
    smtp.send(to=recipient, body=content)

# This call is automatically evaluated; FORBID raises TexBlocked.
send_outbound_email(content="...", recipient="jordan@example.com")
```

## Tool/MCP invocation evaluation

```python
verdict = tex.evaluate(
    tool_call={
        "name": "send_email",
        "server": "gmail-mcp",
        "arguments": {
            "to": "external@competitor.com",
            "subject": "internal pricing",
            "body": "Our internal pricing is $40k floor.",
        },
    },
)
```

## OpenAI / Anthropic chat-style payloads

```python
verdict = tex.evaluate(
    messages=[
        {"role": "system", "content": "You are a sales assistant."},
        {"role": "user", "content": "Send Maria a follow-up."},
    ],
)
```

## Error handling

```python
from tex_guardrail import TexBlocked, TexAuthError, TexError

try:
    verdict = tex.evaluate(content="...", raise_on_forbid=True)
except TexBlocked as exc:
    print(f"Blocked: {exc.verdict.reason}")
    print(f"OWASP findings: {exc.verdict.asi_findings}")
except TexAuthError:
    print("Invalid API key.")
except TexError as exc:
    print(f"Tex error: {exc}")
```

## Why Tex

Tex returns a three-way verdict (PERMIT / ABSTAIN / FORBID) — not just a binary block — so high-stakes actions can be routed to human review instead of silently dropped. Every decision produces a hash-chained, tamper-evident evidence record mapped to OWASP ASI 2026 findings, suitable for SOC 2, FINRA, HIPAA, and EU AI Act audit trails.
