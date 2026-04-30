# Tex Integration Guide

> Tex is the gate between AI and the real world. This guide shows you the six ways you can integrate Tex into your stack.

Tex doesn't replace your AI infrastructure — it plugs into it. Pick whichever path matches where your AI agents already run.

## TL;DR — pick your path

| If you use... | Integration path | Setup time |
|---|---|---|
| Portkey, LiteLLM, TrueFoundry, Cloudflare AI Gateway, Solo.io | Add Tex as a guardrail provider in your gateway config | 2 minutes |
| Microsoft Copilot Studio or OpenAI AgentKit | Register Tex as an external runtime guardrail | 5 minutes |
| Cursor, Claude Desktop, Cline, MCP-aware LangChain | Add Tex's MCP server URL to your MCP config | 1 minute |
| Custom Python or Node.js agent | `pip install tex-guardrail` and wrap your calls | 5 lines of code |
| **Any Python agent codebase, LangChain, CrewAI** | **`tex.enforcement` gate decorator wraps your action functions** | **3 lines of code** |
| **Any HTTP-based agent action** | **Drop the `tex.enforcement.proxy` in front of your endpoint** | **One config block** |
| **Microsoft 365, Salesforce, AWS Bedrock, GitHub, OpenAI, MCP** | **Discovery layer auto-finds existing AI agents and feeds them into the registry — see V13_DISCOVERY.md** | **One scan call** |
| Anything else | Direct REST API to `/v1/guardrail` | Custom |

All paths share the same backend, the same evaluation engine, the same evidence chain. A decision created via Portkey can be replayed via the same audit endpoint as a decision created via the gate decorator.

---

## Path 1: AI gateway (Portkey, LiteLLM, Cloudflare, Solo.io, TrueFoundry, Bedrock)

Each major AI gateway lets you register a third-party guardrail provider via webhook. Tex exposes a native adapter URL for each.

### Portkey

In your Portkey config, add a `webhook` guardrail check:

```yaml
guardrails:
  - name: tex
    type: webhook
    config:
      url: https://api.tex.io/v1/guardrail/portkey
      headers:
        Authorization: "Bearer YOUR_TEX_API_KEY"
```

### LiteLLM

In your LiteLLM proxy config:

```yaml
guardrails:
  - guardrail_name: tex
    litellm_params:
      guardrail: webhook
      api_base: https://api.tex.io/v1/guardrail/litellm
      api_key: os.environ/TEX_API_KEY
      mode: pre_call
      default_on: true
```

### Cloudflare AI Gateway

In the Cloudflare dashboard under your AI Gateway → Guardrails → Custom Webhook:
- URL: `https://api.tex.io/v1/guardrail/cloudflare`
- Auth header: `Authorization: Bearer YOUR_TEX_API_KEY`

### Solo.io / Gloo AI Gateway

```yaml
apiVersion: gateway.solo.io/v1alpha1
kind: GuardrailWebhook
metadata:
  name: tex
spec:
  url: https://api.tex.io/v1/guardrail/solo
  headers:
    Authorization: "Bearer YOUR_TEX_API_KEY"
```

### TrueFoundry

```yaml
guardrails:
  - id: tex
    type: webhook
    url: https://api.tex.io/v1/guardrail/truefoundry
    apiKey: ${TEX_API_KEY}
    hooks: [llm_input, llm_output, mcp_tool_pre_invoke, mcp_tool_post_invoke]
```

### Bedrock-compatible

If you're already calling AWS Bedrock Guardrails and want Tex as a sidecar (or replacement), point at `/v1/guardrail/bedrock`. The response shape is Bedrock-compatible.

---

## Path 2: Agent platform (Copilot Studio, OpenAI AgentKit)

### Microsoft Copilot Studio

In Copilot Studio → Agent settings → Security → External guardrails → Add provider:
- Name: Tex
- Endpoint URL: `https://api.tex.io/v1/guardrail/copilot-studio`
- API key: paste your Tex API key

### OpenAI AgentKit

In AgentKit, register a runtime guardrail:

```python
from openai import AgentKit

agent = AgentKit(
    runtime_guardrails=[
        {
            "name": "tex",
            "url": "https://api.tex.io/v1/guardrail/agentkit",
            "headers": {"Authorization": "Bearer YOUR_TEX_API_KEY"},
        },
    ],
)
```

---

## Path 3: MCP-aware client (Cursor, Claude Desktop, Cline, modern LangChain)

If your agent speaks the Model Context Protocol, add Tex's MCP server to your config:

```json
{
  "mcpServers": {
    "tex": {
      "url": "https://api.tex.io/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TEX_API_KEY"
      }
    }
  }
}
```

Tex exposes a single MCP tool: `evaluate_action`. Your agent will discover it automatically and you can call it before any outbound action.

---

## Path 4: Python SDK (custom agents)

```bash
pip install tex-guardrail
```

```python
from tex_guardrail import TexClient, gate

tex = TexClient(api_key="YOUR_TEX_API_KEY")

@gate(client=tex, action_type="send_email", channel="email")
def send_outbound_email(content: str, recipient: str) -> None:
    smtp.send(to=recipient, body=content)
```

That's it. `send_outbound_email` is now gated. FORBID raises `TexBlocked` instead of executing the wrapped function.

For the full API, see `sdks/python/README.md`.

---

## Path 5: Direct REST API

`POST /v1/guardrail` accepts a canonical request shape that's a superset of every gateway's webhook contract.

```bash
curl https://api.tex.io/v1/guardrail \
  -H "Authorization: Bearer YOUR_TEX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "pre_call",
    "action_type": "send_email",
    "channel": "email",
    "content": "Hi Jordan, saw your job posting...",
    "recipient": "jordan@example.com"
  }'
```

Response:

```json
{
  "allowed": true,
  "verdict": "PERMIT",
  "score": 0.09,
  "confidence": 0.67,
  "reason": "Highest specialist risk came from destructive_or_bypass (0.18).",
  "decision_id": "13b15b27-73ba-4f79-89b9-a22d744810b5",
  "request_id": "f457de9b-c8d8-46e7-95b0-016d0cf1dde1",
  "policy_version": "default-v1",
  "asi_findings": []
}
```

To get a different response shape, append `?format=portkey` (or `litellm`, `cloudflare`, `solo`, `truefoundry`, `bedrock`).

---

## Streaming evaluation

Two streaming modes are supported, for two different use cases.

### Mode A: SSE progressive evaluation

`POST /v1/guardrail/stream` returns a Server-Sent Events stream. Useful when a gateway wants early signals before the full evaluation completes.

```bash
curl -N https://api.tex.io/v1/guardrail/stream \
  -H "Authorization: Bearer YOUR_TEX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hi Jordan...", "action_type": "send_email"}'
```

The stream emits these named events:

```
event: started
data: {"started_at": "2026-04-28T14:22:01Z", "source": null}

event: verdict
data: {"verdict": "PERMIT", "allowed": true, "score": 0.09, ...}

event: done
data: {"ok": true, "elapsed_ms": 187.3}
```

### Mode B: Token-stream chunk evaluation

`POST /v1/guardrail/stream/chunk` lets you evaluate streaming LLM output **chunk-by-chunk** so you can interrupt mid-stream when the response goes off-policy.

You generate a `session_id` (any UUID). For each new chunk of LLM output, POST it. Tex maintains a session buffer and returns the latest verdict you can act on.

```python
from tex_guardrail import TexClient
import uuid

tex = TexClient(api_key="YOUR_TEX_API_KEY")
session_id = str(uuid.uuid4())

for chunk in llm.stream(prompt):
    result = tex.evaluate_chunk(
        session_id=session_id,
        chunk=chunk.text,
        action_type="llm_response",
        channel="chat",
    )
    if result["verdict"] == "FORBID":
        # Drop the rest of the stream immediately.
        llm.cancel()
        break
    yield chunk

# Mark the session final to close the buffer.
tex.evaluate_chunk(session_id=session_id, chunk="", is_final=True)
```

Tex re-evaluates only when meaningful new content has accumulated (default 80 characters), so you don't pay an evaluation per token.

---

## Async (fire-and-forget) evaluation

`POST /v1/guardrail/async` accepts a request and returns `202 Accepted` immediately. The evaluation runs in the background and lands in the durable evidence chain.

```python
submit = tex.evaluate_async(
    content="email content here",
    action_type="send_email",
    channel="email",
)
decision_id = submit["decision_id"]

# Later (or via webhook), poll for the result:
result = tex.poll_async(decision_id)
if result["status"] == "complete":
    print(result["result"]["verdict"])
```

**Important:** async mode is observability-only. By the time the result is available, your action has already shipped. Use this for:

- High-throughput audit and drift monitoring
- Backfilling evidence on AI agent activity that already happened
- Sampling production traffic for compliance review

For pre-release gating, use the synchronous `POST /v1/guardrail` instead.

---

## Authentication

Tex accepts API keys via either header:

- `Authorization: Bearer YOUR_KEY` (recommended)
- `X-Tex-API-Key: YOUR_KEY`

Keys are configured server-side via the `TEX_API_KEYS` environment variable, in the format `key:tenant,key:tenant`. Each tenant gets surfaced into the evidence record so multi-customer deployments can correlate decisions to the calling tenant.

---

## Audit & evidence retrieval

Every decision — regardless of which integration path created it — produces a hash-chained, tamper-evident evidence record. Retrieve it any time:

```bash
# Replay the durable Decision record:
curl https://api.tex.io/decisions/{decision_id}/replay \
  -H "Authorization: Bearer YOUR_TEX_API_KEY"

# Get the signed evidence bundle (suitable for handing to an auditor):
curl https://api.tex.io/decisions/{decision_id}/evidence-bundle \
  -H "Authorization: Bearer YOUR_TEX_API_KEY"
```

The bundle contains:
- The original request
- Every layer's evaluation (deterministic, retrieval, specialists, semantic, routing)
- The OWASP ASI 2026 findings with evidence trails
- The chain hash and verification status

This is what you hand to your SOC 2 auditor, FINRA examiner, or EU AI Act regulator.

---

## What gets evaluated, exactly

Tex runs every action through a six-layer pipeline:

1. **Deterministic gate** — regex/recognizer-based PII, secrets, blocked terms
2. **Retrieval grounding** — pulls relevant policy clauses, precedents, entities
3. **Specialist judges** — data leakage, external sharing, unauthorized commitment, destructive/bypass, policy compliance
4. **Semantic analysis** — schema-locked LLM evaluation against your policy
5. **Fusion router** — weighted score blending + criticality-based escalation
6. **Evidence chain** — hash-chained, tamper-evident record of the entire decision

Three possible verdicts:

- **PERMIT** — clean; release the action
- **ABSTAIN** — uncertain; escalate to human review
- **FORBID** — blocked by policy; never released

---

## What about latency?

Tex's median evaluation latency is ~178ms when the semantic LLM provider is configured. Without an LLM (deterministic + heuristic fallback only), it's sub-10ms. The gateway adapters all run synchronously by default; if your gateway supports async guardrails, configure it that way for non-blocking workflows.

---

## Path 6: In-process enforcement (V12)

For Python agent codebases, the smallest possible integration is the `tex.enforcement` gate. It wraps any callable so the callable cannot execute unless Tex returns PERMIT.

### Decorator form (recommended)

```python
from tex.enforcement import TexGate, GateConfig, DirectCommandTransport, tex_gated
from tex.main import build_runtime

runtime = build_runtime()
gate = TexGate(GateConfig(transport=DirectCommandTransport(runtime.evaluate_action_command)))

@tex_gated(gate, content_arg="body", recipient_arg="to", action_type="send_email")
def send_email(*, to: str, body: str) -> None:
    smtp_client.send(to=to, body=body)

# On FORBID: send_email never runs, TexForbiddenError is raised.
# On PERMIT: send_email runs normally, return value is preserved.
```

### Imperative form (most flexible)

```python
from tex.enforcement import TexGate, GateConfig, AbstainPolicy
from tex.enforcement import HttpClientTransport
import httpx

gate = TexGate(GateConfig(
    transport=HttpClientTransport(client=httpx.Client(), url="https://tex.yourorg.com/evaluate"),
    abstain_policy=AbstainPolicy.REVIEW,  # raise on ABSTAIN so a human can intervene
))

response = gate.check(
    content=email_body,
    action_type="send_email",
    recipient=to_address,
    agent_id=agent_uuid,
)
# Reaches this line only on PERMIT.
smtp_client.send(to=to_address, body=email_body)
```

### LangChain

```python
from tex.enforcement.adapters import make_langchain_tex_tool

gated_tool = make_langchain_tex_tool(
    gate=gate,
    base_tool=my_send_email_tool,
    content_arg="body",
    recipient_arg="to",
)
agent = AgentExecutor(tools=[gated_tool, ...])
# When the LLM calls the tool with content that Tex FORBIDs, the
# AgentExecutor receives the refusal as a tool observation and the
# agent can recover gracefully.
```

### CrewAI

```python
from tex.enforcement.adapters import make_crewai_tex_tool

tool = make_crewai_tex_tool(
    gate=gate,
    fn=send_message,
    name="send_message",
    description="Send a message via internal API",
    content_arg="body",
)
agent = Agent(role="...", tools=[tool])
```

### MCP server middleware

```python
from tex.enforcement.adapters import make_mcp_tool_middleware

@make_mcp_tool_middleware(gate=gate, content_arg="message")
def post_message(arguments: dict) -> dict:
    return slack_client.post(channel=arguments["channel"], text=arguments["message"])

# Mount post_message as your MCP tool. FORBID actions never reach
# the underlying handler.
```

---

## Path 7: HTTP enforcement proxy (V12)

For HTTP-based agent actions, drop the proxy in front of the action endpoint:

```python
from tex.enforcement import TexGate, GateConfig, DirectCommandTransport
from tex.enforcement.proxy import build_enforcement_proxy, UpstreamForwarder
import httpx, uvicorn

gate = TexGate(GateConfig(transport=DirectCommandTransport(runtime.evaluate_action_command)))
forwarder = UpstreamForwarder(client=httpx.Client(), upstream_url="https://internal.example/send-email")
app = build_enforcement_proxy(gate=gate, forwarder=forwarder)

uvicorn.run(app, host="0.0.0.0", port=8443)
```

Now point your agent at `http://your-proxy:8443/...` instead of the original endpoint.

- `200/...` upstream response on PERMIT
- `403` with Tex evidence on FORBID
- `409` with Tex evidence on ABSTAIN
- `502` with Tex evidence on UNAVAILABLE (fail-closed by default)

The proxy is stateless and platform-agnostic. It works in front of any HTTP endpoint regardless of what's running it.

---

## Five guarantees the V12 enforcement layer makes

1. **FORBID always blocks the wrapped action.** No flag overrides this.
2. **PERMIT always passes through transparently.**
3. **ABSTAIN behavior is configurable** — `BLOCK` (default), `ALLOW` (with audit flag), `REVIEW` (raises typed error for human routing).
4. **Failure modes are fail-closed by default.** If Tex is unreachable or errors, the wrapped action does NOT execute. Operators can opt into fail-open with `fail_closed=False`, but the library never does.
5. **Every gated execution emits exactly one `GateEvent`** for audit. Plug in a `GateEventObserver` to route to logs, metrics, or your audit backend.

---

## Questions, partnership inquiries, security review

Email matt@texaegis.com.
