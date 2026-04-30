# V12 — Enforcement: Decision-and-Enforcement End-to-End

## Summary

V10 fused agent governance into the verdict. V11 added cross-agent
content baseline. V12 closes the last gap between **what Tex
decides** and **what actually happens in the real world** by shipping
the enforcement layer that makes verdicts physically stop actions.

Before V12, Tex returned PERMIT / ABSTAIN / FORBID and the calling
code was expected to honor it. That is the architecturally correct
separation of decision and enforcement, but it left a marketing gap:
"Tex decides which AI actions can execute" was true; "Tex stops AI
actions before they reach the real world" was true *only if the
caller integrated correctly*. V12 ships the integration, so both
claims are now end-to-end true out of the box.

## What V12 ships

### Core: `tex.enforcement.TexGate`

The smallest possible piece of code that turns "Tex returned a
verdict" into "the action did or did not happen."

```python
from tex.enforcement import TexGate, GateConfig, DirectCommandTransport, tex_gated

gate = TexGate(GateConfig(transport=DirectCommandTransport(runtime.evaluate_action_command)))

@tex_gated(gate, content_arg="body", recipient_arg="to")
def send_email(*, to: str, body: str) -> None:
    smtp_client.send(to=to, body=body)

# On FORBID: send_email never runs, TexForbiddenError is raised.
# On PERMIT: send_email runs normally, return value is preserved.
# On ABSTAIN: configurable (BLOCK / ALLOW / REVIEW).
# On Tex unavailable: fail-closed by default, TexUnavailableError is raised.
```

Five guarantees the gate makes:

1. **FORBID always blocks.** No flag overrides this.
2. **PERMIT always passes through transparently.**
3. **ABSTAIN behavior is configurable** — BLOCK / ALLOW / REVIEW.
4. **Failure modes are fail-closed by default.** Operators can opt into
   fail-open with `fail_closed=False`, but the library never does.
5. **Every gated execution emits exactly one `GateEvent`.** Observer
   failures are suppressed and never break enforcement.

Both sync (`TexGate`) and async (`TexGateAsync`) flavors ship. The
async flavor runs the synchronous transport on a thread to avoid
blocking the event loop.

### Transports

- **`DirectCommandTransport`** — calls the in-process
  `EvaluateActionCommand` directly. Lowest latency; use when Tex is
  embedded in the same process as the agent.
- **`HttpClientTransport`** — calls a remote `/evaluate` endpoint
  over HTTP. Accepts any `httpx.Client`-shaped object; the library
  itself does not import httpx.
- **`CallableTransport`** — thin shim around any callable, useful
  for testing and custom transport shims (gRPC, queues, etc.).

### Framework adapters: `tex.enforcement.adapters`

Drop-in adapters for the major agent frameworks:

- **`make_langchain_tex_tool`** — wraps any `langchain.tools.BaseTool`
  so its `_run` is gated by Tex. AgentExecutor sees refusals as tool
  observations, so the agent can recover gracefully.
- **`make_crewai_tex_tool`** — gates a CrewAI tool function. Falls
  back to a duck-typed shim if `crewai` isn't installed, so the
  adapter is testable without the dependency.
- **`make_mcp_tool_middleware`** — decorator factory for MCP server-
  side tool functions. Reads content from the structured arguments
  dict, calls Tex, only invokes the underlying handler on PERMIT.
- **`make_langchain_async_tex_tool`** — async-native variant of the
  LangChain adapter for tools whose underlying work is async.

All adapters import their framework lazily.

### HTTP enforcement proxy: `tex.enforcement.proxy`

A small ASGI app that sits in front of any HTTP-based agent action,
calls Tex with the request body as the content under evaluation, and
either forwards or refuses based on the verdict.

```
[agent] -> [tex enforcement proxy] -> [agent's real action endpoint]
```

- 200/upstream response on PERMIT (forwarded transparently)
- **403 with Tex evidence on FORBID**
- **409 with Tex evidence on ABSTAIN**
- **502 with Tex evidence on UNAVAILABLE** (fail-closed default)

Default content extractor handles common JSON fields (`content`,
`body`, `text`, `message`, `input`, `prompt`) and falls back to the
full body. Pluggable for non-standard payloads.

### Errors: `tex.enforcement.errors`

Structured error hierarchy callers catch to react to verdicts:

- `TexEnforcementError` (base)
  - `TexForbiddenError` — verdict was FORBID
  - `TexAbstainError` — verdict was ABSTAIN under BLOCK or REVIEW
  - `TexUnavailableError` — Tex unreachable / errored, fail-closed

Every error carries the full `EvaluationResponse` (when available)
so callers can attach evidence to their own audit trail without
re-evaluating.

### Audit: `tex.enforcement.events`

Every gated execution emits one `GateEvent`. Frozen, slotted, cheap
to construct. Carries the request, the verdict, the decision_id, the
fingerprint, the gate's outcome (`executed` / `blocked` / `reviewed`),
and the wall-clock latency. Plug in a `GateEventObserver` to route
events to logs, metrics, or audit backends. Default is a no-op.

`CollectingObserver` ships for test usage.

## Test coverage

- 293 pre-V12 tests: all passing (zero regressions)
- 34 new V12 tests: all passing
- **Total: 327 passing, 0 failing**

V12 test coverage by guarantee:

| Guarantee | Tests |
|-----------|-------|
| FORBID always blocks | 3 (imperative, decorator, abstain-policy-irrelevant) |
| PERMIT passes through | 2 (imperative, decorator preserves return) |
| ABSTAIN follows policy | 3 (BLOCK / ALLOW / REVIEW) |
| Fail-closed by default | 2 (closed default, open is explicit) |
| Observer contract | 3 (one event per check, observer failure suppressed, blocked event recorded) |

Plus integration coverage for the decorator shape, the async gate
(3 tests), the direct in-process transport against real Tex, the
HTTP transport (3 tests including 4xx → unavailable), the MCP
middleware (3 tests), the CrewAI adapter (2 tests), and the HTTP
proxy (5 tests including PERMIT-forward, FORBID-refuse, ABSTAIN-
refuse, UNAVAILABLE-502, content extractor edge cases). One final
test asserts that V12 is purely additive — importing `tex.enforcement`
does not alter the existing runtime.

## Files added

```
src/tex/enforcement/__init__.py        # public surface
src/tex/enforcement/errors.py          # typed error hierarchy
src/tex/enforcement/events.py          # GateEvent + observer protocol
src/tex/enforcement/transport.py       # 3 transports (direct/http/callable)
src/tex/enforcement/gate.py            # TexGate, TexGateAsync, decorators
src/tex/enforcement/adapters.py        # langchain/crewai/mcp adapters
src/tex/enforcement/proxy.py           # HTTP enforcement proxy
tests/test_enforcement.py              # 34 tests covering all five guarantees
V12_ENFORCEMENT.md                     # this file
```

## Files modified

```
INTEGRATIONS.md   # documents the new enforcement integration patterns
```

## What this means strategically

Before V12, the honest pitch was:

> "Tex evaluates AI actions before they execute and returns
> PERMIT/ABSTAIN/FORBID. Enforcement happens at the call site, the
> way every serious policy product works."

That pitch was true and defensible, but it gave Zenity and Noma a
talking point — "we *block* actions, they only *decide*." V12
removes that gap. The new pitch is:

> "Tex evaluates AI actions before they execute *and* enforces the
> verdict at the call site. Drop our gate decorator on your action
> functions, drop our HTTP proxy in front of your action endpoints,
> or use our LangChain / CrewAI / MCP adapters — and FORBID actions
> physically don't happen, with cryptographic evidence on every
> decision."

That is no longer "decision layer with optional enforcement." That
is decision-and-enforcement end-to-end, with the decision layer
still architecturally separate (so it scales, so it doesn't sit in
the data path of every action), but with first-class adapters that
make enforcement the default integration shape.

## Why this is structurally different from Zenity/Noma's "block"

Zenity and Noma block by being inside the platform — they need
Microsoft Copilot Studio, Salesforce AgentForce, ServiceNow, or one
of their other 80+ platform integrations to be present. Their
"block" is platform-coupled.

Tex's gate is platform-agnostic. The gate decorator works in any
Python codebase. The HTTP proxy works in front of any HTTP endpoint.
The MCP middleware works in any MCP server. The framework adapters
cover LangChain and CrewAI (the dominant homegrown agent stacks).
None of these require Microsoft, Salesforce, ServiceNow, or AWS to
be in the picture.

So when a buyer asks "do you stop the action?": yes. And when they
ask "do I need to be on a specific platform for that to work?": no.
That is a strictly stronger position than the platform-coupled
incumbents on the cross-platform axis Gartner explicitly called out
as the strategic opening in the 2026 Market Guide for Guardian Agents.
