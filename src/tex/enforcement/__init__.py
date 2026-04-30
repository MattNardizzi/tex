"""
Tex Enforcement — in-process and at-the-edge enforcement adapters.

Tex's PDP returns a verdict (PERMIT / ABSTAIN / FORBID). The enforcement
package is what makes that verdict *actually stop the action* before it
reaches the real world. Without it, Tex is a decision layer; with it,
Tex is a decision-and-enforcement layer end-to-end.

Three deployment shapes are supported, sharing one core primitive:

1. In-process gate — `TexGate` + `@tex_gated` decorator wrap a Python
   callable so it cannot execute on FORBID. Works for any agent
   framework that calls Python functions to take actions (the common
   case in 2026).

2. Framework adapters — `LangChainTexTool`, `CrewAITexTool`, and
   `MCPTexMiddleware` apply the same gate to the framework's native
   tool/middleware abstractions.

3. HTTP proxy adapter — `tex.enforcement.proxy` ships a small ASGI
   app that sits in front of any HTTP-based agent action, calls Tex,
   and forwards or refuses based on the verdict.

All three honor the same five contracts:

- FORBID always blocks. There is no flag to override this.
- PERMIT always passes through transparently.
- ABSTAIN behavior is configurable: BLOCK (default — fail closed),
  ALLOW (with a warning callback), or REVIEW (raise a typed error
  the caller can route to a human).
- Failure modes are fail-closed by default: if Tex is unreachable
  or the call times out, the wrapped action does NOT execute.
- Every gated execution emits a structured GateEvent for audit;
  callers can plug in their own observer.

This package has no required dependency on FastAPI, httpx, LangChain,
CrewAI, or any framework. The framework adapters import their
framework lazily so users only pay for what they use.
"""

from __future__ import annotations

from tex.enforcement.errors import (
    TexAbstainError,
    TexEnforcementError,
    TexForbiddenError,
    TexUnavailableError,
)
from tex.enforcement.events import GateEvent, GateEventObserver, NullObserver
from tex.enforcement.gate import (
    AbstainPolicy,
    GateConfig,
    TexGate,
    TexGateAsync,
    tex_gated,
    tex_gated_async,
)
from tex.enforcement.transport import (
    DirectCommandTransport,
    HttpClientTransport,
    TexEvaluationTransport,
)


__all__ = [
    "AbstainPolicy",
    "DirectCommandTransport",
    "GateConfig",
    "GateEvent",
    "GateEventObserver",
    "HttpClientTransport",
    "NullObserver",
    "TexAbstainError",
    "TexEnforcementError",
    "TexEvaluationTransport",
    "TexForbiddenError",
    "TexGate",
    "TexGateAsync",
    "TexUnavailableError",
    "tex_gated",
    "tex_gated_async",
]
