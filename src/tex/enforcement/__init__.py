"""
[Architecture: Layer 4 (Execution Governance)] — TexGate, @tex_gated decorator, framework adapters, ASGI proxy — built but not invoked by the runtime today

See ARCHITECTURE.md for the full six-layer model.

Tex Enforcement — in-process and at-the-edge enforcement adapters.

Tex's PDP returns a verdict (PERMIT / ABSTAIN / FORBID). The enforcement
package is what makes that verdict *actually stop the action* before it
reaches the real world. Without it, Tex is a decision layer; with it,
Tex is a decision-and-enforcement layer end-to-end.

This is the **in-process** deployment shape of one enforcement layer with
three shapes, all sharing one decision authority (StandingGovernance) and one
transport protocol (`TexEvaluationTransport`):

1. In-process gate — `TexGate` + `@tex_gated` wrap a Python callable so it
   cannot execute on FORBID. Construct the production gate in one call with
   `build_standing_gate(governor)` (see `standing_transport`), which routes
   every check through the full two-tier standing PDP — the identical ruling
   the network PEP makes, fail-closed floor included. Works for any agent
   framework that calls Python functions to take actions (the common case).

2. Framework adapters — `make_langchain_tex_tool` (sync + async) and the
   CrewAI gated tool in `adapters.py` apply the same gate to a framework's
   native tool abstraction. The SDK ships HTTP-client equivalents under
   `tex_guardrail.integrations` for customers who call Tex over the wire.

3. Network PEP — the transparent, MCP-aware enforcement proxy and eBPF
   kernel-floor live in **`tex.pep`** (auto-injected by `tex.operator`). That
   is the one network data-plane proxy; the older ASGI proxy that used to
   live here was consolidated into `tex.pep` and removed.

All shapes honor the same contracts:

- FORBID always blocks. There is no flag to override this.
- PERMIT always passes through transparently.
- ABSTAIN behavior is configurable via `AbstainPolicy`: BLOCK (default —
  fail closed), ALLOW (with a warning callback), or REVIEW (raise a typed
  error the caller can route to a human / the one voice).
- Failure modes are fail-closed by default: if Tex is unreachable
  or the call times out, the wrapped action does NOT execute.
- Every gated execution emits a structured GateEvent for audit;
  callers can plug in their own observer.

This package has no required dependency on FastAPI, httpx, LangChain,
CrewAI, or any framework. The framework adapters import their
framework lazily so users only pay for what they use.

"""

from __future__ import annotations

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.enforcement import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'


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
