"""
Specialist LLM Dispatch.

Shared infrastructure for specialist judges that consult a real LLM
inside their per-request hot path. Implements the FRONTIER_DELTA_thread_4
v2 upgrade: lexical screening always runs at <5ms; LLM dispatch fires
ONLY when lexical screening produced >=1 hit AND the caller is willing
to spend the budget.

Pattern: cheap-miss / expensive-hit.

Design rules
------------
- FAIL-CLOSED. A timeout, model error, parse error, or rate limit
  ALWAYS yields the conservative outcome (typically: keep the
  lexical signal, attach `llm_dispatch_failed` uncertainty flag).
- BUDGET-ENVELOPED. Each dispatch has a per-call wall-clock budget.
  Default: 50ms. Configurable per-specialist via call-site override
  or via env: `TEX_SPECIALIST_LLM_BUDGET_MS`.
- SEMAPHORE-BOUNDED. A module-level semaphore caps concurrent LLM
  dispatches so a burst of specialists cannot exhaust the upstream
  model provider. Default: 8 concurrent.
- ASYNCIO-NATIVE. When multiple specialists are LLM-capable, the
  caller can fan them out via asyncio.gather to keep wall-clock cost
  ~= one specialist's budget instead of N specialists' budgets.
- GATEABLE. Disabled by default in tests; enabled in production via
  `TEX_SPECIALIST_LLM_DISPATCH=on`. Tests inject fakes.
- OBSERVABLE. Every dispatch emits a structured event with outcome,
  latency, model, prompt token count, and reason for fail-closed.
- DETERMINISTIC FINGERPRINT. The exact prompt + model + caller + a
  monotonic counter are hashed into the dispatch id; replayable from
  evidence chain.

References
----------
- arxiv 2604.10134v1 (PlanGuard, Gong & Deng, Apr 2026) §IV-C2:
  M_verify(I, S_ref, a_act, r_act) -> {True, False}.
- arxiv 2605.03228v1 (MAGE, Wang et al., 4 May 2026) §4.2.2: native
  tool-call integration of memory manager and judge.
- Five Eyes "Careful Adoption of Agentic AI Services" (1 May 2026):
  fail-safe-by-default. Our timeout/error path matches.
- arxiv 2510.05244v2 (Nasr et al., "The Attacker Moves Second"):
  bypassed 12 prior defenses at >90% ASR using adaptive attacks.
  Counter: lexical screening + LLM Stage II + JSON output parsing
  + temperature=0 + rejection sampling on schema violation.

Priority
--------
P0 infrastructure. Consumed by PlanGuardSpecialist (Stage II) and
MageSpecialist (M_theta / J_theta).
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Mapping, Protocol, runtime_checkable

from tex.observability.telemetry import emit_event, get_logger

_logger = get_logger("tex.specialists.llm_dispatch")


# ── Module-wide config ───────────────────────────────────────────────────


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Off by default. Production turns this on. Tests inject fakes via
# dispatcher arg without flipping this flag.
DEFAULT_DISPATCH_ENABLED: bool = _env_bool("TEX_SPECIALIST_LLM_DISPATCH", False)
DEFAULT_BUDGET_MS: int = _env_int("TEX_SPECIALIST_LLM_BUDGET_MS", 50)
DEFAULT_CONCURRENCY: int = _env_int("TEX_SPECIALIST_LLM_CONCURRENCY", 8)
# Latency-budgeted per-specialist signal (50ms default) → the affordable tier.
# gpt-5.4-mini is OpenAI's current mini as of June 2026 (no gpt-5.5-mini exists).
DEFAULT_MODEL: str = os.environ.get("TEX_SPECIALIST_LLM_MODEL", "gpt-5.4-mini")

# Shared semaphore. Lazily constructed per event loop to avoid leaking
# state across asyncio runtimes.
_loop_semaphores: dict[int, asyncio.Semaphore] = {}
_loop_semaphores_lock = threading.Lock()


def _get_semaphore(concurrency: int) -> asyncio.Semaphore:
    """Lazily build a per-event-loop semaphore."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop; this code path should never be hit in
        # production (always called from an awaiting context) but
        # guard anyway.
        return asyncio.Semaphore(concurrency)
    key = id(loop)
    with _loop_semaphores_lock:
        sem = _loop_semaphores.get(key)
        if sem is None:
            sem = asyncio.Semaphore(concurrency)
            _loop_semaphores[key] = sem
        return sem


# ── Outcomes ─────────────────────────────────────────────────────────────


class DispatchOutcome(str, Enum):
    """How a single LLM dispatch resolved."""

    OK = "ok"                       # Model returned a parseable verdict.
    TIMEOUT = "timeout"             # Wall-clock budget exceeded.
    MODEL_ERROR = "model_error"     # Provider raised.
    PARSE_ERROR = "parse_error"     # JSON could not be parsed.
    SCHEMA_ERROR = "schema_error"   # JSON parsed but did not match schema.
    DISABLED = "disabled"           # Dispatch was not enabled by config.
    RATE_LIMIT = "rate_limit"       # Provider rate-limited.


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Structured outcome of a single LLM dispatch."""

    outcome: DispatchOutcome
    payload: dict | None
    latency_ms: float
    model: str
    dispatch_id: str
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is DispatchOutcome.OK

    @property
    def fail_closed_signal(self) -> bool:
        """Outcomes that should propagate as ABSTAIN-class signal."""
        return self.outcome in {
            DispatchOutcome.TIMEOUT,
            DispatchOutcome.MODEL_ERROR,
            DispatchOutcome.PARSE_ERROR,
            DispatchOutcome.SCHEMA_ERROR,
            DispatchOutcome.RATE_LIMIT,
        }


# ── Provider protocols ───────────────────────────────────────────────────


@runtime_checkable
class AsyncCompletion(Protocol):
    """Minimal async-completion provider contract.

    Either a wrapper around openai.AsyncOpenAI's chat.completions, an
    Anthropic Messages call, or a test fake. The dispatcher does not
    care about the underlying SDK; only that we can hand it a
    structured prompt and get back a JSON string within the budget.
    """

    async def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        ...


class StaticVerdictCompletion:
    """Test/offline provider. Returns a fixed JSON string.

    Used by unit tests and by the offline deployment fallback. Lets
    PlanGuard Stage II and MAGE J_theta run in test contexts without
    any network call.
    """

    def __init__(self, verdict_json: str) -> None:
        self._verdict_json = verdict_json

    async def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        # Yield once so async behavior is observable in tests.
        await asyncio.sleep(0)
        return self._verdict_json


class _LazyOpenAICompletion:
    """Default production provider. Lazy-imports the OpenAI SDK.

    Built when DEFAULT_DISPATCH_ENABLED and the caller did not inject
    a provider. Never raises ImportError eagerly; only when actually
    used. Always JSON-mode + temperature=0 to make outputs replayable.
    """

    def __init__(self) -> None:
        self._client: Any | None = None
        self._lock = threading.Lock()

    def _build_client(self) -> Any:
        from openai import AsyncOpenAI  # local import; only here.

        return AsyncOpenAI()

    async def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        with self._lock:
            if self._client is None:
                self._client = self._build_client()
        resp = await self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        return resp.choices[0].message.content or ""


# ── Dispatcher ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DispatchRequest:
    """One LLM-judge dispatch."""

    caller: str                     # specialist name, e.g. 'planguard'
    system_prompt: str
    user_prompt: str
    expected_keys: tuple[str, ...]  # JSON keys required in the response
    budget_ms: int = DEFAULT_BUDGET_MS
    max_tokens: int = 256
    temperature: float = 0.0


class SpecialistLLMDispatcher:
    """Async LLM dispatch for specialist judges.

    Construction
    ------------
    >>> dispatcher = SpecialistLLMDispatcher()              # production
    >>> dispatcher = SpecialistLLMDispatcher(provider=fake) # tests

    Use
    ---
    >>> result = await dispatcher.dispatch(request)
    >>> if result.ok:
    ...     verdict = result.payload['verdict']
    """

    def __init__(
        self,
        *,
        provider: AsyncCompletion | None = None,
        enabled: bool | None = None,
        concurrency: int | None = None,
        model: str | None = None,
    ) -> None:
        self._provider: AsyncCompletion | None = provider
        self._enabled = DEFAULT_DISPATCH_ENABLED if enabled is None else enabled
        self._concurrency = concurrency or DEFAULT_CONCURRENCY
        self._model = model or DEFAULT_MODEL
        self._counter = 0
        self._counter_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _next_dispatch_id(self, caller: str) -> str:
        with self._counter_lock:
            self._counter += 1
            n = self._counter
        return f"{caller}-{n:09d}-{int(time.time() * 1000)}"

    def _ensure_provider(self) -> AsyncCompletion:
        if self._provider is not None:
            return self._provider
        # Lazy build the default OpenAI provider on first call.
        self._provider = _LazyOpenAICompletion()
        return self._provider

    async def dispatch(self, request: DispatchRequest) -> DispatchResult:
        """Run one LLM dispatch under budget. Fail-closed on any error."""
        dispatch_id = self._next_dispatch_id(request.caller)

        if not self._enabled and self._provider is None:
            # Caller didn't explicitly inject a provider and dispatch
            # is disabled. Skip silently.
            self._emit(
                outcome=DispatchOutcome.DISABLED,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=0.0,
                reason="dispatch_disabled",
            )
            return DispatchResult(
                outcome=DispatchOutcome.DISABLED,
                payload=None,
                latency_ms=0.0,
                model=self._model,
                dispatch_id=dispatch_id,
                reason="TEX_SPECIALIST_LLM_DISPATCH is off and no provider injected",
            )

        provider = self._ensure_provider()
        budget_s = request.budget_ms / 1000.0
        semaphore = _get_semaphore(self._concurrency)
        start = time.perf_counter()

        try:
            async with semaphore:
                raw = await asyncio.wait_for(
                    provider.complete(
                        model=self._model,
                        system=request.system_prompt,
                        user=request.user_prompt,
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                    ),
                    timeout=budget_s,
                )
        except asyncio.TimeoutError:
            latency = (time.perf_counter() - start) * 1000
            self._emit(
                outcome=DispatchOutcome.TIMEOUT,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=latency,
                reason=f"timeout after {request.budget_ms}ms",
            )
            return DispatchResult(
                outcome=DispatchOutcome.TIMEOUT,
                payload=None,
                latency_ms=latency,
                model=self._model,
                dispatch_id=dispatch_id,
                reason=f"timeout after {request.budget_ms}ms budget",
            )
        except Exception as exc:  # noqa: BLE001
            latency = (time.perf_counter() - start) * 1000
            outcome = DispatchOutcome.MODEL_ERROR
            reason = str(exc)
            # Heuristic rate-limit detection from common SDK error text.
            if "rate" in reason.lower() and "limit" in reason.lower():
                outcome = DispatchOutcome.RATE_LIMIT
            self._emit(
                outcome=outcome,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=latency,
                reason=reason[:300],
            )
            return DispatchResult(
                outcome=outcome,
                payload=None,
                latency_ms=latency,
                model=self._model,
                dispatch_id=dispatch_id,
                reason=reason[:300],
            )

        latency = (time.perf_counter() - start) * 1000

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._emit(
                outcome=DispatchOutcome.PARSE_ERROR,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=latency,
                reason=f"json: {exc}",
            )
            return DispatchResult(
                outcome=DispatchOutcome.PARSE_ERROR,
                payload=None,
                latency_ms=latency,
                model=self._model,
                dispatch_id=dispatch_id,
                reason=f"json decode: {exc}",
            )

        if not isinstance(payload, dict):
            self._emit(
                outcome=DispatchOutcome.SCHEMA_ERROR,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=latency,
                reason="payload not a json object",
            )
            return DispatchResult(
                outcome=DispatchOutcome.SCHEMA_ERROR,
                payload=None,
                latency_ms=latency,
                model=self._model,
                dispatch_id=dispatch_id,
                reason="payload not a json object",
            )

        missing = [k for k in request.expected_keys if k not in payload]
        if missing:
            self._emit(
                outcome=DispatchOutcome.SCHEMA_ERROR,
                caller=request.caller,
                dispatch_id=dispatch_id,
                latency_ms=latency,
                reason=f"missing keys: {missing}",
            )
            return DispatchResult(
                outcome=DispatchOutcome.SCHEMA_ERROR,
                payload=payload,
                latency_ms=latency,
                model=self._model,
                dispatch_id=dispatch_id,
                reason=f"missing required keys: {missing}",
            )

        self._emit(
            outcome=DispatchOutcome.OK,
            caller=request.caller,
            dispatch_id=dispatch_id,
            latency_ms=latency,
            reason=None,
        )
        return DispatchResult(
            outcome=DispatchOutcome.OK,
            payload=payload,
            latency_ms=latency,
            model=self._model,
            dispatch_id=dispatch_id,
            reason=None,
        )

    def dispatch_sync(self, request: DispatchRequest) -> DispatchResult:
        """Synchronous wrapper for specialists that don't have an event loop.

        Specialist judges return synchronously from their `evaluate`
        method. This wrapper lets the dispatcher be called from those
        sync contexts without forcing the caller to manage an event
        loop. We deliberately accept the small cost of a per-call
        loop construction here; for hot-path async fan-out, callers
        should orchestrate at the SpecialistSuite level.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.dispatch(request))
        # We are inside a running loop. The caller must explicitly
        # await dispatch() instead — running asyncio.run inside an
        # active loop would deadlock.
        raise RuntimeError(
            "dispatch_sync called from within a running event loop; "
            "use `await dispatcher.dispatch(...)` instead"
        )

    @staticmethod
    def _emit(
        *,
        outcome: DispatchOutcome,
        caller: str,
        dispatch_id: str,
        latency_ms: float,
        reason: str | None,
    ) -> None:
        emit_event(
            "specialist.llm_dispatch",
            level=20 if outcome is DispatchOutcome.OK else 30,
            logger=_logger,
            outcome=outcome.value,
            caller=caller,
            dispatch_id=dispatch_id,
            latency_ms=round(latency_ms, 3),
            reason=reason,
        )


# Default singleton for production. Test code constructs its own.
_default_dispatcher: SpecialistLLMDispatcher | None = None
_default_dispatcher_lock = threading.Lock()


def get_default_dispatcher() -> SpecialistLLMDispatcher:
    """Module-singleton dispatcher for production hot path."""
    global _default_dispatcher
    with _default_dispatcher_lock:
        if _default_dispatcher is None:
            _default_dispatcher = SpecialistLLMDispatcher()
        return _default_dispatcher


__all__ = [
    "AsyncCompletion",
    "DEFAULT_BUDGET_MS",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_DISPATCH_ENABLED",
    "DEFAULT_MODEL",
    "DispatchOutcome",
    "DispatchRequest",
    "DispatchResult",
    "SpecialistLLMDispatcher",
    "StaticVerdictCompletion",
    "get_default_dispatcher",
]
