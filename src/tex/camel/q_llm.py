"""
CaMeL Quarantined-LLM (Q-LLM) interface.

The Q-LLM is the half of the CaMeL dual-LLM architecture that
processes untrusted content. It has **no tool access**. Its single
output channel is structured text that the interpreter reads as a
CapValue tagged with the union of input capabilities (CaMeL §5.3).

This module gives:

- ``QuarantinedLLM`` Protocol — the minimal interface (one method,
  ``answer``).
- ``StubQuarantinedLLM`` — deterministic stub used in tests and
  fallback when no real Q-LLM is wired up. It simply concatenates
  inputs and prefixes them with the query. Production deployments pass
  in a callable that hits a real model (Anthropic / OpenAI / local
  vLLM) through ``tex.llm_bridge``.

The Q-LLM never sees the *plan*. It receives only ``query`` (a trusted
string from the P-LLM) plus a tuple of untrusted ``inputs``. The plan
itself is private to the P-LLM, preventing the untrusted side from
influencing control flow — the load-bearing CaMeL invariant.

Reference: arxiv 2503.18813 §5.3 (Q-LLM separation); SentinelAI ablation
of unified vs. separated LLMs in arxiv 2505.22852 §6.
"""

from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable


@runtime_checkable
class QuarantinedLLM(Protocol):
    """Anything that can answer a query over a tuple of untrusted strings."""

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:
        ...


class StubQuarantinedLLM:
    """
    Deterministic stub Q-LLM. Used in tests and as a safe fallback.

    Behaviour: produces ``f"{query} :: {' | '.join(inputs)}"`` truncated
    to 2,048 chars. The truncation is deliberate: a real Q-LLM has
    bounded context, and we want the stub to surface the truncation
    behaviour in tests.
    """

    __slots__ = ("_max_len",)

    def __init__(self, *, max_len: int = 2048) -> None:
        if max_len <= 0:
            raise ValueError("max_len must be positive")
        self._max_len = max_len

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:
        body = " | ".join(str(i) for i in inputs)
        out = f"{query} :: {body}"
        return out[: self._max_len]


class CallableQuarantinedLLM:
    """
    Wraps an arbitrary ``Callable[[str, tuple[str, ...]], str]`` as a
    ``QuarantinedLLM``. Convenience for plugging in a real LLM bridge
    without subclassing.
    """

    __slots__ = ("_fn",)

    def __init__(self, fn: Callable[[str, tuple[str, ...]], str]) -> None:
        if not callable(fn):
            raise TypeError("fn must be callable")
        self._fn = fn

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:
        result = self._fn(query, inputs)
        if not isinstance(result, str):
            raise TypeError(
                f"Q-LLM callable must return str, got {type(result).__name__}"
            )
        return result


__all__ = ["CallableQuarantinedLLM", "QuarantinedLLM", "StubQuarantinedLLM"]
