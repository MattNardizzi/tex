"""
LangChain integration for the Tex guardrail SDK.

Two shapes, both routing through the same ``TexClient`` (HTTP) so they make
the identical ruling the network PEP and the in-process gate make:

1. ``TexCallbackHandler`` — a LangChain callback handler. On every tool call
   it asks Tex; a FORBID raises ``TexBlocked`` before the tool runs. Drop it
   into any chain/agent via ``config={"callbacks": [TexCallbackHandler(tex)]}``.

2. ``guard_tool`` — wraps a single LangChain ``BaseTool`` so its ``func`` /
   ``coroutine`` cannot execute unless Tex permits. This is the strong form:
   it does not depend on the framework honoring a callback's exception, it
   gates the call site directly.

LangChain is imported lazily, only when these symbols are used. The base SDK
never requires it.
"""

from __future__ import annotations

import functools
import json
from typing import TYPE_CHECKING, Any, Callable

from tex_guardrail.client import TexBlocked, TexClient

if TYPE_CHECKING:  # pragma: no cover - typing only
    from langchain_core.tools import BaseTool

__all__ = ["TexCallbackHandler", "guard_tool"]


def _tool_content(tool_name: str, tool_input: Any) -> str:
    """Render a tool call into the content string Tex evaluates."""
    if isinstance(tool_input, str):
        args = tool_input
    else:
        try:
            args = json.dumps(tool_input, default=str, sort_keys=True)
        except (TypeError, ValueError):
            args = str(tool_input)
    return f"{tool_name}({args})"


def _load_base_callback_handler() -> type:
    """Import LangChain's BaseCallbackHandler lazily with an actionable error."""
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError:  # pragma: no cover - exercised only without langchain
        try:
            from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "TexCallbackHandler requires LangChain. Install it with "
                "`pip install langchain-core` (or `langchain`)."
            ) from exc
    return BaseCallbackHandler


def TexCallbackHandler(  # noqa: N802 - factory that returns a handler instance
    tex: TexClient,
    *,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    raise_on_forbid: bool = True,
):
    """Build a LangChain callback handler that gates tool calls through Tex.

    Returns an instance of a ``BaseCallbackHandler`` subclass. On
    ``on_tool_start`` it evaluates the tool call; when ``raise_on_forbid`` is
    True (default) a FORBID raises ``TexBlocked`` and the tool never runs.
    """
    base = _load_base_callback_handler()

    class _TexCallbackHandler(base):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__()
            self._tex = tex

        def on_tool_start(
            self,
            serialized: dict[str, Any],
            input_str: str,
            **kwargs: Any,
        ) -> None:
            tool_name = (serialized or {}).get("name", "tool")
            verdict = self._tex.evaluate(
                content=_tool_content(tool_name, input_str),
                action_type=action_type or tool_name,
                channel=channel,
                environment=environment,
                stage="pre_call",
            )
            if raise_on_forbid and verdict.is_forbid:
                raise TexBlocked(verdict.reason, verdict)

    return _TexCallbackHandler()


def guard_tool(
    tool: "BaseTool",
    tex: TexClient,
    *,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
) -> "BaseTool":
    """Return a copy of ``tool`` whose execution is gated by Tex.

    The wrapped tool evaluates its input through Tex before running; a FORBID
    raises ``TexBlocked`` and the underlying ``func`` / ``coroutine`` is never
    invoked. This is the strong form — it gates the call site directly rather
    than relying on a callback's exception being honored.
    """
    resolved_action = action_type or getattr(tool, "name", "tool")

    def _gate(content: str) -> None:
        verdict = tex.evaluate(
            content=content,
            action_type=resolved_action,
            channel=channel,
            environment=environment,
            stage="pre_call",
        )
        if verdict.is_forbid:
            raise TexBlocked(verdict.reason, verdict)

    original_func: Callable[..., Any] | None = getattr(tool, "func", None)
    original_coro: Callable[..., Any] | None = getattr(tool, "coroutine", None)

    if original_func is not None:

        @functools.wraps(original_func)
        def gated_func(*args: Any, **kwargs: Any) -> Any:
            _gate(_tool_content(resolved_action, kwargs or args))
            return original_func(*args, **kwargs)

        tool.func = gated_func  # type: ignore[attr-defined]

    if original_coro is not None:

        @functools.wraps(original_coro)
        async def gated_coro(*args: Any, **kwargs: Any) -> Any:
            _gate(_tool_content(resolved_action, kwargs or args))
            return await original_coro(*args, **kwargs)

        tool.coroutine = gated_coro  # type: ignore[attr-defined]

    return tool
