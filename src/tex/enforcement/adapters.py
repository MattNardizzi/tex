"""
Framework adapters for Tex enforcement.

These wrap the enforcement gate around the native abstractions of
the most common agent frameworks. Each adapter:

- imports its framework lazily, so users only pay for what they use
- gives a clear ImportError if the framework is missing
- delegates 100% of policy decisions to the gate
- raises TexForbiddenError / TexAbstainError so the surrounding
  framework's error handling kicks in naturally

If a framework you use isn't here, the imperative `gate.check()`
interface works in any Python codebase. These adapters are
ergonomics, not capability.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable
from uuid import UUID

from tex.enforcement.gate import TexGate, TexGateAsync


# --------------------------------------------------------------------------- #
# LangChain                                                                   #
# --------------------------------------------------------------------------- #


def make_langchain_tex_tool(
    *,
    gate: TexGate,
    base_tool: Any,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Any:
    """
    Wrap a LangChain BaseTool so its `_run` is gated by Tex.

    Returns a new tool subclass whose `_run` calls Tex first. On
    PERMIT, the original tool runs. On FORBID/ABSTAIN-blocked, the
    tool raises TexForbiddenError / TexAbstainError, which LangChain's
    AgentExecutor surfaces to the LLM as an observation — so the agent
    actually sees that its action was refused and can recover.

    `content_arg` is the name of the kwarg whose value should be
    treated as the action's outbound content. `recipient_arg` is the
    optional kwarg whose value should be used as the recipient.
    """
    try:
        from langchain.tools import BaseTool  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dep
        raise ImportError(
            "make_langchain_tex_tool requires `langchain`. "
            "Install with: pip install langchain"
        ) from exc

    if not isinstance(base_tool, BaseTool):
        raise TypeError(
            "base_tool must be an instance of langchain.tools.BaseTool"
        )

    inner = base_tool

    class _GatedTool(BaseTool):  # type: ignore[misc]
        name: str = inner.name
        description: str = inner.description

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            content = kwargs.get(content_arg) or (args[0] if args else "")
            if not isinstance(content, str) or not content.strip():
                raise ValueError(
                    f"gated tool {inner.name!r} requires non-empty string "
                    f"content via {content_arg!r}"
                )
            recipient = (
                kwargs.get(recipient_arg) if recipient_arg is not None else None
            )
            gate.check(
                content=content,
                action_type=action_type or inner.name,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_id,
            )
            return inner._run(*args, **kwargs)  # type: ignore[attr-defined]

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:  # noqa: D401
            # LangChain's async path; gate via the sync gate is fine
            # because the gate's transport is sync. Users wanting fully
            # async transports should use TexGateAsync directly.
            return self._run(*args, **kwargs)

    return _GatedTool()


# --------------------------------------------------------------------------- #
# CrewAI                                                                      #
# --------------------------------------------------------------------------- #


def make_crewai_tex_tool(
    *,
    gate: TexGate,
    fn: Callable[..., Any],
    name: str,
    description: str,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Any:
    """
    Wrap a callable as a CrewAI Tool with Tex enforcement.

    CrewAI tools are simpler than LangChain's — a name, a
    description, and a function. The wrapper produces a new function
    that calls Tex before delegating to the original.
    """
    try:
        from crewai.tools import BaseTool as CrewBaseTool  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - optional dep
        # CrewAI is not installed; fall back to a duck-typed shim that
        # exposes .name / .description / .run so users can plug it
        # into a Crew without us pulling crewai as a hard dep.
        CrewBaseTool = None  # type: ignore[assignment]

    gated_fn = gate.wrap(
        fn,
        content_arg=content_arg,
        recipient_arg=recipient_arg,
        action_type=action_type,
        channel=channel,
        environment=environment,
        agent_id=agent_id,
    )

    if CrewBaseTool is None:
        # Duck-typed result object. Has the surface CrewAI expects.
        class _DuckTool:
            def __init__(self) -> None:
                self.name = name
                self.description = description

            def run(self, *args: Any, **kwargs: Any) -> Any:
                return gated_fn(*args, **kwargs)

            __call__ = run

        return _DuckTool()

    class _GatedCrewTool(CrewBaseTool):  # type: ignore[misc]
        name: str = name
        description: str = description

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            return gated_fn(*args, **kwargs)

    return _GatedCrewTool()


# --------------------------------------------------------------------------- #
# MCP server middleware                                                       #
# --------------------------------------------------------------------------- #


def make_mcp_tool_middleware(
    *,
    gate: TexGate,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type_from: str = "tool_name",
    channel: str = "mcp",
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator factory for MCP server-side tool functions.

    MCP tool handlers receive a structured arguments dict. This
    middleware extracts the content and recipient from that dict,
    calls Tex, and only invokes the underlying handler on PERMIT.

    `action_type_from` controls how the `action_type` is derived:
    - "tool_name": use the wrapped function's __name__
    - any other string: use that string as the action_type literal

    Returns a decorator. Apply to MCP tool functions like:

        @make_mcp_tool_middleware(gate=gate, content_arg="body")
        def send_message(arguments: dict) -> dict: ...
    """

    def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
        resolved_action_type = (
            handler.__name__ if action_type_from == "tool_name" else action_type_from
        )

        def wrapped(arguments: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            if not isinstance(arguments, dict):
                raise TypeError(
                    "MCP middleware expects the first positional arg to be "
                    "the tool's arguments dict"
                )
            content = arguments.get(content_arg)
            if not isinstance(content, str) or not content.strip():
                raise ValueError(
                    f"MCP-gated handler {handler.__name__!r} requires "
                    f"non-empty string content via arguments[{content_arg!r}]"
                )
            recipient = (
                arguments.get(recipient_arg) if recipient_arg is not None else None
            )
            gate.check(
                content=content,
                action_type=resolved_action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_id,
            )
            return handler(arguments, *args, **kwargs)

        wrapped.__name__ = handler.__name__
        wrapped.__doc__ = handler.__doc__
        return wrapped

    return decorator


# --------------------------------------------------------------------------- #
# Async LangChain variant                                                     #
# --------------------------------------------------------------------------- #


def make_langchain_async_tex_tool(
    *,
    gate: TexGateAsync,
    arun: Callable[..., Awaitable[Any]],
    name: str,
    description: str,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Any:
    """
    Build an async-native LangChain tool with TexGateAsync enforcement.

    Use this when your tool's underlying work is itself async (e.g.
    httpx, asyncpg) and you don't want the gate to run on a thread.
    """
    try:
        from langchain.tools import BaseTool  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "make_langchain_async_tex_tool requires `langchain`. "
            "Install with: pip install langchain"
        ) from exc

    gated_arun = gate.wrap(
        arun,
        content_arg=content_arg,
        recipient_arg=recipient_arg,
        action_type=action_type,
        channel=channel,
        environment=environment,
        agent_id=agent_id,
    )

    class _GatedAsyncTool(BaseTool):  # type: ignore[misc]
        name: str = name
        description: str = description

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError("This tool is async-only; use ainvoke / arun.")

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            return await gated_arun(*args, **kwargs)

    return _GatedAsyncTool()
