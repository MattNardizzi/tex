"""
tex_guardrail.integrations — first-party adapters for popular agent frameworks.

Each integration imports its framework lazily, so importing
``tex_guardrail`` never requires LangChain, CrewAI, or any framework to be
installed. You only pay for what you import.

LangChain
---------

    from tex_guardrail import TexClient
    from tex_guardrail.integrations.langchain import TexCallbackHandler, guard_tool

    tex = TexClient(api_key="...")

    # Option A — callback handler (observes + blocks tool calls on FORBID):
    chain.invoke(input, config={"callbacks": [TexCallbackHandler(tex)]})

    # Option B — wrap a tool so it cannot execute on FORBID (the strong form):
    safe_tool = guard_tool(my_tool, tex, action_type="send_email", channel="email")
"""

from __future__ import annotations

__all__ = ["TexCallbackHandler", "guard_tool"]


def __getattr__(name: str):  # pragma: no cover - thin lazy re-export
    # Lazily surface the LangChain symbols only when actually requested, so a
    # bare ``import tex_guardrail.integrations`` does not require LangChain.
    if name in __all__:
        from tex_guardrail.integrations import langchain as _lc

        return getattr(_lc, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
