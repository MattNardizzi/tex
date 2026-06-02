"""
@gate decorator - five-line agent integration.

Usage
-----

    from tex_guardrail import TexClient, gate

    tex = TexClient(api_key="...")

    @gate(client=tex, action_type="send_email", channel="email")
    def send_outbound_email(content, recipient):
        smtp.send(to=recipient, body=content)

By default the decorator extracts content from a `content` kwarg or the
first positional arg. For non-trivial signatures, supply a custom
`extract_content` callable.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from tex_guardrail.client import TexBlocked, TexClient, TexVerdict


def gate(
    *,
    client: TexClient,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    extract_content: Callable[..., str] | None = None,
    extract_recipient: Callable[..., str | None] | None = None,
    on_abstain: Callable[[TexVerdict], Any] | None = None,
    on_forbid: Callable[[TexVerdict], Any] | None = None,
    raise_on_forbid: bool = True,
):
    """
    Wrap a function so its outbound action is evaluated by Tex first.

    Parameters
    ----------
    client
        Configured TexClient instance.
    action_type, channel, environment
        Tex taxonomy hints. Optional but improve evaluation accuracy.
    extract_content
        Function (*args, **kwargs) -> str that returns the content to
        evaluate. Defaults to `kwargs['content']` or `args[0]`.
    extract_recipient
        Function returning a recipient identifier (email, user id, etc.).
        Optional.
    on_abstain
        Callback invoked with the TexVerdict when verdict is ABSTAIN.
        If it returns a non-None value, that value is returned to the
        caller in place of executing the wrapped function.
    on_forbid
        Callback invoked with the TexVerdict when verdict is FORBID.
        Same return-value semantics as on_abstain.
    raise_on_forbid
        When True (default) and no on_forbid callback is supplied, raise
        TexBlocked instead of executing the wrapped function.
    """

    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            content = _extract_content(extract_content, fn, sig, args, kwargs)
            recipient = (
                extract_recipient(*args, **kwargs)
                if extract_recipient is not None
                else None
            )

            verdict = client.evaluate(
                content=content,
                action_type=action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
                raise_on_forbid=False,
            )

            if verdict.is_forbid:
                if on_forbid is not None:
                    return on_forbid(verdict)
                if raise_on_forbid:
                    raise TexBlocked(verdict.reason, verdict)
                return None

            if verdict.is_abstain and on_abstain is not None:
                fallback = on_abstain(verdict)
                if fallback is not None:
                    return fallback

            return fn(*args, **kwargs)

        _wrapped.__tex_gated__ = True  # type: ignore[attr-defined]
        return _wrapped

    return _decorator


def _extract_content(
    custom: Callable[..., str] | None,
    fn: Callable[..., Any],
    sig: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    if custom is not None:
        return custom(*args, **kwargs)

    if "content" in kwargs:
        value = kwargs["content"]
        if isinstance(value, str):
            return value

    if args:
        first = args[0]
        if isinstance(first, str):
            return first

    # Last resort: serialize the whole call as evaluation content. This is
    # rarely what you want; supply extract_content for non-trivial cases.
    return f"{fn.__qualname__}(args={args!r}, kwargs={kwargs!r})"
