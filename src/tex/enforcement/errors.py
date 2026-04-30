"""
Typed errors raised by the enforcement layer.

Callers catch these to react to verdicts. The hierarchy is:

    TexEnforcementError
        TexForbiddenError      — verdict was FORBID
        TexAbstainError        — verdict was ABSTAIN and abstain_policy=REVIEW
        TexUnavailableError    — Tex was unreachable, timed out, or errored
                                 internally; with fail_closed=True (the
                                 default) this aborts the action

The errors carry the full evaluation response when one is available so
callers can log it, surface it to humans, or attach it to an audit
trail without re-evaluating.
"""

from __future__ import annotations

from typing import Any


class TexEnforcementError(Exception):
    """
    Base class for every enforcement-layer error.

    Every subclass carries the same shape of payload so callers can
    introspect uniformly. `verdict` is the verdict string (PERMIT /
    ABSTAIN / FORBID / UNAVAILABLE), `response` is the public Tex
    EvaluationResponse if one was produced, and `details` is a free
    dict for adapter-specific context (HTTP status, timeout duration,
    etc.).
    """

    __slots__ = ("verdict", "response", "details")

    def __init__(
        self,
        message: str,
        *,
        verdict: str,
        response: Any | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.verdict = verdict
        self.response = response
        self.details = dict(details) if details else {}


class TexForbiddenError(TexEnforcementError):
    """
    Raised when Tex returns FORBID and the gate is configured to block.

    There is no way to bypass FORBID. The gate exists specifically so
    that this exception terminates the wrapped action's execution path.
    """

    def __init__(
        self,
        message: str,
        *,
        response: Any | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, verdict="FORBID", response=response, details=details)


class TexAbstainError(TexEnforcementError):
    """
    Raised when Tex returns ABSTAIN and the abstain policy is REVIEW.

    Callers that want to route ABSTAIN to a human approval flow should
    catch this, persist the request, and re-execute the action only
    after a reviewer signs off.
    """

    def __init__(
        self,
        message: str,
        *,
        response: Any | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, verdict="ABSTAIN", response=response, details=details)


class TexUnavailableError(TexEnforcementError):
    """
    Raised when Tex itself is unreachable, times out, or errors.

    With `fail_closed=True` (the default), this aborts the wrapped
    action. With `fail_closed=False`, the gate logs a GateEvent and
    allows the action through — but this is operator-explicit; the
    library never enables fail-open by default.
    """

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, verdict="UNAVAILABLE", response=None, details=details)
