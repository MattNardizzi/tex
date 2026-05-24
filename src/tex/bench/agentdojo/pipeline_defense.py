"""
TexPipelineDefense — exposes the Tex PDP as an AgentDojo
``PipelineDefense``.

AgentDojo expects defenses to implement an interface roughly equivalent
to: ``query(messages, tools, environment) -> (response, tool_calls)``.
Each call into the agent loop runs the defense first; the defense may
abort the call, rewrite messages, or pass through.

Our adapter:

1. Builds an ``EvaluationRequest`` from the current step's pending
   tool call + the conversation context.
2. Runs the seven specialist streams synchronously (the PDP's normal
   adjudication path).
3. Maps the verdict:
   - PERMIT  → pass the tool call through unchanged
   - FORBID  → return a refusal message in place of the tool call
   - ABSTAIN → pass through with a low-confidence note appended to the
              agent's scratchpad (AgentDojo evaluators count
              abstentions as utility losses but not as exploits)

We don't depend on the AgentDojo package being installed at import
time; the adapter speaks AgentDojo's shape *structurally* and the CLI
binds it via duck-typing. This means the harness works in CI without
``pip install agentdojo`` and the user can still run the real benchmark
by installing the package and pointing the CLI at it.

References
----------
- arxiv 2406.13352 §4 (defense interface)
- arxiv 2503.18813 CaMeL §6 (the closest analogous defense adapter)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field


class PdpVerdict(str, Enum):
    PERMIT = "PERMIT"
    ABSTAIN = "ABSTAIN"
    FORBID = "FORBID"


class DefenseDecision(BaseModel):
    """Per-step defense output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: PdpVerdict
    permitted_tool_call: bool
    refusal_message: str | None = Field(default=None, max_length=2000)
    notes: tuple[str, ...] = Field(default_factory=tuple)


# A PDP callable accepts a dict describing the candidate tool call and
# returns a ``(verdict, notes)`` pair. We don't import Tex's PDP module
# directly here to keep this layer free of import cycles; the harness
# injects the bound function.
PdpCallable = Callable[[dict[str, Any]], tuple[PdpVerdict, tuple[str, ...]]]


class TexPipelineDefense:
    """
    Adapter that runs Tex's PDP between the agent's tool-call decision
    and the actual tool dispatch.

    Usage in AgentDojo's run loop::

        defense = TexPipelineDefense(pdp_callable=my_pdp_fn)
        decision = defense.adjudicate({
            "tool": "send_email",
            "args": {"to": "alice@example.com", "body": "..."},
            "context": {...},
        })
        if not decision.permitted_tool_call:
            # AgentDojo: the agent's response becomes the refusal text;
            # the tool is *not* dispatched
            ...
    """

    __slots__ = ("_pdp", "_refusal_template")

    def __init__(
        self,
        *,
        pdp_callable: PdpCallable,
        refusal_template: str = (
            "I cannot perform this action because the Tex governance layer "
            "blocked it. Verdict: {verdict}. Notes: {notes}."
        ),
    ) -> None:
        if not callable(pdp_callable):
            raise TypeError("pdp_callable must be callable")
        self._pdp = pdp_callable
        self._refusal_template = refusal_template

    def adjudicate(self, candidate: dict[str, Any]) -> DefenseDecision:
        verdict, notes = self._pdp(candidate)
        if verdict is PdpVerdict.PERMIT:
            return DefenseDecision(
                verdict=verdict, permitted_tool_call=True, notes=notes
            )
        if verdict is PdpVerdict.ABSTAIN:
            return DefenseDecision(
                verdict=verdict,
                permitted_tool_call=True,
                notes=notes + ("pdp_abstain",),
            )
        # FORBID
        refusal = self._refusal_template.format(
            verdict=verdict.value, notes=", ".join(notes) or "policy"
        )
        return DefenseDecision(
            verdict=verdict,
            permitted_tool_call=False,
            refusal_message=refusal,
            notes=notes,
        )


__all__ = ["DefenseDecision", "PdpCallable", "PdpVerdict", "TexPipelineDefense"]
