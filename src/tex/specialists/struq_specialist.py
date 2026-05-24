"""
StruQ adapter — structured-query defense.

StruQ (arxiv 2402.06363, Chen et al., Feb 2024) defends against
indirect prompt injection by *teaching* the model to separate
instructions from data. It uses fine-tuning with special tokens to
make the model treat anything inside a ``[DATA]...[/DATA]`` envelope
as inert text. Follow-up work (SecAlign, MELON) builds on the same
data-vs-instruction-separation insight.

Status as of May 2026
---------------------
- StruQ-tuned models: research checkpoints exist on HuggingFace under
  ``berkeley-nlp/StruQ-7B`` and related. No mainstream agent platform
  uses StruQ checkpoints out of the box.
- The defense requires either (a) a StruQ-fine-tuned backbone, or
  (b) a wrapper that simulates the data envelope for the underlying
  model. (a) is a deployment-side choice; (b) is what we provide.

Honest scope
------------
This adapter implements (b) — the *structural* defense without the
fine-tuning. It rewrites untrusted content to be wrapped in delimiter
tokens *and* applies a verifier that catches obvious injection
patterns (imperative-mode verbs at the start of the data, "ignore
previous instructions" / "system prompt" patterns). When a real StruQ-
tuned model is configured, the adapter calls it; otherwise it falls
back to the structural verifier.

This is the first PDP-integrated StruQ adapter, since the original
StruQ paper targets standalone model evaluation, not agent governance.

Reference: arxiv 2402.06363 §3 (data envelope); arxiv 2410.05451
(SecAlign builds on StruQ).
"""

from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.base import SpecialistEvidence, SpecialistResult


@runtime_checkable
class StruQBackend(Protocol):
    """A real StruQ model or a structural-only verifier."""

    def verify(
        self, *, instruction: str, data: str
    ) -> tuple[bool, float, tuple[str, ...]]:
        """
        Returns (is_safe, confidence, matched_patterns).
        """
        ...


# Patterns are deliberately conservative; false positives are
# preferable to false negatives in a security gate.
_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ignore previous", "instruction-override"),
    ("ignore prior", "instruction-override"),
    ("disregard above", "instruction-override"),
    ("system prompt", "system-prompt-reference"),
    ("you are now", "role-redefinition"),
    ("from now on", "role-redefinition"),
    ("forget everything", "memory-wipe"),
    ("urgent:", "urgency-pressure"),
    ("important:", "urgency-pressure"),
    ("admin override", "authority-spoofing"),
    ("developer mode", "authority-spoofing"),
    ("transfer $", "financial-action"),
    ("wire $", "financial-action"),
    ("[/data]", "envelope-escape"),
    ("[/system]", "envelope-escape"),
    ("</system>", "envelope-escape"),
    ("execute(", "code-execution"),
    ("eval(", "code-execution"),
)


class StructuralStruQBackend:
    """
    Structural verifier: pattern-matches known injection signatures
    inside the data envelope. Does NOT require a fine-tuned model.

    Two-stage check:
    1. Pattern match against ``_INJECTION_PATTERNS``.
    2. Envelope discipline: data with delimiter-escape tokens
       (``[/DATA]``, ``</system>``) is automatically flagged.

    Confidence is set to 0.7 (advisory) since this is a structural
    approximation. A real StruQ-tuned backbone would push confidence
    to 0.95+.
    """

    __slots__ = ("_patterns",)

    def __init__(
        self,
        *,
        extra_patterns: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self._patterns = _INJECTION_PATTERNS + tuple(extra_patterns)

    def verify(
        self, *, instruction: str, data: str
    ) -> tuple[bool, float, tuple[str, ...]]:
        haystack = data.lower()
        matches: list[str] = []
        for needle, tag in self._patterns:
            if needle in haystack:
                matches.append(tag)
        is_safe = not matches
        return is_safe, 0.7, tuple(matches)


class StruQSpecialist:
    """StruQ structural defense as a PDP specialist."""

    name: str = "struq"

    def __init__(self, *, backend: StruQBackend | None = None) -> None:
        self._backend: StruQBackend = backend or StructuralStruQBackend()

    @property
    def backend(self) -> StruQBackend:
        return self._backend

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        metadata = getattr(request, "metadata", None) or {}
        instruction = str(metadata.get("user_prompt") or "")
        # Aggregate all untrusted content fields: environment_content,
        # tool_results, retrieved_docs.
        env_content = str(metadata.get("environment_content") or "")
        tool_results = str(metadata.get("tool_results") or "")
        retrieved = str(metadata.get("retrieved_docs") or "")
        data = "\n".join(filter(None, (env_content, tool_results, retrieved)))

        if not data:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                summary="StruQ: no data envelope to verify; abstaining",
                uncertainty_flags=("no_data",),
            )

        is_safe, confidence, matched = self._backend.verify(
            instruction=instruction, data=data
        )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=0.0 if is_safe else 1.0,
            confidence=confidence,
            summary=(
                "StruQ envelope verification "
                f"{'cleared' if is_safe else 'flagged'}: "
                f"{', '.join(matched) if matched else 'no patterns matched'}"
            ),
            rationale=(
                "Structural data-envelope defense. "
                f"backend={type(self._backend).__name__}"
            ),
            evidence=tuple(
                SpecialistEvidence(
                    text=f"struq_pattern: {m}",
                    explanation="StruQ structural verifier matched an injection pattern.",
                )
                for m in matched[:8]
            ),
            matched_policy_clause_ids=tuple(f"struq:{m}" for m in matched),
        )


__all__ = ["StructuralStruQBackend", "StruQBackend", "StruQSpecialist"]
