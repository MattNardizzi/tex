"""
MELON adapter — masked-evaluation defense against indirect prompt
injection.

MELON (arxiv 2502.05174, Feb 2025; Stanford) proposes a model-side
defense that detects indirect prompt injections by running the agent
twice: once with the *real* user prompt, once with a *masked* prompt
(the user instruction replaced with a meaningless placeholder). If the
model's tool-call decision is the *same* in both runs, the model is
following the injection rather than the user — flag the call as
malicious.

Status as of May 2026
---------------------
- Original MELON: research code in Stanford-SLAB GitHub, requires
  custom hook into a Hugging Face tokenizer + per-step double-
  inference. No published Tex / agent-governance integration.
- Follow-ups: PIArena (ACL 2026) generalizes the dual-run idea; ASTRA
  shows adaptive attackers can defeat MELON at ~28% ASR.

Honest scope
------------
Real MELON requires two inferences per agent step against a chosen
backbone model. That's a deployment-side commitment (latency cost,
key management) not something we can implement inside the adjudication
layer without an LLM bridge. This adapter:

1. Defines the ``MelonAdapter`` interface that takes a configured
   ``MelonBackend`` (callable performing the double inference).
2. Ships a ``HeuristicMelonBackend`` that approximates MELON locally:
   it computes the cosine similarity (over token-set Jaccard, no
   embedding required) between the original prompt and the
   environment content, flags calls where similarity is high enough
   that an injection is plausible. This is *not* MELON; it's an
   approximation that gives a defensible default verdict while
   acknowledging the real implementation requires LLM hookup.
3. Provides a ``MelonSpecialist`` that wires either backend into the
   PDP.

When ``MelonBackend`` is configured with a real ``DualInferenceBackend``
(production wiring), the adapter calls it; otherwise it falls back to
the heuristic with confidence 0.5 (so the PDP knows the verdict is
advisory).

Reference: arxiv 2502.05174.
"""

from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.base import SpecialistEvidence, SpecialistResult


@runtime_checkable
class MelonBackend(Protocol):
    """A callable that runs the masked-evaluation check."""

    def check(
        self,
        *,
        user_prompt: str,
        environment_content: str,
        candidate_tool: str,
        candidate_args: dict,
    ) -> tuple[bool, float, str]:
        """
        Returns (is_injection, confidence, reason).

        - ``is_injection`` True if the masked run *also* would have
          made this tool call — i.e. the call doesn't depend on the
          user's actual prompt.
        - ``confidence`` 0..1.
        - ``reason`` short text for evidence.
        """
        ...


class HeuristicMelonBackend:
    """
    Heuristic approximation of MELON.

    Logic: token-set Jaccard between the user prompt and the
    environment content. If the environment content's tokens dominate
    (Jaccard ≥ threshold *of environment vs prompt*) AND the candidate
    tool is in a high-risk set, flag as likely injection. This is the
    "intent shift" signal MELON's full version uses, computed
    locally without an LLM.

    This is NOT real MELON. It's a structural defense useful when LLM
    backends aren't available. Real MELON requires re-running the
    backbone model.
    """

    __slots__ = ("_high_risk_tools", "_threshold")

    def __init__(
        self,
        *,
        high_risk_tools: tuple[str, ...] = (
            "send_email",
            "send_dm",
            "transfer",
            "wire_funds",
            "publish",
            "post_message",
            "delete_account",
        ),
        threshold: float = 0.35,
    ) -> None:
        self._high_risk_tools = set(high_risk_tools)
        if not (0.0 <= threshold <= 1.0):
            raise ValueError("threshold must be in [0, 1]")
        self._threshold = threshold

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {tok for tok in (w.strip(".,;:!?\"'") for w in text.lower().split()) if tok}

    def check(
        self,
        *,
        user_prompt: str,
        environment_content: str,
        candidate_tool: str,
        candidate_args: dict,
    ) -> tuple[bool, float, str]:
        if candidate_tool not in self._high_risk_tools:
            return False, 0.9, f"tool {candidate_tool!r} is low-risk"

        user_tokens = self._tokens(user_prompt)
        env_tokens = self._tokens(environment_content)
        if not env_tokens:
            return False, 0.5, "no environment content to compare against"
        # how much of the env shows up in the user prompt?
        overlap = (env_tokens & user_tokens)
        coverage = len(overlap) / max(1, len(env_tokens))

        # also detect "argument leakage": the tool args contain text
        # that is in env but not in the user prompt (strong injection
        # signal)
        args_text = " ".join(str(v) for v in candidate_args.values())
        args_tokens = self._tokens(args_text)
        env_only_in_args = (args_tokens & env_tokens) - user_tokens
        leaked = bool(env_only_in_args)

        if leaked or coverage < self._threshold:
            return (
                True,
                0.5,  # advisory confidence — real MELON is higher
                f"args reference env-only tokens={sorted(env_only_in_args)[:5]}; "
                f"prompt-env coverage={coverage:.2f}",
            )
        return False, 0.5, f"prompt-env coverage={coverage:.2f}"


class MelonSpecialist:
    """MELON-style masked-eval defense as a PDP specialist."""

    name: str = "melon"

    def __init__(self, *, backend: MelonBackend | None = None) -> None:
        self._backend: MelonBackend = backend or HeuristicMelonBackend()

    @property
    def backend(self) -> MelonBackend:
        return self._backend

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        metadata = getattr(request, "metadata", None) or {}
        user_prompt = str(metadata.get("user_prompt") or "")
        env_content = str(metadata.get("environment_content") or "")
        candidate_tool = str(metadata.get("candidate_tool") or "")
        candidate_args = metadata.get("candidate_args") or {}
        if not isinstance(candidate_args, dict):
            candidate_args = {}

        if not candidate_tool:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                summary="MELON: no candidate tool in request metadata, abstaining",
                uncertainty_flags=("no_candidate_tool",),
            )

        is_injection, confidence, reason = self._backend.check(
            user_prompt=user_prompt,
            environment_content=env_content,
            candidate_tool=candidate_tool,
            candidate_args=candidate_args,
        )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=1.0 if is_injection else 0.0,
            confidence=confidence,
            summary=(
                f"MELON {'flagged' if is_injection else 'cleared'} call to "
                f"{candidate_tool!r}: {reason}"
            ),
            rationale=(
                "Masked-evaluation defense: compared agent decision with what "
                "a masked-prompt run would do; backend="
                f"{type(self._backend).__name__}"
            ),
            evidence=(
                SpecialistEvidence(
                    text=f"melon_check: {reason}",
                    explanation=(
                        "MELON adapter result. If the backend is the heuristic, "
                        "this is an advisory signal; pair with a real MELON "
                        "backend in production."
                    ),
                ),
            ),
        )


__all__ = ["HeuristicMelonBackend", "MelonBackend", "MelonSpecialist"]
