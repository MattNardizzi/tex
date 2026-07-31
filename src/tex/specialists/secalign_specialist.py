"""
SecAlign adapter — preference-aligned defense.

SecAlign (arxiv 2410.05451, Chen-Mittal et al., Oct 2024) fine-tunes
a language model with a preference-optimization objective (DPO-style)
that teaches the model to *prefer* responses ignoring injected
instructions. Reported ASR drops from ~70% (baseline) to ~1% on
AgentDojo's Banking suite. ASTRA (arxiv 2507.07417) and PISmith
(arxiv 2603.13026) show adaptive attackers can still defeat
SecAlign at 21-70% ASR with optimization budget, so it is *not* a
finished story; it pairs cleanly with structural defenses like Tex's
PDP.

Status as of May 2026
---------------------
- SecAlign checkpoints: published on HuggingFace; integration into
  production agent stacks is rare. No agent-governance product wires
  SecAlign-tuned models as a first-class signal.

Honest scope
------------
A real SecAlign defense requires a SecAlign-fine-tuned backbone model.
We cannot perform that fine-tuning in this codebase — it's a GPU job
that requires the SecAlign training pipeline and a base model. This
adapter:

1. Defines the ``SecAlignBackend`` Protocol: any callable that calls
   a SecAlign-tuned model and returns a risk verdict on an agent
   step.
2. Provides ``DPODistilledHeuristic``: a structural fallback that
   uses the same *features* SecAlign is trained on (instruction-vs-
   data conflict, imperative-mode density in untrusted content,
   anomalous tool-name-vs-arg patterns) but without a fine-tuned
   model. Confidence is fixed at 0.5 to signal it's advisory.
3. ``SecAlignSpecialist`` wires either backend into the PDP.

To deploy real SecAlign in production: implement ``SecAlignBackend``
that calls your fine-tuned model endpoint and feed the specialist a
``RealSecAlignBackend`` instance at PDP startup.

Reference: arxiv 2410.05451 §4 (DPO objective); ASTRA arxiv
2507.07417 (adaptive attacks).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.base import SpecialistEvidence, SpecialistResult


@runtime_checkable
class SecAlignBackend(Protocol):
    """SecAlign-tuned model or feature-only fallback."""

    def score(
        self,
        *,
        user_prompt: str,
        untrusted_content: str,
        candidate_action: str,
    ) -> tuple[float, float, str]:
        """
        Returns (risk_score, confidence, reason).
        risk_score in [0, 1]; higher = more likely injection.
        """
        ...


def _imperative_density(text: str) -> float:
    """
    Fraction of sentences that start with imperative-mode verbs.
    Cheap proxy for "instruction-shaped" content.
    """
    imperatives = {
        "ignore",
        "disregard",
        "forget",
        "delete",
        "send",
        "transfer",
        "wire",
        "execute",
        "run",
        "post",
        "publish",
        "share",
        "give",
        "tell",
        "respond",
        "reply",
        "include",
        "use",
        "set",
        "make",
        "create",
        "write",
        "click",
        "visit",
    }
    sentences = [s.strip() for s in text.replace("\n", ".").split(".") if s.strip()]
    if not sentences:
        return 0.0
    hits = 0
    for s in sentences:
        first = s.split(None, 1)
        if not first:
            continue
        if first[0].lower().strip(",;:!?\"'") in imperatives:
            hits += 1
    return hits / len(sentences)


def _instruction_data_conflict(
    user_prompt: str, untrusted_content: str
) -> float:
    """
    How many tokens that *act* like instructions (per the imperative
    density) appear only in the untrusted content and not in the user
    prompt? More = more conflict = higher SecAlign-style risk.
    """
    user_lower = user_prompt.lower()
    score = 0.0
    for verb in (
        "send", "transfer", "wire", "delete", "publish", "post",
        "ignore", "disregard", "execute",
    ):
        if verb in untrusted_content.lower() and verb not in user_lower:
            score += 1.0
    return min(score / 5.0, 1.0)  # normalize


class DPODistilledHeuristic:
    """
    Structural fallback approximating SecAlign features without a
    fine-tuned model.

    Features
    --------
    - imperative_density(untrusted): higher = data is instruction-shaped
    - instruction_data_conflict(user, untrusted): higher = verbs the
      user did not ask for are in the data
    - candidate_action_alignment: simple check whether the candidate
      action verb appears in the user prompt

    Confidence fixed at 0.5 to flag this as advisory. Production:
    replace with real SecAlign-tuned backbone.
    """

    __slots__ = ("_threshold",)

    def __init__(self, *, threshold: float = 0.4) -> None:
        if not (0.0 <= threshold <= 1.0):
            raise ValueError("threshold must be in [0, 1]")
        self._threshold = threshold

    def score(
        self,
        *,
        user_prompt: str,
        untrusted_content: str,
        candidate_action: str,
    ) -> tuple[float, float, str]:
        if not untrusted_content:
            return 0.0, 0.5, "no untrusted content"
        imp = _imperative_density(untrusted_content)
        conflict = _instruction_data_conflict(user_prompt, untrusted_content)
        action_in_prompt = (
            candidate_action.lower() in user_prompt.lower()
        )
        # weighted combination
        risk = 0.5 * imp + 0.4 * conflict + (0.3 if not action_in_prompt else 0.0)
        risk = min(risk, 1.0)
        reason = (
            f"imp_density={imp:.2f} conflict={conflict:.2f} "
            f"action_in_prompt={action_in_prompt}"
        )
        return risk, 0.5, reason


class SecAlignSpecialist:
    """SecAlign defense as a PDP specialist."""

    name: str = "secalign"

    def __init__(self, *, backend: SecAlignBackend | None = None) -> None:
        self._backend: SecAlignBackend = backend or DPODistilledHeuristic()

    @property
    def backend(self) -> SecAlignBackend:
        return self._backend

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        metadata = getattr(request, "metadata", None) or {}
        user_prompt = str(metadata.get("user_prompt") or "")
        untrusted = str(metadata.get("environment_content") or "")
        candidate = str(metadata.get("candidate_tool") or "")

        if not untrusted:
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                summary="SecAlign: no untrusted content, abstaining",
                uncertainty_flags=("no_untrusted",),
            )

        risk, confidence, reason = self._backend.score(
            user_prompt=user_prompt,
            untrusted_content=untrusted,
            candidate_action=candidate,
        )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=risk,
            confidence=confidence,
            summary=f"SecAlign risk={risk:.2f}: {reason}",
            rationale=(
                "DPO-style alignment defense. "
                f"backend={type(self._backend).__name__}"
            ),
            evidence=(
                SpecialistEvidence(
                    text=f"secalign_features: {reason}",
                    explanation=(
                        "SecAlign-style risk scoring. Heuristic backend is "
                        "advisory; configure a fine-tuned SecAlign model in "
                        "production for high-confidence verdicts."
                    ),
                ),
            ),
            uncertainty_flags=(("heuristic_backend",) if confidence < 0.7 else ()),
        )


__all__ = [
    "DPODistilledHeuristic",
    "SecAlignBackend",
    "SecAlignSpecialist",
]
