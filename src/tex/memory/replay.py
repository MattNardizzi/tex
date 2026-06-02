"""
Memory replay engine — locked spec § 6.

A replay reconstructs a historical decision and re-runs the evaluator
against the same input under the same policy snapshot. The output is
compared against the original record. If they diverge, replay fails
and the divergence is reported.

Why this is in ``tex.memory`` and not ``tex.engine``
----------------------------------------------------
Replay is a *consumer* of the memory layer, not a producer. It needs
read-only access to decisions, inputs, and policy snapshots, plus a
callable that knows how to evaluate. The engine itself is injected so
this module stays decoupled from the orchestrator's wiring — useful
for tests that swap in a stub evaluator.

Determinism caveat
------------------
The engine produces a deterministic verdict only when the evaluator
itself is deterministic. The semantic layer (LLM-backed) is *not*
strictly deterministic; the existing ``determinism_fingerprint`` on
each Decision captures the inputs to deterministic + specialist +
semantic-score paths. Replay compares fingerprints first; only if
those match does it compare verdicts. This way a replay failure points
at the right layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from uuid import UUID

from tex.domain.decision import Decision
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.memory.decision_input_store import DecisionInputStore, StoredDecisionInput
from tex.memory.decision_store import DurableDecisionStore
from tex.memory.policy_snapshot_store import DurablePolicyStore

_logger = logging.getLogger(__name__)


class _Evaluator(Protocol):
    """
    Minimum contract a replay-able evaluator must satisfy.

    The orchestrator exposes a synchronous evaluate method that takes a
    raw request payload and returns a Decision. Anything that conforms
    to this shape works — production engine, test stub, golden-set
    runner, etc.
    """

    def __call__(
        self,
        *,
        request: dict[str, Any],
        policy: PolicySnapshot,
    ) -> Decision: ...


@dataclass(frozen=True, slots=True)
class ReplayDivergence:
    field: str
    original: Any
    replayed: Any


@dataclass(frozen=True, slots=True)
class ReplayResult:
    decision_id: UUID
    request_id: UUID
    matched: bool
    fingerprint_matched: bool
    verdict_matched: bool
    confidence_matched: bool
    final_score_matched: bool
    divergences: tuple[ReplayDivergence, ...]
    original_verdict: Verdict
    replayed_verdict: Verdict

    @property
    def is_clean(self) -> bool:
        return self.matched

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": str(self.decision_id),
            "request_id": str(self.request_id),
            "matched": self.matched,
            "fingerprint_matched": self.fingerprint_matched,
            "verdict_matched": self.verdict_matched,
            "confidence_matched": self.confidence_matched,
            "final_score_matched": self.final_score_matched,
            "original_verdict": self.original_verdict.value,
            "replayed_verdict": self.replayed_verdict.value,
            "divergences": [
                {
                    "field": d.field,
                    "original": d.original,
                    "replayed": d.replayed,
                }
                for d in self.divergences
            ],
        }


class ReplayMissingArtifactError(RuntimeError):
    """
    Raised when replay can't proceed because a required artifact —
    decision, input, or policy snapshot — is not in memory.
    """


class MemoryReplayEngine:
    """
    Implements the spec's five-step replay:

      1. Load decision
      2. Load policy snapshot
      3. Load original input
      4. Re-run evaluation
      5. Compare outputs
    """

    def __init__(
        self,
        *,
        decisions: DurableDecisionStore,
        inputs: DecisionInputStore,
        policies: DurablePolicyStore,
        evaluator: _Evaluator,
        confidence_tolerance: float = 1e-6,
        score_tolerance: float = 1e-6,
    ) -> None:
        self._decisions = decisions
        self._inputs = inputs
        self._policies = policies
        self._evaluator = evaluator
        self._confidence_tol = confidence_tolerance
        self._score_tol = score_tolerance

    def replay(self, decision_id: UUID) -> ReplayResult:
        original = self._decisions.get(decision_id)
        if original is None:
            raise ReplayMissingArtifactError(
                f"decision not found in memory: {decision_id}"
            )

        stored_input = self._inputs.get(original.request_id)
        if stored_input is None:
            raise ReplayMissingArtifactError(
                f"input not found for request {original.request_id}"
            )

        policy = self._policies.get(original.policy_version)
        if policy is None:
            raise ReplayMissingArtifactError(
                f"policy snapshot not found: {original.policy_version}"
            )

        replayed = self._evaluator(
            request=dict(stored_input.full_input),
            policy=policy,
        )

        return self._compare(original=original, replayed=replayed)

    # ---- internals ----------------------------------------------------

    def _compare(
        self,
        *,
        original: Decision,
        replayed: Decision,
    ) -> ReplayResult:
        divergences: list[ReplayDivergence] = []

        fingerprint_matched = (
            original.determinism_fingerprint == replayed.determinism_fingerprint
        )
        if not fingerprint_matched:
            divergences.append(
                ReplayDivergence(
                    field="determinism_fingerprint",
                    original=original.determinism_fingerprint,
                    replayed=replayed.determinism_fingerprint,
                )
            )

        verdict_matched = original.verdict == replayed.verdict
        if not verdict_matched:
            divergences.append(
                ReplayDivergence(
                    field="verdict",
                    original=original.verdict.value,
                    replayed=replayed.verdict.value,
                )
            )

        confidence_matched = (
            abs(original.confidence - replayed.confidence) <= self._confidence_tol
        )
        if not confidence_matched:
            divergences.append(
                ReplayDivergence(
                    field="confidence",
                    original=original.confidence,
                    replayed=replayed.confidence,
                )
            )

        final_score_matched = (
            abs(original.final_score - replayed.final_score) <= self._score_tol
        )
        if not final_score_matched:
            divergences.append(
                ReplayDivergence(
                    field="final_score",
                    original=original.final_score,
                    replayed=replayed.final_score,
                )
            )

        matched = (
            fingerprint_matched
            and verdict_matched
            and confidence_matched
            and final_score_matched
        )

        return ReplayResult(
            decision_id=original.decision_id,
            request_id=original.request_id,
            matched=matched,
            fingerprint_matched=fingerprint_matched,
            verdict_matched=verdict_matched,
            confidence_matched=confidence_matched,
            final_score_matched=final_score_matched,
            divergences=tuple(divergences),
            original_verdict=original.verdict,
            replayed_verdict=replayed.verdict,
        )
