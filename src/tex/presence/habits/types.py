"""The shapes of an "I've noticed…" habit hypothesis — and the seam it mines over.

A :class:`HabitHypothesis` is the whole point of L3, and its type encodes the
discipline: it is a HYPOTHESIS, never an asserted fact. It carries

  * the exact sealed records that support it (``supporting`` — the receipts), so a
    human (or an auditor) can re-verify the pattern against real evidence;
  * a COMPUTED :class:`~tex.presence.habits.confidence.PatternConfidence` (Wilson +
    Bonferroni), never a model's self-reported certainty;
  * a single, always-toward-caution :class:`HypothesisAction` describing the ONE
    thing confirming it would do.

It changes nothing until a human confirms it. The miner that produces it is
deterministic and read-only; the generator that PHRASES it is grounded only in
these fields (see :mod:`tex.presence.habits.phrasing`) and is never the source of
the pattern.

WHAT L3 DOES NOT DO (honest edges baked into the types)
-------------------------------------------------------
  * **No causation / intent.** A hypothesis reports a COUNT ("every sealed decision
    about X carried a FORBID, 6 of 6"), never "you want" / "because". There is no
    field for inferred motive.
  * **Only toward caution.** :class:`HypothesisAction` can only ever propose a
    *tightening* (a tier ceiling that is ``DERIVED``/``ABSTAIN`` — never ``SEALED``)
    or a non-inflating confirmation. A "you're always confident about X" pattern
    cannot become a rule that makes Tex MORE confident — there is no shape for it,
    and L2's write-gate refuses it anyway (defence in depth).
  * **Subject-level, not value-conditional.** A habit is scoped to a normalised
    ``subject_key`` (the same handle L2 keys corrections on), so a confirmed habit
    is faithfully representable as ONE L2 correction. L3 does NOT invent a
    value-threshold language ("over $X"): L2's tier ceiling is unconditional, so a
    value-conditional rule could not be enforced and is therefore never offered
    (see ``NOTES.md`` for the rejected threshold design).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from tex.presence.contract import EvidenceRef, PresenceTier

from tex.presence.habits.confidence import PatternConfidence

__all__ = [
    "HABITS_INTERFACE_VERSION",
    "OutcomeDimension",
    "HabitKind",
    "norm_subject",
    "ObservedOutcome",
    "HypothesisAction",
    "HabitHypothesis",
    "HistorySource",
]

HABITS_INTERFACE_VERSION = "1.0.0"


def norm_subject(claim_id: str) -> str:
    """The subject key a habit is scoped to — the SAME normalisation L2 applies to
    a correction's subject (``tex.presence.profile.types._norm_subject``):
    ``strip().casefold()``. Kept in lock-step deliberately so a confirmed habit's
    correction lands on exactly the subject the gate will key the next verdict on.
    EXACT subject only — never a prefix/fuzzy widen (widening would tighten an
    unrelated claim and misrepresent the pattern)."""
    return (claim_id or "").strip().casefold()


class OutcomeDimension(StrEnum):
    """Which field of a sealed record an observation reads. The miner groups by
    ``(dimension, subject_key)`` so two dimensions never bleed into one pattern."""

    GOVERNANCE_VERDICT = "governance_verdict"
    """The cross-referenced governance verdict (PERMIT/FORBID/ABSTAIN) the sealed
    presence record carried. "You forbid every decision about X" lives here."""

    TIER = "tier"
    """The presence credibility tier (SEALED/DERIVED/ABSTAIN) the claim was spoken
    at. "You always make me abstain on X" lives here."""

    CORRECTION_TIER = "correction_tier"
    """The ceiling of a prior L2 CORRECTION. "You keep correcting X to abstain"
    lives here (a repeated explicit operator tightening)."""


class HabitKind(StrEnum):
    """The shape of the pattern. V1 ships CATEGORICAL only (see module docstring /
    NOTES.md for why THRESHOLD is deliberately omitted)."""

    CATEGORICAL = "categorical"
    """One outcome value dominates a subject's observations (e.g. FORBID in 6/6)."""


@dataclass(frozen=True, slots=True)
class ObservedOutcome:
    """One DETERMINISTIC observation read off a single sealed record. Never
    inferred: every field is a value present in the record, and ``evidence`` points
    back at that exact record so the observation is re-verifiable. The miner counts
    these; it never counts anything a model said."""

    subject_key: str
    """Normalised claim_id (:func:`norm_subject`) — the grouping handle."""
    dimension: OutcomeDimension
    outcome_value: str
    """The categorical value at ``dimension`` (e.g. "forbid", "abstain"),
    lower-cased for stable grouping."""
    evidence: EvidenceRef
    """The exact sealed record this observation was read from — a receipt."""
    observed_at: str = ""
    """ISO-8601 UTC of the underlying record; metadata only, used only for
    deterministic tie-breaks and display, never part of the content anchor."""

    def dedupe_key(self) -> tuple[str, str, str]:
        """Identity for de-duplication: one physical record contributes at most one
        observation per dimension, so an idempotent re-seal (same ``record_id``)
        cannot inflate support."""
        return (self.dimension.value, self.subject_key, self.evidence.record_id)


@dataclass(frozen=True, slots=True)
class HypothesisAction:
    """The single, always-toward-caution effect of confirming a hypothesis: write
    ONE L2 correction capping the subject's tier at ``proposed_tier``. V1 produces
    only this tightening action — never an inflating or value-conditional one."""

    subject_key: str
    proposed_tier: PresenceTier
    """The ceiling to impose — ``DERIVED`` or ``ABSTAIN``, never ``SEALED``."""
    statement: str
    """Human-readable boundary text, surfaced in the UI and stored on the L2 fact —
    NEVER spoken as a grounded claim."""

    def __post_init__(self) -> None:
        # Defence in depth: the type itself refuses an inflating proposal, so no
        # caller can construct a habit that would raise a tier (L2 also refuses it).
        if self.proposed_tier is PresenceTier.SEALED:
            raise ValueError(
                "a habit action must propose DERIVED or ABSTAIN, never SEALED "
                "(a habit may only ever move a tier toward caution)"
            )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass(frozen=True, slots=True)
class HabitHypothesis:
    """A noticed pattern, OFFERED — never asserted. Content-addressed so that
    confirming ``hypothesis_id`` always means exactly the same thing (the same
    subject, dominant outcome, proposed action, and supporting record set)."""

    hypothesis_id: str
    """``"hh-" + sha256`` over the time-independent content (tenant, kind,
    dimension, subject, dominant outcome, action, sorted supporting record ids)."""
    tenant: str
    kind: HabitKind
    dimension: OutcomeDimension
    subject_key: str
    dominant_outcome: str
    action: HypothesisAction
    confidence: PatternConfidence
    supporting: tuple[EvidenceRef, ...]
    """The EXACT sealed records that support the pattern — the receipts a human or
    auditor re-verifies. Non-empty by construction (a hypothesis with no evidence
    is not a hypothesis)."""
    phrasing: str = ""
    """The deterministic "I've noticed…" text (see :mod:`phrasing`). Cosmetic: the
    load-bearing content is the structured fields above, not this prose."""

    def supporting_count(self) -> int:
        return len(self.supporting)

    @staticmethod
    def content_id(
        *,
        tenant: str,
        kind: HabitKind,
        dimension: OutcomeDimension,
        subject_key: str,
        dominant_outcome: str,
        action: HypothesisAction,
        supporting: tuple[EvidenceRef, ...],
    ) -> str:
        payload = {
            "v": HABITS_INTERFACE_VERSION,
            "tenant": tenant,
            "kind": kind.value,
            "dimension": dimension.value,
            "subject_key": subject_key,
            "dominant_outcome": dominant_outcome,
            "action": {
                "subject_key": action.subject_key,
                "proposed_tier": action.proposed_tier.value,
            },
            # Sorted record_ids: order-independent, so the same pattern from the same
            # records is the same hypothesis regardless of mining order.
            "supporting": sorted(r.record_id for r in supporting),
        }
        return "hh-" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@runtime_checkable
class HistorySource(Protocol):
    """The seam the miner reads. Any source that can yield a tenant's sealed
    observations satisfies it — :class:`~tex.presence.habits.sources.S5MemoryHistorySource`
    over presence memory, an iterable wrapper, or an orchestrator-provided adapter
    over governance resolutions. Strictly per-tenant; the source must NEVER return
    another tenant's records."""

    def outcomes(self, *, tenant: str) -> tuple[ObservedOutcome, ...]:
        ...
