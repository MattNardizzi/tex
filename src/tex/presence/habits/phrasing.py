"""Turn a mined hypothesis into the "I've noticed…" line — without ever letting the
phrasing become the source of the pattern.

THE RULE THAT KEEPS THIS HONEST
-------------------------------
The pattern comes from the deterministic miner; the phrasing is cosmetic. The
DEFAULT :class:`TemplatePhraser` is a pure function of the hypothesis's already-
computed fields (counts, subject, dominant outcome, proposed tier) — no model, no
new facts, nothing to hallucinate. It speaks only COUNTS ("6 of 6"), never inferred
intent ("you want", "because").

An LLM MAY rephrase for fluency, but it is handed ONLY those same structured fields
and is forbidden to add any fact; the load-bearing content stays the structured
:class:`HabitHypothesis` (its numbers and its supporting EvidenceRefs), not the
prose. If a phraser drifts (adds a digit/subject not in the hypothesis), the
caller can detect it by re-rendering the template — the template is the ground
truth. We ship only the template phraser in V1; the :class:`Phraser` protocol is
the seam an LLM phraser would implement, kept here so no one wires a generator that
sources facts.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tex.presence.contract import PresenceTier

from tex.presence.habits.types import HabitHypothesis, OutcomeDimension

__all__ = ["Phraser", "TemplatePhraser", "render_hypothesis"]


def render_hypothesis(hyp: HabitHypothesis) -> str:
    """The deterministic, fact-grounded "I've noticed…" line. Pure function of the
    hypothesis — identical input always yields identical text."""
    c = hyp.confidence
    subject = hyp.subject_key
    tier = hyp.action.proposed_tier
    pct = round(100.0 * c.point_rate)

    if hyp.dimension is OutcomeDimension.GOVERNANCE_VERDICT:
        lead = (
            f"I've noticed that of the {c.n} decisions about {subject!r} I have on "
            f"record for you, {c.k} resolved to {hyp.dominant_outcome.upper()} "
            f"({pct}%)."
        )
    else:  # CORRECTION_TIER
        lead = (
            f"I've noticed you've corrected {subject!r} to "
            f"{hyp.dominant_outcome.upper()} {c.k} of the last {c.n} times "
            f"({pct}%)."
        )

    offer = _offer(tier, subject)
    floor = (
        f" (consistency lower bound {c.wilson_lower:.2f} over {c.family_size} "
        f"subject(s) considered — a heuristic screen, not a guarantee.)"
    )
    return f"{lead} {offer}{floor}"


def _offer(tier: PresenceTier, subject: str) -> str:
    if tier is PresenceTier.ABSTAIN:
        return (
            f"Want me to treat {subject!r} as cautious by default — defer to you "
            f"(abstain) rather than answer it on my own — until you say otherwise?"
        )
    # DERIVED ceiling
    return (
        f"Want me to treat {subject!r} as an estimate at most (never a sealed fact) "
        f"until you say otherwise?"
    )


@runtime_checkable
class Phraser(Protocol):
    """The phrasing seam. ``TemplatePhraser`` is the default; an LLM phraser would
    implement this, receiving ONLY the structured hypothesis and adding no facts."""

    def phrase(self, hyp: HabitHypothesis) -> str:
        ...


class TemplatePhraser:
    """The only phraser shipped in V1: deterministic, no model, no fabrication."""

    def phrase(self, hyp: HabitHypothesis) -> str:
        return render_hypothesis(hyp)
