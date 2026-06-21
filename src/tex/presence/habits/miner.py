"""The deterministic habit miner — counts, never guesses.

Given a tenant's sealed observations, it finds subjects whose outcomes are
dominated by ONE value strongly and consistently enough to OFFER as a hypothesis,
and abstains from offering anything otherwise. It is the opposite of an LLM
"noticing" a pattern: every decision here is a count compared against a computed
statistic (:mod:`tex.presence.habits.confidence`), reproducible to the bit.

THE PIPELINE (all deterministic, read-only)
-------------------------------------------
1. **De-duplicate** observations by ``(dimension, subject, record_id)`` so an
   idempotent re-seal (same content anchor) cannot inflate support.
2. **Group** by ``(dimension, subject_key)``.
3. **Count the multiplicity** ``m`` = how many groups have ``>= min_support``
   observations across ALL mined dimensions. Every such group is a hypothesis we
   are about to test, so ``m`` is the family size the Bonferroni correction divides
   the error budget across (the guard against a noisy subject looking clean by
   chance).
4. For each eligible group, find the dominant outcome and score it. Surface it
   ONLY if it clears support, observed-rate, and the (corrected) Wilson lower bound
   — AND the dominant outcome maps to a *cautious* action (a tightening). A
   non-cautionary dominance (e.g. "you PERMIT everything about X") is never offered
   as a verdict rule: turning it into one would raise confidence, which L3 must
   never do.

WHY THE OUTCOME→ACTION MAP IS CAUTION-ONLY
------------------------------------------
A habit can only ever tighten (constitution: signals may only lower a verdict).
So the map deliberately covers only the cautionary outcomes:

  * ``governance_verdict`` dominant in {forbid, abstain} → cap the subject's
    presence tier at ABSTAIN: "you consistently block / escalate this, so I'll
    defer to you on it rather than assert." A dominant ``permit`` has no entry — a
    "you always allow X" pattern is real but offering it as a rule would make Tex
    speak X more confidently, so it is surfaced as nothing.
  * ``correction_tier`` dominant in {derived, abstain} → re-affirm that ceiling:
    "you keep correcting X to <tier>." (A correction can never be to SEALED, so
    this axis is cautious by construction.)
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from tex.presence.contract import PresenceTier

from tex.presence.habits.confidence import score_pattern
from tex.presence.habits.types import (
    HabitHypothesis,
    HabitKind,
    HypothesisAction,
    HistorySource,
    ObservedOutcome,
    OutcomeDimension,
)

_logger = logging.getLogger(__name__)

__all__ = ["MinerConfig", "HabitMiner"]


# The cautious tier a dominant categorical outcome would impose, per dimension.
# Absence from this map == "not a cautionary pattern" == never offered as a rule.
# Keyed by (dimension, lowercased-outcome-value).
_CAUTIOUS_ACTION: dict[tuple[OutcomeDimension, str], PresenceTier] = {
    (OutcomeDimension.GOVERNANCE_VERDICT, "forbid"): PresenceTier.ABSTAIN,
    (OutcomeDimension.GOVERNANCE_VERDICT, "abstain"): PresenceTier.ABSTAIN,
    (OutcomeDimension.CORRECTION_TIER, "abstain"): PresenceTier.ABSTAIN,
    (OutcomeDimension.CORRECTION_TIER, "derived"): PresenceTier.DERIVED,
}


@dataclass(frozen=True, slots=True)
class MinerConfig:
    """The thresholds that decide "real pattern" vs "noise". Conservative by
    design — the cost of a false "I've noticed…" (eroding the operator's trust that
    Tex only speaks what it can support) is higher than the cost of staying quiet.

    Boundary behaviour these defaults produce (verified in the tests):
      * a clean 5-of-5 single subject SURFACES (Wilson lower ≈ 0.75 at m=1);
      * a 4-of-5 single subject does NOT (Wilson lower ≈ 0.51 < 0.55);
      * a 3-of-5 (or any rate < 0.8) does NOT (observed rate gate);
      * a 5-of-5 subject hiding among 20 noisy subjects does NOT — Bonferroni over
        m=20 drops its Wilson lower to ≈ 0.43 (the multiple-comparisons guard).
    """

    min_support: int = 5
    """At least this many DISTINCT observations for a subject to be eligible."""
    min_point_rate: float = 0.8
    """The observed dominant-outcome rate must be at least this (a genuinely strong
    pattern, not a bare majority)."""
    min_confidence: float = 0.55
    """The Bonferroni-corrected Wilson lower bound must clear this."""
    alpha_family: float = 0.10
    """Family-wise one-sided error budget, split across the subjects tested. 0.10
    (90% one-sided) suits a HUMAN-CONFIRMED suggestion — this is not a safety
    verdict, and a human reviews every surfaced hypothesis."""
    dimensions: tuple[OutcomeDimension, ...] = (
        OutcomeDimension.GOVERNANCE_VERDICT,
        OutcomeDimension.CORRECTION_TIER,
    )
    """Which outcome dimensions to mine. ``TIER`` is intentionally absent: the only
    tier S5 reliably seals is SEALED/DERIVED, and a "you're always confident about
    X" pattern is the inflating direction L3 must never turn into a rule."""


@dataclass(frozen=True, slots=True)
class _Group:
    dimension: OutcomeDimension
    subject_key: str
    observations: tuple[ObservedOutcome, ...]


class HabitMiner:
    """Stateless, deterministic. Construct once (optionally with a tuned
    :class:`MinerConfig`) and call :meth:`mine` / :meth:`mine_source` repeatedly.
    Never writes anything — surfacing a hypothesis changes nothing until a human
    confirms it through :mod:`tex.presence.habits.confirm`."""

    def __init__(self, config: MinerConfig | None = None) -> None:
        self._config = config or MinerConfig()

    @property
    def config(self) -> MinerConfig:
        return self._config

    def mine_source(self, *, tenant: str, source: HistorySource) -> tuple[HabitHypothesis, ...]:
        """Mine a tenant's hypotheses from a :class:`HistorySource`. Read-only; the
        source itself must be strictly per-tenant."""
        try:
            outcomes = source.outcomes(tenant=tenant)
        except Exception:  # noqa: BLE001 — a faulty source must never crash a surface
            _logger.warning("habit miner: source.outcomes failed for tenant %r", tenant, exc_info=True)
            return ()
        return self.mine(tenant=tenant, outcomes=outcomes)

    def mine(self, *, tenant: str, outcomes: Iterable[ObservedOutcome]) -> tuple[HabitHypothesis, ...]:
        """Mine hypotheses from an explicit iterable of observations. Deterministic:
        the same observations always yield the same hypotheses, in the same order."""
        if not tenant or not tenant.strip():
            raise ValueError("habit miner requires a non-empty tenant")
        cfg = self._config
        mined_dims = set(cfg.dimensions)

        # 1. de-dupe; keep only the dimensions we mine and this tenant's records.
        seen: set[tuple[str, str, str]] = set()
        deduped: list[ObservedOutcome] = []
        for o in outcomes:
            if o.dimension not in mined_dims:
                continue
            key = o.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(o)

        # 2. group by (dimension, subject).
        buckets: dict[tuple[OutcomeDimension, str], list[ObservedOutcome]] = defaultdict(list)
        for o in deduped:
            buckets[(o.dimension, o.subject_key)].append(o)

        groups = [
            _Group(dimension=dim, subject_key=subj, observations=tuple(obs))
            for (dim, subj), obs in buckets.items()
        ]

        # 3. multiplicity: every group eligible by support is a hypothesis we test.
        eligible = [g for g in groups if len(g.observations) >= cfg.min_support]
        family_size = max(1, len(eligible))

        # 4. score + map each eligible group; surface only what clears every floor.
        hypotheses: list[HabitHypothesis] = []
        for g in eligible:
            hyp = self._score_group(tenant=tenant, group=g, family_size=family_size)
            if hyp is not None:
                hypotheses.append(hyp)

        # Deterministic order: subject, then dimension.
        hypotheses.sort(key=lambda h: (h.subject_key, h.dimension.value))
        return tuple(hypotheses)

    # ------------------------------------------------------------------ internals

    def _score_group(
        self, *, tenant: str, group: _Group, family_size: int
    ) -> HabitHypothesis | None:
        cfg = self._config
        n = len(group.observations)

        # Dominant outcome — deterministic tie-break: highest count, then lexically
        # smallest value (a true tie has rate ~0.5 and fails min_point_rate anyway).
        counts = Counter(o.outcome_value for o in group.observations)
        dominant, k = min(
            counts.items(), key=lambda kv: (-kv[1], kv[0])
        )

        confidence = score_pattern(
            k=k,
            n=n,
            family_size=family_size,
            alpha_family=cfg.alpha_family,
            min_support=cfg.min_support,
            min_point_rate=cfg.min_point_rate,
            min_confidence=cfg.min_confidence,
        )
        if not confidence.surfaced:
            return None

        proposed_tier = _CAUTIOUS_ACTION.get((group.dimension, dominant))
        if proposed_tier is None:
            # A real but non-cautionary dominance (e.g. always-PERMIT) — never
            # offered as a verdict rule (would raise confidence). Logged, not surfaced.
            _logger.debug(
                "habit miner: subject %r has a non-cautionary %s dominance (%s, %d/%d) "
                "— not offered as a rule (would inflate)",
                group.subject_key, group.dimension.value, dominant, k, n,
            )
            return None

        # The supporting receipts: the records carrying the dominant outcome, sorted
        # for a stable content anchor. (Only matching records support the claim "you
        # consistently <dominant> this" — the minority records are excluded.)
        supporting = tuple(
            sorted(
                (o.evidence for o in group.observations if o.outcome_value == dominant),
                key=lambda r: r.record_id,
            )
        )
        statement = _statement(group.dimension, group.subject_key, dominant, proposed_tier, k, n)
        action = HypothesisAction(
            subject_key=group.subject_key,
            proposed_tier=proposed_tier,
            statement=statement,
        )
        hypothesis_id = HabitHypothesis.content_id(
            tenant=tenant,
            kind=HabitKind.CATEGORICAL,
            dimension=group.dimension,
            subject_key=group.subject_key,
            dominant_outcome=dominant,
            action=action,
            supporting=supporting,
        )
        return HabitHypothesis(
            hypothesis_id=hypothesis_id,
            tenant=tenant,
            kind=HabitKind.CATEGORICAL,
            dimension=group.dimension,
            subject_key=group.subject_key,
            dominant_outcome=dominant,
            action=action,
            confidence=confidence,
            supporting=supporting,
            phrasing="",  # filled by the phraser at surface time
        )


def _statement(
    dimension: OutcomeDimension,
    subject_key: str,
    dominant: str,
    proposed_tier: PresenceTier,
    k: int,
    n: int,
) -> str:
    """The boundary text stored on the confirmed L2 fact (NEVER spoken as a grounded
    claim). Pure count language — no inferred intent."""
    if dimension is OutcomeDimension.GOVERNANCE_VERDICT:
        return (
            f"Tenant consistently resolved decisions about {subject_key!r} to "
            f"{dominant.upper()} ({k} of {n} sealed); proposed standing tier ceiling "
            f"{proposed_tier.value.upper()} (defer/abstain on this subject)."
        )
    return (
        f"Tenant repeatedly corrected {subject_key!r} to {dominant.upper()} "
        f"({k} of {n} corrections); proposed standing tier ceiling "
        f"{proposed_tier.value.upper()}."
    )
