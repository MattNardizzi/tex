"""
Five Eyes-Aligned Human Review Escalation.

Implements the ``requires_human_review`` flag per the Five Eyes joint
guidance "Careful Adoption of Agentic AI Services" (1 May 2026), which
explicitly recommends fail-safe-by-default and human-in-the-loop on
high-risk agentic actions.

How specialists opt in
----------------------
Any specialist can signal a human-review request by adding the special
uncertainty flag ``REQUIRES_HUMAN_REVIEW`` to its result. The flag is
namespaced via the constant ``REQUIRES_HUMAN_REVIEW_FLAG`` (which
includes a structured reason after a colon) so multiple specialists can
contribute distinct escalation reasons without collision.

For example::

    SpecialistResult(
        ...,
        uncertainty_flags=(
            "specialist_heuristic",
            "REQUIRES_HUMAN_REVIEW: AttriGuard found two independent "
            "causal-driver observations; per Five Eyes May 2026 guidance "
            "this action should not be auto-committed.",
        ),
    )

Escalation rules
----------------
The ``HumanReviewEscalation.from_bundle()`` factory aggregates across
the bundle and applies the Five Eyes-aligned escalation policy:

  1. Any specialist that emitted REQUIRES_HUMAN_REVIEW → review_required.
  2. ``bundle.max_risk_score >= HIGH_RISK_THRESHOLD`` (default 0.7) AND
     any of ARGUS, AttriGuard, VIGIL fired a structural reason code →
     review_required.
  3. >= 3 specialists firing reason codes simultaneously
     (defense-in-depth cascade pattern) → review_required.
  4. ASI08 (cascading failure) tagged anywhere → review_required.

The escalation verdict is informational only; the PDP's existing fusion
math still owns the synchronous PERMIT/ABSTAIN/FORBID outcome. But the
flag is preserved in the hash-chained evidence so downstream
operators / audit replay can verify human review was triggered when
the policy required it.

References
----------
- Five Eyes joint guidance "Careful Adoption of Agentic AI Services"
  (Australia, Canada, NZ, UK, US — 1 May 2026; 30 pages, 5 risk
  categories, 23 risks, 100+ best practices).
- arxiv 2603.10749 (AttriGuard) — uses parallel counterfactual tests;
  the structural reason codes from AttriGuard are the highest-signal
  "needs human review" triggers in the suite.
- arxiv 2605.03378 (ARGUS) — provenance-aware decision audit.
"""

from __future__ import annotations

from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.owasp_asi import ASI_CASCADING_FAILURE
from tex.specialists.base import SpecialistBundle, SpecialistResult


REQUIRES_HUMAN_REVIEW_FLAG_PREFIX = "REQUIRES_HUMAN_REVIEW"
"""Convention: uncertainty_flags entries starting with this string opt
the request into human review. The portion after ``: `` is the
structured reason.
"""


HIGH_RISK_THRESHOLD = 0.7
"""Per Five Eyes guidance, actions scoring above this threshold without
explicit human approval are out-of-policy for high-risk environments."""


STRUCTURAL_SPECIALIST_NAMES = frozenset(
    {"argus", "attriguard", "vigil", "agentarmor"}
)
"""Specialists whose reason codes carry structural — not lexical —
evidence. A FORBID-class signal from any of these is the highest-fidelity
trigger for human review under Five Eyes guidance."""


CASCADE_SPECIALIST_THRESHOLD = 3
"""Number of distinct specialists with at least one reason code firing
that constitutes a 'defense-in-depth cascade' triggering review."""


class HumanReviewEscalation(BaseModel):
    """Five Eyes-aligned human review escalation verdict.

    Composed onto a SpecialistBundle — does NOT modify the existing
    contract surface. Persisted into hash-chained evidence so audit
    replay can verify review was triggered per policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    review_required: bool
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    contributing_specialists: tuple[str, ...] = Field(default_factory=tuple)
    triggered_by_rules: tuple[str, ...] = Field(default_factory=tuple)
    bundle_max_risk: float = Field(ge=0.0, le=1.0)

    @classmethod
    def from_bundle(cls, bundle: SpecialistBundle) -> "HumanReviewEscalation":
        reasons: list[str] = []
        contributing: list[str] = []
        rules_triggered: list[str] = []

        # Rule 1: any explicit REQUIRES_HUMAN_REVIEW from a specialist.
        for result in bundle.results:
            explicit = _extract_explicit_human_review(result.uncertainty_flags)
            if explicit:
                reasons.extend(explicit)
                contributing.append(result.specialist_name)
                if "rule_1_explicit_specialist_request" not in rules_triggered:
                    rules_triggered.append("rule_1_explicit_specialist_request")

        # Rule 2: high-risk score + a structural specialist contribution.
        if bundle.max_risk_score >= HIGH_RISK_THRESHOLD:
            structural_hits = [
                r for r in bundle.results
                if r.specialist_name in STRUCTURAL_SPECIALIST_NAMES
                and r.matched_policy_clause_ids
            ]
            if structural_hits:
                reasons.append(
                    f"Bundle max risk {bundle.max_risk_score:.3f} >= "
                    f"{HIGH_RISK_THRESHOLD} with structural specialist "
                    f"contribution from "
                    f"{','.join(h.specialist_name for h in structural_hits)}."
                )
                for h in structural_hits:
                    if h.specialist_name not in contributing:
                        contributing.append(h.specialist_name)
                if "rule_2_high_risk_structural" not in rules_triggered:
                    rules_triggered.append("rule_2_high_risk_structural")

        # Rule 3: defense-in-depth cascade (>= N specialists with reason codes).
        firing_count = sum(
            1 for r in bundle.results if r.matched_policy_clause_ids
        )
        if firing_count >= CASCADE_SPECIALIST_THRESHOLD:
            reasons.append(
                f"{firing_count} specialists fired reason codes "
                f"concurrently — defense-in-depth cascade signal "
                f"(threshold {CASCADE_SPECIALIST_THRESHOLD})."
            )
            for r in bundle.results:
                if r.matched_policy_clause_ids and r.specialist_name not in contributing:
                    contributing.append(r.specialist_name)
            if "rule_3_cascade" not in rules_triggered:
                rules_triggered.append("rule_3_cascade")

        # Rule 4: ASI08 (cascading failure) is the OWASP-recognized
        # human-review trigger.
        for r in bundle.results:
            if ASI_CASCADING_FAILURE in r.matched_policy_clause_ids:
                reasons.append(
                    f"{r.specialist_name} tagged ASI08 "
                    f"(cascading_failure) — Five Eyes guidance requires "
                    "human review on cascade-class signals."
                )
                if r.specialist_name not in contributing:
                    contributing.append(r.specialist_name)
                if "rule_4_asi08_cascading_failure" not in rules_triggered:
                    rules_triggered.append("rule_4_asi08_cascading_failure")
                break  # one mention is enough

        return cls(
            review_required=bool(rules_triggered),
            reasons=tuple(_dedupe(reasons)),
            contributing_specialists=tuple(_dedupe(contributing)),
            triggered_by_rules=tuple(rules_triggered),
            bundle_max_risk=round(bundle.max_risk_score, 4),
        )


def build_specialist_human_review_flag(reason: str) -> str:
    """Helper for specialists to construct their uncertainty_flag string."""
    if not reason.strip():
        raise ValueError("reason must not be blank")
    return f"{REQUIRES_HUMAN_REVIEW_FLAG_PREFIX}: {reason.strip()}"


def _extract_explicit_human_review(flags: Iterable[str]) -> list[str]:
    """Pull the structured reasons out of REQUIRES_HUMAN_REVIEW flags."""
    out: list[str] = []
    for f in flags:
        if not isinstance(f, str):
            continue
        if f.startswith(REQUIRES_HUMAN_REVIEW_FLAG_PREFIX):
            # Format: 'REQUIRES_HUMAN_REVIEW: <reason>' or just the prefix.
            _, _, reason = f.partition(":")
            reason = reason.strip()
            if reason:
                out.append(reason)
            else:
                out.append("(specialist requested human review)")
    return out


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


__all__ = [
    "HIGH_RISK_THRESHOLD",
    "HumanReviewEscalation",
    "REQUIRES_HUMAN_REVIEW_FLAG_PREFIX",
    "STRUCTURAL_SPECIALIST_NAMES",
    "build_specialist_human_review_flag",
]
