"""
Build structured OWASP ASI findings from raw Tex pipeline signals.

This is the bridge between Tex's internal evaluation artifacts
(deterministic findings, specialist results, semantic dimensions) and
the public ``ASIFinding`` contract. It encapsulates:

- aggregation: one finding per ASI category, multiple triggers per
  finding
- severity: max trigger score across all triggers for the category
- confidence: a weighted function of trigger count, max score, and
  source diversity
- verdict influence: decisive / contributing / informational based on
  which upstream signals drove the verdict
- counterfactual: a plain-English explanation of why the category fired
  and what would have prevented it

The function is pure: given the same upstream inputs it produces the
same tuple of findings in the same order. That determinism is required
for the determinism fingerprint used elsewhere in the pipeline.
"""

from __future__ import annotations

from tex.deterministic.gate import DeterministicGateResult
from tex.domain.asi_finding import (
    ASIFinding,
    ASITrigger,
    ASITriggerSource,
    ASIVerdictInfluence,
)
from tex.domain.owasp_asi import (
    SEMANTIC_DIMENSION_MIN_SCORE,
    SPECIALIST_MIN_RISK_SCORE,
    all_asi_categories,
    asi_tags_for_recognizer,
    asi_tags_for_semantic_dimension,
    asi_tags_for_specialist,
    require_asi_metadata,
)
from tex.domain.severity import Severity
from tex.semantic.schema import SemanticAnalysis
from tex.specialists.base import SpecialistBundle


# Severity tier -> normalized score for recognizer triggers.
_SEVERITY_TO_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.WARNING: 0.55,
    Severity.INFO: 0.20,
}

# A trigger score at or above this bar is considered "strong" and
# eligible to make a finding decisive or contributing.
_STRONG_TRIGGER_SCORE: float = 0.55

# A trigger score at or above this bar earns the "decisive" label when
# combined with an upstream deterministic block or a semantic-dominance
# override.
_DECISIVE_TRIGGER_SCORE: float = 0.85


def build_asi_findings(
    *,
    deterministic_result: DeterministicGateResult,
    specialist_bundle: SpecialistBundle,
    semantic_analysis: SemanticAnalysis,
    semantic_dominance_override_fired: bool,
) -> tuple[ASIFinding, ...]:
    """
    Produce the structured ASI findings for one evaluation.

    The caller is responsible for deciding whether the semantic-
    dominance override actually fired (the router owns that logic).
    We accept it as a boolean so this module does not duplicate
    routing rules.
    """
    # Collect per-category triggers first, then aggregate.
    triggers_by_category: dict[str, list[ASITrigger]] = {
        category: [] for category in all_asi_categories()
    }

    # Deterministic recognizer triggers.
    # A recognizer finding always emits for its mapped categories; the
    # severity tier drives the trigger score.
    for finding in deterministic_result.findings:
        categories = asi_tags_for_recognizer(finding.rule_name)
        if not categories:
            continue
        score = _SEVERITY_TO_SCORE.get(finding.severity, 0.0)
        excerpt = finding.matched_text or finding.message
        trigger = ASITrigger(
            source=ASITriggerSource.DETERMINISTIC_RECOGNIZER,
            signal_name=finding.rule_name,
            score=score,
            evidence_excerpt=excerpt,
        )
        for category in categories:
            triggers_by_category[category].append(trigger)

    # Specialist triggers.
    for specialist_result in specialist_bundle.results:
        categories = asi_tags_for_specialist(
            specialist_result.specialist_name,
            risk_score=specialist_result.risk_score,
        )
        if not categories:
            continue

        excerpt: str | None = None
        if specialist_result.evidence:
            excerpt = specialist_result.evidence[0].text

        trigger = ASITrigger(
            source=ASITriggerSource.SPECIALIST,
            signal_name=specialist_result.specialist_name,
            score=specialist_result.risk_score,
            evidence_excerpt=excerpt,
        )
        for category in categories:
            triggers_by_category[category].append(trigger)

    # Semantic dimension triggers.
    for dimension_result in semantic_analysis.dimension_results:
        categories = asi_tags_for_semantic_dimension(
            dimension_result.dimension,
            score=dimension_result.score,
        )
        if not categories:
            continue

        excerpt: str | None = None
        if dimension_result.evidence_spans:
            excerpt = dimension_result.evidence_spans[0].text

        trigger = ASITrigger(
            source=ASITriggerSource.SEMANTIC_DIMENSION,
            signal_name=dimension_result.dimension,
            score=dimension_result.score,
            evidence_excerpt=excerpt,
        )
        for category in categories:
            triggers_by_category[category].append(trigger)

    # Aggregate into findings in canonical ASI ordering so the output
    # is deterministic for the determinism fingerprint.
    findings: list[ASIFinding] = []
    for category in all_asi_categories():
        triggers = tuple(triggers_by_category[category])
        if not triggers:
            continue

        metadata = require_asi_metadata(category)

        severity = max(trigger.score for trigger in triggers)
        confidence = _compute_confidence(triggers)
        influence = _classify_influence(
            triggers=triggers,
            deterministic_blocked=deterministic_result.blocked,
            semantic_dominance_override_fired=semantic_dominance_override_fired,
        )
        counterfactual = _build_counterfactual(
            metadata_title=metadata.title,
            triggers=triggers,
        )

        findings.append(
            ASIFinding(
                category=metadata.category,
                short_code=metadata.short_code,
                title=metadata.title,
                description=metadata.description,
                severity=round(severity, 4),
                confidence=round(confidence, 4),
                verdict_influence=influence,
                triggered_by=triggers,
                counterfactual=counterfactual,
            )
        )

    return tuple(findings)


def _compute_confidence(triggers: tuple[ASITrigger, ...]) -> float:
    """
    Confidence that a category truly fired.

    Composed of:
    - a base from the max trigger score
    - a source-diversity bonus (independent layers corroborating)
    - a trigger-count bonus (multiple signals in the same layer)

    Capped at 1.0.
    """
    if not triggers:
        return 0.0

    max_score = max(trigger.score for trigger in triggers)

    unique_sources = {trigger.source for trigger in triggers}
    diversity_bonus = 0.0
    if len(unique_sources) >= 2:
        diversity_bonus = 0.12
    if len(unique_sources) >= 3:
        diversity_bonus = 0.20

    count_bonus = 0.0
    if len(triggers) >= 2:
        count_bonus = 0.04
    if len(triggers) >= 4:
        count_bonus = 0.08

    return min(1.0, max(0.0, max_score + diversity_bonus + count_bonus))


def _classify_influence(
    *,
    triggers: tuple[ASITrigger, ...],
    deterministic_blocked: bool,
    semantic_dominance_override_fired: bool,
) -> ASIVerdictInfluence:
    """
    Decide how much this category influenced the verdict.

    DECISIVE cases:
    - a deterministic CRITICAL trigger exists for this category and the
      gate blocked
    - the semantic-dominance override fired and a semantic trigger on
      this category carries a score at or above _DECISIVE_TRIGGER_SCORE

    CONTRIBUTING cases:
    - any trigger on this category meets _STRONG_TRIGGER_SCORE

    INFORMATIONAL otherwise.
    """
    max_score = max(trigger.score for trigger in triggers)

    has_deterministic_critical = any(
        trigger.source is ASITriggerSource.DETERMINISTIC_RECOGNIZER
        and trigger.score >= _SEVERITY_TO_SCORE[Severity.CRITICAL]
        for trigger in triggers
    )
    if deterministic_blocked and has_deterministic_critical:
        return ASIVerdictInfluence.DECISIVE

    if semantic_dominance_override_fired:
        has_strong_semantic = any(
            trigger.source is ASITriggerSource.SEMANTIC_DIMENSION
            and trigger.score >= _DECISIVE_TRIGGER_SCORE
            for trigger in triggers
        )
        if has_strong_semantic:
            return ASIVerdictInfluence.DECISIVE

    if max_score >= _STRONG_TRIGGER_SCORE:
        return ASIVerdictInfluence.CONTRIBUTING

    return ASIVerdictInfluence.INFORMATIONAL


def _build_counterfactual(
    *,
    metadata_title: str,
    triggers: tuple[ASITrigger, ...],
) -> str:
    """
    Build a one-line counterfactual for the finding.

    Shape: "Fired because <top-signal-description>. Would not have
    fired without <top-signal-name>."
    """
    top = max(triggers, key=lambda trigger: trigger.score)

    source_label = {
        ASITriggerSource.SEMANTIC_DIMENSION: "semantic dimension",
        ASITriggerSource.DETERMINISTIC_RECOGNIZER: "deterministic recognizer",
        ASITriggerSource.SPECIALIST: "specialist judge",
    }[top.source]

    fired_because = (
        f"Fired because {source_label} '{top.signal_name}' scored "
        f"{top.score:.2f}"
    )
    if top.evidence_excerpt:
        excerpt = top.evidence_excerpt.strip()
        # Trim to keep the counterfactual under the model length bound.
        max_excerpt_length = 200
        if len(excerpt) > max_excerpt_length:
            excerpt = excerpt[: max_excerpt_length - 1].rstrip() + "…"
        fired_because += f" on evidence: \"{excerpt}\""
    fired_because += "."

    would_not = (
        f" Would not have fired on this request without the "
        f"{source_label} '{top.signal_name}' signal for "
        f"{metadata_title}."
    )

    return fired_because + would_not


__all__ = [
    "build_asi_findings",
]
