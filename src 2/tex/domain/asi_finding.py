"""
OWASP Top 10 for Agentic Applications (ASI) structured findings.

This module replaces opaque ASI string tags with structured, evidence-
linked, verdict-influence-weighted findings. Every ASI category that
fires on a request becomes one first-class ``ASIFinding`` on the
response, carrying the canonical taxonomy code, severity, confidence,
verdict-influence classification, triggering signals, and a
counterfactual explanation.

Non-responsibilities:
- This module does not execute detection. That is owned by the
  deterministic gate, specialist suite, and semantic analyzer.
- This module does not decide final verdicts. That is owned by the
  router.
- This module does not persist findings. That is owned by Decision
  and the evidence recorder.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ASITriggerSource(str, Enum):
    """Where a signal that triggered an ASI finding came from."""

    SEMANTIC_DIMENSION = "semantic_dimension"
    DETERMINISTIC_RECOGNIZER = "deterministic_recognizer"
    SPECIALIST = "specialist"


class ASIVerdictInfluence(str, Enum):
    """
    How much a specific ASI category influenced the final verdict.

    - DECISIVE: this category alone would have moved the verdict
      (e.g. a deterministic CRITICAL block, or the semantic-dominance
      override firing on this category's semantic trigger).
    - CONTRIBUTING: this category's signal crossed its emit threshold
      and fed the fused risk score.
    - INFORMATIONAL: this category fired at a low-score level that
      did not meaningfully affect the fused outcome. Surfaced for
      completeness and audit trail.
    """

    DECISIVE = "decisive"
    CONTRIBUTING = "contributing"
    INFORMATIONAL = "informational"


class ASITrigger(BaseModel):
    """One concrete signal that contributed to an ASI finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: ASITriggerSource = Field(
        description="The Tex layer that produced the triggering signal.",
    )
    signal_name: str = Field(
        min_length=1,
        max_length=150,
        description=(
            "Name of the upstream signal. Semantic dimension name for "
            "SEMANTIC_DIMENSION, rule name for DETERMINISTIC_RECOGNIZER, "
            "specialist name for SPECIALIST."
        ),
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Severity of the triggering signal, normalized to [0.0, 1.0]. "
            "Deterministic findings are mapped from severity tiers."
        ),
    )
    evidence_excerpt: str | None = Field(
        default=None,
        max_length=2_000,
        description=(
            "Short excerpt of the content that fired the signal, when "
            "available. Not every upstream signal carries an excerpt."
        ),
    )

    @field_validator("signal_name", mode="before")
    @classmethod
    def _strip_signal_name(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise TypeError("signal_name must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("signal_name must not be blank")
        return normalized

    @field_validator("evidence_excerpt", mode="before")
    @classmethod
    def _strip_evidence_excerpt(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("evidence_excerpt must be a string")
        normalized = value.strip()
        return normalized or None


class ASIFinding(BaseModel):
    """
    One OWASP ASI 2026 category that fired for a single evaluation.

    Aggregates all triggers for the same category into a single
    audit-shaped object. The JSON is designed to read clearly without
    a decoder ring:

        - ``category`` and ``short_code`` locate it in the taxonomy
        - ``title`` and ``description`` explain it in prose
        - ``severity`` states how severe this category got
        - ``confidence`` states Tex's confidence it truly fired
        - ``verdict_influence`` states whether it drove the outcome
        - ``triggered_by`` shows the evidence trail
        - ``counterfactual`` explains what would have prevented it
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: str = Field(
        min_length=1,
        max_length=100,
        description="Canonical ASI category identifier, e.g. 'ASI02_tool_misuse'.",
    )
    short_code: str = Field(
        min_length=5,
        max_length=5,
        pattern=r"^ASI\d{2}$",
        description="Short category code, e.g. 'ASI02'.",
    )
    title: str = Field(
        min_length=1,
        max_length=200,
        description="Human-readable title for the ASI category.",
    )
    description: str = Field(
        min_length=1,
        max_length=1_000,
        description="One-paragraph description of the category.",
    )
    severity: float = Field(
        ge=0.0,
        le=1.0,
        description="Max triggering signal score for this category.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Tex's confidence that this ASI category genuinely fired. "
            "Aggregates trigger count, max score, and source diversity."
        ),
    )
    verdict_influence: ASIVerdictInfluence = Field(
        description="Whether this finding drove, contributed to, or merely accompanied the verdict.",
    )
    triggered_by: tuple[ASITrigger, ...] = Field(
        default_factory=tuple,
        description="Individual signals that fired this category.",
    )
    counterfactual: str | None = Field(
        default=None,
        max_length=600,
        description=(
            "One-line explanation of why this category fired and what "
            "would have prevented it."
        ),
    )

    @field_validator("category", "short_code", "title", "description", mode="before")
    @classmethod
    def _strip_required(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise TypeError("string field must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("string field must not be blank")
        return normalized

    @field_validator("counterfactual", mode="before")
    @classmethod
    def _strip_counterfactual(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("counterfactual must be a string")
        normalized = value.strip()
        return normalized or None

    @property
    def is_decisive(self) -> bool:
        return self.verdict_influence is ASIVerdictInfluence.DECISIVE

    @property
    def trigger_sources(self) -> tuple[ASITriggerSource, ...]:
        seen: set[ASITriggerSource] = set()
        ordered: list[ASITriggerSource] = []
        for trigger in self.triggered_by:
            if trigger.source in seen:
                continue
            seen.add(trigger.source)
            ordered.append(trigger.source)
        return tuple(ordered)
