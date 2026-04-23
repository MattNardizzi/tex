"""
OWASP Top 10 for Agentic Applications 2026 (ASI) mapping.

This module maps Tex's internal signals (semantic dimensions, specialist
names, deterministic recognizers) to the ten ASI risk categories
published by the OWASP GenAI Security Project in December 2025. It
exists so Tex's verdicts can be labeled with the specific agentic risk
they address, which is the vocabulary auditors, buyers, and integrators
now use.

The mapping is intentionally conservative. It only emits a tag when the
signal is directly interpretable as that risk. It does not try to infer
ASI categories from weak co-occurrences.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

from typing import Final


ASI_GOAL_HIJACK: Final[str] = "ASI01_goal_hijack"
ASI_TOOL_MISUSE: Final[str] = "ASI02_tool_misuse"
ASI_IDENTITY_ABUSE: Final[str] = "ASI03_identity_and_privilege_abuse"
ASI_SUPPLY_CHAIN: Final[str] = "ASI04_agentic_supply_chain"
ASI_UNEXPECTED_CODE_EXECUTION: Final[str] = "ASI05_unexpected_code_execution"
ASI_MEMORY_POISONING: Final[str] = "ASI06_memory_poisoning"
ASI_INSECURE_INTER_AGENT_COMM: Final[str] = "ASI07_insecure_inter_agent_communication"
ASI_CASCADING_FAILURE: Final[str] = "ASI08_cascading_failure"
ASI_HUMAN_TRUST_EXPLOIT: Final[str] = "ASI09_human_agent_trust_exploitation"
ASI_ROGUE_AGENT: Final[str] = "ASI10_rogue_agent"


class ASICategoryMetadata:
    """Immutable descriptor for a single ASI category."""

    __slots__ = ("category", "short_code", "title", "description")

    def __init__(
        self,
        *,
        category: str,
        short_code: str,
        title: str,
        description: str,
    ) -> None:
        self.category = category
        self.short_code = short_code
        self.title = title
        self.description = description


_ASI_METADATA: Final[dict[str, ASICategoryMetadata]] = {
    ASI_GOAL_HIJACK: ASICategoryMetadata(
        category=ASI_GOAL_HIJACK,
        short_code="ASI01",
        title="Goal Hijack",
        description=(
            "Agent content is redirected toward objectives the operator "
            "did not authorize, including policy violations and "
            "instruction-planted redirection."
        ),
    ),
    ASI_TOOL_MISUSE: ASICategoryMetadata(
        category=ASI_TOOL_MISUSE,
        short_code="ASI02",
        title="Tool Misuse",
        description=(
            "Agent invokes tools or takes binding actions outside its "
            "authorized scope, including exfiltration, financial "
            "commitments, and destructive operations."
        ),
    ),
    ASI_IDENTITY_ABUSE: ASICategoryMetadata(
        category=ASI_IDENTITY_ABUSE,
        short_code="ASI03",
        title="Identity and Privilege Abuse",
        description=(
            "Agent content exposes, escalates, or misuses identity, "
            "credentials, tokens, or entitlements in ways that expand "
            "effective privilege beyond intent."
        ),
    ),
    ASI_SUPPLY_CHAIN: ASICategoryMetadata(
        category=ASI_SUPPLY_CHAIN,
        short_code="ASI04",
        title="Agentic Supply Chain",
        description=(
            "Compromise enters through upstream components, datasets, "
            "model artifacts, or third-party tool integrations in the "
            "agent's supply chain."
        ),
    ),
    ASI_UNEXPECTED_CODE_EXECUTION: ASICategoryMetadata(
        category=ASI_UNEXPECTED_CODE_EXECUTION,
        short_code="ASI05",
        title="Unexpected Code Execution",
        description=(
            "Agent emits, requests, or facilitates code that executes in "
            "unintended contexts with unintended privileges."
        ),
    ),
    ASI_MEMORY_POISONING: ASICategoryMetadata(
        category=ASI_MEMORY_POISONING,
        short_code="ASI06",
        title="Memory Poisoning",
        description=(
            "Agent content embeds directives designed to shape the "
            "behavior of future sessions, retrieved memory, or "
            "downstream agent context."
        ),
    ),
    ASI_INSECURE_INTER_AGENT_COMM: ASICategoryMetadata(
        category=ASI_INSECURE_INTER_AGENT_COMM,
        short_code="ASI07",
        title="Insecure Inter-Agent Communication",
        description=(
            "Agent-to-agent messages lack integrity, authenticity, or "
            "scoping protections, enabling trust-chain abuse between "
            "agents."
        ),
    ),
    ASI_CASCADING_FAILURE: ASICategoryMetadata(
        category=ASI_CASCADING_FAILURE,
        short_code="ASI08",
        title="Cascading Failure",
        description=(
            "One agent's failure, hallucination, or misstep propagates "
            "through downstream agents, workflows, or automated systems."
        ),
    ),
    ASI_HUMAN_TRUST_EXPLOIT: ASICategoryMetadata(
        category=ASI_HUMAN_TRUST_EXPLOIT,
        short_code="ASI09",
        title="Human-Agent Trust Exploitation",
        description=(
            "Agent content falsely invokes authority, urgency, or "
            "institutional legitimacy to bypass recipient scrutiny. "
            "Classic business-email-compromise and social-engineering "
            "vectors live here."
        ),
    ),
    ASI_ROGUE_AGENT: ASICategoryMetadata(
        category=ASI_ROGUE_AGENT,
        short_code="ASI10",
        title="Rogue Agent",
        description=(
            "Agent behaves in ways that indicate it is attempting to "
            "bypass controls, disable monitoring, or otherwise operate "
            "outside the governance boundary it was assigned."
        ),
    ),
}


def get_asi_metadata(category: str) -> ASICategoryMetadata | None:
    """Return the OWASP metadata for an ASI category, or None if unknown."""
    return _ASI_METADATA.get(category)


def require_asi_metadata(category: str) -> ASICategoryMetadata:
    """Return the OWASP metadata for an ASI category or raise KeyError."""
    metadata = _ASI_METADATA.get(category)
    if metadata is None:
        raise KeyError(f"unknown ASI category: {category}")
    return metadata


_SEMANTIC_DIMENSION_TO_ASI: Final[dict[str, tuple[str, ...]]] = {
    "policy_compliance": (ASI_GOAL_HIJACK, ASI_HUMAN_TRUST_EXPLOIT),
    "data_leakage": (ASI_GOAL_HIJACK, ASI_IDENTITY_ABUSE),
    "external_sharing": (ASI_TOOL_MISUSE, ASI_IDENTITY_ABUSE),
    "unauthorized_commitment": (ASI_TOOL_MISUSE, ASI_HUMAN_TRUST_EXPLOIT),
    "destructive_or_bypass": (ASI_TOOL_MISUSE, ASI_ROGUE_AGENT),
}


_RECOGNIZER_TO_ASI: Final[dict[str, tuple[str, ...]]] = {
    "blocked_terms": (ASI_GOAL_HIJACK,),
    "sensitive_entities": (ASI_GOAL_HIJACK, ASI_IDENTITY_ABUSE),
    "secret_leak": (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
    "pii": (ASI_TOOL_MISUSE, ASI_HUMAN_TRUST_EXPLOIT),
    "unauthorized_commitment": (ASI_TOOL_MISUSE, ASI_HUMAN_TRUST_EXPLOIT),
    "monetary_transfer": (ASI_TOOL_MISUSE, ASI_HUMAN_TRUST_EXPLOIT),
    "external_sharing": (ASI_TOOL_MISUSE, ASI_IDENTITY_ABUSE),
    "destructive_or_bypass": (ASI_TOOL_MISUSE, ASI_ROGUE_AGENT),
    "urgency_pressure": (ASI_HUMAN_TRUST_EXPLOIT, ASI_GOAL_HIJACK),
    "memory_instruction": (ASI_MEMORY_POISONING, ASI_GOAL_HIJACK),
    "authority_impersonation": (ASI_HUMAN_TRUST_EXPLOIT, ASI_GOAL_HIJACK),
}


_SPECIALIST_TO_ASI: Final[dict[str, tuple[str, ...]]] = {
    "secret_and_pii": (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
    "external_sharing": (ASI_TOOL_MISUSE, ASI_IDENTITY_ABUSE),
    "unauthorized_commitment": (ASI_TOOL_MISUSE, ASI_HUMAN_TRUST_EXPLOIT),
    "destructive_or_bypass": (ASI_TOOL_MISUSE, ASI_ROGUE_AGENT),
}


SEMANTIC_DIMENSION_MIN_SCORE: Final[float] = 0.55
SPECIALIST_MIN_RISK_SCORE: Final[float] = 0.35


def asi_tags_for_semantic_dimension(
    dimension_name: str,
    *,
    score: float,
    min_score: float = SEMANTIC_DIMENSION_MIN_SCORE,
) -> tuple[str, ...]:
    """Return ASI tags for a semantic dimension that scored above min_score."""
    if score < min_score:
        return tuple()
    return _SEMANTIC_DIMENSION_TO_ASI.get(dimension_name, tuple())


def asi_tags_for_recognizer(recognizer_name: str) -> tuple[str, ...]:
    """Return ASI tags for a deterministic recognizer by name."""
    return _RECOGNIZER_TO_ASI.get(recognizer_name, tuple())


def asi_tags_for_specialist(
    specialist_name: str,
    *,
    risk_score: float,
    min_risk_score: float = SPECIALIST_MIN_RISK_SCORE,
) -> tuple[str, ...]:
    """Return ASI tags for a specialist whose risk_score crossed min_risk_score."""
    if risk_score < min_risk_score:
        return tuple()
    return _SPECIALIST_TO_ASI.get(specialist_name, tuple())


def dedupe_asi_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    """Deduplicate ASI tags while preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        ordered.append(tag)
    return tuple(ordered)


def all_asi_categories() -> tuple[str, ...]:
    """Return the canonical ten ASI category identifiers in order."""
    return (
        ASI_GOAL_HIJACK,
        ASI_TOOL_MISUSE,
        ASI_IDENTITY_ABUSE,
        ASI_SUPPLY_CHAIN,
        ASI_UNEXPECTED_CODE_EXECUTION,
        ASI_MEMORY_POISONING,
        ASI_INSECURE_INTER_AGENT_COMM,
        ASI_CASCADING_FAILURE,
        ASI_HUMAN_TRUST_EXPLOIT,
        ASI_ROGUE_AGENT,
    )
