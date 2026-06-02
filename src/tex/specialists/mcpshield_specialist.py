"""
MCPShield Specialist Judge.

Wraps MCPShield's formal verification framework (LTS + four security
properties) as a specialist judge. Targets the MCP-specific attack
surfaces enumerated in the canonical MCP security literature.

Reference
---------
- arxiv 2604.05969v1 (MCPShield: Acharya & Gupta, 7 Apr 2026)

  Unified MCP threat taxonomy: 7 threat categories, 23 attack vectors,
  4 attack surfaces (client / protocol / server / host). Labeled
  transition system MMCP with trust-boundary annotations.

  Four fundamental security properties:
    P1. Tool Integrity        — hash of tool definition at invocation
                                matches the registry-approved hash.
    P2. Data Confinement      — sensitive labels never reach unauthorized
                                trust domains.
    P3. Privilege Boundedness — agent effective caps ⊆ tool declared caps
                                ∩ agent caps at state.
    P4. Context Isolation     — cross-domain knowledge transfer requires
                                explicit authorized cross_domain action.

- arxiv 2512.15163 (MCP-SafetyBench, v2 5 Mar 2026) — 20 attack types,
  five domains. ASR ranges 29.80% (Qwen3-235B) to 48.16% (o4-mini) across
  current frontier LLMs.

- arxiv 2508.13220 (MCPSecBench) — 17 attack types, 4 attack surfaces.
  85%+ of identified attacks compromise at least one MCP platform.

- arxiv 2603.18063 (MCP-38) — comprehensive threat taxonomy for MCP
  systems mapping to STRIDE, OWASP LLM Top 10 2025, and OWASP Agentic
  Top 10 2026.

This specialist surfaces:
  - The four MCPShield property classes (P1-P4) as reason codes.
  - The 20 MCP-SafetyBench attack types collapsed to the MCPShield 4
    attack surfaces.
  - Optional dispatch to the wrapped LTS verifier when metadata carries
    a constructed LtsModel.

Priority
--------
P0 — deterministic short-circuit class when LTS verifier returns a
property violation (similar to ClawGuard boundary DENY). Lexical
patterns are voting.
"""

from __future__ import annotations

import re
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_CASCADING_FAILURE,
    ASI_GOAL_HIJACK,
    ASI_IDENTITY_ABUSE,
    ASI_INSECURE_INTER_AGENT_COMM,
    ASI_MEMORY_POISONING,
    ASI_ROGUE_AGENT,
    ASI_SUPPLY_CHAIN,
    ASI_TOOL_MISUSE,
    ASI_UNEXPECTED_CODE_EXECUTION,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.runtime.mcpshield.lts_model import LtsModel
from tex.runtime.mcpshield.verifier import verify_property
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── P1 Tool Integrity — signature/hash drift, tool rug-pull, swap ────────
# Tool integrity violations cover the "rug pull" attack (silent tool
# definition change post-approval), tool spoofing, and definition-hash
# mismatch at invocation.

_TOOL_INTEGRITY_PATTERNS: tuple[str, ...] = (
    "tool definition changed",
    "tool was updated silently",
    "rug pull",
    "tool name spoofing",
    "duplicate tool name",
    "tool hash mismatch",
    "tool signature drift",
    "approved tool replaced",
    "swap tool implementation",
    "shadow tool registration",
)

# ── P2 Data Confinement — exfiltration, cross-domain data leak ───────────

_DATA_CONFINEMENT_PATTERNS: tuple[str, ...] = (
    "exfiltrate secret",
    "exfiltrate credential",
    "exfiltrate api key",
    "leak to external server",
    "send secret to untrusted",
    "cross-domain leak",
    "untrusted domain receives secret",
    "label downgrade for secret",
    "declassify without authorization",
    "post-hoc data downgrade",
    "leak across trust boundary",
)

# ── P3 Privilege Boundedness — capability escalation, privilege creep ────

_PRIVILEGE_VIOLATION_PATTERNS: tuple[str, ...] = (
    "elevate privileges",
    "escalate to admin",
    "sudo without authorization",
    "request elevated capabilities",
    "expand tool capabilities",
    "grant additional permissions",
    "exceed approved scope",
    "bypass capability check",
    "agent capability override",
    "privilege escalation chain",
    "post-invocation capability grant",
    # Real attack-payload shape
    "required scope: admin",
    "scope: admin:write",
    "approve without further review",
    "compatibility shim for new mcp",
    "capability_request",
    "elevated permissions on first run",
)

# ── P4 Context Isolation — context bleed, memory contamination ───────────

_CONTEXT_ISOLATION_PATTERNS: tuple[str, ...] = (
    "context bleed",
    "context leak between sessions",
    "tenant isolation breach",
    "cross-tenant data flow",
    "cross-session memory access",
    "cross-customer leak",
    "context confusion attack",
    "unauthorized cross-domain action",
    "trust domain confusion",
    "implicit cross-domain transfer",
    # Real attack-payload shape (customer A + customer B in same response)
    "without checking tenant isolation",
    "customer a includes data from customer b",
    "data from customer b in the same payload",
    "return both records to the requester",
)

# ── MCP-specific protocol patterns (MCP-SafetyBench 20 attack types) ─────
# These are the lexical fingerprints of the attack categories
# enumerated across MCP-SafetyBench, MCPSecBench, and MCP-38.

_MCP_PROTOCOL_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "MCP_TOOL_POISONING",
        "tool poisoning",
        (
            "tool poisoning",
            "poisoned tool description",
            "tool description override",
            "hidden instruction in description",
            "tool description injection",
        ),
    ),
    (
        "MCP_TOOL_DESCRIPTION_INJECTION",
        "tool description prompt injection",
        (
            "tool description prompt injection",
            "tool description prompt:",
            "tool descr inject",
        ),
    ),
    (
        "MCP_PARASITIC_TOOL_CHAIN",
        "parasitic tool chaining",
        (
            "parasitic tool chain",
            "host parasitic invocation",
            "parasitic mcp call",
        ),
    ),
    (
        "MCP_INTENT_INJECTION",
        "intent injection at planning",
        (
            "intent injection",
            "modify host intent",
            "host intent override",
        ),
    ),
    (
        "MCP_DATA_TAMPERING",
        "tool output tampering",
        (
            "tamper tool output",
            "falsify tool response",
            "modify mcp response",
            "spoof api response",
        ),
    ),
    (
        "MCP_IDENTITY_SPOOFING",
        "host identity spoofing",
        (
            "spoof mcp identity",
            "forge mcp client id",
            "fake server certificate",
            "mcp host identity spoof",
        ),
    ),
    (
        "MCP_DYNAMIC_TRUST_VIOLATION",
        "dynamic trust boundary violation",
        (
            "dynamic trust violation",
            "trust elevation mid-session",
            "mid-session privilege grant",
        ),
    ),
    (
        "MCP_SUPPLY_CHAIN",
        "MCP supply chain compromise",
        (
            "malicious mcp server",
            "mcp supply chain compromise",
            "unverified mcp publisher",
            "unsigned mcp tool",
            # Additions for real attack payload shape
            "unverified-pub",
            "package is unsigned",
            "publisher claims compatibility",
            "install mcp-server",
            "grant elevated permissions on first run",
        ),
    ),
)


# ── Scoring constants ────────────────────────────────────────────────────

_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.42
_CONF_PER_HIT = 0.07
_CONF_CAP = 0.88

# Severity weights.
_SEV_TOOL_INTEGRITY = 0.34
_SEV_DATA_CONFINEMENT = 0.38
_SEV_PRIVILEGE = 0.34
_SEV_CONTEXT_ISOLATION = 0.30
_SEV_MCP_PROTOCOL = 0.28
_SEV_PROPERTY_VIOLATION = 1.00  # short-circuit on formal verifier output


# Maps from MCPShield property name to reason code + ASI tags.
_PROPERTY_TO_REASON: dict[str, tuple[str, tuple[str, ...]]] = {
    "tool_integrity": (
        "MCPSHIELD_P1_TOOL_INTEGRITY_VIOLATION",
        (ASI_TOOL_MISUSE, ASI_SUPPLY_CHAIN),
    ),
    "data_confinement": (
        "MCPSHIELD_P2_DATA_CONFINEMENT_VIOLATION",
        (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
    ),
    "privilege_boundedness": (
        "MCPSHIELD_P3_PRIVILEGE_VIOLATION",
        (ASI_IDENTITY_ABUSE, ASI_ROGUE_AGENT),
    ),
    "context_isolation": (
        "MCPSHIELD_P4_CONTEXT_ISOLATION_VIOLATION",
        (ASI_INSECURE_INTER_AGENT_COMM, ASI_MEMORY_POISONING),
    ),
}


class McpShieldSpecialist:
    """
    Specialist wrapping MCPShield's formal verification framework.

    Two paths:
      1. Lexical scan over content for the 4 MCPShield property
         violation classes plus the 8 MCP-specific protocol attack
         categories from MCP-SafetyBench / MCPSecBench / MCP-38.

      2. Optional formal verification dispatch: when metadata carries
         ``metadata['mcpshield']['lts_model']`` (a constructed LtsModel),
         the specialist runs ``verify_property`` against each of the
         four MCPShield properties. Any failure short-circuits risk
         to 1.0 with a paper-faithful counterexample path in the
         evidence explanation.
    """

    name = "mcpshield"

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        content = request.content
        lowered = content.casefold()

        all_evidence: list[SpecialistEvidence] = []
        reason_codes: list[str] = []
        asi_tags: list[str] = []
        risk_accum = 0.0
        short_circuited = False

        # 1. Four MCPShield property classes by lexical pattern.
        for code, patterns, weight, asi in (
            (
                "MCPSHIELD_P1_TOOL_INTEGRITY_SIGNAL",
                _TOOL_INTEGRITY_PATTERNS,
                _SEV_TOOL_INTEGRITY,
                (ASI_TOOL_MISUSE, ASI_SUPPLY_CHAIN),
            ),
            (
                "MCPSHIELD_P2_DATA_CONFINEMENT_SIGNAL",
                _DATA_CONFINEMENT_PATTERNS,
                _SEV_DATA_CONFINEMENT,
                (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
            ),
            (
                "MCPSHIELD_P3_PRIVILEGE_SIGNAL",
                _PRIVILEGE_VIOLATION_PATTERNS,
                _SEV_PRIVILEGE,
                (ASI_IDENTITY_ABUSE, ASI_ROGUE_AGENT),
            ),
            (
                "MCPSHIELD_P4_CONTEXT_ISOLATION_SIGNAL",
                _CONTEXT_ISOLATION_PATTERNS,
                _SEV_CONTEXT_ISOLATION,
                (ASI_INSECURE_INTER_AGENT_COMM, ASI_MEMORY_POISONING, ASI_CASCADING_FAILURE),
            ),
        ):
            matched = _match_pattern_set(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=code,
            )
            if matched:
                all_evidence.extend(matched)
                reason_codes.append(code)
                risk_accum += weight
                for tag in asi:
                    if tag not in asi_tags:
                        asi_tags.append(tag)

        # 2. MCP-specific protocol attacks.
        for code, _label, patterns in _MCP_PROTOCOL_PATTERNS:
            matched = _match_pattern_set(
                content=content,
                lowered_content=lowered,
                keywords=patterns,
                reason_code=code,
            )
            if matched:
                all_evidence.extend(matched)
                reason_codes.append(code)
                risk_accum += _SEV_MCP_PROTOCOL
                for tag in (ASI_TOOL_MISUSE, ASI_SUPPLY_CHAIN):
                    if tag not in asi_tags:
                        asi_tags.append(tag)

        # 3. Formal verification dispatch.
        verifier_outcomes = _try_verifier_dispatch(metadata=request.metadata)
        for property_name, ok, counterexample in verifier_outcomes:
            if not ok:
                reason_code, asi = _PROPERTY_TO_REASON.get(
                    property_name,
                    ("MCPSHIELD_UNKNOWN_PROPERTY_VIOLATION", (ASI_TOOL_MISUSE,)),
                )
                counter_text = " → ".join(counterexample) if counterexample else "no counterexample path"
                all_evidence.append(
                    SpecialistEvidence(
                        text=f"property:{property_name}",
                        explanation=(
                            f"{reason_code}: LTS verifier rejected the "
                            f"agent model — counterexample: {counter_text[:1500]}"
                        ),
                    )
                )
                reason_codes.append(reason_code)
                risk_accum = _SEV_PROPERTY_VIOLATION  # short-circuit
                short_circuited = True
                for tag in asi:
                    if tag not in asi_tags:
                        asi_tags.append(tag)
                # Extra ASI05 when tool integrity is violated and the
                # counterexample names exec/shell/code paths.
                if property_name == "tool_integrity" and any(
                    x in counter_text.lower() for x in ("exec", "shell", "code")
                ):
                    if ASI_UNEXPECTED_CODE_EXECUTION not in asi_tags:
                        asi_tags.append(ASI_UNEXPECTED_CODE_EXECUTION)

        if not reason_codes:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary="No MCPShield formal-verification signals detected.",
                rationale=(
                    "Specialist scans for the four MCPShield property "
                    "classes (tool integrity, data confinement, "
                    "privilege boundedness, context isolation) per arxiv "
                    "2604.05969 + the 8 MCP-protocol attack categories "
                    "from MCP-SafetyBench (arxiv 2512.15163) and "
                    "MCPSecBench (arxiv 2508.13220). No signals matched."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        risk_score = min(1.0, risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(all_evidence))

        all_evidence.sort(
            key=lambda ev: (
                ev.start_index if ev.start_index is not None else 10**9,
                ev.text.casefold(),
            )
        )
        deduped_codes = _dedupe_preserve_order(reason_codes)
        deduped_asi = _dedupe_preserve_order(asi_tags)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            reason_codes=tuple(deduped_codes),
        )

        if short_circuited:
            summary = (
                f"MCPShield formal-verification FAILURE on property "
                f"{len(deduped_codes)} class(es) — short-circuited to "
                f"deterministic FORBID."
            )
        else:
            summary = (
                f"MCPShield signals detected: {len(deduped_codes)} reason "
                f"code(s) — {', '.join(deduped_codes)}."
            )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Per arxiv 2604.05969 §IV, MCPShield formalizes MCP "
                "agent systems as labeled transition systems with trust-"
                "boundary annotations and verifies four security "
                "properties. This specialist surfaces lexical signals "
                "for each property class plus 8 MCP-specific protocol "
                "attack categories, and dispatches to the formal LTS "
                "verifier when a model is supplied in metadata."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple([*deduped_codes, *deduped_asi]),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _try_verifier_dispatch(
    *, metadata: dict[str, Any]
) -> list[tuple[str, bool, tuple[str, ...]]]:
    """
    Dispatch to verify_property when caller supplies an LtsModel.

    Expected metadata shape:
        metadata['mcpshield'] = {
            'lts_model': LtsModel,
            'properties': ('tool_integrity', 'data_confinement', ...),  # optional
        }

    When 'properties' is omitted, all four are checked.
    """
    out: list[tuple[str, bool, tuple[str, ...]]] = []
    ms = metadata.get("mcpshield")
    if not isinstance(ms, dict):
        return out
    model = ms.get("lts_model")
    if not isinstance(model, LtsModel):
        return out
    properties = ms.get("properties") or (
        "tool_integrity",
        "data_confinement",
        "privilege_boundedness",
        "context_isolation",
    )
    if isinstance(properties, str):
        properties = (properties,)
    for property_name in properties:
        try:
            ok, counter = verify_property(model, property_ltl=property_name)
        except (ValueError, Exception):  # noqa: BLE001
            # Unknown property or verifier exception → treat as
            # verification failure (fail-closed).
            ok, counter = False, ("verifier_exception",)
        out.append((property_name, ok, tuple(counter or ())))
    return out


def _match_pattern_set(
    *,
    content: str,
    lowered_content: str,
    keywords: tuple[str, ...],
    reason_code: str,
) -> tuple[SpecialistEvidence, ...]:
    out: list[SpecialistEvidence] = []
    seen: set[tuple[int, int, str]] = set()
    for keyword in keywords:
        lowered_kw = keyword.casefold()
        if not lowered_kw:
            continue
        start = 0
        while True:
            found_at = lowered_content.find(lowered_kw, start)
            if found_at == -1:
                break
            end = found_at + len(lowered_kw)
            key = (found_at, end, lowered_kw)
            if key not in seen:
                seen.add(key)
                out.append(
                    SpecialistEvidence(
                        text=content[found_at:end],
                        start_index=found_at,
                        end_index=end,
                        explanation=f"{reason_code}: matched pattern '{keyword}'",
                    )
                )
            start = end
    return tuple(out)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _emit(*, request_id: str, risk_score: float, reason_codes: tuple[str, ...]) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "mcpshield",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
    }
    emit_event("specialist.mcpshield.evaluated", **fields)


__all__ = ["McpShieldSpecialist"]
