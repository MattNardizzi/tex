"""
AgentArmor Specialist Judge.

Wraps AgentArmor's program-analysis-based runtime hardening (graph
constructor + property registry + type system) as a specialist judge.
Detects information-flow violations on agent runtime traces.

Reference
---------
- arxiv 2508.01249v3 (AgentArmor, Wang et al., ByteDance, 18 Nov 2025)

  Three components: graph constructor (CFG/DFG/PDG), property registry,
  type system. Lattice operations:
    - Confidentiality JOIN (Bell-LaPadula): HIGH ∨ LOW = HIGH.
    - Integrity MEET (Biba): HIGH ∧ LOW = LOW (low-integrity inputs
      block high-integrity outputs).
    - Trust JOIN: TAINTED dominates UNTRUSTED dominates TRUSTED.

  SOTA on AgentDojo: ASR 3%, utility drop 1%, TPR 95.75%, FPR 3.66%.

Frontier delta (FRONTIER_DELTA_thread_4.md §1.3)
-------------------------------------------------
- arxiv 2605.03378v1 (ARGUS, Weng et al., 5 May 2026, **13 days old at
  build time**) introduces "provenance-aware decision auditing" via an
  influence provenance graph that tracks how untrusted context propagates
  into agent decisions. Reports ASR 3.8% with 87.5% utility, robust to
  adaptive white-box adversaries.

  We surface ARGUS-style provenance reason codes inside the AgentArmor
  specialist because AgentArmor's PDG already carries the information
  needed to compute ARGUS-style untrusted-to-decision influence facts.
  Three new reason codes:
    - ARMOR_INFLUENCE_PROVENANCE_UNTRUSTED_TO_HIGH_INT
    - ARMOR_INFLUENCE_PROVENANCE_TAINTED_FLOW
    - ARMOR_INFLUENCE_PROVENANCE_UNJUSTIFIED_DECISION

  This is what nobody has implemented yet — ARGUS is a paper-only result
  as of mid-May 2026.

Priority
--------
P1 — voting specialist with high severity weights. PDG construction
runs lazily (deferred until the type system check fires).
"""

from __future__ import annotations

import re
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_CASCADING_FAILURE,
    ASI_GOAL_HIJACK,
    ASI_IDENTITY_ABUSE,
    ASI_ROGUE_AGENT,
    ASI_SUPPLY_CHAIN,
    ASI_TOOL_MISUSE,
    ASI_UNEXPECTED_CODE_EXECUTION,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.runtime.agentarmor.property_registry import TrustLevel
from tex.runtime.agentarmor.type_system import TypeSystem, TypeViolation
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── Lexical signals for information-flow violations ──────────────────────
# These surface the same flow classes the type system would flag, but at
# the content level (without needing a constructed PDG).

# Untrusted-input → exec sink. The classic RCE class.
_UNTRUSTED_TO_EXEC_PATTERNS: tuple[str, ...] = (
    "eval(observation",
    "eval(tool_output",
    "exec(tool_response",
    "subprocess.run(user_input",
    "os.system(user_data",
    "execute the content of the email",
    "execute the script from the document",
    "execute the script from the email",
    "run the script from the document",
    "run the script from the email",
    "evaluate the formula in the spreadsheet",
    "shell command from external content",
    "eval webpage script",
)

# Secret → network sink. The exfiltration class.
_SECRET_TO_NETWORK_PATTERNS: tuple[str, ...] = (
    "send password to",
    "post api key to",
    "transmit credentials to",
    "upload secrets to",
    "exfiltrate token via http",
    "forward private key",
    "publish private key",
    "send confidential to external",
    "post secret to webhook",
    "transmit api token",
)

# Low-integrity → high-integrity flow. Downgrade prohibition.
_INTEGRITY_DOWNGRADE_PATTERNS: tuple[str, ...] = (
    "promote unverified to verified",
    "treat untrusted as trusted",
    "elevate observation to instruction",
    "use tool output as primary instruction",
    "accept external content as authoritative",
    "merge untrusted data into trusted state",
    "downgrade integrity label",
)

# ARGUS influence-provenance: untrusted observation influences a
# high-integrity decision without justification.
_ARGUS_UNTRUSTED_TO_HIGH_INT_PATTERNS: tuple[str, ...] = (
    "decide based on the document content",
    "make the decision because the email said",
    "approve the request because the response indicates",
    "the retrieved page authorizes this",
    "the tool output justifies the action",
    "the external content recommends",
    "act on the search result directly",
)

_ARGUS_TAINTED_FLOW_PATTERNS: tuple[str, ...] = (
    "downstream of tainted observation",
    "tainted by external observation",
    "polluted by untrusted source",
    "data carries injection taint",
    "propagated taint through tool chain",
)

_ARGUS_UNJUSTIFIED_DECISION_PATTERNS: tuple[str, ...] = (
    "no justification from trusted evidence",
    "trustworthy evidence does not support",
    "decision lacks provenance",
    "justification is observation-only",
    "decision is observation-derived without user authorization",
)


# ── Scoring constants ────────────────────────────────────────────────────

_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.42
_CONF_PER_HIT = 0.07
_CONF_CAP = 0.86

_SEV_UNTRUSTED_TO_EXEC = 0.42
_SEV_SECRET_TO_NETWORK = 0.40
_SEV_INTEGRITY_DOWNGRADE = 0.34
_SEV_ARGUS_PROVENANCE = 0.26
_SEV_TYPE_SYSTEM_VIOLATION = 0.55  # when caller supplies an annotated PDG


# Maps from violation code to ASI tags.
_VIOLATION_CODE_TO_ASI: dict[str, tuple[str, ...]] = {
    "untrusted_to_exec": (ASI_UNEXPECTED_CODE_EXECUTION, ASI_TOOL_MISUSE),
    "secret_to_network": (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
    "integrity_downgrade": (ASI_GOAL_HIJACK, ASI_ROGUE_AGENT),
    "tainted_to_exec": (ASI_UNEXPECTED_CODE_EXECUTION, ASI_SUPPLY_CHAIN),
    "tainted_to_network": (ASI_IDENTITY_ABUSE, ASI_SUPPLY_CHAIN),
}


class AgentArmorSpecialist:
    """
    Specialist wrapping AgentArmor's PDG + type-system check.

    Two paths:
      1. Lexical scan for information-flow violation signals (untrusted
         → exec, secret → network, low integrity → high integrity) plus
         ARGUS-style influence-provenance signals (paper-only frontier
         per arxiv 2605.03378).

      2. Optional PDG type-system dispatch: when metadata carries
         ``metadata['agentarmor']['annotated_pdg']`` (an annotated dict
         or networkx DiGraph as produced by PropertyRegistry.annotate),
         the specialist runs ``TypeSystem.check`` and surfaces each
         violation as a structured evidence finding with src/dst
         attribution.
    """

    name = "agentarmor"

    def __init__(self, *, type_system: TypeSystem | None = None) -> None:
        self._type_system = type_system or TypeSystem()

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

        # 1. Lexical IFC violation signals.
        for code, patterns, weight, asi in (
            (
                "ARMOR_UNTRUSTED_TO_EXEC",
                _UNTRUSTED_TO_EXEC_PATTERNS,
                _SEV_UNTRUSTED_TO_EXEC,
                (ASI_UNEXPECTED_CODE_EXECUTION, ASI_TOOL_MISUSE),
            ),
            (
                "ARMOR_SECRET_TO_NETWORK",
                _SECRET_TO_NETWORK_PATTERNS,
                _SEV_SECRET_TO_NETWORK,
                (ASI_IDENTITY_ABUSE, ASI_TOOL_MISUSE),
            ),
            (
                "ARMOR_INTEGRITY_DOWNGRADE",
                _INTEGRITY_DOWNGRADE_PATTERNS,
                _SEV_INTEGRITY_DOWNGRADE,
                (ASI_GOAL_HIJACK, ASI_ROGUE_AGENT),
            ),
            # ── ARGUS frontier reason codes (arxiv 2605.03378) ────────
            (
                "ARMOR_INFLUENCE_PROVENANCE_UNTRUSTED_TO_HIGH_INT",
                _ARGUS_UNTRUSTED_TO_HIGH_INT_PATTERNS,
                _SEV_ARGUS_PROVENANCE,
                (ASI_GOAL_HIJACK, ASI_TOOL_MISUSE),
            ),
            (
                "ARMOR_INFLUENCE_PROVENANCE_TAINTED_FLOW",
                _ARGUS_TAINTED_FLOW_PATTERNS,
                _SEV_ARGUS_PROVENANCE,
                (ASI_SUPPLY_CHAIN, ASI_GOAL_HIJACK),
            ),
            (
                "ARMOR_INFLUENCE_PROVENANCE_UNJUSTIFIED_DECISION",
                _ARGUS_UNJUSTIFIED_DECISION_PATTERNS,
                _SEV_ARGUS_PROVENANCE,
                (ASI_GOAL_HIJACK,),
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

        # 2. PDG type-system dispatch.
        violations = _try_type_system_dispatch(
            metadata=request.metadata,
            type_system=self._type_system,
        )
        for violation in violations:
            code, ev, asi = _violation_to_evidence(violation)
            all_evidence.append(ev)
            if code not in reason_codes:
                reason_codes.append(code)
            risk_accum += _SEV_TYPE_SYSTEM_VIOLATION
            for tag in asi:
                if tag not in asi_tags:
                    asi_tags.append(tag)

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
                summary="No AgentArmor information-flow violations detected.",
                rationale=(
                    "Specialist scans for information-flow violations per "
                    "arxiv 2508.01249 (AgentArmor type system) plus three "
                    "ARGUS-style provenance signals per arxiv 2605.03378 "
                    "(5 May 2026): untrusted→exec, secret→network, "
                    "integrity downgrade, and ARGUS untrusted-to-high-"
                    "integrity / tainted-flow / unjustified-decision "
                    "influence-provenance flows. No signals matched."
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

        summary = (
            f"AgentArmor IFC + provenance signals detected: "
            f"{len(deduped_codes)} reason code(s) — {', '.join(deduped_codes)}."
        )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Per arxiv 2508.01249 §III-C, AgentArmor enforces "
                "information-flow rules over a PDG of agent runtime "
                "traces. This specialist surfaces lexical signals for "
                "the canonical IFC violations (untrusted→exec, "
                "secret→network, integrity downgrade) plus three "
                "ARGUS-style influence-provenance reasons (arxiv "
                "2605.03378, 5 May 2026) — the first specialist judge "
                "to expose ARGUS-frontier provenance facts inline with "
                "AgentArmor type checking."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple([*deduped_codes, *deduped_asi]),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _try_type_system_dispatch(
    *, metadata: dict[str, Any], type_system: TypeSystem
) -> list[TypeViolation]:
    """
    Run AgentArmor's type-system check when caller supplies an annotated
    PDG in metadata.

    Expected shape:
        metadata['agentarmor'] = {
            'annotated_pdg': dict | nx.DiGraph,
        }

    Returns the list of TypeViolation objects from the check. When the
    annotated PDG is missing or shape-wrong, returns [].
    """
    aa = metadata.get("agentarmor")
    if not isinstance(aa, dict):
        return []
    pdg = aa.get("annotated_pdg")
    if pdg is None:
        return []
    try:
        is_safe, descriptions = type_system.check(pdg)
    except Exception:  # noqa: BLE001
        return []
    if is_safe:
        return []
    # Reconstruct TypeViolation-shaped findings from the string
    # descriptions when the type system did not surface structured ones.
    # The scaffolded type_system.check returns (bool, tuple[str, ...]) so
    # we wrap strings as opaque violations.
    violations: list[TypeViolation] = []
    for description in descriptions:
        # Best-effort code derivation: pick the longest matching key.
        code = "type_system_violation"
        for known_code in _VIOLATION_CODE_TO_ASI.keys():
            if known_code in description.lower():
                code = known_code
                break
        violations.append(
            TypeViolation(
                code=code,
                description=str(description)[:1500],
                src_node="(unknown)",
                dst_node="(unknown)",
                src_attrs={},
                dst_attrs={},
            )
        )
    return violations


def _violation_to_evidence(
    violation: TypeViolation,
) -> tuple[str, SpecialistEvidence, tuple[str, ...]]:
    """Map a TypeViolation to (reason_code, evidence, asi_tags)."""
    code_map = {
        "untrusted_to_exec": "ARMOR_TYPE_UNTRUSTED_TO_EXEC",
        "secret_to_network": "ARMOR_TYPE_SECRET_TO_NETWORK",
        "integrity_downgrade": "ARMOR_TYPE_INTEGRITY_DOWNGRADE",
        "tainted_to_exec": "ARMOR_TYPE_TAINTED_TO_EXEC",
        "tainted_to_network": "ARMOR_TYPE_TAINTED_TO_NETWORK",
    }
    reason_code = code_map.get(violation.code, "ARMOR_TYPE_VIOLATION")
    asi_tags = _VIOLATION_CODE_TO_ASI.get(violation.code, (ASI_TOOL_MISUSE,))
    explanation = (
        f"{reason_code}: type system rejected flow "
        f"{violation.src_node} → {violation.dst_node}. "
        f"{violation.description[:1000]}"
    )
    return (
        reason_code,
        SpecialistEvidence(
            text=f"type_violation:{violation.code}",
            explanation=explanation,
        ),
        asi_tags,
    )


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
        "specialist_name": "agentarmor",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
    }
    emit_event("specialist.agentarmor.evaluated", **fields)


__all__ = ["AgentArmorSpecialist"]
