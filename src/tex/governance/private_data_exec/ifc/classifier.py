"""
Classify Tex request fields into IFC labels.

The IfcSpecialist runs over the live `/v1/guardrail` request path; the
request arrives as a Tex `EvaluationRequest` with retrieved context.
This module converts those fields into labeled source nodes for the
provenance graph.

Classification rules (mapped to ARM integrity lattice)
------------------------------------------------------
- request.content                → USER_INPUT (the caller's text)
  Exception: when request.metadata["content_origin"] == "tool_output",
  the content is re-classified by tool trust; when
  "untrusted_source" is set, the content drops to TOOL_UNTRUSTED.
- request.metadata["tool_call"]  → tool input flowing into a CALL node;
  label depends on the tool's manifest trust class.
- retrieval_context.policy_clauses
                                 → SYS_INSTR (operator-controlled).
- retrieval_context.precedents   → TOOL_TRUSTED (Tex's own prior
  decisions are operator-attestable).
- retrieval_context.entities     → TOOL_TRUSTED (operator-defined).
- retrieval_context.metadata["untrusted_sources"]
                                 → TOOL_UNTRUSTED (operator-marked).

Confidentiality classification
------------------------------
- secret/PII patterns in content → CONFIDENTIAL or RESTRICTED.
- request.action_type in {"send_email","post_message","transfer_funds",
  "publish","share_link"} and request.recipient outside an allowlist
  → sink classification (sensitive).
- request.metadata["sensitivity"] when present overrides the inferred
  level (operator-asserted classification).

CI norm extraction
------------------
We extract the candidate CI norm from the request as:
  sender  = request.agent_identity.agent_name or "agent"
  receiver = request.recipient or request.channel
  subject = request.metadata.get("data_subject", "user")
  information_type = request.metadata.get("information_type", action_type)
  transmission_principle = request.metadata.get("transmission_principle",
                                                "default_forbidden")
  purpose = request.metadata.get("purpose", action_type)

The IfcSpecialist then matches this candidate against the operator's
permitted CI norm registry.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.governance.private_data_exec.ifc.ci_norms import (
    CiNorm,
    TransmissionPrinciple,
)
from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)


# Action types that constitute external-communication sinks per the
# Lethal Trifecta (Willison 2025) and Rule of Two (Meta 2025). The
# IfcSpecialist treats these as the sink axis when checking flow
# violations.
SINK_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "send_email",
        "send_message",
        "post_message",
        "publish",
        "share_link",
        "transfer_funds",
        "create_payment",
        "deploy_code",
        "external_api_call",
        "share_document",
        "post_to_social",
        "outbound_webhook",
    }
)


# Patterns that justify elevating confidentiality. Lexical, intentionally
# narrow. Other Tex specialists (SecretAndPiiSpecialist) own the broad
# secret/PII detection — this classifier only needs to KNOW that secret
# material is present in order to set the label, not to enumerate every
# variant.
_HIGH_SENSITIVITY_HINTS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pat, re.IGNORECASE)
    for pat in (
        r"\bssn\b",
        r"social\s+security",
        r"\bapi[\s_-]?key\b",
        r"\bsecret\s+key\b",
        r"\bprivate[\s_-]?key\b",
        r"\bpassword\b",
        r"\bbearer\s+token\b",
        r"sk-[a-zA-Z0-9_-]{16,}",
        r"AKIA[0-9A-Z]{16}",
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
        r"\b4\d{15}\b",  # 16-digit card-like
        r"medical\s+record",
        r"\bpii\b",
        r"\bphi\b",
        r"hipaa",
        r"protected\s+health",
    )
)


@dataclass(frozen=True, slots=True)
class ClassifiedSource:
    """One classified piece of request context."""

    source_id: str
    name: str
    label: IfcLabel
    content_hash: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CallSpec:
    """A proposed tool call extracted from request metadata."""

    name: str
    arguments: dict[str, object]


def classify_content(text: str) -> ConfidentialityLevel:
    """Lexical confidentiality classifier for free-text content."""
    for pat in _HIGH_SENSITIVITY_HINTS:
        if pat.search(text):
            return ConfidentialityLevel.RESTRICTED
    return ConfidentialityLevel.INTERNAL


def classify_request(
    *,
    request: EvaluationRequest,
    retrieval_context: RetrievalContext,
) -> tuple[ClassifiedSource, ...]:
    """
    Produce labeled source nodes from a request and its retrieval
    context. Used by the IfcSpecialist to seed the provenance graph.
    """
    sources: list[ClassifiedSource] = []

    # 1. Primary user content.
    origin_hint = str(request.metadata.get("content_origin", "")).strip().lower()
    if origin_hint == "tool_output_untrusted" or bool(
        request.metadata.get("untrusted_source", False)
    ):
        integrity = IntegrityLevel.TOOL_UNTRUSTED
        reason = "metadata-marked untrusted source"
    elif origin_hint == "tool_output_trusted":
        integrity = IntegrityLevel.TOOL_TRUSTED
        reason = "metadata-marked trusted tool output"
    else:
        integrity = IntegrityLevel.USER_INPUT
        reason = "default request.content classification (USER_INPUT)"

    confidentiality_override = request.metadata.get("sensitivity")
    if isinstance(confidentiality_override, str):
        try:
            confidentiality = ConfidentialityLevel[
                confidentiality_override.strip().upper()
            ]
        except KeyError:
            confidentiality = classify_content(request.content)
    else:
        confidentiality = classify_content(request.content)

    sources.append(
        ClassifiedSource(
            source_id="src:request_content",
            name="request.content",
            label=IfcLabel(
                integrity=integrity,
                confidentiality=confidentiality,
                capacity=CapacityType.TEXT,
            ),
            content_hash=_hash_text(request.content),
            reason=reason,
        )
    )

    # 2. Retrieved policy clauses → SYS_INSTR (operator-authored).
    for clause in retrieval_context.policy_clauses:
        sources.append(
            ClassifiedSource(
                source_id=f"src:policy:{clause.clause_id}",
                name=f"policy:{clause.clause_id}",
                label=IfcLabel(
                    integrity=IntegrityLevel.SYS_INSTR,
                    confidentiality=ConfidentialityLevel.INTERNAL,
                    capacity=CapacityType.TEXT,
                ),
                content_hash=_hash_text(clause.text),
                reason="operator-authored policy clause",
            )
        )

    # 3. Retrieved entities → TOOL_TRUSTED (operator-curated lists).
    for entity in retrieval_context.entities:
        # Sensitivity from the operator-asserted level on the entity.
        sensitivity_label = entity.sensitivity.strip().casefold()
        if sensitivity_label in ("restricted", "high"):
            entity_confidentiality = ConfidentialityLevel.RESTRICTED
        elif sensitivity_label in ("confidential", "medium"):
            entity_confidentiality = ConfidentialityLevel.CONFIDENTIAL
        elif sensitivity_label in ("internal", "low"):
            entity_confidentiality = ConfidentialityLevel.INTERNAL
        else:
            entity_confidentiality = ConfidentialityLevel.INTERNAL
        sources.append(
            ClassifiedSource(
                source_id=f"src:entity:{entity.entity_id}",
                name=f"entity:{entity.canonical_name}",
                label=IfcLabel(
                    integrity=IntegrityLevel.TOOL_TRUSTED,
                    confidentiality=entity_confidentiality,
                    capacity=CapacityType.TEXT,
                ),
                content_hash=_hash_text(entity.canonical_name),
                reason=f"sensitive entity (level={sensitivity_label})",
            )
        )

    # 4. Operator-marked untrusted sources from retrieval metadata.
    raw_untrusted = retrieval_context.metadata.get("untrusted_sources")
    if isinstance(raw_untrusted, (list, tuple)):
        for idx, item in enumerate(raw_untrusted):
            if not isinstance(item, str) or not item.strip():
                continue
            sources.append(
                ClassifiedSource(
                    source_id=f"src:untrusted:{idx}",
                    name=f"untrusted_source[{idx}]",
                    label=IfcLabel(
                        integrity=IntegrityLevel.TOOL_UNTRUSTED,
                        confidentiality=ConfidentialityLevel.INTERNAL,
                        capacity=CapacityType.TEXT,
                    ),
                    content_hash=_hash_text(item),
                    reason="retrieval_context untrusted_sources entry",
                )
            )

    return tuple(sources)


def extract_proposed_tool_call(request: EvaluationRequest) -> CallSpec | None:
    """Pull a proposed tool call from metadata if present.

    Compatible with the same convention used by ClawGuardSpecialist
    (`metadata["tool_call"]` or `metadata["proposed_tool_call"]`).
    """
    for key in ("tool_call", "proposed_tool_call"):
        candidate = request.metadata.get(key)
        if isinstance(candidate, dict):
            name = candidate.get("name")
            arguments = candidate.get("input", {})
            if (
                isinstance(name, str)
                and name.strip()
                and isinstance(arguments, dict)
            ):
                return CallSpec(name=name.strip(), arguments=dict(arguments))
    return None


def proposed_recipient(request: EvaluationRequest) -> str:
    """Return the best-guess receiver string for CI extraction."""
    if request.recipient:
        return request.recipient
    return request.channel


def is_sink_action(action_type: str) -> bool:
    """True iff this action type is an external-communication sink."""
    return action_type.strip().casefold() in SINK_ACTION_TYPES


def extract_ci_norm(request: EvaluationRequest) -> CiNorm:
    """
    Extract the candidate CI norm from a request for matching against
    the operator's permitted-norm registry. CA-CI six-tuple.
    """
    md = request.metadata
    sender = "agent"
    if request.agent_identity and request.agent_identity.agent_name:
        sender = request.agent_identity.agent_name
    elif isinstance(md.get("sender"), str) and md["sender"].strip():
        sender = md["sender"].strip()

    receiver = proposed_recipient(request)

    subject_raw = md.get("data_subject", "user")
    subject = (
        subject_raw if isinstance(subject_raw, str) and subject_raw.strip()
        else "user"
    )

    info_type_raw = md.get("information_type", request.action_type)
    information_type = (
        info_type_raw
        if isinstance(info_type_raw, str) and info_type_raw.strip()
        else request.action_type
    )

    tp_raw = md.get("transmission_principle")
    transmission_principle = TransmissionPrinciple.DEFAULT_FORBIDDEN
    if isinstance(tp_raw, str):
        normalized = tp_raw.strip().lower()
        for candidate in TransmissionPrinciple:
            if candidate.value == normalized:
                transmission_principle = candidate
                break

    purpose_raw = md.get("purpose", request.action_type)
    purpose = (
        purpose_raw
        if isinstance(purpose_raw, str) and purpose_raw.strip()
        else request.action_type
    )

    return CiNorm(
        sender=sender,
        receiver=receiver,
        subject=subject,
        information_type=information_type,
        transmission_principle=transmission_principle,
        purpose=purpose,
    )


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


__all__ = [
    "SINK_ACTION_TYPES",
    "ClassifiedSource",
    "CallSpec",
    "classify_content",
    "classify_request",
    "extract_proposed_tool_call",
    "extract_ci_norm",
    "proposed_recipient",
    "is_sink_action",
]
