"""
[Architecture: Voice cognition] — the authored answer registry.

THE IRON RULE (inherited verbatim from ``tex.vigil.utterances``):

    The router chooses WHICH sealed truth to speak. It never writes the
    words. Every answer Tex speaks through ``/v1/ask`` is one authored
    template filled ONLY with sealed slot values that trace to real data —
    every number, every hash, every verdict traces to a sealed field. There
    is no template engine, no model call, no free-text concatenation. A line
    is produced solely by ``template.format(**sealed_slots)`` over a fixed,
    authored template, via ``tex.vigil.utterances.fill`` (which REFUSES to
    speak — raises — if a required sealed slot is absent).

This file is the complete, auditable set of sentences Tex is allowed to say.
If a word is not here, Tex cannot say it. The slots are extracted from the
sealed ``EvidenceFacts`` produced by ``tex.vigil`` — pulled from the structured
``details`` by exact key, NEVER re-parsed out of the headline string (the
headline embeds the same integer as prose; parsing it twice is a second source
of truth and a bug).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from tex.vigil.utterances import UtteranceForm, fill

__all__ = [
    "AnswerBuild",
    "build_dimension_answer",
    "build_record_answer",
    "RECORD_TEMPLATE",
    "ABSTAIN_NO_ROUTE",
    "ABSTAIN_NO_FACT",
    "ABSTAIN_NO_RECORD",
    "FORBID_CONTRADICTION",
]


# ── Authored decline / refusal sentences (no sealed slots; fixed strings) ────
# These are spoken when Tex cannot ground an answer (ABSTAIN) or when the
# question asserted something the sealed fact contradicts (FORBID). They carry
# no object and no proof_ref — there is nothing to hand over.
ABSTAIN_NO_ROUTE = "I can't tell what you're asking about from what I can prove. Ask me again."
ABSTAIN_NO_FACT = "I don't have a sealed fact for that yet, so I won't answer it."
ABSTAIN_NO_RECORD = "I have no sealed record under that handle."
FORBID_CONTRADICTION = "That isn't what the record shows, so I won't say it."


@dataclass(frozen=True, slots=True)
class AnswerBuild:
    """A grounded answer ready for the gate.

    ``answer`` is ``template.format(**slots)``; ``template`` and ``slots`` are
    carried so the gate can re-prove the reconstruction (the answer is exactly
    an authored template filled with sealed values) rather than trust it.
    """

    answer: str
    template: str
    slots: dict[str, Any]
    object: dict[str, str] | None = None     # {value, kind} — the one handle, or none
    proof_ref: dict[str, Any] | None = None  # first sealed anchor, or none


@dataclass(frozen=True, slots=True)
class _DimensionForm:
    """One authored dimension answer + the extractor that fills it from facts."""

    template: str
    required_slots: tuple[str, ...]
    extract: Callable[[Any], dict[str, Any] | None]  # facts -> slots, or None to abstain


def _detail0(facts: Any) -> dict[str, Any]:
    details = list(getattr(facts, "details", None) or [])
    return details[0] if details else {}


def _extract_execution(facts: Any) -> dict[str, Any] | None:
    d = _detail0(facts)
    if "forbidden_total" not in d:
        return None
    return {"forbidden_total": int(d["forbidden_total"])}


def _extract_human_decision(facts: Any) -> dict[str, Any] | None:
    d = _detail0(facts)
    if "awaiting_total" not in d:
        return None
    return {"awaiting_total": int(d["awaiting_total"])}


def _extract_evidence(facts: Any) -> dict[str, Any] | None:
    d = _detail0(facts)
    if "sealed_records" not in d or "chain_intact" not in d:
        return None
    return {
        "sealed_records": int(d["sealed_records"]),
        # Authored, fixed phrasings for the boolean — not free text.
        "integrity_word": "intact" if bool(d["chain_intact"]) else "broken",
    }


def _extract_identity(facts: Any) -> dict[str, Any] | None:
    d = _detail0(facts)
    if "high_risk_ungoverned" not in d or "high_risk_total" not in d:
        return None
    return {
        "high_risk_ungoverned": int(d["high_risk_ungoverned"]),
        "high_risk_total": int(d["high_risk_total"]),
    }


def _extract_monitoring(facts: Any) -> dict[str, Any] | None:
    details = list(getattr(facts, "details", None) or [])
    # A real failing entry carries a "connector" key; the zero-case is the
    # sentinel {"failing_connectors": 0}. Count by structure, never by headline.
    failing_count = sum(1 for it in details if isinstance(it, dict) and "connector" in it)
    return {"failing_count": int(failing_count)}


def _extract_discovery(facts: Any) -> dict[str, Any] | None:
    d = _detail0(facts)
    if "registered_count" not in d:
        return None
    return {"registered_count": int(d["registered_count"])}


# The authored registry. One sentence form per dimension.
_FORMS: dict[str, _DimensionForm] = {
    "execution": _DimensionForm(
        template="{forbidden_total} actions were forbidden in the recent window.",
        required_slots=("forbidden_total",),
        extract=_extract_execution,
    ),
    "human_decision": _DimensionForm(
        template="{awaiting_total} actions are waiting on a human decision.",
        required_slots=("awaiting_total",),
        extract=_extract_human_decision,
    ),
    "evidence": _DimensionForm(
        template="The evidence chain is {integrity_word} across {sealed_records} sealed records.",
        required_slots=("integrity_word", "sealed_records"),
        extract=_extract_evidence,
    ),
    "identity": _DimensionForm(
        template="{high_risk_ungoverned} of {high_risk_total} high-risk agents are acting outside governance.",
        required_slots=("high_risk_ungoverned", "high_risk_total"),
        extract=_extract_identity,
    ),
    "monitoring": _DimensionForm(
        template="{failing_count} connectors have stopped reporting.",
        required_slots=("failing_count",),
        extract=_extract_monitoring,
    ),
    "discovery": _DimensionForm(
        template="The most recent scan brought {registered_count} new agents into view.",
        required_slots=("registered_count",),
        extract=_extract_discovery,
    ),
}


def _proof_ref_dict(anchors: Any) -> dict[str, Any] | None:
    """First sealed anchor as a plain dict, or None when nothing is sealed."""
    anchors = list(anchors or [])
    if not anchors:
        return None
    a = anchors[0]
    ref = {
        "kind": getattr(a, "kind", None),
        "id": getattr(a, "id", None),
        "sha256": getattr(a, "sha256", None),
        "seq": getattr(a, "seq", None),
    }
    # An anchor with no addressable content is not proof.
    if ref["id"] is None and ref["sha256"] is None and ref["seq"] is None:
        return None
    return ref


def build_dimension_answer(dimension: str, facts: Any) -> AnswerBuild | None:
    """Build the grounded answer for a dimension, or None to ABSTAIN.

    Returns None when there is no authored form, the sealed slot is absent, or
    ``fill`` refuses (a missing required slot). Tex stays silent on the answer
    rather than improvise a number.
    """
    form = _FORMS.get(dimension)
    if form is None:
        return None
    slots = form.extract(facts)
    if slots is None:
        return None
    try:
        u = UtteranceForm(
            dimension=dimension,
            template=form.template,
            required_slots=form.required_slots,
            speaks_when=lambda _s: True,
        )
        answer = fill(u, slots)
    except (ValueError, KeyError):
        # The IRON RULE fired: a required sealed slot was missing. Do not speak.
        return None
    return AnswerBuild(
        answer=answer,
        template=form.template,
        slots=slots,
        object=None,  # a count is meaning (spoken), not a handle to grab
        proof_ref=_proof_ref_dict(getattr(facts, "anchors", None)),
    )


# ── The record path: the operator named one exact sealed object ─────────────
RECORD_TEMPLATE = "Decision {decision_id} resolved to {verdict}."


def build_record_answer(decision: Any) -> AnswerBuild | None:
    """Verbalize one sealed Decision deterministically, or None to ABSTAIN.

    The spoken meaning is the verdict; the object handed over is the content
    hash (a thing you grab, not comprehend). Both are read verbatim from the
    sealed record — never derived.
    """
    decision_id = str(getattr(decision, "decision_id", "") or "")
    verdict = getattr(getattr(decision, "verdict", None), "value", None)
    content_sha256 = getattr(decision, "content_sha256", None)
    if not decision_id or not verdict:
        return None
    slots = {"decision_id": decision_id, "verdict": str(verdict)}
    try:
        u = UtteranceForm(
            dimension="record",
            template=RECORD_TEMPLATE,
            required_slots=("decision_id", "verdict"),
            speaks_when=lambda _s: True,
        )
        answer = fill(u, slots)
    except (ValueError, KeyError):
        return None
    obj = (
        {"value": str(content_sha256), "kind": "hash"}
        if content_sha256
        else {"value": decision_id, "kind": "name"}
    )
    evidence_hash = getattr(decision, "evidence_hash", None)
    proof_ref = {
        "kind": "decision",
        "id": decision_id,
        "sha256": (str(evidence_hash) if evidence_hash else None),
        "seq": None,
    }
    return AnswerBuild(answer=answer, template=RECORD_TEMPLATE, slots=slots, object=obj, proof_ref=proof_ref)
