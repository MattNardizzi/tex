"""
POST /v1/answer — Tex answering a question under oath.

This is the assembly point of the fluid-truth pipeline. A question comes in;
Tex may only speak values deterministic code computed from real rows. The
route never writes a digit and never lets the model write one: it parses the
intent with regex (no LLM), asks the exhibit primitives to measure the store,
lets the drafter propose digit-free span skeletons, fills each skeleton from
the sealed exhibits, and runs every filled span through the truth gate. Only
sealed survivors reach the caller; if nothing seals, Tex speaks a calm ABSTAIN.

Doctrine held in this file:

  * A zero count is a SEALED truth, never an ABSTAIN — a measured zero is an
    answer. ABSTAIN is reserved for "I have no sealed way to answer that",
    which is calm and first-class, not an apology.
  * The model writes the music (span templates), never the digits. Every
    number leaves through a gate-sealed exhibit slot or not at all.
  * Tenant boxing is identical to /v1/vigil: a scoped key is pinned to its
    own tenant, and a scoped key querying a different tenant is 403'd before
    any row is read.

Auth posture: the route speaks real, tenant-scoped findings, so it requires
``decision:read`` exactly like /v1/vigil. A keyless dev backend authenticates
anonymously (every scope), so the local UI works without a key.

This is a strict read. No side effects on the store.

Contract note: the ``exhibits.list_decisions`` primitive (built in parallel)
takes ``since``/``until`` but no ``window_label``, so v1 list answers are
always over the recent window. Today / this-week windowing is honored for the
count ask, which the primitive parameterizes with ``window_label``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from tex.answers import drafter, exhibits, gate
from tex.answers.spans import AnswerResponse, Exhibit, Slot, Span
from tex.api.auth import RequireScope, TexPrincipal
from tex.api.vigil_routes import _resolve_effective_tenant

__all__ = ["build_answer_router"]


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

# The one line Tex speaks when it has no sealed way to answer. Exact by
# contract — the UI and the voice both key off this text.
ABSTAIN_LINE = "I can't say — I don't have a sealed way to answer that yet."


# --------------------------------------------------------------------------- #
# Request DTO                                                                 #
# --------------------------------------------------------------------------- #


class AnswerRequestDTO(BaseModel):
    """The question and an optional tenant override. Tenant boxing then
    reconciles this override against the caller's key (see /v1/vigil)."""

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=2000)
    tenant_id: str | None = Field(default=None, max_length=200)


# --------------------------------------------------------------------------- #
# Intent parse (deterministic — no LLM anywhere on this path)                 #
# --------------------------------------------------------------------------- #

# Verdict vocabulary. The question's plain words map to the store's verdict
# space. HELD is the operator word for a decision awaiting a human — it maps
# to the store's ABSTAIN verdict (requires_human_review), which the exhibit
# layer resolves. Matching is word-boundary so "permitted" hits but
# "supermitted" would not, and "blockchain" never reads as "block".
_VERDICT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(forbid|forbidden|forbade|block|blocked|stop|stopped|deny|denied|refuse|refused)\b", "FORBID"),
    (r"\b(permit|permitted|allow|allowed|approve|approved)\b", "PERMIT"),
    (r"\b(held|hold|holding|waiting|await|awaiting|abstain|abstained|pending)\b", "HELD"),
)

# Window vocabulary. "today" and "this week" are explicit; anything else with
# a countable/listable ask defaults to the recent window (the store's existing
# recent semantics). The label travels into the exhibit query so the tz math
# lives in one place (the exhibit layer), never re-derived from prose.
_TODAY_RE = re.compile(r"\btoday\b", re.IGNORECASE)
_THIS_WEEK_RE = re.compile(r"\bthis week\b", re.IGNORECASE)

# Ask vocabulary. A question is answerable only if it asks to COUNT, to LIST,
# or to fetch one RECORD. No recognizable ask → ABSTAIN (unsupported_intent),
# rather than inventing a query.
_COUNT_RE = re.compile(
    r"\b(how many|how much|count|number of|total|tally|were there|are there|"
    r"how often)\b",
    re.IGNORECASE,
)
_LIST_RE = re.compile(
    r"\b(list|show|which|what were|what are|name the|enumerate|give me the)\b",
    re.IGNORECASE,
)
# A record ask names a specific decision by its id (uuid) or asks for the
# "record"/"details" of one. The uuid capture lets the exhibit layer fetch the
# exact row.
_UUID_RE = re.compile(
    r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
_RECORD_RE = re.compile(r"\b(record|details of|decision id|decision record)\b", re.IGNORECASE)


class _Intent:
    """Parsed, deterministic reading of the question. ``kind`` is one of
    ``count`` | ``list`` | ``record`` | ``unsupported``."""

    __slots__ = ("kind", "verdict", "window_label", "decision_id")

    def __init__(
        self,
        kind: str,
        verdict: str | None,
        window_label: str | None,
        decision_id: str | None,
    ) -> None:
        self.kind = kind
        self.verdict = verdict
        self.window_label = window_label
        self.decision_id = decision_id


def _parse_window(question: str) -> str:
    if _TODAY_RE.search(question):
        return "today"
    if _THIS_WEEK_RE.search(question):
        return "this week"
    return "recent"


def _parse_verdict(question: str) -> str | None:
    for pattern, verdict in _VERDICT_PATTERNS:
        if re.search(pattern, question, re.IGNORECASE):
            return verdict
    return None


def _parse_intent(question: str) -> _Intent:
    """Map a natural question onto exactly one deterministic ask, or declare
    it unsupported. Record beats list beats count when the question carries a
    concrete decision id, because a named row is the most specific ask."""
    window = _parse_window(question)
    verdict = _parse_verdict(question)

    uuid_match = _UUID_RE.search(question)
    if uuid_match is not None and _RECORD_RE.search(question):
        return _Intent("record", verdict, window, uuid_match.group(1))
    if uuid_match is not None:
        # A bare id with no record framing is still most-naturally a record ask.
        return _Intent("record", verdict, window, uuid_match.group(1))

    if _LIST_RE.search(question):
        return _Intent("list", verdict, window, None)

    if _COUNT_RE.search(question):
        return _Intent("count", verdict, window, None)

    # A verdict word with no explicit count/list framing ("what did you forbid
    # today?") is still a countable ask about that verdict.
    if verdict is not None:
        return _Intent("count", verdict, window, None)

    return _Intent("unsupported", None, None, None)


# --------------------------------------------------------------------------- #
# Assembly helpers                                                            #
# --------------------------------------------------------------------------- #


def _abstain_response(
    tenant_id: str, question: str, reason: str
) -> AnswerResponse:
    """One calm ABSTAIN span, the exact contract line, no exhibits. A measured
    zero never lands here — only a genuine "no sealed way to answer" does."""
    span = Span(
        template=ABSTAIN_LINE,
        text=ABSTAIN_LINE,
        slots=[],
        verdict="ABSTAIN",
        anchor_sha256=None,
        prosody="abstain",
    )
    return AnswerResponse(
        tenant_id=tenant_id,
        question=question,
        spans=[span],
        exhibits=[],
        spoken_text=ABSTAIN_LINE,
        overall_tier="ABSTAIN",
        abstain_reason=reason,
    )


def _proposal_to_span(proposal: dict[str, Any], answer_exhibits: list[Exhibit]) -> Span | None:
    """Turn a drafter proposal ``{template, slots}`` into a fillable Span.

    The text is derived from the sealed exhibits with the same ``fill`` the
    gate will re-run — so a span reaching the gate already carries the exact
    text the gate must byte-match. A template whose slots don't resolve yields
    no span (the gate would have killed it anyway; dropping it here keeps the
    survivors honest without fabricating text)."""
    template = proposal.get("template")
    if not isinstance(template, str) or not template:
        return None

    raw_slots = proposal.get("slots") or []
    slots: list[Slot] = []
    for raw in raw_slots:
        if not isinstance(raw, dict):
            return None
        handle = raw.get("handle")
        rendering = raw.get("rendering", "spoken")
        if not isinstance(handle, str) or not handle:
            return None
        if rendering not in ("spoken", "raw"):
            rendering = "spoken"
        slots.append(Slot(handle=handle, rendering=rendering))

    text = gate.fill(template, slots, answer_exhibits)
    if text is None:
        return None

    # Provisional verdict/prosody — the gate reassigns SEALED on a clean seal.
    # A template with no slots (pure prose from the drafter) still has to be
    # non-empty text to satisfy the Span contract; fill returns the template
    # verbatim in that case, which is a valid (if slot-free) span the gate
    # lints and seals.
    if not text:
        return None

    return Span(
        template=template,
        text=text,
        slots=slots,
        verdict="ABSTAIN",
        anchor_sha256=None,
        prosody="abstain",
    )


def _gather_exhibit_dicts(
    request: Request, intent: _Intent, tenant: str
) -> list[dict[str, Any]]:
    """Ask the exhibit primitives to measure the store for this intent.

    The decision store is pulled from ``app.state.decision_store`` (the same
    attribute the vigil, learning, and routes modules read). The exhibit layer
    owns the store→value mapping and the tz-correct window resolution; this
    function only routes the parsed intent to the right primitive. Each
    primitive returns an Exhibit *dict* (the shape in :mod:`tex.answers.spans`);
    the caller parses those into sealed :class:`Exhibit` models.

    A record lookup that misses raises ``KeyError`` (the sibling primitive's
    contract) — the caller catches it and abstains rather than speaking a guess.
    A count over an empty match still returns an exhibit (``value=0``), so a
    measured zero seals as a truth."""
    store = getattr(request.app.state, "decision_store", None)
    if store is None:
        return []

    if intent.kind == "record":
        # get_decision_record(store, decision_id, tenant) — raises KeyError when
        # the row is absent or outside the tenant's visibility.
        record = exhibits.get_decision_record(store, intent.decision_id, tenant)
        return [record]

    if intent.kind == "list":
        # list_decisions has no window_label parameter (sibling contract): it
        # lists over the recent window. See the module docstring's deviation note.
        listing = exhibits.list_decisions(store, tenant, intent.verdict)
        return [listing]

    # count (the default answerable ask). window_label carries today / this week
    # / recent into the exhibit layer, which owns the tz-correct resolution.
    count = exhibits.count_decisions(
        store, tenant, intent.verdict, window_label=intent.window_label
    )
    return [count]


def _overall_tier(spans: list[Span]) -> str:
    """The weakest tier among survivors. v1 survivors are all SEALED, but the
    reducer is written to the contract's ordering so a future DERIVED span
    lowers the whole answer correctly (ABSTAIN < DERIVED < SEALED)."""
    order = {"ABSTAIN": 0, "DERIVED": 1, "SEALED": 2}
    weakest = min((order[s.verdict] for s in spans), default=2)
    for name, rank in order.items():
        if rank == weakest:
            return name
    return "SEALED"


# --------------------------------------------------------------------------- #
# Router                                                                      #
# --------------------------------------------------------------------------- #


def build_answer_router() -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["answer"])

    @router.get("/answer/ping", summary="Liveness for the answer surface")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    @router.post(
        "/answer",
        response_model=AnswerResponse,
        summary="Answer a question with sealed, tool-computed values (Claude under oath)",
    )
    def answer(
        request: Request,
        body: AnswerRequestDTO = Body(...),
        # Speaks real, tenant-scoped findings -> authed like /v1/vigil.
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> AnswerResponse:
        # Tenant boxing first: a scoped key querying another tenant is 403'd
        # before any row is read (raises inside _resolve_effective_tenant).
        effective = _resolve_effective_tenant(principal, body.tenant_id)
        tenant = effective if effective is not None else "default"

        intent = _parse_intent(body.question)
        if intent.kind == "unsupported":
            return _abstain_response(tenant, body.question, "unsupported_intent")

        # Measure the store. A record miss raises KeyError from the exhibit
        # layer — that is an honest "no sealed way to answer", not a crash and
        # never a guessed record. Any other exhibit-layer failure abstains too.
        try:
            exhibit_dicts = _gather_exhibit_dicts(request, intent, tenant)
        except KeyError:
            return _abstain_response(tenant, body.question, "no_scoped_tool")
        except Exception:  # noqa: BLE001 — an unmeasurable store yields ABSTAIN
            return _abstain_response(tenant, body.question, "exhibit_error")

        if not exhibit_dicts:
            # No exhibit at all means no sealed way to answer. A zero COUNT is
            # NOT this branch — count_decisions returns an exhibit whose value
            # is 0, which seals as a truth.
            return _abstain_response(tenant, body.question, "no_scoped_tool")

        # Parse the exhibit dicts into sealed Exhibit models (the gate fills and
        # seals against these). A malformed exhibit dict is an exhibit_error.
        try:
            answer_exhibits = [Exhibit.model_validate(d) for d in exhibit_dicts]
        except Exception:  # noqa: BLE001 — a malformed exhibit is not speakable
            return _abstain_response(tenant, body.question, "exhibit_error")

        # The model drafts digit-free skeletons from REDACTED exhibits (v1:
        # llm=None -> the deterministic floor). It never sees a value.
        proposals = drafter.draft(body.question, exhibit_dicts, llm=None)

        spans: list[Span] = []
        for proposal in proposals:
            span = _proposal_to_span(proposal, answer_exhibits)
            if span is not None:
                spans.append(span)

        # The truth gate seals what it can and kills the rest.
        result = gate.gate_all(spans, answer_exhibits)
        survivors = result.survivors

        if not survivors:
            # Every span died (or none was proposed). Speak a calm ABSTAIN.
            return _abstain_response(tenant, body.question, "gate_killed_all")

        spoken_text = " ".join(s.text for s in survivors)
        return AnswerResponse(
            tenant_id=tenant,
            question=body.question,
            spans=survivors,
            exhibits=answer_exhibits,
            spoken_text=spoken_text,
            overall_tier=_overall_tier(survivors),
            abstain_reason=None,
        )

    return router
