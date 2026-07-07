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
    reconciles this override against the caller's key (see /v1/vigil).

    ``prior_question`` / ``prior_answer`` carry the operator's previous
    exchange so the LLM router can resolve follow-ups ("what about
    yesterday?"). Optional and ignored on the keyless deterministic path —
    the regex parse reads only the question, exactly as before. The 4000
    cap mirrors the legacy /v1/ask context contract (texApi.js slices to
    the same bound)."""

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=2000)
    tenant_id: str | None = Field(default=None, max_length=200)
    prior_question: str | None = Field(default=None, max_length=4000)
    prior_answer: str | None = Field(default=None, max_length=4000)


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
_YESTERDAY_RE = re.compile(r"\byesterday\b", re.IGNORECASE)
_THIS_MONTH_RE = re.compile(r"\bthis month\b", re.IGNORECASE)
_TOTAL_RE = re.compile(r"\b(in total|total|all time|all-time|overall|ever)\b", re.IGNORECASE)
# Temporal phrases Tex CANNOT window yet. A question that names one must
# ABSTAIN, never answer a different window than it was asked — a true number
# at the wrong altitude is the exact sin this pipeline exists to kill.
_UNSUPPORTED_WINDOW_RE = re.compile(
    r"\b(last\s+(night|week|month|year)|"
    r"(in|since|during)\s+(january|february|march|april|may|june|july|august|"
    r"september|october|november|december|19\d\d|20\d\d))\b",
    re.IGNORECASE,
)
# The agents-roster ask — who Tex governs, not what it decided. Only fires
# when the question carries NO verdict word: "which agents did you forbid"
# is a decisions ask that happens to say agents.
_AGENTS_RE = re.compile(r"\bagents?\b", re.IGNORECASE)
_NAME_RE = re.compile(r"\bname\b", re.IGNORECASE)

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
    if _YESTERDAY_RE.search(question):
        return "yesterday"
    if _THIS_WEEK_RE.search(question):
        return "this week"
    if _THIS_MONTH_RE.search(question):
        return "this month"
    if _TOTAL_RE.search(question):
        return "in total"
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

    # A temporal phrase Tex can't window yet → honest abstain. Only fires when
    # no supported window matched, so "last year vs today" still answers today.
    if window == "recent" and _UNSUPPORTED_WINDOW_RE.search(question):
        return _Intent("unsupported_window", None, None, None)

    # The roster ask: agents named, no verdict word, WITH a count/list/name
    # framing. A verdict word makes it a decisions ask ("which agents did you
    # forbid"); a mention without a provable framing ("who owns the most
    # agents") falls through to unsupported — answering the roster count to an
    # ownership question would be a true number at the wrong altitude.
    if verdict is None and _AGENTS_RE.search(question):
        if _LIST_RE.search(question) or _NAME_RE.search(question):
            return _Intent("agents_list", None, None, None)
        if _COUNT_RE.search(question):
            return _Intent("agents_count", None, None, None)

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
    if intent.kind in ("agents_count", "agents_list"):
        # The roster buttons read the agent REGISTRY, not the decision store —
        # who is governed, not what was decided. No registry wired → empty →
        # the caller abstains (no_scoped_tool) rather than guessing.
        registry = getattr(request.app.state, "agent_registry", None)
        if registry is None:
            return []
        if intent.kind == "agents_list":
            return [exhibits.list_agents(registry, tenant)]
        return [exhibits.count_agents(registry, tenant)]

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


def _intent_from_route(
    routed: dict[str, Any] | None, question: str
) -> _Intent | None:
    """Translate the LLM router's decision into a deterministic ``_Intent``.

    The seam already re-validated against its enum vocabularies; this maps
    that vocabulary onto the pipeline's own and applies two laws:

    * ``tool == "none"`` returns None — the model found no sealed button, so
      the regex parse gets its say before Tex abstains. The LLM path is a
      strict SUPERSET of the deterministic one, never a subtraction.
    * ``window == "unsupported"`` is DECISIVE — the model heard a temporal
      phrase no window can compute ("last week", "since March"). Honest law:
      abstain rather than answer a true number at the wrong altitude.

    ``decision_id`` stays regex-extracted (``_UUID_RE``): exact identifiers
    are the one thing pattern-matching does better than a model, and it makes
    a hallucinated id structurally impossible. A ``record`` routing without
    an id means "the latest one" — the exhibit layer resolves it.
    """
    if routed is None:
        return None
    tool = routed["tool"]
    if tool == "none":
        return None
    if routed["window"] == "unsupported":
        return _Intent("unsupported_window", None, None, None)
    verdict = None if routed["verdict"] == "ANY" else routed["verdict"]
    if tool in ("agents_count", "agents_list"):
        # The roster reads the registry; a verdict has no meaning there.
        return _Intent(tool, None, routed["window"], None)
    decision_id = None
    if tool == "record":
        uuid_match = _UUID_RE.search(question)
        decision_id = uuid_match.group(1) if uuid_match else None
    return _Intent(tool, verdict, routed["window"], decision_id)


def build_answer_router(llm_seam: Any | None = None) -> APIRouter:
    """Build the /v1/answer router.

    ``llm_seam`` (keyword, default None) is an
    :class:`tex.answers.router_llm.AnswerLLM` — or any duck-typed object with
    ``.route(question, prior_question, prior_answer)`` and ``.draft(prompt)``.
    None is the keyless v1 posture, byte-identical to before the seam existed:
    regex routing, deterministic drafter floor.
    """
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

        # UNDERSTANDING: the LLM router reads the question (and the prior
        # exchange, so follow-ups resolve) and picks the sealed tool. Routing
        # is an upgrade, never a dependency — seam absent, model silent, or
        # "none" all fall back to the deterministic regex parse, so the
        # keyless posture stays byte-identical and an outage cannot mute Tex.
        # The model chooses WHICH button; it still cannot author a value.
        intent: _Intent | None = None
        if llm_seam is not None:
            routed = llm_seam.route(
                body.question, body.prior_question, body.prior_answer
            )
            intent = _intent_from_route(routed, body.question)
        if intent is None:
            intent = _parse_intent(body.question)
        if intent.kind == "unsupported":
            return _abstain_response(tenant, body.question, "unsupported_intent")
        if intent.kind == "unsupported_window":
            # Tex heard a time window it cannot compute yet. Answering the
            # nearest window it DOES know would be a true number at the wrong
            # altitude — so it says it can't say.
            return _abstain_response(tenant, body.question, "unsupported_window")

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

        # DRAFTING STAYS DETERMINISTIC — BY DESIGN, for truth-safety. The
        # byte-verify gate confirms only that the digit SLOTS fill the same
        # way; it does NOT check the prose FRAME around them. An LLM allowed
        # to author that frame could write a fabricated verdict, window, or
        # agent name into the prose and the gate would seal it — the digit is
        # real, the words lie (agent names are redacted before the drafter,
        # so any name it inlines is pure hallucination). So the model ROUTES
        # (above) but the deterministic floor writes the words: it phrases
        # ONLY from each exhibit's own sealed query fields, so the prose
        # cannot contradict the record. Re-enabling an LLM drafter requires a
        # real entailment guard first (see router_llm's module docstring).
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
