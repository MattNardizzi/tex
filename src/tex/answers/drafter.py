"""The Drafter — where the model writes the music and never the digits.

The drafter proposes the *shape* of an answer: one to three spans, each a
``{template, slots}`` pair in speaking order. A template is prose with slot
references in braces (``"{e1} actions were forbidden today."``) and carries NO
digits and NO number-words of its own — every quantity reaches the sentence
only by substitution from an exhibit the gate has already sealed. The drafter
is therefore incapable of speaking a wrong number: it never authors one.

That guarantee is made structural, not merely stylistic. The drafter is handed
exhibits with their ``value`` and ``spoken`` fields REDACTED — it sees only the
handle, kind, unit, and query. A model cannot leak a digit it was never shown.

Two postures, one contract:

  * DETERMINISTIC FLOOR (``llm=None``) — the keyless local posture, which MUST
    work with no vendor in the loop. Deterministic pattern templates per exhibit
    kind, phrased from the exhibit's own query (verdict word, window label), with
    a distinct zero-count phrasing. This is the floor every other posture falls
    back to, so it is always correct and always available.

  * LLM MODE (``llm`` is a callable ``(prompt) -> str``) — the model is asked to
    return strict JSON templates that carry only ``{handle}`` refs. Each proposed
    template is linted for smuggled digits/number-words; a lint failure buys ONE
    retry with the reason appended, then the drafter falls back to the floor.
    The injected callable is the sole seam — no real client is wired here — so
    tests drive it with deterministic fakes.

Nothing the drafter returns is trusted downstream on its own: the gate recomputes
values and only substitutes sealed renderings into these templates. The drafter
shapes the sentence; the gate owns every digit inside it.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

__all__ = ["draft", "DrafterProposal"]

# A drafter proposal is the pre-gate skeleton of one span: a template with brace
# slots and the slot list naming which exhibit fills each, at which rendering.
DrafterProposal = dict[str, Any]

_MAX_SPANS = 3

_BRACE_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")

# ---------------------------------------------------------------------------
# Vendored template lint (lexicon parity with tex.answers.gate.lint_template).
#
# Builder B ships the canonical ``lint_template`` in ``tex.answers.gate``. When
# it is importable at runtime we defer to it (see ``_lint_template`` below) so
# there is a single source of truth. Until it lands, this vendored copy keeps the
# drafter honest on its own. DUPLICATION FLAG: this lexicon MUST stay in lockstep
# with the gate's — if the two ever disagree, the gate's ruling wins and this
# copy should be deleted in favour of the import.
# ---------------------------------------------------------------------------

# Any bare digit is a smuggled quantity — templates carry numbers only in slots.
_DIGIT_RE = re.compile(r"\d")

# Number-words the model must not spell out in prose. A template that says
# "seventeen" has authored a digit in words; only a slot may carry a count.
_NUMBER_WORDS = frozenset(
    {
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
        "thirty",
        "forty",
        "fifty",
        "sixty",
        "seventy",
        "eighty",
        "ninety",
        "hundred",
        "thousand",
        "million",
        "billion",
        "trillion",
        "dozen",
        "dozens",
        "couple",
        "score",
    }
)

# "No" is allowed as zero-count prose ("No actions were forbidden today.") — it
# is a determiner, not a spelled quantity, so it is NOT in the number-word set.

_WORD_RE = re.compile(r"[a-zA-Z]+")


def _vendored_lint_template(
    template: str, known_handles: frozenset[str] | set[str]
) -> str | None:
    """Return a machine-readable failure reason, or ``None`` if the template is
    clean. Mirrors ``tex.answers.gate.lint_template`` exactly: a clean template
    has no digit and no spelled number-word in its prose, no half-written brace,
    and every slot reference names a handle we actually hold. Numbers may enter
    only through a well-formed slot."""
    # Slot refs are legitimate; strip them before scanning prose so a handle like
    # ``{e1}`` never trips the digit check on its own characters.
    prose = _BRACE_RE.sub(" ", template)
    # A leftover brace means a botched slot — reject so a number cannot slip
    # through a half-written reference.
    if "{" in prose or "}" in prose:
        return "malformed_slot"
    if _DIGIT_RE.search(prose):
        return "digit_in_template"
    for word in _WORD_RE.findall(prose):
        if word.lower() in _NUMBER_WORDS:
            return "number_word_in_template"
    for ref in _BRACE_RE.findall(template):
        if ref not in known_handles:
            return f"unknown_handle:{ref}"
    return None


def _lint_template(
    template: str, known_handles: frozenset[str] | set[str]
) -> str | None:
    """Lint one template, preferring the gate's canonical lexicon when present.

    Deferred import: builder B's ``tex.answers.gate.lint_template`` is the single
    source of truth. Its contract is ``lint_template(template, known_handles) ->
    LintResult`` where ``LintResult.ok`` is the pass flag and ``.reason`` is the
    machine-readable failure. This adapter normalizes that to ``reason | None``
    (``None`` == clean). The vendored copy above is the keyless fallback and is
    kept in lockstep with the gate's rules."""
    try:
        from tex.answers.gate import lint_template as _gate_lint  # type: ignore
    except Exception:
        return _vendored_lint_template(template, known_handles)
    result = _gate_lint(template, known_handles)
    return None if getattr(result, "ok", False) else getattr(result, "reason", "lint_failed")


# ---------------------------------------------------------------------------
# Deterministic floor.
# ---------------------------------------------------------------------------

# Verdict → the natural word Tex uses for it. FORBID reads as an action stopped;
# PERMIT as one allowed through; a held/abstained decision is one kept back for
# the operator. These are prose choices, never the count.
_VERDICT_PHRASE = {
    "FORBID": "forbidden",
    "PERMIT": "permitted",
    "HELD": "held for you",
    "ABSTAIN": "held for you",
}

# Fallback when a count exhibit names no verdict — an untyped tally of decisions.
_PLAIN_COUNT_VERB = "recorded"

# window_label → trailing time prose. ``None`` yields no time clause at all.
_WINDOW_CLAUSE = {
    "today": " today",
    "this week": " this week",
    "recent": " recently",
}


def _query_field(exhibit: dict[str, Any], key: str) -> Any:
    query = exhibit.get("query") or {}
    return query.get(key)


def _window_clause(exhibit: dict[str, Any]) -> str:
    label = _query_field(exhibit, "window_label")
    return _WINDOW_CLAUSE.get(label, "")


def _count_predicate(exhibit: dict[str, Any]) -> str:
    """The verb phrase for a count span, chosen from the exhibit's verdict.

    A typed count (verdict set) reads as that verdict's action word; an untyped
    count falls back to a plain tally verb. The count itself is NEVER named here
    — it arrives only through the ``{handle}`` slot."""
    verdict = _query_field(exhibit, "verdict")
    if verdict in _VERDICT_PHRASE:
        return f"were {_VERDICT_PHRASE[verdict]}"
    return _PLAIN_COUNT_VERB


def _count_noun(exhibit: dict[str, Any]) -> str:
    """The plural noun a count is measured in — the exhibit's unit, or a neutral
    'decisions' when none is declared."""
    unit = exhibit.get("unit")
    if unit:
        return str(unit)
    return "decisions"


def _floor_count_span(exhibit: dict[str, Any]) -> DrafterProposal:
    """One count span, phrased purely from the exhibit's query. The count is a
    slot; the sentence around it is structural prose. Zero is a sealed truth, so
    a known-zero count earns its own calm phrasing that leads with 'No' — the
    determiner, not a spelled number.

    The drafter cannot see the value, so it cannot *know* the count is zero from
    the value. It learns zero only from an explicit, redaction-safe query hint
    (``is_zero``) that the tool layer may set alongside the redacted exhibit; in
    its absence the drafter phrases for the general case and lets the gate seal
    whatever digit it recomputes — including zero, rendered through the slot."""
    handle = exhibit["handle"]
    noun = _count_noun(exhibit)
    clause = _window_clause(exhibit)

    if _query_field(exhibit, "is_zero") is True:
        verdict = _query_field(exhibit, "verdict")
        # Zero-count prose: "No actions were forbidden today." The slot still
        # rides along (rendering the sealed zero) so the gate remains the author
        # of the quantity even when that quantity is nothing.
        if verdict in _VERDICT_PHRASE:
            template = f"No {noun} were {_VERDICT_PHRASE[verdict]}{clause}."
        else:
            template = f"No {noun} were {_PLAIN_COUNT_VERB}{clause}."
        return {
            "template": template,
            "slots": [{"handle": handle, "rendering": "spoken"}],
        }

    predicate = _count_predicate(exhibit)
    template = f"{{{handle}}} {noun} {predicate}{clause}."
    return {
        "template": template,
        "slots": [{"handle": handle, "rendering": "spoken"}],
    }


def _floor_list_span(exhibit: dict[str, Any]) -> DrafterProposal:
    """One list span. Names are values too, so the drafter never inlines them:
    it emits the list through a single ``spoken``-rendered slot and keeps the
    template purely structural. The exhibit's ``spoken`` field IS the ear's
    version of the list (up to three names + a humanized remainder), computed
    deterministically by the tool layer — a ``raw`` rendering over a structured
    value would serialize brackets and timestamps into speech, and the gate
    kills it."""
    handle = exhibit["handle"]
    noun = exhibit.get("unit") or "agents"
    clause = _window_clause(exhibit)
    template = f"The {noun}{clause}: {{{handle}}}."
    return {
        "template": template,
        "slots": [{"handle": handle, "rendering": "spoken"}],
    }


def _floor_record_span(exhibit: dict[str, Any]) -> DrafterProposal:
    """One record span — a single named fact rendered through its slot. The
    template states what the record is (from its unit) and lets the exhibit's
    deterministic ``spoken`` sentence-fragment speak the value — never a
    serialized structure (a ``raw`` slot over a structured value dies at the
    gate)."""
    handle = exhibit["handle"]
    unit = exhibit.get("unit")
    if unit:
        template = f"The {unit} is {{{handle}}}."
    else:
        template = f"{{{handle}}}."
    return {
        "template": template,
        "slots": [{"handle": handle, "rendering": "spoken"}],
    }


_FLOOR_BY_KIND: dict[str, Callable[[dict[str, Any]], DrafterProposal]] = {
    "count": _floor_count_span,
    "list": _floor_list_span,
    "record": _floor_record_span,
}


def _floor(exhibits: list[dict[str, Any]]) -> list[DrafterProposal]:
    """The deterministic floor: one span per exhibit, in the exhibits' order,
    capped at three spans. Always available, always digit-free."""
    proposals: list[DrafterProposal] = []
    for exhibit in exhibits[:_MAX_SPANS]:
        builder = _FLOOR_BY_KIND.get(exhibit.get("kind"))
        if builder is None:
            # Unknown kind: fall back to the barest structural span so the
            # exhibit still reaches the gate rather than being dropped silently.
            handle = exhibit["handle"]
            proposals.append(
                {
                    "template": f"{{{handle}}}.",
                    "slots": [{"handle": handle, "rendering": "raw"}],
                }
            )
            continue
        proposals.append(builder(exhibit))
    return proposals


# ---------------------------------------------------------------------------
# Redaction — the structural guarantee.
# ---------------------------------------------------------------------------

# Fields the model is never shown. It cannot leak a digit it never saw.
_REDACTED_FIELDS = ("value", "spoken", "anchor_sha256")


def _redact(exhibit: dict[str, Any]) -> dict[str, Any]:
    """A view of one exhibit with the value/spoken/anchor stripped — only handle,
    kind, unit, and query survive to reach the model."""
    return {k: v for k, v in exhibit.items() if k not in _REDACTED_FIELDS}


# ---------------------------------------------------------------------------
# LLM mode.
# ---------------------------------------------------------------------------

_PROMPT_HEADER = (
    "You are drafting the SHAPE of a sealed answer. Return STRICT JSON: a list of "
    "1 to 3 objects, each {\"template\": str, \"slots\": [{\"handle\": str, "
    "\"rendering\": \"spoken\"|\"raw\"}]}, in speaking order.\n"
    "HARD RULES:\n"
    "- Templates carry NO digits and NO number-words (no '17', no 'seventeen', no "
    "'dozen'). Every quantity arrives ONLY as a {handle} slot reference.\n"
    "- Use ONLY the handles listed below; each {handle} in a template must appear "
    "in that span's slots.\n"
    "- 'No' as a determiner is allowed for a zero result; spelled numbers are not.\n"
    "- Keep it plain and calm. One clause per exhibit.\n"
    "Return ONLY the JSON, nothing else."
)


def _build_prompt(
    exhibits: list[dict[str, Any]], question: str, retry_reason: str | None
) -> str:
    """Assemble the model prompt from REDACTED exhibits only. The model sees the
    question and each exhibit's handle/kind/unit/query — never a value."""
    redacted = [_redact(e) for e in exhibits]
    parts = [
        _PROMPT_HEADER,
        f"\nQUESTION: {question}",
        f"\nEXHIBITS (values withheld by design): {json.dumps(redacted, sort_keys=True)}",
    ]
    if retry_reason:
        parts.append(
            f"\nYour previous draft was REJECTED: {retry_reason}. "
            "Re-draft with the offending quantity moved into a {handle} slot."
        )
    return "".join(parts)


def _known_handles(exhibits: list[dict[str, Any]]) -> set[str]:
    return {e["handle"] for e in exhibits}


def _parse_and_validate(
    raw: str, handles: set[str]
) -> tuple[list[DrafterProposal] | None, str | None]:
    """Parse the model's JSON and structurally validate it, then lint every
    template. Returns ``(proposals, None)`` on success or ``(None, reason)`` with
    a machine-readable reason on any failure — malformed JSON, bad shape, an
    unknown handle, or a smuggled quantity."""
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, "malformed_json"

    if not isinstance(parsed, list) or not parsed:
        return None, "not_a_span_list"

    proposals: list[DrafterProposal] = []
    for span in parsed[:_MAX_SPANS]:
        if not isinstance(span, dict):
            return None, "span_not_object"
        template = span.get("template")
        slots = span.get("slots")
        if not isinstance(template, str) or not isinstance(slots, list):
            return None, "span_missing_fields"

        # The gate's lint owns the digit/number-word/malformed-brace/unknown-handle
        # rulings over the template's own text — a single source of truth.
        lint_reason = _lint_template(template, handles)
        if lint_reason is not None:
            return None, lint_reason

        clean_slots: list[dict[str, Any]] = []
        for slot in slots:
            if not isinstance(slot, dict):
                return None, "slot_not_object"
            handle = slot.get("handle")
            if handle not in handles:
                return None, "unknown_handle"
            rendering = slot.get("rendering")
            if rendering not in ("spoken", "raw"):
                # Default a missing/odd rendering to spoken rather than reject —
                # rendering is a hint, not a quantity.
                rendering = "spoken"
            clean_slots.append({"handle": handle, "rendering": rendering})

        proposals.append({"template": template, "slots": clean_slots})

    return proposals, None


def draft(
    question: str,
    exhibits: list[dict[str, Any]],
    llm: Callable[[str], str] | None = None,
) -> list[DrafterProposal]:
    """Propose 1-3 span skeletons (``{template, slots}``) in speaking order.

    With ``llm=None`` this is the deterministic floor — pattern templates built
    from each exhibit's redacted query, always digit-free and always available.

    With ``llm`` a callable ``(prompt) -> str``, the model drafts strict-JSON
    templates from REDACTED exhibits (it never sees a value). Each template is
    linted for smuggled digits/number-words; a lint or parse failure buys ONE
    retry with the reason appended, then the drafter falls back to the floor.

    The return is always the pre-gate skeleton: never a digit, never a value —
    only structure the gate will later fill with sealed renderings."""
    if not exhibits:
        return []

    if llm is None:
        return _floor(exhibits)

    handles = _known_handles(exhibits)

    # First attempt.
    try:
        raw = llm(_build_prompt(exhibits, question, retry_reason=None))
        proposals, reason = _parse_and_validate(raw, handles)
    except Exception:
        proposals, reason = None, "llm_call_failed"

    if proposals is not None:
        return proposals

    # One retry, with the failure reason fed back to the model.
    try:
        raw = llm(_build_prompt(exhibits, question, retry_reason=reason))
        proposals, _ = _parse_and_validate(raw, handles)
    except Exception:
        proposals = None

    if proposals is not None:
        return proposals

    # Model could not produce a clean draft twice — fall to the floor, which is
    # always correct and always digit-free.
    return _floor(exhibits)
