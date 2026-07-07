"""
The per-claim truth gate — the moat stage of the fluid-truth pipeline.

Every span the model authors passes through here before Tex will speak it.
The gate is deterministic and has no LLM anywhere. Its whole job is to make
one guarantee unbreakable: the only numbers that leave Tex's mouth are the
ones deterministic code computed and placed in an exhibit.

It enforces that in two moves. First ``lint_template`` refuses any template
that carries a digit or a number-word in its own prose — a template may
only get a number by referencing an exhibit slot. Second ``verify``
re-derives the span's text from the template and its exhibits and demands
byte-equality: if the model hand-edited a digit into ``text``, the derived
text won't match and the span dies. A span that cannot be sealed is never
downgraded to "spoken anyway" — it is dropped, and the router speaks a calm
ABSTAIN if every span died.

"no" and "none" are allowed: they are prose, not smuggled digits. A zero
count still arrives as an exhibit whose spoken form ("zero") lives inside a
slot, so it seals like any other truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from tex.answers.spans import Exhibit, Span

# The number-word lexicon a template's prose may NOT contain. Units, teens,
# tens, and the scale words — everything that spells a quantity. "no" and
# "none" are deliberately absent: they read as prose, not as smuggled digits.
_NUMBER_WORDS: frozenset[str] = frozenset(
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
        # Colloquial quantities — "a dozen actions" smuggles a count as surely
        # as "twelve". Vague hedges ("few", "several") and ordinals are
        # deliberately NOT here: they read as prose, and over-linting floors
        # legitimate drafts. The precise-quantity words are the contraband.
        "dozen",
        "dozens",
        "couple",
        "score",
    }
)

# Public alias: the drafter (and any future authoring layer) must share THIS
# lexicon — the gate is the final authority, so a private fork upstream can
# only ever be weaker. One list, one law.
NUMBER_WORDS = _NUMBER_WORDS

# Slot references: a handle in braces, e.g. "{e1}". Handles are word-safe
# tokens (letters, digits, underscore) — nothing that could hide a brace.
_SLOT_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")

# Any numeric character anywhere in the template's prose is forbidden — and
# "numeric" means Unicode-numeric, not ASCII: Arabic-Indic ٣, fullwidth ５,
# superscripts, fractions, Roman numerals, and CJK numerals are all smuggled
# quantities. str.isnumeric() covers the Nd/Nl/No categories plus numeric
# letters, which is the widest honest net Python offers.
def _contains_numeric(prose: str) -> bool:
    return any(ch.isnumeric() for ch in prose)

# Word tokens for the number-word scan, lowercased at match time.
_WORD_RE = re.compile(r"[A-Za-z]+")


@dataclass(frozen=True)
class LintResult:
    """Outcome of linting one template. ``reason`` is machine-readable."""

    ok: bool
    reason: str | None = None


def _strip_slots(template: str) -> str:
    """Return the template's prose with every ``{handle}`` slot removed."""

    return _SLOT_RE.sub(" ", template)


def lint_template(template: str, known_handles: frozenset[str] | set[str]) -> LintResult:
    """
    Reject any template that could speak a number the code did not compute.

    A clean template has no digits and no number-words in its prose, no
    malformed braces, and every slot references a handle we actually hold.
    Numbers may enter only through a well-formed slot. Rejection reasons are
    machine-readable: ``digit_in_template``, ``number_word_in_template``,
    ``malformed_slot``, ``unknown_handle:<handle>``.
    """

    # A lone brace means a slot the author botched; treat it as malformed so
    # a number can never leak through a half-written reference.
    prose = _strip_slots(template)
    if "{" in prose or "}" in prose:
        return LintResult(ok=False, reason="malformed_slot")

    if _contains_numeric(prose):
        return LintResult(ok=False, reason="digit_in_template")

    for match in _WORD_RE.finditer(prose):
        if match.group(0).lower() in _NUMBER_WORDS:
            return LintResult(ok=False, reason="number_word_in_template")

    for match in _SLOT_RE.finditer(template):
        handle = match.group(1)
        if handle not in known_handles:
            return LintResult(ok=False, reason=f"unknown_handle:{handle}")

    return LintResult(ok=True)


def _render_slot(exhibit: Exhibit, rendering: str) -> str | None:
    """Pull a slot's substitution value from its exhibit, deterministically.

    ``raw`` is legal ONLY for scalar values (int/str). A structured value
    (list/dict) has no honest raw voice — str() would serialize brackets,
    timestamps and ids into spoken text that no one sealed as speech. A raw
    slot over a structure returns None and the span dies; structures speak
    only through the exhibit's deterministic ``spoken`` rendering.
    """

    if rendering == "raw":
        if isinstance(exhibit.value, (int, str)):
            return str(exhibit.value)
        return None
    return exhibit.spoken


def fill(template: str, slots: list, exhibits: list[Exhibit]) -> str | None:
    """
    Substitute every ``{handle}`` in ``template`` from its exhibit.

    Pure and byte-deterministic. The slot list names the rendering
    ("spoken" or "raw") per handle; a handle present in the template but
    absent from ``exhibits`` (or from the slot list) makes the fill fail and
    return ``None`` — the gate never guesses a value.
    """

    exhibit_by_handle = {ex.handle: ex for ex in exhibits}
    rendering_by_handle = {slot.handle: slot.rendering for slot in slots}

    referenced = _SLOT_RE.findall(template)
    for handle in referenced:
        if handle not in exhibit_by_handle:
            return None
        if handle not in rendering_by_handle:
            return None
        # A rendering the exhibit cannot honestly voice (raw over a
        # structure) fails the whole fill — the span dies rather than
        # letting a serialized structure reach spoken text.
        if _render_slot(exhibit_by_handle[handle], rendering_by_handle[handle]) is None:
            return None

    def _sub(match: re.Match[str]) -> str:
        handle = match.group(1)
        exhibit = exhibit_by_handle[handle]
        rendered = _render_slot(exhibit, rendering_by_handle[handle])
        return rendered if rendered is not None else ""

    return _SLOT_RE.sub(_sub, template)


def _canonical(obj: object) -> bytes:
    """Canonical JSON, byte-stable across runs (matches the codebase style)."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _span_anchor(span: Span, exhibits: list[Exhibit]) -> str:
    """
    Compute the span's seal: sha256 over its canonical form + exhibit anchors.

    The digest binds the template, the ordered slots, the rendered text, and
    the anchors of exactly the exhibits the span references (sorted, so the
    digest does not depend on exhibit order). Two runs over the same span and
    exhibits yield the same anchor.
    """

    referenced = set(_SLOT_RE.findall(span.template))
    exhibit_anchors = sorted(
        ex.anchor_sha256 for ex in exhibits if ex.handle in referenced and ex.anchor_sha256
    )
    payload = {
        "template": span.template,
        "slots": [{"handle": s.handle, "rendering": s.rendering} for s in span.slots],
        "text": span.text,
        "exhibit_anchors": exhibit_anchors,
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def verify(span: Span, exhibits: list[Exhibit]) -> Span | None:
    """
    Seal a span, or let it die.

    Re-derive the text from the template and exhibits and require byte
    equality with ``span.text``. Every slot handle must resolve. On success
    return a new span carrying verdict SEALED, prosody "sealed", and a fresh
    ``anchor_sha256``. On any failure return ``None`` — the span is never
    downgraded to spoken-anyway.
    """

    derived = fill(span.template, span.slots, exhibits)
    if derived is None:
        return None
    if derived != span.text:
        return None

    sealed = span.model_copy(
        update={
            "verdict": "SEALED",
            "prosody": "sealed",
            "anchor_sha256": None,  # cleared so the digest never eats a stale seal
        }
    )
    sealed = sealed.model_copy(update={"anchor_sha256": _span_anchor(sealed, exhibits)})
    return sealed


@dataclass(frozen=True)
class GateResult:
    """Survivors of the gate, and whether anything died along the way."""

    survivors: list[Span]
    anything_died: bool


def gate_all(spans: list[Span], exhibits: list[Exhibit]) -> GateResult:
    """
    Run every span through the gate.

    Templates are linted before verification: a template that smuggles a
    digit or number-word kills its span the same as a forged text does.
    Returns the surviving sealed spans in input order and a flag the router
    reads to decide whether to append an honest ABSTAIN (true when at least
    one span died).
    """

    known_handles = frozenset(ex.handle for ex in exhibits)
    survivors: list[Span] = []
    anything_died = False

    for span in spans:
        lint = lint_template(span.template, known_handles)
        if not lint.ok:
            anything_died = True
            continue
        sealed = verify(span, exhibits)
        if sealed is None:
            anything_died = True
            continue
        survivors.append(sealed)

    return GateResult(survivors=survivors, anything_died=anything_died)
