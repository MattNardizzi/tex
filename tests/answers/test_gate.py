"""
Tests for the per-claim truth gate — the moat stage.

The gate's one promise: the only numbers Tex speaks are the ones
deterministic code computed. These tests attack that promise from every
side — a forged text, an unknown handle, a digit or number-word smuggled
into the template — and each attack must kill the span. The honest cases
(a legit count, a zero count, the raw rendering) must seal, and the seal
must be byte-stable across runs.
"""

from __future__ import annotations

from tex.answers.gate import fill, gate_all, lint_template, verify
from tex.answers.spans import Exhibit, ExhibitQuery, Slot, Span


def _exhibit(handle: str, value, spoken: str, *, anchor: str | None = "a" * 64) -> Exhibit:
    """Build a count exhibit with a fixed anchor for deterministic tests."""

    return Exhibit(
        handle=handle,
        kind="count",
        value=value,
        spoken=spoken,
        unit="decisions",
        query=ExhibitQuery(tool="count_decisions", tenant="acme", verdict="FORBID"),
        anchor_sha256=anchor,
        computed_at="2026-07-06T12:00:00+00:00",
    )


def _span(template: str, text: str, slots: list[Slot]) -> Span:
    """Author a span pre-gate: verdict/prosody are placeholders the gate sets."""

    return Span(
        template=template,
        text=text,
        slots=slots,
        verdict="ABSTAIN",
        anchor_sha256=None,
        prosody="abstain",
    )


# --- lint_template -------------------------------------------------------


def test_digit_in_template_rejected() -> None:
    handles = {"e1"}
    result = lint_template("{e1} of 3 actions were forbidden.", handles)
    assert not result.ok
    assert result.reason == "digit_in_template"


def test_number_word_in_template_rejected() -> None:
    handles = {"e1"}
    result = lint_template("{e1} actions, seventeen of them, were forbidden.", handles)
    assert not result.ok
    assert result.reason == "number_word_in_template"


def test_no_and_none_allowed_as_prose() -> None:
    handles = {"e1"}
    # "no" and "none" are prose, not smuggled digits — they must pass lint.
    assert lint_template("{e1} actions, none pending, no holds.", handles).ok


def test_unknown_handle_rejected_by_lint() -> None:
    handles = {"e1"}
    result = lint_template("{e2} actions were forbidden.", handles)
    assert not result.ok
    assert result.reason == "unknown_handle:e2"


def test_malformed_slot_rejected() -> None:
    handles = {"e1"}
    result = lint_template("{e1} actions were {forbidden today.", handles)
    assert not result.ok
    assert result.reason == "malformed_slot"


def test_clean_template_passes() -> None:
    handles = {"e1"}
    assert lint_template("{e1} actions were forbidden today.", handles).ok


# --- fill ----------------------------------------------------------------


def test_fill_spoken_rendering() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e1", rendering="spoken")]
    out = fill("{e1} actions were forbidden today.", slots, exhibits)
    assert out == "seventeen actions were forbidden today."


def test_fill_raw_rendering() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e1", rendering="raw")]
    out = fill("Count is {e1}.", slots, exhibits)
    assert out == "Count is 17."


def test_fill_missing_exhibit_returns_none() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e2", rendering="spoken")]
    assert fill("{e2} actions.", slots, exhibits) is None


# --- verify --------------------------------------------------------------


def test_forged_text_dies() -> None:
    # Author claims a different digit than the exhibit renders — must die.
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e1", rendering="spoken")]
    span = _span("{e1} actions were forbidden today.", "eighteen actions were forbidden today.", slots)
    assert verify(span, exhibits) is None


def test_unknown_handle_dies() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e2", rendering="spoken")]
    span = _span("{e2} actions.", "seventeen actions.", slots)
    assert verify(span, exhibits) is None


def test_legit_span_seals() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e1", rendering="spoken")]
    span = _span("{e1} actions were forbidden today.", "seventeen actions were forbidden today.", slots)
    sealed = verify(span, exhibits)
    assert sealed is not None
    assert sealed.verdict == "SEALED"
    assert sealed.prosody == "sealed"
    assert sealed.anchor_sha256 is not None
    assert len(sealed.anchor_sha256) == 64


def test_zero_count_seals_not_abstains() -> None:
    # A zero count is a sealed truth. The digit lives inside the slot, so the
    # template's prose stays clean and the span seals like any other.
    exhibits = [_exhibit("e1", 0, "zero")]
    slots = [Slot(handle="e1", rendering="spoken")]
    span = _span("{e1} actions were forbidden today.", "zero actions were forbidden today.", slots)
    sealed = verify(span, exhibits)
    assert sealed is not None
    assert sealed.verdict == "SEALED"


def test_anchor_stable_across_runs() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    slots = [Slot(handle="e1", rendering="spoken")]
    span = _span("{e1} actions were forbidden today.", "seventeen actions were forbidden today.", slots)
    first = verify(span, exhibits)
    second = verify(span, exhibits)
    assert first is not None and second is not None
    assert first.anchor_sha256 == second.anchor_sha256


def test_anchor_independent_of_exhibit_order() -> None:
    e1 = _exhibit("e1", 17, "seventeen", anchor="1" * 64)
    e2 = _exhibit("e2", 3, "three", anchor="2" * 64)
    slots = [Slot(handle="e1", rendering="spoken"), Slot(handle="e2", rendering="spoken")]
    span = _span("{e1} forbidden and {e2} held.", "seventeen forbidden and three held.", slots)
    a = verify(span, [e1, e2])
    b = verify(span, [e2, e1])
    assert a is not None and b is not None
    assert a.anchor_sha256 == b.anchor_sha256


def test_anchor_changes_when_text_changes() -> None:
    # Same template, different sealed text (via different exhibit) → different seal.
    slots = [Slot(handle="e1", rendering="spoken")]
    tmpl = "{e1} actions were forbidden today."
    a = verify(_span(tmpl, "seventeen actions were forbidden today.", slots), [_exhibit("e1", 17, "seventeen")])
    b = verify(_span(tmpl, "three actions were forbidden today.", slots), [_exhibit("e1", 3, "three")])
    assert a is not None and b is not None
    assert a.anchor_sha256 != b.anchor_sha256


# --- gate_all ------------------------------------------------------------


def test_gate_all_survivors_and_death_flag() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    good = _span(
        "{e1} actions were forbidden today.",
        "seventeen actions were forbidden today.",
        [Slot(handle="e1", rendering="spoken")],
    )
    forged = _span(
        "{e1} actions were forbidden today.",
        "eighteen actions were forbidden today.",
        [Slot(handle="e1", rendering="spoken")],
    )
    result = gate_all([good, forged], exhibits)
    assert len(result.survivors) == 1
    assert result.survivors[0].verdict == "SEALED"
    assert result.anything_died is True


def test_gate_all_digit_template_killed() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    smuggled = _span(
        "{e1} of 99 actions were forbidden.",
        "seventeen of 99 actions were forbidden.",
        [Slot(handle="e1", rendering="spoken")],
    )
    result = gate_all([smuggled], exhibits)
    assert result.survivors == []
    assert result.anything_died is True


def test_gate_all_all_clean_nothing_dies() -> None:
    exhibits = [_exhibit("e1", 17, "seventeen")]
    good = _span(
        "{e1} actions were forbidden today.",
        "seventeen actions were forbidden today.",
        [Slot(handle="e1", rendering="spoken")],
    )
    result = gate_all([good], exhibits)
    assert len(result.survivors) == 1
    assert result.anything_died is False


# --- the reviewer's regression pack: the breaches that shipped green ------


def test_unicode_digits_rejected() -> None:
    """Arabic-Indic, fullwidth, superscript, and CJK numerals are all smuggled
    quantities — the lint's net is Unicode-numeric, not ASCII."""
    handles = {"e1"}
    for smuggle in ("٣ actions were forbidden.", "５ actions were forbidden.",
                    "² actions were forbidden.", "五 actions were forbidden."):
        result = lint_template(smuggle, handles)
        assert not result.ok, smuggle
        assert result.reason == "digit_in_template"


def test_colloquial_quantity_words_rejected() -> None:
    """'A dozen' smuggles a count as surely as 'twelve'."""
    handles = {"e1"}
    for smuggle in ("A dozen actions were forbidden.",
                    "A couple of actions were held.",
                    "Dozens were permitted."):
        result = lint_template(smuggle, handles)
        assert not result.ok, smuggle
        assert result.reason == "number_word_in_template"


def test_raw_rendering_over_structure_dies() -> None:
    """A raw slot over a structured value has no honest voice — str() would
    serialize brackets, ids and timestamps into speech nobody sealed. The
    fill fails and the span dies rather than downgrade."""
    listing = Exhibit(
        handle="e1",
        kind="list",
        value=[{"decision_id": "6a9f", "agent": "ops", "verdict": "FORBID",
                "at": "2026-07-07T01:41:54+00:00"}],
        spoken="ops",
        unit="decisions",
        query=ExhibitQuery(tool="list_decisions", tenant="acme", verdict="FORBID"),
        anchor_sha256=None,
        computed_at="2026-07-06T12:00:00+00:00",
    )
    filled = fill("The decisions: {e1}.", [Slot(handle="e1", rendering="raw")], [listing])
    assert filled is None
    span = _span("The decisions: {e1}.", "The decisions: whatever.",
                 [Slot(handle="e1", rendering="raw")])
    assert verify(span, [listing]) is None


def test_spoken_rendering_over_structure_seals() -> None:
    """The same structured exhibit speaks honestly through its deterministic
    spoken field."""
    listing = Exhibit(
        handle="e1",
        kind="list",
        value=[{"decision_id": "6a9f", "agent": "ops", "verdict": "FORBID",
                "at": "2026-07-07T01:41:54+00:00"}],
        spoken="ops",
        unit="decisions",
        query=ExhibitQuery(tool="list_decisions", tenant="acme", verdict="FORBID"),
        anchor_sha256=None,
        computed_at="2026-07-06T12:00:00+00:00",
    )
    slots = [Slot(handle="e1", rendering="spoken")]
    text = fill("The decisions: {e1}.", slots, [listing])
    assert text == "The decisions: ops."
    sealed = verify(_span("The decisions: {e1}.", text, slots), [listing])
    assert sealed is not None
    assert sealed.verdict == "SEALED"
