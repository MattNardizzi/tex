"""Tests for the Drafter — the model writes the music, never the digits.

The invariants under test:
  * The floor is always available and always digit-free, across verdict x window.
  * Zero is a sealed truth with its own calm 'No ...' prose.
  * Templates never inline names or numbers — quantities live only in slots.
  * The model never sees a value (redaction is structural).
  * LLM mode: clean JSON passes; a digit-smuggling draft is retried then floored;
    malformed JSON is floored.
"""

from __future__ import annotations

import re

from tex.answers.drafter import (
    _BRACE_RE,
    _redact,
    _vendored_lint_template,
    draft,
)

# ---------------------------------------------------------------------------
# Exhibit fixtures (redacted-shape ready — value/spoken present so we can prove
# the drafter never surfaces them).
# ---------------------------------------------------------------------------


def _count_exhibit(handle="e1", verdict=None, window_label=None, unit="actions", is_zero=None):
    query = {
        "tool": "count_decisions",
        "tenant": "acme",
        "verdict": verdict,
        "since": None,
        "until": None,
        "window_label": window_label,
    }
    if is_zero is not None:
        query["is_zero"] = is_zero
    return {
        "handle": handle,
        "kind": "count",
        "value": 17,
        "spoken": "seventeen",
        "unit": unit,
        "query": query,
        "anchor_sha256": "deadbeef" * 8,
        "computed_at": "2026-07-06T12:00:00Z",
    }


def _list_exhibit(handle="e1", window_label=None, unit="agents"):
    return {
        "handle": handle,
        "kind": "list",
        "value": ["atlas-pay", "meridian", "orion"],
        "spoken": "atlas-pay, meridian, and orion",
        "unit": unit,
        "query": {
            "tool": "list_agents",
            "tenant": "acme",
            "verdict": None,
            "since": None,
            "until": None,
            "window_label": window_label,
        },
        "anchor_sha256": None,
        "computed_at": "2026-07-06T12:00:00Z",
    }


# Number-words and digits that must NEVER appear in template prose.
_NUM_WORDS = re.compile(
    r"\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
    r"thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|"
    r"billion|dozen)\b",
    re.IGNORECASE,
)


def _assert_no_digits_or_numberwords(proposals):
    """Every template's prose (slots stripped) must be free of digits and
    number-words, and must never inline an exhibit value."""
    for span in proposals:
        prose = _BRACE_RE.sub(" ", span["template"])
        assert not re.search(r"\d", prose), f"digit leaked: {span['template']!r}"
        assert not _NUM_WORDS.search(prose), f"number-word leaked: {span['template']!r}"
        # Values / spoken renderings must never appear literally.
        assert "seventeen" not in span["template"].lower()
        assert "17" not in span["template"]
        assert "atlas-pay" not in span["template"].lower()


def _assert_slots_reference_braces(proposals):
    """Each brace ref in a template must be backed by a slot entry."""
    for span in proposals:
        refs = set(_BRACE_RE.findall(span["template"]))
        slot_handles = {s["handle"] for s in span["slots"]}
        assert refs <= slot_handles, f"unbacked ref in {span['template']!r}"


# ---------------------------------------------------------------------------
# Floor mode — verdict x window matrix.
# ---------------------------------------------------------------------------


def test_floor_forbid_today():
    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("how many forbidden today", [ex], llm=None)
    assert len(spans) == 1
    assert spans[0]["template"] == "{e1} actions were forbidden today."
    _assert_no_digits_or_numberwords(spans)
    _assert_slots_reference_braces(spans)


def test_floor_permit_week():
    ex = _count_exhibit(verdict="PERMIT", window_label="this week")
    spans = draft("permits this week", [ex], llm=None)
    assert spans[0]["template"] == "{e1} actions were permitted this week."
    _assert_no_digits_or_numberwords(spans)


def test_floor_held_recent():
    ex = _count_exhibit(verdict="HELD", window_label="recent")
    spans = draft("held recently", [ex], llm=None)
    assert spans[0]["template"] == "{e1} actions were held for you recently."
    _assert_no_digits_or_numberwords(spans)


def test_floor_abstain_maps_to_held():
    ex = _count_exhibit(verdict="ABSTAIN", window_label="today")
    spans = draft("abstained today", [ex], llm=None)
    assert spans[0]["template"] == "{e1} actions were held for you today."


def test_floor_no_verdict_no_window():
    ex = _count_exhibit(verdict=None, window_label=None)
    spans = draft("count", [ex], llm=None)
    # Untyped tally, no time clause.
    assert spans[0]["template"] == "{e1} actions recorded."
    _assert_no_digits_or_numberwords(spans)


def test_floor_zero_forbid_today():
    ex = _count_exhibit(verdict="FORBID", window_label="today", is_zero=True)
    spans = draft("any forbidden today", [ex], llm=None)
    # Zero is a sealed truth — calm 'No ...' prose, not an apology, not ABSTAIN.
    assert spans[0]["template"] == "No actions were forbidden today."
    _assert_no_digits_or_numberwords(spans)
    # The slot still rides along so the gate authors the (zero) quantity.
    assert spans[0]["slots"] == [{"handle": "e1", "rendering": "spoken"}]


def test_floor_zero_permit_week():
    ex = _count_exhibit(verdict="PERMIT", window_label="this week", is_zero=True)
    spans = draft("permits this week", [ex], llm=None)
    assert spans[0]["template"] == "No actions were permitted this week."


def test_floor_zero_untyped():
    ex = _count_exhibit(verdict=None, window_label=None, is_zero=True)
    spans = draft("count", [ex], llm=None)
    assert spans[0]["template"] == "No actions were recorded."


def test_floor_list_names_never_inlined():
    ex = _list_exhibit(window_label="today")
    spans = draft("which agents today", [ex], llm=None)
    assert len(spans) == 1
    # Names are values — one SPOKEN slot (the exhibit's deterministic names
    # summary), purely structural template. A raw slot over a structured
    # value dies at the gate, so the drafter never proposes one.
    assert "atlas-pay" not in spans[0]["template"]
    assert spans[0]["template"] == "The agents today: {e1}."
    assert spans[0]["slots"] == [{"handle": "e1", "rendering": "spoken"}]
    _assert_no_digits_or_numberwords(spans)


def test_floor_caps_at_three_spans():
    exhibits = [_count_exhibit(handle=f"e{i}", verdict="FORBID") for i in range(5)]
    spans = draft("many", exhibits, llm=None)
    assert len(spans) == 3


def test_floor_empty_exhibits_returns_empty():
    assert draft("nothing", [], llm=None) == []


def test_floor_custom_unit():
    ex = _count_exhibit(verdict="FORBID", window_label="today", unit="transfers")
    spans = draft("transfers", [ex], llm=None)
    assert spans[0]["template"] == "{e1} transfers were forbidden today."


# ---------------------------------------------------------------------------
# Redaction — the model never sees a value.
# ---------------------------------------------------------------------------


def test_redact_strips_value_spoken_anchor():
    ex = _count_exhibit(verdict="FORBID")
    view = _redact(ex)
    assert "value" not in view
    assert "spoken" not in view
    assert "anchor_sha256" not in view
    assert view["handle"] == "e1"
    assert view["kind"] == "count"
    assert view["unit"] == "actions"
    assert view["query"]["verdict"] == "FORBID"


def test_llm_prompt_never_contains_value():
    """The prompt string handed to the model must not carry the exhibit's value,
    spoken rendering, or anchor — captured via the injected callable. Distinctive
    sentinels are used so they cannot collide with the prompt header's own
    'do-not-do-this' examples."""
    seen = {}

    def spy_llm(prompt):
        seen["prompt"] = prompt
        return '[{"template": "{e1} actions were forbidden today.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    ex["value"] = 424242
    ex["spoken"] = "fourhundredtwentyfourthousand"
    ex["anchor_sha256"] = "c0ffee" * 10
    draft("q", [ex], llm=spy_llm)
    assert "fourhundredtwentyfourthousand" not in seen["prompt"]
    assert "c0ffee" not in seen["prompt"]
    # The literal value must not reach the model.
    assert "424242" not in seen["prompt"]


# ---------------------------------------------------------------------------
# LLM mode — good JSON, digit-smuggling (retry then floor), malformed (floor).
# ---------------------------------------------------------------------------


def test_llm_good_json_passes_through():
    def good_llm(prompt):
        return '[{"template": "{e1} decisions were forbidden today.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=good_llm)
    assert spans == [
        {
            "template": "{e1} decisions were forbidden today.",
            "slots": [{"handle": "e1", "rendering": "spoken"}],
        }
    ]


def test_llm_digit_smuggle_retried_then_accepted():
    """A first draft that spells a number is rejected; the retry (fed the reason)
    returns a clean draft, which is accepted."""
    calls = []

    def flaky_llm(prompt):
        calls.append(prompt)
        if len(calls) == 1:
            # Smuggles the number-word 'seventeen' into prose.
            return '[{"template": "seventeen actions were forbidden today.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'
        return '[{"template": "{e1} actions were forbidden today.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=flaky_llm)
    assert len(calls) == 2
    # The retry prompt carries the machine-readable rejection reason.
    assert "number_word_in_template" in calls[1]
    assert spans[0]["template"] == "{e1} actions were forbidden today."


def test_llm_bare_digit_smuggle_retried_then_floored():
    """A model that smuggles a bare digit twice is floored — the floor is clean."""
    def stubborn_llm(prompt):
        return '[{"template": "17 actions were forbidden today.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=stubborn_llm)
    # Fell to the floor: deterministic, clean.
    assert spans[0]["template"] == "{e1} actions were forbidden today."
    _assert_no_digits_or_numberwords(spans)


def test_llm_malformed_json_floored():
    def broken_llm(prompt):
        return "this is not json at all {"

    ex = _count_exhibit(verdict="PERMIT", window_label="this week")
    spans = draft("q", [ex], llm=broken_llm)
    # Malformed twice → floor.
    assert spans[0]["template"] == "{e1} actions were permitted this week."


def test_llm_malformed_then_good_json():
    calls = []

    def recover_llm(prompt):
        calls.append(prompt)
        if len(calls) == 1:
            return "garbage"
        return '[{"template": "{e1} actions were permitted this week.", "slots": [{"handle": "e1", "rendering": "spoken"}]}]'

    ex = _count_exhibit(verdict="PERMIT", window_label="this week")
    spans = draft("q", [ex], llm=recover_llm)
    assert len(calls) == 2
    assert "malformed_json" in calls[1]
    assert spans[0]["template"] == "{e1} actions were permitted this week."


def test_llm_unknown_handle_floored():
    """A template referencing a handle no exhibit owns is rejected, then floored."""
    def invent_llm(prompt):
        return '[{"template": "{e99} actions were forbidden today.", "slots": [{"handle": "e99", "rendering": "spoken"}]}]'

    ex = _count_exhibit(handle="e1", verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=invent_llm)
    assert spans[0]["template"] == "{e1} actions were forbidden today."


def test_llm_raising_callable_floored():
    """If the injected callable raises, the drafter still returns the floor —
    the keyless posture is never worse than a broken vendor."""
    def raising_llm(prompt):
        raise RuntimeError("vendor down")

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=raising_llm)
    assert spans[0]["template"] == "{e1} actions were forbidden today."


def test_llm_empty_list_floored():
    def empty_llm(prompt):
        return "[]"

    ex = _count_exhibit(verdict="FORBID", window_label="today")
    spans = draft("q", [ex], llm=empty_llm)
    assert spans[0]["template"] == "{e1} actions were forbidden today."


def test_llm_caps_to_three_spans():
    def many_llm(prompt):
        spans = [
            f'{{"template": "{{e{i}}} actions were forbidden today.", "slots": [{{"handle": "e{i}", "rendering": "spoken"}}]}}'
            for i in range(5)
        ]
        return "[" + ",".join(spans) + "]"

    exhibits = [_count_exhibit(handle=f"e{i}", verdict="FORBID", window_label="today") for i in range(5)]
    spans = draft("q", exhibits, llm=many_llm)
    assert len(spans) == 3


# ---------------------------------------------------------------------------
# Vendored lint lexicon — parity guard.
# ---------------------------------------------------------------------------


def test_lint_passes_clean_template():
    assert _vendored_lint_template("{e1} actions were forbidden today.", {"e1"}) is None
    assert _vendored_lint_template("No actions were forbidden today.", {"e1"}) is None


def test_lint_catches_bare_digit():
    assert _vendored_lint_template("17 actions were forbidden.", {"e1"}) == "digit_in_template"


def test_lint_catches_number_word():
    assert (
        _vendored_lint_template("seventeen actions were forbidden.", {"e1"})
        == "number_word_in_template"
    )


def test_lint_allows_no_determiner():
    # "No" is a determiner, not a spelled quantity.
    assert _vendored_lint_template("No agents were held.", {"e1"}) is None


def test_lint_ignores_digits_inside_slots():
    # A handle like {e1} carries a digit in the ref; that must not trip the lint.
    assert _vendored_lint_template("{e1} were forbidden.", {"e1"}) is None


def test_lint_catches_unknown_handle():
    assert (
        _vendored_lint_template("{e9} were forbidden.", {"e1"})
        == "unknown_handle:e9"
    )


def test_lint_catches_malformed_brace():
    assert _vendored_lint_template("{e1 were forbidden.", {"e1"}) == "malformed_slot"
