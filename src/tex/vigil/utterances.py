"""
[Architecture: Cross-cutting (Vigil cognition)] — authored utterance forms.

THE IRON RULE, ENFORCED HERE:

    Surprise chooses which sealed truths to speak. It never writes the
    words. The sentence forms below are authored and deterministic. They
    are filled ONLY from sealed slot values that trace to real data — every
    word traces to a hash. A witness whose claim is proof cannot have a
    mouth that improvises.

There is no template engine, no model call, no string concatenation from
free text. A line is produced solely by ``template.format(**sealed_slots)``
over a fixed, authored template. If a form's required slots are not present
in the sealed reading, the line is not spoken — the vigil stays silent
rather than guess. ``speaks_when`` gates lines that have nothing to say
this cycle (e.g. zero new agents): a dimension only becomes a candidate
utterance when it actually has sealed content to report.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["UtteranceForm", "FORMS", "fill"]


@dataclass(frozen=True, slots=True)
class UtteranceForm:
    """One authored sentence form bound to a dimension."""

    dimension: str
    template: str
    required_slots: tuple[str, ...]
    # Returns True iff this form has sealed content worth speaking.
    speaks_when: Callable[[dict[str, Any]], bool]


def _gt0(slots: dict[str, Any]) -> bool:
    return float(slots.get("count", 0) or 0) > 0


# The authored registry. One primary form per dimension. Evidence has two
# (intact / broken) selected by the sealed ``intact`` flag.
FORMS: dict[str, UtteranceForm] = {
    "discovery": UtteranceForm(
        dimension="discovery",
        template="Overnight, discovery brought {count} agents into view I had not seen before.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "identity": UtteranceForm(
        dimension="identity",
        template="{count} high-risk agents are acting outside governance.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "monitoring": UtteranceForm(
        dimension="monitoring",
        template="{count} connectors have stopped reporting.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "monitoring_single": UtteranceForm(
        dimension="monitoring",
        template="{connector} has gone {failures} cycles without reporting.",
        required_slots=("connector", "failures"),
        speaks_when=lambda s: float(s.get("count", 0) or 0) == 1 and bool(s.get("connector")),
    ),
    "execution": UtteranceForm(
        dimension="execution",
        template="I held back {count} actions tonight.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "human_decision": UtteranceForm(
        dimension="human_decision",
        template="{count} actions are waiting on your decision.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "evidence_intact": UtteranceForm(
        dimension="evidence",
        template="The evidence chain is whole across {length} sealed records.",
        required_slots=("length",),
        speaks_when=lambda s: bool(s.get("intact", True)),
    ),
    "evidence_broken": UtteranceForm(
        dimension="evidence",
        template="The evidence chain broke; {length} records no longer verify.",
        required_slots=("length",),
        speaks_when=lambda s: not bool(s.get("intact", True)),
    ),
    "learning": UtteranceForm(
        dimension="learning",
        template="{count} learning proposals are waiting for your review.",
        required_slots=("count",),
        # Retired: a pending calibration no longer speaks as a vigil line (that
        # was the proposals-list/notification pattern). Learning now surfaces
        # only as a calibration hold inside the Held state — one proposal at a
        # time, pull-only. The dimension reading still feeds the model of
        # normal; it just never becomes a spoken utterance.
        speaks_when=lambda s: False,
    ),
    # v5: authored counterfactual forms. Spoken ONLY when filled from a
    # sealed CausalAttributionPort.counterfactual() claim (provability gate).
    # Witness law: they recall what would have happened; they never advise.
    "execution_counterfactual": UtteranceForm(
        dimension="execution",
        template="Had I not held back those {count} actions, they would have reached the world unreviewed.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
    "identity_counterfactual": UtteranceForm(
        dimension="identity",
        template="Had governance not been watching, {count} high-risk agents would have acted unchecked.",
        required_slots=("count",),
        speaks_when=_gt0,
    ),
}


def select_form(dimension: str, slots: dict[str, Any]) -> UtteranceForm | None:
    """
    Choose the authored form for ``dimension`` given sealed slots.

    Returns None when no form has speakable content this cycle. Handles
    the dimensions that own more than one form (monitoring, evidence).
    """
    if dimension == "monitoring":
        single = FORMS["monitoring_single"]
        if single.speaks_when(slots):
            return single
        agg = FORMS["monitoring"]
        return agg if agg.speaks_when(slots) else None
    if dimension == "evidence":
        broken = FORMS["evidence_broken"]
        if broken.speaks_when(slots):
            return broken
        intact = FORMS["evidence_intact"]
        return intact if intact.speaks_when(slots) else None
    form = FORMS.get(dimension)
    if form is None:
        return None
    return form if form.speaks_when(slots) else None


def fill(form: UtteranceForm, slots: dict[str, Any]) -> str:
    """
    Produce the spoken line. IRON RULE enforcement point.

    Every required slot must be present in the sealed reading. The text is
    produced solely by formatting the authored template with sealed values.
    No other source of words exists.
    """
    missing = [s for s in form.required_slots if s not in slots]
    if missing:
        raise ValueError(
            f"refusing to speak: form for '{form.dimension}' is missing sealed "
            f"slots {missing}. The vigil does not improvise."
        )
    sealed = {k: slots[k] for k in form.required_slots}
    return form.template.format(**sealed)
