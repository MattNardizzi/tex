"""
Typed models for the fluid-truth answer pipeline ("Claude under oath").

These are the wire contracts the whole pipeline joins on. The doctrine they
enforce in shape: Tex may only speak values computed by deterministic code
from real rows. An ``Exhibit`` is a tool-computed fact — the model never
writes its digits. A ``Span`` is one sentence of the answer, bound to its
exhibits by a template whose only variables are exhibit handles. An
``AnswerResponse`` is the sealed transcript that reaches the caller.

A zero count is a sealed truth, not an abstention. ABSTAIN is calm and
first-class — a span that cannot be sealed dies rather than being spoken
anyway.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# The three tiers a span (or the whole answer) can carry. v1 emits only
# SEALED or ABSTAIN at the span level; DERIVED is reserved for a later stage
# that composes sealed exhibits into arithmetic the store did not hand us.
Verdict = Literal["SEALED", "DERIVED", "ABSTAIN"]

# Prosody is the lowercase mirror of the verdict; it drives /v1/speak?prosody=.
Prosody = Literal["sealed", "derived", "abstain"]

# How a slot pulls a value out of its exhibit: the humanized "spoken" form
# ("seventeen") or the machine "raw" form (the value cast to string).
SlotRendering = Literal["spoken", "raw"]


class ExhibitQuery(BaseModel):
    """
    The deterministic tool call that produced an exhibit's value.

    This is the provenance of a fact: which tool ran, scoped to which tenant,
    over which window. It is carried so the answer can be audited back to the
    exact query, never re-guessed from prose.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=200)
    tenant: str = Field(min_length=1, max_length=200)
    verdict: str | None = Field(default=None, max_length=50)
    since: str | None = Field(default=None, max_length=64)
    until: str | None = Field(default=None, max_length=64)
    window_label: str | None = Field(default=None, max_length=64)
    # Redaction-safe zero flag: the drafter never sees value/spoken, but a
    # zero count deserves the calm "No ..." phrasing — so the tool layer
    # discloses zero-ness here, in provenance, where no quantity can leak.
    is_zero: bool = Field(default=False)


class Exhibit(BaseModel):
    """
    A single tool-computed fact, sealed for one answer.

    ``value`` is what deterministic code measured; ``spoken`` is that same
    value humanized for the ear. The two must agree — the gate never renders
    a slot from anything but this exhibit. ``handle`` is stable only within
    the answer that carries it.
    """

    model_config = ConfigDict(extra="forbid")

    handle: str = Field(min_length=1, max_length=64)
    kind: Literal["count", "list", "record"]
    value: int | str | list[Any]
    spoken: str = Field(min_length=1)
    unit: str = Field(min_length=1, max_length=64)
    query: ExhibitQuery
    anchor_sha256: str | None = Field(default=None, max_length=64)
    computed_at: str = Field(min_length=1, max_length=64)


class Slot(BaseModel):
    """A template variable: which exhibit fills it, and in which rendering."""

    model_config = ConfigDict(extra="forbid")

    handle: str = Field(min_length=1, max_length=64)
    rendering: SlotRendering = "spoken"


class Span(BaseModel):
    """
    One sentence of the answer, bound to its exhibits.

    ``template`` carries slot references in braces and NO digits or
    number-words outside those slots — the gate enforces this. ``text`` is
    the template with every slot substituted from its exhibit. ``verdict``
    is assigned by the gate, never by the author; ``anchor_sha256`` is the
    sha256 over the span's canonical form plus its exhibits' anchors.
    """

    model_config = ConfigDict(extra="forbid")

    template: str = Field(min_length=1)
    text: str = Field(min_length=1)
    slots: list[Slot] = Field(default_factory=list)
    verdict: Verdict
    anchor_sha256: str | None = Field(default=None, max_length=64)
    prosody: Prosody


class AnswerResponse(BaseModel):
    """
    The sealed transcript for POST /v1/answer.

    ``spans`` are the surviving spans in speaking order; ``spoken_text`` is
    their texts concatenated. ``overall_tier`` is the weakest tier among the
    survivors, and ``abstain_reason`` is machine-readable when Tex declines.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    question: str
    spans: list[Span] = Field(default_factory=list)
    exhibits: list[Exhibit] = Field(default_factory=list)
    spoken_text: str = ""
    overall_tier: Verdict
    abstain_reason: str | None = None
