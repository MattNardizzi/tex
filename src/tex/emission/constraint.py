"""
The ``DecoderConstraint`` builder — the pure, sealable core of the emission gate.

The emission gate is a THIRD, EARLIER enforcement point off the *same* sealed
``CapabilitySurface`` the discovery filter (``pep/proxy._filter_tools_list``) and
the capability stream (``agent/capability_evaluator``) already read: discovery →
**emission** → adjudication. Where adjudication *refuses* an emitted forbidden
call, the emission gate aims to make that call **un-emittable** — its tokens
masked before the sampler runs (Tex-hosted, Approach A) or stripped from the
request the provider decodes (provider-trusted, Approach B).

This module owns only the *pure* part: turning one ``CapabilitySurface`` into a
backend-neutral ``DecoderConstraint`` that the two actuators (``provider_rewrite``,
``vllm_mapping``) project, and the seal (``seal``) commits as proof. No I/O, no
mutation, fully unit-testable.

Design fork (the two genuinely distinct representations, attacked)
-----------------------------------------------------------------
**Chosen — a structured, backend-neutral constraint** (an allowlist set + per-tool
JSON schema + value regexes), projected into each backend's dialect at the edge.

**Rejected — pre-compile the surface into one grammar string** (an EBNF/CFG like
``"name":"(toolA|toolB)"``). Rejected for THIS codebase because (a) the constraint
must be sealed as a stable digest so a verdict can later prove "this turn was
decoded under allowlist H" — binding that digest to one grammar dialect (xgrammar
vs llguidance vs outlines differ) would make the replay backend-specific; and
(b) Approach B does not consume a grammar at all — it consumes a trimmed ``tools``
array + ``tool_choice``. The structured form seals the *policy*; each backend maps
it. Grammar generation, if ever needed, becomes a downstream projection of the
same structured object, not its internal representation.

Honest floor (read before relying on this)
-------------------------------------------
Covers ONLY the tool-emission actuator, ONLY where Tex owns or can constrain the
decoder, ONLY at name/shape granularity. A *permitted* tool can still semantically
launder (SSRF/exfil via a permitted ``http_get``); intent stays the PDP's +
specialists' job. The tool-name allowlist is the high-confidence floor
(``production``-grade as a mask); value-level regexes are ``research-early`` —
their soundness across BPE merges / token-healing / Unicode homoglyphs must be
adversarially fuzzed at the actuator, not assumed here.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.agent import CapabilitySurface

# The value "roles" this builder knows how to turn into a decode-time regex. Only
# ``recipient`` is derivable from the surface today (``allowed_recipient_domains``).
# Kept explicit so an unknown role is a loud error, never a silently-dropped
# constraint.
_RECIPIENT_ROLE = "recipient"


def _recipient_domain_regex(domains: tuple[str, ...]) -> str:
    """A regex matching an e-mail recipient whose domain is in ``domains``.

    Mirrors ``CapabilitySurface.permits_recipient`` for the *e-mail* shape: the
    domain must equal an allowed domain OR be a sub-domain of one
    (``x@sub.allowed.com`` passes for ``allowed.com``). Case-insensitive.

    Honest scope: this constrains the e-mail-recipient string shape only. URL
    recipients, display-name forms (``"Name" <a@b>``), and tokenizer-level
    soundness are NOT covered here — that is the ``research-early`` surface the
    module docstring names. A value the regex *accepts* is still subject to the
    PDP; the regex only narrows what is *typeable*.
    """
    alts = "|".join(re.escape(d) for d in sorted(set(domains)))
    return rf"(?i)^[^@\s]+@(?:[A-Za-z0-9-]+\.)*(?:{alts})$"


class DecoderConstraint(BaseModel):
    """A backend-neutral description of which tool calls are *emittable*.

    Produced purely from a ``CapabilitySurface`` by :func:`compile_constraint`.
    Frozen + ``extra="forbid"`` like every sealed Tex model, so its
    :meth:`canonical_payload` / :meth:`digest` are stable inputs to the seal.

    Fields
    ------
    allowed_tool_names:
        The permitted tool-name allowlist, sorted + de-duplicated. EMPTY means
        the surface declared *no* tool restriction (``CapabilitySurface`` treats
        an empty collection as "unrestricted" for that dimension) — see
        ``constrains_tool_names``, which states that honestly so the seal never
        claims a mask that was not applied.
    per_tool_json_schema:
        Optional per-tool argument schema (JSON-Schema fragments) used to shape
        ``arguments``. Empty unless the caller supplied ``tool_value_fields`` —
        the surface alone carries no per-tool argument schema, so the builder
        does not fabricate one.
    value_regexes:
        Value-role → regex (e.g. ``recipient`` → allowed-domain regex). The
        ``research-early`` tier.
    constrains_tool_names / constrains_values:
        Honesty flags: whether a name allowlist / any value regex was actually
        produced. The seal records these so "decoded under allowlist H" is only
        claimed when H actually masks something.
    surface_is_unrestricted:
        True when the source surface declared no restriction at all — recorded so
        a fully-open posture is visible in the proof, never mistaken for a mask.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_tool_names: tuple[str, ...] = Field(default_factory=tuple)
    per_tool_json_schema: dict[str, dict[str, Any]] = Field(default_factory=dict)
    value_regexes: dict[str, str] = Field(default_factory=dict)
    constrains_tool_names: bool = False
    constrains_values: bool = False
    surface_is_unrestricted: bool = False

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Whether ``tool_name`` may be emitted.

        When no name allowlist was declared (``constrains_tool_names`` is False)
        every name is allowed — the surface imposed no tool restriction, and this
        gate must not invent one. When an allowlist IS declared, membership is
        exact on the surface's normalized (casefolded) form.
        """
        if not self.constrains_tool_names:
            return True
        return tool_name.strip().casefold() in self.allowed_tool_names

    def canonical_payload(self) -> dict[str, Any]:
        """The ordered, JSON-safe dict the digest and seal commit.

        Deterministic regardless of input ordering: tool names are sorted, dict
        keys are emitted sorted by :func:`json.dumps(sort_keys=True)` at digest
        time. This is what makes "decoded under allowlist H" a *replayable* claim.
        """
        return {
            # Sorted so the digest treats the allowlist as a set — independent of
            # construction order, even for a directly-built constraint.
            "allowed_tool_names": sorted(self.allowed_tool_names),
            "per_tool_json_schema": self.per_tool_json_schema,
            "value_regexes": self.value_regexes,
            "constrains_tool_names": self.constrains_tool_names,
            "constrains_values": self.constrains_values,
            "surface_is_unrestricted": self.surface_is_unrestricted,
        }

    def digest(self) -> str:
        """A stable SHA-256 hex digest of the constraint — the allowlist ``H``.

        Two constraints built from equivalent surfaces (even with differently
        ordered ``allowed_tools`` inputs) share a digest; any change to the
        allowlist, schema, or value regex changes it. This is the value sealed so
        a verdict can prove *which* constraint a turn was decoded under.
        """
        canonical = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compile_constraint(
    surface: CapabilitySurface,
    *,
    tool_value_fields: Mapping[str, Mapping[str, str]] | None = None,
) -> DecoderConstraint:
    """Compile a ``CapabilitySurface`` into a ``DecoderConstraint``. Pure.

    Reads only the surface for the high-confidence floor:
      * ``allowed_tools`` → ``allowed_tool_names`` (the ``production`` tier).
      * ``allowed_recipient_domains`` → a ``recipient`` value regex
        (``research-early``).

    ``tool_value_fields`` is an OPTIONAL operator-supplied map
    ``{tool_name: {arg_field: role}}`` projecting a value regex onto a concrete
    tool argument (e.g. ``{"send_email": {"to": "recipient"}}``). It is a
    *separate* input on purpose: the surface alone cannot say *which* field of
    *which* tool carries a recipient, so binding that would be a fabrication. With
    it supplied, the builder emits a real per-tool JSON-Schema ``pattern`` so an
    out-of-domain recipient becomes un-typeable, not merely rejected.

    Raises ``ValueError`` on an unknown role — a mis-typed field map fails loud,
    never silently drops a constraint (fail-closed posture).
    """
    # The surface normalizes to casefolded, de-duped INSERTION order; an allowlist
    # is a set, so sort it here to make guided_choice/enum output deterministic and
    # the sealed digest independent of how the operator ordered allowed_tools.
    allowed = tuple(sorted(surface.allowed_tools))
    constrains_names = len(allowed) > 0

    value_regexes: dict[str, str] = {}
    if surface.allowed_recipient_domains:
        value_regexes[_RECIPIENT_ROLE] = _recipient_domain_regex(
            surface.allowed_recipient_domains
        )

    per_tool_json_schema: dict[str, dict[str, Any]] = {}
    if tool_value_fields:
        per_tool_json_schema = _project_value_fields(
            tool_value_fields,
            value_regexes=value_regexes,
            allowed_tool_names=allowed,
            constrains_names=constrains_names,
        )

    return DecoderConstraint(
        allowed_tool_names=allowed,
        per_tool_json_schema=per_tool_json_schema,
        value_regexes=value_regexes,
        constrains_tool_names=constrains_names,
        constrains_values=bool(value_regexes),
        surface_is_unrestricted=surface.is_unrestricted,
    )


def _project_value_fields(
    tool_value_fields: Mapping[str, Mapping[str, str]],
    *,
    value_regexes: Mapping[str, str],
    allowed_tool_names: tuple[str, ...],
    constrains_names: bool,
) -> dict[str, dict[str, Any]]:
    """Project value-role regexes onto concrete tool arguments as JSON Schema.

    Skips tools that are not in the name allowlist when one is present (a
    forbidden tool is stripped wholesale — shaping its arguments is moot). Raises
    on an unknown role so a typo cannot silently disable a value constraint.
    """
    schemas: dict[str, dict[str, Any]] = {}
    for raw_tool, field_roles in tool_value_fields.items():
        tool = raw_tool.strip().casefold()
        if constrains_names and tool not in allowed_tool_names:
            continue
        properties: dict[str, Any] = {}
        for field_name, role in field_roles.items():
            if role not in value_regexes:
                if role != _RECIPIENT_ROLE:
                    raise ValueError(
                        f"unknown value role {role!r} for {tool!r}.{field_name!r}; "
                        f"known roles: {sorted({_RECIPIENT_ROLE})}"
                    )
                # Known role, but the surface declared no domains to constrain it
                # with: emit no pattern rather than an empty (vacuously-true) one.
                continue
            properties[field_name] = {"type": "string", "pattern": value_regexes[role]}
        if properties:
            schemas[tool] = {"type": "object", "properties": properties}
    return schemas
