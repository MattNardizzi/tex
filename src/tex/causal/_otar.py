"""
OTAR parsing — Observation/Thought/Action/Result tuples per CHIEF §4.1.1.

Each Agent Node ``a ∈ V_agt`` in CHIEF's Hierarchical Causal Graph is
characterized by a structured ``⟨Observation, Thought, Action, Result⟩``
tuple, extended from the TAR schema (Bouzenia & Pradel, 2025) by the
addition of an explicit Observation field.

Reference: arxiv 2602.23701 §4.1.1; OTAR prompt in Appx. B.

Parser strategy
---------------
The CHIEF paper uses an LLM-based parser. For deterministic enforcement
in Tex we accept three trace shapes and parse them deterministically:

1. **Tex-native** — explicit ``observation`` / ``thought`` / ``action``
   / ``result`` keys. Pass-through.
2. **Who&When format** — ``{role, name, content}`` per
   https://github.com/ag2ai/Agents_Failure_Attribution. Roles
   ``"assistant"`` / ``"user"`` are mapped to OTAR fields by simple
   structural rules.
3. **Free-text content** — split on canonical markers (``Observation:``,
   ``Thought:``, ``Action:``, ``Result:``) when present; otherwise the
   whole content becomes ``action`` and the other fields are empty.

TODO(P1, arxiv:2602.23701 Appx.B): replace deterministic parser with an
LLM-based parser path when an LLM provider is wired into the causal
package; the LLM-based parser handles natural-language traces that this
deterministic parser cannot disentangle.
"""

from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict


class OTARTuple(BaseModel):
    """
    Frozen ⟨Observation, Thought, Action, Result⟩ tuple.

    Each field is a normalised string; empty strings are allowed when
    the underlying step did not surface that component (per the paper,
    the parser is best-effort).

    Reference: arxiv 2602.23701 §4.1.1, Bouzenia & Pradel 2025 (TAR).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation: str = ""
    thought: str = ""
    action: str = ""
    result: str = ""


# Canonical OTAR section markers (case-insensitive). Conservative set.
_OTAR_MARKERS: tuple[tuple[str, str], ...] = (
    ("observation:", "observation"),
    ("thought:", "thought"),
    ("action:", "action"),
    ("result:", "result"),
)


def parse_otar(step: Mapping[str, Any]) -> OTARTuple:
    """
    Parse a single trace step into an OTARTuple.

    Detection order:
      1. If the step has any of {observation, thought, action, result}
         as keys, treat it as Tex-native and read those fields directly.
      2. If the step has {role, name, content}, treat it as Who&When.
         Assistant content → ``thought`` + ``action``; user/tool content
         → ``observation`` + ``result``.
      3. Otherwise, parse marker-delimited free-text from ``content``,
         falling back to placing the whole text in ``action`` if no
         markers are found.

    Reference: arxiv 2602.23701 §4.1.1.
    """
    # Path 1: Tex-native
    native_keys = {"observation", "thought", "action", "result"}
    if any(key in step for key in native_keys):
        return OTARTuple(
            observation=_string(step.get("observation", "")),
            thought=_string(step.get("thought", "")),
            action=_string(step.get("action", "")),
            result=_string(step.get("result", "")),
        )

    # Path 2: Who&When format
    if {"role", "content"}.issubset(step.keys()):
        role = _string(step.get("role", "")).lower()
        content = _string(step.get("content", ""))

        # If markers are embedded in the content, prefer them — even on
        # Who&When traces the assistant sometimes emits structured logs.
        marker_parsed = _parse_markers(content)
        if marker_parsed is not None:
            return marker_parsed

        if role == "assistant":
            return OTARTuple(thought=content, action=content)
        # user / tool / system → observation channel
        return OTARTuple(observation=content, result=content)

    # Path 3: free-text content, marker-delimited
    content = _string(step.get("content", ""))
    marker_parsed = _parse_markers(content)
    if marker_parsed is not None:
        return marker_parsed

    return OTARTuple(action=content)


def _parse_markers(content: str) -> OTARTuple | None:
    """
    Split ``content`` on OTAR markers; return None if no marker present.

    Matches case-insensitively at line starts. Conservative: a single
    marker is sufficient to trigger marker-mode parsing.
    """
    if not content:
        return None

    lower = content.lower()
    if not any(marker in lower for marker, _ in _OTAR_MARKERS):
        return None

    # Walk lines, accumulate into the last-seen section.
    sections: dict[str, list[str]] = {
        "observation": [],
        "thought": [],
        "action": [],
        "result": [],
    }
    current: str | None = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        marker_field = _match_marker(line)
        if marker_field is not None:
            current = marker_field
            # Capture inline text after the marker.
            for marker, _ in _OTAR_MARKERS:
                if line.lower().startswith(marker):
                    inline = line[len(marker) :].strip()
                    if inline:
                        sections[current].append(inline)
                    break
            continue
        if current is not None and line:
            sections[current].append(line)

    return OTARTuple(
        observation=" ".join(sections["observation"]).strip(),
        thought=" ".join(sections["thought"]).strip(),
        action=" ".join(sections["action"]).strip(),
        result=" ".join(sections["result"]).strip(),
    )


def _match_marker(line: str) -> str | None:
    lower = line.lower()
    for marker, field in _OTAR_MARKERS:
        if lower.startswith(marker):
            return field
    return None


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
