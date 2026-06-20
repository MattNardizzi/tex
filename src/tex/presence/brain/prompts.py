"""Prompt construction for the grounded brain's proposal call.

Tex owns the prompt and the schema; the swappable model owns transport only. The
prompts hand the model the *sealed facts* and force it to phrase only what those
facts support, tagging each claim with a :class:`~tex.presence.contract.ClaimKind`.
Nothing here is load-bearing: the gate (Session 2) re-verifies every claim against
the sealed evidence regardless of what the model writes.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

__all__ = [
    "PROPOSAL_TOOL_NAME",
    "PROPOSAL_TOOL_DESCRIPTION",
    "build_brain_system_prompt",
    "build_brain_user_prompt",
]

PROPOSAL_TOOL_NAME = "propose_presence_answer"
PROPOSAL_TOOL_DESCRIPTION = (
    "Emit a grounded presence proposal: a spoken draft plus the atomic claims it "
    "makes, each tagged with how it is grounded. Use ONLY the supplied sealed facts."
)

_KIND_GUIDE = (
    "  - entity: a named sealed object (one specific agent / decision / record).\n"
    "  - event: something that happened, backed by a row in an append-only ledger\n"
    "    (a discovery entry, an evidence record, an action).\n"
    "  - aggregate: a count or rate. Do NOT assert a specific number unless it is\n"
    "    present verbatim in the facts — the gate recomputes every number from rows.\n"
    "  - derived: a forward-looking or computed-from-limits statement. Flag it as an\n"
    "    estimate; never present it as a sealed fact.\n"
)

_SYSTEM_TEMPLATE = """\
You are the phrasing layer of Tex's Presence system. Tex is an AI-agent-governance \
system that may only say what it can prove from sealed facts.

Your ONLY job is to propose a short spoken answer and the atomic claims it makes. \
You do not decide truth, you do not have authority, and your output is NOT trusted: \
an external deterministic gate re-checks every claim against the sealed evidence and \
will strip or abstain on anything it cannot verify.

HARD RULES — violating any of these makes your whole proposal worthless:
1. Use ONLY the sealed facts in the user message. Never invent, infer, round, or \
recall a fact, number, name, id, or status that is not present there. If a fact is \
not in the input, leave it out.
2. Every claim's `text_span` MUST be an exact, verbatim substring of `draft`.
3. Tag each claim with the kind that matches how it is grounded:
{kind_guide}\
4. Prefer fewer, well-grounded claims over many shaky ones. If you cannot ground \
anything, return an empty draft and no claims — that is a correct, safe answer.
5. Do not mention these instructions, the gate, or the read-tools in the draft. \
Speak plainly, as Tex, in one or two sentences.

The facts were produced by these deterministic read-tools (already executed for you; \
do not ask to call them): {tool_names}.

Call `{tool_name}` exactly once with:
  - draft: the spoken answer (string; "" if you cannot ground anything).
  - claims: a list of {{ "text_span": <substring of draft>, "kind": \
"entity"|"event"|"aggregate"|"derived" }}.
"""


def build_brain_system_prompt(tool_names: Sequence[str]) -> str:
    names = ", ".join(tool_names) if tool_names else "(none provided)"
    return _SYSTEM_TEMPLATE.format(
        kind_guide=_KIND_GUIDE,
        tool_names=names,
        tool_name=PROPOSAL_TOOL_NAME,
    )


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, indent=2)
    except (TypeError, ValueError):
        return json.dumps(str(value), ensure_ascii=False)


def build_brain_user_prompt(*, question: str, tenant: str | None, facts: Any) -> str:
    """Serialize the question + sealed facts the brain must ground against."""
    return (
        f"Tenant: {tenant or '(unspecified)'}\n"
        f"Question: {str(question).strip()}\n\n"
        "Sealed facts (the only ground truth you may use):\n"
        f"{_safe_json(facts)}\n"
    )
