"""The LLM seam for /v1/answer — Claude UNDERSTANDS, the sealed floor SPEAKS.

One role, one law. The model gets exactly ONE job in the fluid-truth
pipeline, and it cannot put a value — or a word — in Tex's mouth:

* ROUTING — read the question (plus the prior exchange, for follow-ups) and
  choose which SEALED tool answers it: count / list / record / agents_count /
  agents_list, a verdict, a window. The worst a wrong routing can do is press
  the wrong TRUE button or abstain; it cannot fabricate, because every value
  still comes from the exhibit primitives and every span still dies at the
  byte-verify gate. The routing reply is constrained by a strict JSON schema
  (``output_config.format``) with enums — a malformed or off-menu decision is
  impossible at the API layer, not merely unlikely.

WHY THE MODEL DOES NOT DRAFT THE PROSE. The byte-verify gate confirms only
that the digit SLOTS fill identically; it does NOT check the sentence FRAME
around them. An LLM that authored the frame could assert a fabricated verdict,
window, or agent name in prose ("{e1} agents were forbidden today" over a
PERMIT-total count) and the gate would seal it — real digit, lying words. And
agent names are redacted before any drafter prompt, so a name the model
inlines is pure hallucination the gate cannot catch. So drafting stays with
the deterministic floor in :mod:`tex.answers.drafter`, which phrases ONLY from
each exhibit's own sealed query fields — prose that structurally cannot
contradict the record. Re-enabling an LLM drafter is a real build: it needs an
entailment/consistency check between the drafted template and the exhibit's
verdict/window/names before a span may seal. Until that guard exists, this
seam exposes ROUTING ONLY, and the answer route wires ``drafter.draft(...,
llm=None)`` unconditionally.

FAIL-OPEN, NEVER FAIL-BROKEN. ``build_seam_from_env`` returns ``None`` on any
missing dependency (no key, no package, opt-out) and ``route`` returns ``None``
on any wire fault — the route handler falls back to the deterministic regex
parse, so the keyless posture stays byte-identical and an Anthropic outage can
never silence /v1/answer.

Env contract (mirrors the presence-brain idiom in main.py):
  ANTHROPIC_API_KEY       — required for the seam to exist.
  TEX_ANSWER_LLM          — opt-OUT: "0"/"off"/"false"/"no" disables the seam
                            even with a key present. Default is ON with a key.
  TEX_ANSWER_MODEL        — model override; default claude-opus-4-8.
  TEX_ANSWER_LLM_TIMEOUT  — routing timeout seconds; default 6.0. The drafter
                            call gets 2x this (it writes a sentence, not a
                            token) before the drafter's own floor takes over.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

_logger = logging.getLogger("tex.answers.router_llm")

_DEFAULT_MODEL = "claude-opus-4-8"
_DEFAULT_ROUTE_TIMEOUT_SECONDS = 6.0
_ROUTE_MAX_TOKENS = 200

_MODEL_ENV = "TEX_ANSWER_MODEL"
_TOGGLE_ENV = "TEX_ANSWER_LLM"
_TIMEOUT_ENV = "TEX_ANSWER_LLM_TIMEOUT"
_OFF_VALUES = {"0", "off", "false", "no"}

# The COMPLETE routing vocabulary — every enum below names something the
# deterministic pipeline already implements. Adding a value here without a
# matching sealed tool would let the router promise a button that does not
# exist; the answer route validates against these sets again on receipt.
ROUTE_TOOLS = ("count", "list", "record", "agents_count", "agents_list", "none")
ROUTE_VERDICTS = ("FORBID", "PERMIT", "HELD", "ANY")
ROUTE_WINDOWS = (
    "today",
    "yesterday",
    "this week",
    "this month",
    "in total",
    "recent",
    "unsupported",
)

# Strict JSON schema for the routing decision. Enums + additionalProperties:
# false + required means the API's structured-output constraint guarantees a
# parseable, on-menu reply — the seam never has to trust model prose.
_ROUTE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tool": {"type": "string", "enum": list(ROUTE_TOOLS)},
        "verdict": {"type": "string", "enum": list(ROUTE_VERDICTS)},
        "window": {"type": "string", "enum": list(ROUTE_WINDOWS)},
    },
    "required": ["tool", "verdict", "window"],
    "additionalProperties": False,
}

# The router's whole worldview. Kept compact on purpose: this runs on every
# ask, so every token here is latency. It describes ONLY what exists.
_ROUTE_SYSTEM = (
    "You route questions for Tex, a governance witness that answers ONLY from "
    "sealed decision records. Choose which sealed tool answers the question; "
    "you never answer it yourself and never invent values.\n"
    "\n"
    "Tools:\n"
    "- count: how many decisions matched a verdict and a time window.\n"
    "- list: list matching decisions (by agent name).\n"
    "- record: one decision's full record — a specific decision id, or the "
    "latest / most recent / last decision.\n"
    "- agents_count: how many agents are running.\n"
    "- agents_list: name the agents.\n"
    "- none: no tool answers this question.\n"
    "\n"
    "Verdicts: FORBID (blocked, denied, stopped), PERMIT (allowed, approved), "
    "HELD (held, waiting on a human, abstained, pending), ANY (no verdict "
    "named).\n"
    "Windows: today, yesterday, this week, this month, in total, recent (no "
    "time stated), unsupported (a time range none of the others can express — "
    "e.g. 'last week', 'since March', a specific date).\n"
    "\n"
    "Rules:\n"
    "- Never stretch a tool to avoid none. If the question is not about the "
    "decisions, the agents, or their counts/lists/records, return none.\n"
    "- When a PRIOR exchange is given, resolve follow-ups against it: 'what "
    "about yesterday' keeps the prior tool and verdict and changes the window; "
    "'and permitted?' keeps the tool and window and changes the verdict; "
    "'list them' turns the prior count into a list.\n"
    "- The window must reflect the question's own words. unsupported beats a "
    "wrong guess — Tex abstains honestly rather than answer a window it "
    "cannot compute."
)


def _route_user_content(
    question: str, prior_question: str | None, prior_answer: str | None
) -> str:
    parts: list[str] = []
    if prior_question:
        parts.append(f"PRIOR QUESTION: {prior_question}")
    if prior_answer:
        parts.append(f"PRIOR ANSWER: {prior_answer}")
    parts.append(f"QUESTION: {question}")
    return "\n".join(parts)


class AnswerLLM:
    """Transport-only routing seam: Tex owns prompts and validation, this owns
    the wire. Exposes ``route`` only — NOT a drafting callable — so the model
    can never author the prose the gate does not fully verify (see module
    docstring). ``client`` is duck-typed (anything with ``.messages.create``
    and ``.with_options``) so tests inject fakes without the network.
    """

    __slots__ = ("_client", "_model", "_route_timeout")

    def __init__(
        self,
        client: Any,
        model: str = _DEFAULT_MODEL,
        route_timeout: float = _DEFAULT_ROUTE_TIMEOUT_SECONDS,
    ) -> None:
        self._client = client
        self._model = model
        self._route_timeout = route_timeout

    def route(
        self,
        question: str,
        prior_question: str | None = None,
        prior_answer: str | None = None,
    ) -> dict[str, Any] | None:
        """Ask the model which sealed tool answers ``question``.

        Returns ``{"tool", "verdict", "window"}`` drawn strictly from the
        ROUTE_* vocabularies, or ``None`` on ANY fault — timeout, refusal,
        schema surprise, network — so the caller falls back to the regex
        parse. This method must never raise: routing is an upgrade, not a
        dependency.
        """
        try:
            response = self._client.with_options(
                timeout=self._route_timeout, max_retries=0
            ).messages.create(
                model=self._model,
                max_tokens=_ROUTE_MAX_TOKENS,
                system=_ROUTE_SYSTEM,
                messages=[
                    {
                        "role": "user",
                        "content": _route_user_content(
                            question, prior_question, prior_answer
                        ),
                    }
                ],
                output_config={
                    "format": {"type": "json_schema", "schema": _ROUTE_SCHEMA}
                },
            )
            if getattr(response, "stop_reason", None) == "refusal":
                return None
            text = "".join(
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
            )
            decision = json.loads(text)
            # Re-validate on receipt — the schema constraint should make this
            # unreachable, but the seam never trusts the wire more than once.
            if (
                not isinstance(decision, dict)
                or decision.get("tool") not in ROUTE_TOOLS
                or decision.get("verdict") not in ROUTE_VERDICTS
                or decision.get("window") not in ROUTE_WINDOWS
            ):
                return None
            return {
                "tool": decision["tool"],
                "verdict": decision["verdict"],
                "window": decision["window"],
            }
        except Exception as exc:  # noqa: BLE001 — fail-open by contract
            _logger.warning("answer llm route failed (falling back): %s", exc)
            return None


def build_seam_from_env() -> AnswerLLM | None:
    """Construct the live seam, or None — the keyless/opt-out/broken posture.

    Mirrors ``_build_presence_brain``: every missing dependency logs a warning
    and returns None so boot never fails and the deterministic floor carries
    the surface. The client itself is the official SDK with a tight timeout;
    retries stay at 0 because the architecture IS the retry (regex parse for
    routing, drafter floor for phrasing).
    """
    toggle = os.environ.get(_TOGGLE_ENV, "").strip().lower()
    if toggle in _OFF_VALUES:
        _logger.info("answer llm seam disabled by %s=%s", _TOGGLE_ENV, toggle)
        return None
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        _logger.info("answer llm seam off — ANTHROPIC_API_KEY is unset")
        return None
    try:
        from anthropic import Anthropic
    except ImportError:
        _logger.warning(
            "answer llm seam off — the anthropic package is not installed"
        )
        return None
    try:
        timeout = float(
            os.environ.get(_TIMEOUT_ENV, "") or _DEFAULT_ROUTE_TIMEOUT_SECONDS
        )
    except ValueError:
        timeout = _DEFAULT_ROUTE_TIMEOUT_SECONDS
    model = os.environ.get(_MODEL_ENV, "").strip() or _DEFAULT_MODEL
    try:
        client = Anthropic(api_key=api_key, timeout=timeout, max_retries=0)
    except Exception as exc:  # noqa: BLE001 — fail-open by contract
        _logger.warning("answer llm seam off — client construction failed: %s", exc)
        return None
    _logger.info("answer llm seam ON — model=%s timeout=%.1fs", model, timeout)
    return AnswerLLM(client, model=model, route_timeout=timeout)
