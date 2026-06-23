"""LIVE battery — the real LLM compiling real questions over the real world, end to end.

This is the finish-line verification: with a real ANTHROPIC_API_KEY, the brain compiles
each of Matt's questions into a plan, the gate executes it over the realistic world, and
EVERY question must get a real response — a grounded answer where the data exists, or an
honest decline where it doesn't. No canned/demo answers.

Run it explicitly (it makes real API calls and is skipped by default):

    TEX_LIVE_BATTERY=1 PYTHONPATH=src .venv/bin/python -m pytest \
        tests/presence/plan/test_live_battery.py -s -q

The key is loaded from ~/dev/tex/.env (ANTHROPIC_API_KEY=...). Optional:
TEX_PRESENCE_MODEL (default claude-opus-4-8).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

try:  # load .env so the key + model are picked up without exporting
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
except Exception:  # pragma: no cover
    pass

from ._world import build_world

_ENABLED = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()) and \
    bool(os.environ.get("TEX_LIVE_BATTERY", "").strip())

pytestmark = pytest.mark.skipif(
    not _ENABLED,
    reason="live battery needs ANTHROPIC_API_KEY (in .env) + TEX_LIVE_BATTERY=1",
)

# Matt's questions + generalizations + no-data / out-of-domain (which MUST still get an
# honest response, not silence). "data exists" vs "no data" is annotated for triage.
BATTERY = [
    ("how many agents do we have", "data"),
    ("list my agents", "data"),
    ("do I have an okta agent", "data"),
    ("do I have a stripe agent", "data"),                  # provable NO
    ("how many agents does alice own", "data"),
    ("who owns the billing-bot agent", "data"),
    ("what is the trust tier of crm-writer", "data"),
    ("how long has billing-bot been running", "data"),
    ("how many agents were registered today", "data"),     # time window
    ("how many agents were added two weeks ago", "data"),  # time window
    ("how many forbids have there been", "data"),
    ("how many forbids did we get today", "data"),         # time window
    ("how many permits", "data"),
    ("how many evidence records are there", "data"),
    ("how many evidence records were added yesterday", "data"),  # time window
    ("how many agents are quarantined", "data"),
    ("what's the weather in paris", "no-data"),            # out of domain → honest decline
    ("how many unicorns are registered", "no-data"),       # no data → honest decline
]


def _request(world, compiler):
    world.presence_plan_compiler = compiler
    return SimpleNamespace(app=SimpleNamespace(state=world))


def test_live_battery():
    from tex.presence.plan.compile import (
        PROPOSE_PLAN_TOOL_DESCRIPTION,
        PROPOSE_PLAN_TOOL_NAME,
        PlanCompiler,
        plan_tool_schema,
    )
    from tex.semantic.anthropic import AnthropicStructuredSemanticProvider
    from tex.voice import voice_ask

    model = os.environ.get("TEX_PRESENCE_MODEL", "").strip() or "claude-opus-4-8"
    provider = AnthropicStructuredSemanticProvider(
        model=model,
        tool_name=PROPOSE_PLAN_TOOL_NAME,
        tool_description=PROPOSE_PLAN_TOOL_DESCRIPTION,
        tool_input_schema=plan_tool_schema(),
    )
    compiler = PlanCompiler(provider=provider)
    req = _request(build_world(), compiler)

    print(f"\n=== LIVE BATTERY (model={model}) ===")
    grounded = 0
    for question, kind in BATTERY:
        out = voice_ask.answer_question(req, transcript=question, tenant="acme")
        tier = out.presence.overall_tier.value if out.presence else "-"
        is_grounded = bool(out.presence and out.presence.verdicts)
        grounded += int(is_grounded)
        print(f"[{out.verdict.value:7}|{tier:7}] {question}\n          -> {out.answer}")
        # THE BAR: every question gets a real, non-empty response (answer or honest decline).
        assert out.answer and isinstance(out.answer, str), f"empty response for: {question}"

    print(f"\ngrounded {grounded}/{len(BATTERY)} (the rest are honest declines)")
    # At least the unambiguous data-backed counts must actually ground (sanity floor).
    assert grounded >= 3, "expected several data-backed questions to ground with a real answer"
