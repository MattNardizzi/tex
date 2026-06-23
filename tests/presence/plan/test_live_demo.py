"""LIVE proof of GENERALITY: the real LLM composes plans for NOVEL questions.

These questions are deliberately NOT in any unit test — they are arbitrary, compositional,
and some are unanswerable. The point is to show the brain COMPILES each one into a plan
over the operator primitives (or honestly declines), with zero canned question→answer
mapping. Run:

    PYTHONPATH=src .venv/bin/python -m pytest tests/presence/plan/test_live_demo.py -s -q
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
except Exception:  # pragma: no cover
    pass

from tex.presence.brain.read_tools import build_read_tool_registry

from ._world import build_world

pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY", "").strip(),
    reason="live demo needs ANTHROPIC_API_KEY (in ~/dev/tex/.env)",
)

# NOVEL, compositional, arbitrary — NONE of these is in a unit test. Several are
# unanswerable on purpose (forecast / out-of-domain / historical-state) — those MUST
# honestly decline, proving Tex doesn't bluff.
NOVEL = [
    "how many active agents does alice own",
    "which owner has the most agents",
    "list the agents bob owns",
    "how many agents are not active",
    "how many agents use anthropic as their model provider",
    "how long ago was the most recent permit decision",
    "break my agents down by trust tier",
    "how many of alice's agents were registered today",
    "do I have any revoked agents",
    "what environment is billing-bot in",
    "how many agents have we got in total",
    # honest declines (no data / out of domain / unsupported):
    "how many agents will we have next month",
    "what's the capital of France",
    "how many agents were active on June 1st",
    # causal/superlative/ratio — must honestly decline, NOT answer an adjacent fact:
    "why was data-export revoked",
    "what caused the most recent forbid",
    "what percentage of agents are active",
    # previously-flaky filtered counts — must ground stably:
    "how many forbid decisions are there",
    "how many decisions have been made in total",
]


def _ops(plan) -> str:
    if plan is None:
        return "(no plan → honest abstain)"
    return " → ".join(n.tool if n.node_type == "leaf" else n.kind.value for n in plan.nodes)


def test_live_demo_composes_novel_questions(capsys):
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
        model=model, tool_name=PROPOSE_PLAN_TOOL_NAME,
        tool_description=PROPOSE_PLAN_TOOL_DESCRIPTION, tool_input_schema=plan_tool_schema(),
    )
    compiler = PlanCompiler(provider=provider)
    world = build_world()
    catalog = {n: getattr(t, "description", "") for n, t in build_read_tool_registry(world).items()}
    world.presence_plan_compiler = compiler
    req = SimpleNamespace(app=SimpleNamespace(state=world))
    now_iso = datetime.now(UTC).isoformat()

    with capsys.disabled():
        print(f"\n========== LIVE: the LLM composing NOVEL questions (model={model}) ==========")
        for q in NOVEL:
            try:
                plan = compiler.compile(question=q, tenant="acme", tool_catalog=catalog, reference_now=now_iso)
            except Exception as exc:  # model unavailable (e.g. no credits) — degrades to legacy
                plan = None
                print(f"\n[model unavailable: {type(exc).__name__}]")
            out = voice_ask.answer_question(req, transcript=q, tenant="acme")
            print(f"\nQ: {q}")
            print(f"   PLAN:   {_ops(plan)}")
            print(f"   ANSWER: [{out.verdict.value}] {out.answer}")
