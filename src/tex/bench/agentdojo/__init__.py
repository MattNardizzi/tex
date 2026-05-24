"""
AgentDojo evaluation harness for Tex.

AgentDojo (NeurIPS 2024 Datasets and Benchmarks; Debenedetti et al.,
arxiv 2406.13352) is the dominant standardized benchmark for measuring
agent robustness against indirect prompt injection. It defines four
task suites (Banking, Slack, Travel, Workspace) with 97 tasks and 629
injection cases.

As of May 2026 the leaderboard shows:
- CaMeL: 67% utility, 23% targeted-attack success rate (provable upper
  bound 23%).
- DRIFT (arxiv 2410.04509): 75% utility, 12% ASR.
- AgentSys (arxiv 2602.07398, Feb 7 2026): 89.4% utility, 0.78% ASR.
- ASTRA (arxiv 2507.07417, May 2026): adaptive attacker; pushes
  SecAlign-tuned models back to 21% ASR.

Tex's published score
---------------------
Not yet measured. This harness is the integration that lets us run
AgentDojo against the live Tex PDP. The expensive part — actually
running 97 tasks × multiple injection cases × per-task LLM judging — is
gated behind a real LLM API key. We ship:

- A `PipelineDefense` adapter that wraps the Tex PDP as an
  AgentDojo-compatible defense.
- A `TexAgentPipeline` that mediates between AgentDojo's tool-calling
  loop and our specialist suite (so every model output passes through
  our seven streams before any tool fires).
- A smoke-test driver that runs 2 tasks with a stub model so the
  harness is verifiably working without API keys.
- A scoring CLI (`python -m tex.bench.agentdojo`) for running the
  full benchmark when keys are configured.

Smoke results emit evidence-chained JSONL to `var/agentdojo/`, one row
per task, with the per-step PDP verdict embedded. Each row joins the
existing Tex evidence chain via `prev_hash`.

Honest constraint
-----------------
A published leaderboard score requires API keys (per AgentDojo's
design — the benchmark needs a real frontier model to drive the
agent). Once `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is set in the
environment, `python -m tex.bench.agentdojo --model <model>` produces
a publishable number.

Reference: arxiv 2406.13352 AgentDojo; arxiv 2602.07398 AgentSys.
"""

from tex.bench.agentdojo.harness import (
    AgentDojoHarness,
    HarnessConfig,
    StubAgentModel,
    TaskOutcome,
)
from tex.bench.agentdojo.pipeline_defense import (
    TexPipelineDefense,
    PdpVerdict,
)

__all__ = [
    "AgentDojoHarness",
    "HarnessConfig",
    "PdpVerdict",
    "StubAgentModel",
    "TaskOutcome",
    "TexPipelineDefense",
]
