"""
[Architecture: Tooling] — fuzz testing harness — runs AgentDojo, MCPSafeBench, AgentLAB, SIREN fixtures against the PDP. Tooling, not runtime.

See ARCHITECTURE.md for the full six-layer model.

Tex Adversarial Harness.

Stress-tests the live ``/v1/guardrail`` endpoint against curated fixture
sets from the major IPI benchmarks and produces a measured per-
specialist Attack Success Rate (ASR). This is what converts CLAIMS.md
from "we cite paper SOTA" to "we measure our own ASR against the same
benchmarks the papers do."

Benchmarks integrated
---------------------
- **AgentDojo** (Debenedetti et al.) — 97 user tasks × Important
  Instructions attack suite. Original paper ASR for undefended GPT-4o:
  18.0%. ClawGuard paper drops this to 0.6-3.1%; AgentArmor paper
  drops to 3%.
- **MCPSafeBench** (Wang & Yang, May 2026) — cross-domain MCP attack
  cases. Paper baseline 36.5-46.1%; ClawGuard drops to 7.1-11.2%.
- **AgentLAB** (arxiv 2602.16901) — 5 attack families: intent hijack,
  tool chain, task injection, objective drift, memory poisoning.
- **SIREN** (arxiv 2601.05755v2) — 959 tool-stream injection cases.
- **InjecAgent** (arxiv 2403.02691) — 1,054 cases, 17 user tools, 62
  attacker tools, Type I (tool hijack) + Type II (param hijack).
- **Adaptive attacks** (Nasr et al. October 2025) — 12-defense bypass
  patterns adapted to the Tex specialist stack.

Why this matters
----------------
Nasr et al. October 2025 demonstrated that 12 published IPI defenses
were bypassed at >90% ASR by adaptive attacks. Static-fixture testing
is necessary but not sufficient. The Tex harness ships:

  1. The static fixture suite for reproducible measurement against
     each paper's reported ASR.
  2. An adaptive-attack mutator that perturbs fixtures through paraphrase
     + obfuscation channels Nasr et al. flagged.

Usage
-----
::

    from tex.adversarial.fuzz_runner import FuzzRunner

    runner = FuzzRunner.against_test_client(client)  # FastAPI TestClient
    report = runner.run(suites=("agentdojo", "injecagent"))

    print(f"AgentDojo ASR: {report.per_suite['agentdojo'].asr:.1%}")
    print(f"Per-specialist contribution:")
    for spec, rate in report.per_specialist_block_rate.items():
        print(f"  {spec}: {rate:.1%}")

CI hook
-------
``scripts/run_adversarial.py`` ships a runnable entrypoint. The
intended cadence is nightly; results land in ``var/adversarial/*.json``
for trend tracking.

Performance
-----------
Each fixture is one ``/v1/guardrail`` call. With 50 fixtures per suite
and 5 suites, the full sweep is ~250 calls (≈ 30s at p95 = 150ms).

"""

from __future__ import annotations

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.adversarial import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'tooling'


from tex.adversarial.fuzz_runner import (
    FuzzRunner,
    FuzzReport,
    SuiteResult,
    AttackFixture,
)

__all__ = [
    "AttackFixture",
    "FuzzReport",
    "FuzzRunner",
    "SuiteResult",
]
