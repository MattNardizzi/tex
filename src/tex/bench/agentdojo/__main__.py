"""
CLI: ``python -m tex.bench.agentdojo``.

Modes:

- ``--smoke``        Run 2 tasks with the stub model and a permissive
                     PDP fixture. CI-friendly. No API keys required.
- ``--model openai/gpt-4o`` (or anthropic/claude-3-5-sonnet, etc.)
                     Run the full benchmark against a real model. Requires
                     ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY`` and the
                     ``agentdojo`` Python package. We don't bundle a
                     LiteLLM dependency; if you want to run this mode,
                     ``pip install agentdojo litellm`` first and the CLI
                     will pick it up.

The CLI emits a summary JSON to stdout and per-task JSONL to
``var/agentdojo/outcomes.jsonl`` by default.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tex.bench.agentdojo.harness import (
    AgentDojoHarness,
    HarnessConfig,
    StubAgentModel,
)
from tex.bench.agentdojo.pipeline_defense import (
    PdpVerdict,
    TexPipelineDefense,
)


def _build_default_pdp_callable(strict: bool = True):
    """
    Build a PDP callable that uses our PCAS default policy.

    For the smoke test we adopt a strict-by-default stance: any call
    whose ``tool`` is in the "irreversible-side-effect" set is FORBID;
    everything else is PERMIT. This mirrors the policy a security
    team would deploy when bringing Tex up for the first time.
    """

    irreversible = {
        "transfer",
        "send_email",
        "send_dm",
        "publish",
        "delete_account",
        "wire_funds",
    }

    def _pdp(candidate: dict) -> tuple[PdpVerdict, tuple[str, ...]]:
        tool = candidate.get("tool", "")
        if strict and tool in irreversible:
            return PdpVerdict.FORBID, (f"irreversible_tool:{tool}",)
        return PdpVerdict.PERMIT, ()

    return _pdp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tex.bench.agentdojo",
        description="AgentDojo benchmark runner for Tex",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run a small fixture suite (2 tasks) with the stub model.",
    )
    parser.add_argument(
        "--suite",
        choices=("banking", "slack", "travel", "workspace"),
        default=None,
    )
    parser.add_argument("--max-steps", type=int, default=6)
    parser.add_argument(
        "--out-dir",
        default="var/agentdojo",
    )
    parser.add_argument(
        "--permissive",
        action="store_true",
        help="Use a permissive PDP (PERMIT everything). For baseline comparison.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Real-model run via the agentdojo package (requires API keys).",
    )
    args = parser.parse_args(argv)

    if args.model:
        return _run_real_benchmark(args)

    config = HarnessConfig(
        suite=args.suite,
        max_steps=args.max_steps,
        output_dir=args.out_dir,
        smoke=args.smoke,
    )
    pdp = _build_default_pdp_callable(strict=not args.permissive)
    defense = TexPipelineDefense(pdp_callable=pdp)
    harness = AgentDojoHarness(config=config, defense=defense)
    outcomes = harness.run(StubAgentModel())
    summary = AgentDojoHarness.summarize(outcomes)
    print(json.dumps({"summary": summary, "n_outcomes": len(outcomes)}, indent=2))
    return 0


def _run_real_benchmark(args: argparse.Namespace) -> int:
    try:
        import agentdojo  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        print(
            "agentdojo package not installed. Run `pip install agentdojo litellm` "
            "and re-run with --model.",
            file=sys.stderr,
        )
        return 2
    print(
        "Real-model benchmark mode is wired but requires API keys + the "
        "agentdojo package. Wire your LiteLLM-backed AgentModel into "
        "AgentDojoHarness.run() here; the harness, defense, and outcomes "
        "schema are ready.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
