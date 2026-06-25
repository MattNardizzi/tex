"""
Runnable entry: ``python -m tex.bench.exec_sota_bench_main``.

Runs the DoD-7 exec-SOTA mechanism benchmark (``exec_sota_bench.run_benchmark``)
through the REAL ``EvaluateActionCommand.execute()`` → pdp path, mechanisms ON vs
OFF, and prints a single deterministic JSON report.

To guarantee the ON and OFF passes do not contaminate each other through
process-global PDP state (agent behavioral history), ``run_benchmark`` runs each
pass in a FRESH subprocess. This same module is that subprocess: invoked with
``--single-pass '<json>'`` it runs exactly ONE pass in this process and prints
ONLY the pass result JSON to stdout (runtime logs are routed to stderr).

Deterministic re-run (the canonical command):

    PYTHONPATH=src python -m tex.bench.exec_sota_bench_main

Honest scope is printed in the report's ``scope`` field: this is the Tex-internal
mechanism benchmark over representative fixtures, NOT the external AgentDojo /
AgentDyn leaderboard.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _silence_runtime_logs() -> None:
    """Route tex's noisy boot logs to stderr so stdout carries ONLY the JSON
    result line (the parent subprocess parses stdout)."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    root.addHandler(handler)
    root.setLevel(logging.ERROR)
    logging.getLogger("tex").setLevel(logging.ERROR)


def _run_single_pass(payload: str) -> int:
    """Subprocess child: run exactly one pass and print its result JSON to stdout."""
    _silence_runtime_logs()
    from tex.bench.exec_sota_bench import BenchConfig, run_pass

    spec = json.loads(payload)
    config = BenchConfig(budget_b=int(spec.get("budget_b", 12)))
    result = run_pass(config, mechanisms_on=bool(spec["mechanisms_on"]))
    # Print ONLY the JSON on stdout — the parent reads the last {-line.
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tex.bench.exec_sota_bench_main",
        description=(
            "Tex-internal exec-SOTA mechanism benchmark (DoD-7): ASR + utility, "
            "mechanisms ON vs OFF, through the real pdp path. NOT the external "
            "AgentDojo/AgentDyn leaderboard."
        ),
    )
    parser.add_argument(
        "--budget-b",
        type=int,
        default=12,
        help="Cumulative value-budget B (TEX_BUDGET_CONFIDENTIAL_MAX). Default 12.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional path to also write the JSON report to.",
    )
    parser.add_argument(
        "--no-isolate",
        action="store_true",
        help=(
            "Run both passes in-process instead of in fresh subprocesses. Faster "
            "but the OFF pass may be contaminated by the prior ON pass (flagged in "
            "the report). The default isolates each pass in a subprocess."
        ),
    )
    parser.add_argument(
        "--single-pass",
        default=None,
        help=argparse.SUPPRESS,  # internal: the subprocess child entry
    )
    args = parser.parse_args(argv)

    if args.single_pass is not None:
        return _run_single_pass(args.single_pass)

    from tex.bench.exec_sota_bench import BenchConfig, run_benchmark

    config = BenchConfig(budget_b=args.budget_b)
    report = run_benchmark(config, isolate=not args.no_isolate)
    payload = json.dumps(
        {
            "config": report.config,
            "scope": report.scope,
            "metrics": report.metrics,
            "outcomes": report.outcomes,
        },
        indent=2,
        default=str,
    )
    print(payload)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
