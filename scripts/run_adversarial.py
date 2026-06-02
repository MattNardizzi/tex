#!/usr/bin/env python3
"""
Tex Adversarial Fuzz Runner — CLI entry point.

Runs the curated benchmark fixture suites against the live FastAPI app
and prints a measured ASR report. Used both interactively and from
CI (nightly).

Usage:
  scripts/run_adversarial.py                       # all suites
  scripts/run_adversarial.py agentdojo injecagent  # specific suites
  TEX_SPECIALIST_LLM_MODE=tiered scripts/run_adversarial.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make `src/` importable when running from repo root.
_THIS = Path(__file__).resolve()
_REPO = _THIS.parent.parent
_SRC = _REPO / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from fastapi.testclient import TestClient  # noqa: E402

from tex.adversarial import FuzzRunner  # noqa: E402
from tex.adversarial.fixtures import known_suites  # noqa: E402
from tex.main import create_app  # noqa: E402


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args:
        unknown = [a for a in args if a not in known_suites()]
        if unknown:
            print(
                f"Unknown suite(s): {unknown}\n"
                f"Available: {known_suites()}",
                file=sys.stderr,
            )
            return 2
        suites = tuple(args)
    else:
        suites = None

    app = create_app()
    client = TestClient(app)
    runner = FuzzRunner.against_test_client(client)
    report = runner.run(suites=suites)
    print(report.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
