#!/usr/bin/env python3
"""
The Honest-Decline demo — Tex refuses and names the missing fact (CLI wrapper).

Run::

    PYTHONPATH=src python scripts/honest_decline_demo.py

Tex is asked to stand behind a moderate-stakes approval by an agent it has never
sealed any evidence about. It ABSTAINs and names the single fact whose absence
is the reason — engine output, not a script. The decline is itself sealed and
offline-verifiable. See ``tex.bench.honest_decline`` for the importable core.

Exit code 0 iff Tex declined, named a real missing fact, and sealed it.
"""

from __future__ import annotations

import logging
import os
import tempfile


def main() -> int:
    logging.disable(logging.CRITICAL)

    from tex.bench.honest_decline import DECLINE_QUESTION, run_honest_decline
    from tex.main import build_runtime

    work = tempfile.mkdtemp(prefix="tex-honest-decline-")
    runtime = build_runtime(evidence_path=os.path.join(work, "evidence.jsonl"))
    res = run_honest_decline(runtime, bundle_path=os.path.join(work, "decline.bundle.jsonl"))

    print("=" * 70)
    print("THE HONEST-DECLINE DEMO")
    print("=" * 70)
    print(f"\nQuestion to Tex : «{DECLINE_QUESTION}»")
    print("Agent           : one Tex has never sealed any evidence about")
    print(f"\nVerdict         : {res.verdict}")
    print(f"Declined        : {res.declined}")
    print(f"Pivotal flag    : {res.pivotal_flag}")
    print(f"Missing fact    : {res.named_missing_fact}")
    print(f"\nTex says        : {res.sentence}")
    print(f"                  {res.detail}")
    print(f"\nDecline sealed  : {res.sealed_record_count} record(s)")
    print("    " + res.verification.summary().replace("\n", "\n    "))
    for note in res.notes:
        print(f"\n    note: {note}")

    print("\n" + "=" * 70)
    print(f"HONEST DECLINE: {'PASSED' if res.passed else 'FAILED'}")
    print("=" * 70)
    return 0 if res.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
