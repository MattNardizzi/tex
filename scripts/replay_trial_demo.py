#!/usr/bin/env python3
"""
The Replay Trial — Tex's flagship proof-of-superiority demo (CLI wrapper).

Run::

    PYTHONPATH=src python scripts/replay_trial_demo.py

Three claims, each verified by code (see ``tex.bench.replay_trial`` for the
importable core and the per-claim docstrings):

  1. A structural FORBID survives 10 paraphrases of the attack content.
  2. The PEP would block it (release iff PERMIT); the eBPF datapath is
     Linux-only and is honestly NOT executed here.
  3. The ten sealed decisions are offline-verifiable, and a tampered or
     re-signed forgery is caught.

Exit code 0 iff every claim held.
"""

from __future__ import annotations

import logging
import os
import tempfile


def main() -> int:
    # Quiet the structured request logs so the demo narrative is readable.
    logging.disable(logging.CRITICAL)

    from tex.bench.replay_trial import PARAPHRASES, run_replay_trial
    from tex.main import build_runtime

    work = tempfile.mkdtemp(prefix="tex-replay-trial-")
    evidence_path = os.path.join(work, "evidence.jsonl")
    bundle_path = os.path.join(work, "replay.bundle.jsonl")

    # Fresh runtime on an isolated evidence chain — the shared chain is untouched.
    runtime = build_runtime(evidence_path=evidence_path)
    res = run_replay_trial(runtime, bundle_path=bundle_path)

    print("=" * 70)
    print("THE REPLAY TRIAL")
    print("=" * 70)

    print("\n[1] Structural FORBID survives paraphrase")
    print(f"    {res.paraphrase_count} paraphrases of one refund-without-idcheck attack:")
    for content, verdict in zip(PARAPHRASES, res.verdicts):
        print(f"      {verdict:7}  «{content[:52]}»")
    print(f"    => all FORBID: {res.all_forbid}  (verdicts seen: {sorted(set(res.verdicts))})")

    print("\n[2] The PEP would block it")
    print(f"    release iff PERMIT -> released = {res.pep_released}  (FORBID never releases)")
    for note in res.notes:
        if note.startswith("kernel"):
            print(f"    {note}")

    print("\n[3] Offline, tamper-evident evidence")
    print(f"    sealed decisions : {res.sealed_record_count}")
    print(f"    bundle           : {res.bundle_path}")
    print("    " + res.clean_verification.summary().replace("\n", "\n    "))
    print(
        f"    tamper (byte-flip) caught : {res.tamper_byteflip_caught}  "
        f"{res.tamper_byteflip_codes}"
    )
    print(f"    tamper (re-sign)   caught : {res.tamper_resign_caught}")
    for note in res.notes:
        if note.startswith("tamper-then-resign"):
            print(f"    {note}")

    print("\n" + "=" * 70)
    print(f"REPLAY TRIAL: {'PASSED' if res.passed else 'FAILED'}")
    print("=" * 70)
    return 0 if res.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
