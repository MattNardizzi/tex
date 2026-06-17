#!/usr/bin/env python3
"""
Verify Tex without trusting Tex — zero-configuration wrapper.

Run::

    python scripts/verify_it_yourself.py                  # the Replay Trial
    python scripts/verify_it_yourself.py --capstone       # the full capstone
    python scripts/verify_it_yourself.py --anchor         # external proof-of-age
    python scripts/verify_it_yourself.py --forge-target   # verify the armed dare
    python scripts/verify_it_yourself.py --forge-target --ecdsa  # classical bundle

This only bootstraps sys.path (so a fresh clone needs no PYTHONPATH) and
then runs the existing demo unchanged:

  * default   -> scripts/replay_trial_demo.py — seals ten decisions,
                 verifies the bundle offline, then byte-flips one record
                 and re-signs a forged one; both tampers must be caught.
  * --capstone -> scripts/capstone_demo.py — the full sealed verdict
                 object (eight properties, three chains) plus an
                 eleven-row tamper matrix. Read its honesty header: parts
                 of the composition run on labeled test-mode stand-ins.
  * --anchor   -> scripts/anchor_demo.py — anchors a gix checkpoint
                 tree-head to a (local, offline) RFC 3161 TSA, verifies the
                 receipt offline against the pinned cert, and shows a forged
                 tree-head is rejected. Proves the verification logic with no
                 network; the real-TSA path is scripts/anchor_checkpoint.py.
  * --forge-target -> verifies the COMMITTED forge bundle against the
                 published out-of-band pin (forge/PUBKEY_STATEMENT.json),
                 printing the verdict mix and the pin fingerprint. Add
                 --ecdsa to verify the classical verify-anywhere bundle
                 instead of the composite post-quantum one.

Exit code 0 iff every claim held.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

# This file lives in scripts/, so parents[1] is the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))


def _run_forge_target() -> int:
    """Verify the committed forge bundle against its published out-of-band pin."""
    from tex.bench.forge_target import _main

    if "--ecdsa" in sys.argv[1:]:
        bundle = _REPO_ROOT / "forge" / "canonical_bundle.ecdsa.jsonl"
        pin = _REPO_ROOT / "forge" / "PUBKEY_STATEMENT.ecdsa.json"
    else:
        bundle = _REPO_ROOT / "forge" / "canonical_bundle.pq.jsonl"
        pin = _REPO_ROOT / "forge" / "PUBKEY_STATEMENT.json"
    return _main([str(bundle), str(pin)])


if __name__ == "__main__":
    if "--forge-target" in sys.argv[1:]:
        raise SystemExit(_run_forge_target())

    if "--anchor" in sys.argv[1:]:
        _TARGET = "anchor_demo.py"
    elif "--capstone" in sys.argv[1:]:
        _TARGET = "capstone_demo.py"
    else:
        _TARGET = "replay_trial_demo.py"
    sys.argv = [_TARGET]
    runpy.run_path(str(_REPO_ROOT / "scripts" / _TARGET), run_name="__main__")
