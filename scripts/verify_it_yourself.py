#!/usr/bin/env python3
"""
Verify Tex without trusting Tex — zero-configuration wrapper.

Run::

    python scripts/verify_it_yourself.py              # the Replay Trial
    python scripts/verify_it_yourself.py --capstone   # the full capstone

This only bootstraps sys.path (so a fresh clone needs no PYTHONPATH) and
then runs the existing demo unchanged:

  * default   -> scripts/replay_trial_demo.py — seals ten decisions,
                 verifies the bundle offline, then byte-flips one record
                 and re-signs a forged one; both tampers must be caught.
  * --capstone -> scripts/capstone_demo.py — the full sealed verdict
                 object (eight properties, three chains) plus an
                 eleven-row tamper matrix. Read its honesty header: parts
                 of the composition run on labeled test-mode stand-ins.

Exit code 0 iff every claim held.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

# This file lives in scripts/, so parents[1] is the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

_TARGET = (
    "capstone_demo.py" if "--capstone" in sys.argv[1:] else "replay_trial_demo.py"
)

if __name__ == "__main__":
    sys.argv = [_TARGET]
    runpy.run_path(str(_REPO_ROOT / "scripts" / _TARGET), run_name="__main__")
