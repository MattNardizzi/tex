#!/usr/bin/env python3
"""
Tex quickstart — one real verdict on your machine, zero configuration.

Run::

    python scripts/quickstart.py

No server, no database, no API key. The script drives two requests
through the real Tex engine in-process — a business-email-compromise
wire-transfer attempt (forbidden) and a routine follow-up email
(permitted) — then replays the forbidden decision from its evidence
record. Exit code 0 iff all three behaved as printed.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import textwrap
import time
from pathlib import Path

# Self-bootstrap: make a fresh `git clone` runnable with no PYTHONPATH.
# This file lives in scripts/, so parents[1] is the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

# The evidence ledger defaults to ./var/tex/evidence/evidence.jsonl
# (gitignored); run from the repo root so it always lands there.
os.chdir(_REPO_ROOT)

# The quickstart demonstrates the local development posture: in-process,
# anonymous. With TEX_API_KEYS unset the engine serves requests without
# auth in a development environment (and fails closed — 401 — in
# production postures; see src/tex/api/auth.py). Clearing these inherited
# variables keeps the demo deterministic regardless of the parent shell.
for _var in ("TEX_API_KEYS", "TEX_REQUIRE_AUTH", "TEX_APP_ENV"):
    os.environ.pop(_var, None)

# Quiet the structured request logs and dependency deprecation chatter
# so the verdict is what you see.
logging.disable(logging.CRITICAL)
import warnings  # noqa: E402

warnings.filterwarnings("ignore")

_WIDTH = 66
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def _rule() -> None:
    print("─" * _WIDTH)


def _quote(text: str) -> None:
    for line in textwrap.wrap(text, _WIDTH - 8):
        print(f'    {_c("2", line)}')


def _wrapped(text: str, indent: int = 4) -> None:
    pad = " " * indent
    for line in textwrap.wrap(text, _WIDTH - indent):
        print(pad + line)


BEC_EMAIL = (
    "URGENT - Wire $40,000 to a new vendor account I was just emailed "
    "about. CEO needs this settled before EOD, do not loop in finance."
)

CLEAN_EMAIL = (
    "Hi Jordan, following up on Tuesday's call - attaching the deck we "
    "discussed. Happy to walk through it whenever suits."
)


def _payload(content: str) -> dict:
    return {
        "stage": "pre_call",
        "action_type": "send_email",
        "channel": "email",
        "environment": "production",
        "recipient": "ap-team@example.com",
        "content": content,
        "source": "quickstart",
    }


def main() -> int:
    try:
        from fastapi.testclient import TestClient

        from tex.main import app
    except ImportError as exc:
        print(f"missing dependency: {exc.name or exc}")
        print()
        print("install first (about 20 seconds), then re-run:")
        print()
        print("    python3 -m venv .venv && . .venv/bin/activate")
        print("    pip install -r requirements.txt")
        print("    python scripts/quickstart.py")
        return 1

    client = TestClient(app)

    print()
    _rule()
    print("  TEX — first verdict")
    _rule()
    print()
    print("  An AI agent is about to send this email:")
    print()
    _quote(f'"{BEC_EMAIL}"')
    print()

    t0 = time.perf_counter()
    forbid = client.post("/v1/guardrail", json=_payload(BEC_EMAIL)).json()
    forbid_ms = (time.perf_counter() - t0) * 1000

    print(f"  Tex's verdict — real engine, this machine, just now:")
    print()
    verdict = forbid.get("verdict", "?")
    color = "31;1" if verdict == "FORBID" else "33;1"
    print(f'    {_c(color, verdict)} — {forbid.get("reason", "?")}'
          f'    ({forbid_ms:.1f} ms)')
    print()
    decisive = next(
        (f for f in forbid.get("asi_findings", [])
         if f.get("verdict_influence") == "decisive"),
        None,
    )
    if decisive is not None:
        print("    why, precisely:")
        _wrapped(decisive.get("counterfactual", ""), indent=6)
        print()

    t0 = time.perf_counter()
    permit = client.post("/v1/guardrail", json=_payload(CLEAN_EMAIL)).json()
    permit_ms = (time.perf_counter() - t0) * 1000

    print("  A routine follow-up email, for contrast:")
    print()
    _quote(f'"{CLEAN_EMAIL}"')
    print()
    pv = permit.get("verdict", "?")
    pcolor = "32;1" if pv == "PERMIT" else "33;1"
    fused = next(
        (r for r in permit.get("reasons", []) if r.startswith("Fused")), ""
    )
    print(f'    {_c(pcolor, pv)}    ({permit_ms:.1f} ms)')
    if fused:
        _wrapped(fused, indent=6)
    print()

    # Replay the forbidden decision from its evidence record — a claim
    # the script checks rather than makes.
    decision_id = forbid.get("decision_id", "")
    replay = client.get(f"/decisions/{decision_id}/replay")
    replay_ok = (
        replay.status_code == 200
        and replay.json().get("verdict") == forbid.get("verdict")
    )

    print("  The forbidden decision is already an evidence record on the")
    print("  local ledger (var/tex/evidence/evidence.jsonl), and replays:")
    print()
    print(f"    decision  {decision_id}")
    print(f'    replayed  {replay.json().get("verdict", "?")}'
          f"  — same verdict from the stored record: {replay_ok}")
    print()
    print("  Verify Tex without trusting Tex:")
    print()
    print(f'    {_c("1", "python scripts/verify_it_yourself.py")}')
    print()
    _wrapped(
        "It seals ten decisions, verifies the bundle offline, then "
        "tampers with it two ways — and shows you the verifier "
        "catching both. Exit code 0 means every claim held.",
        indent=4,
    )
    _rule()
    print()

    ok = (
        forbid.get("verdict") == "FORBID"
        and permit.get("verdict") == "PERMIT"
        and replay_ok
    )
    if not ok:
        print("  QUICKSTART CHECK FAILED — one of the three claims above")
        print("  did not hold on this run. Please open an issue with the")
        print("  full output:")
        print(json.dumps({"forbid": forbid, "permit": permit}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
