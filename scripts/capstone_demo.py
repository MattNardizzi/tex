#!/usr/bin/env python3
"""
THE CAPSTONE — one sealed verdict object + the replay-proof demo (CLI).

Run::

    PYTHONPATH=src python scripts/capstone_demo.py

One run does all of it (see ``tex.capstone`` for the importable core):

  1. drives the full mixed epoch through a REAL ledger-wired PDP
     (the PQ-claim resolution — env-dependent: ABSTAIN where no durable
     ML-DSA backend exists, PERMIT where pyca cryptography>=48 provides
     one; denied reflexive weakening, drift-breach ABSTAIN, the
     action-class FORBID, the seeded paraphrase neighborhood, the
     adaptive adversary campaign, the spoken seal) — only the LLM-provider
     seam is stubbed;
  2. composes the eight properties onto ONE sealed ``CapstoneVerdict``
     manifest, sealed into the verdict's own chain and witness-cosigned;
  3. re-verifies EVERYTHING offline from the bundle files + pins alone;
  4. runs the TAMPER MATRIX — eleven adversary rows, each caught and
     attributed to the RIGHT proof;
  5. folds in the Replay Trial and the Honest Decline as sub-demos.

Exit code 0 iff every positive claim verifies AND every tamper is caught
AND both sub-demos pass.

Honesty header: the composition is research-early. L1 rides a keyed-hash
stand-in under TEX_ZKPDP_ALLOW_SHIM=1 (never a proof); L2 is a test-mode
alg=none JWT; the L4/L12 certificates are certified=False pending a field
corpus; L12's QIF figure is a point estimate; L11's entailment half is
BLOCKED. The manifest carries each of those labels machine-readably — that
labelling IS the product bar, not a disclaimer.
"""

from __future__ import annotations

import logging
import os
import tempfile


def main() -> int:
    logging.disable(logging.CRITICAL)

    # The honest opt-ins, all named: M0 sealing + witness wiring for the
    # runtime sub-demos; shim/test-mode for the L1/L2 halves.
    os.environ["TEX_SEAL_DECISIONS"] = "1"
    os.environ["TEX_GIX_WITNESS"] = "1"
    os.environ["TEX_ZKPDP_ALLOW_SHIM"] = "1"
    os.environ["TEX_TEE_ATTESTATION_MODE"] = "test"

    from tex.capstone.flow import run_capstone_flow
    from tex.capstone.tamper import run_tamper_matrix
    from tex.capstone.verify import CapstonePins, verify_capstone

    work = tempfile.mkdtemp(prefix="tex-capstone-")
    print("=" * 72)
    print("THE CAPSTONE — one sealed verdict, eight properties, one replay")
    print("=" * 72)
    print(f"work dir: {work}")

    # ── 1+2: drive the epoch and compose ─────────────────────────────────
    flow = run_capstone_flow(
        work, neighborhood_samples=40, campaign_seeds=8, campaign_query_budget=60
    )
    manifest = flow.compose.manifest
    ledger = flow.materials.ledger
    print("\n[1] The epoch (one SealedFactLedger chain)")
    print(f"    sealed records   : {len(ledger)} (incl. the capstone fact)")
    print(
        f"    decision         : {manifest.decision.verdict} "
        f"request {manifest.decision.request_id}"
    )
    print(f"    manifest sha256  : {flow.compose.manifest_sha256}")
    print(f"    bundle dir       : {flow.bundle_dir}")
    l10 = manifest.property_for("L10")
    print(
        f"    PQ maturity      : {l10.verification.get('maturity_outcome')} "
        f"(backend {l10.verification.get('active_backend_id')!r})"
    )

    print("\n[2] The eight properties (honest split, machine-readable)")
    for status, leaps in manifest.honest_split.items():
        print(f"    {status:17}: {', '.join(leaps)}")

    # ── 3: offline verification from files + pins alone ──────────────────
    pins = CapstonePins.from_file(flow.pins_path)
    offline = verify_capstone(flow.bundle_dir, pins)
    print("\n[3] Offline verification (files + pins only)")
    print("    " + offline.summary().replace("\n", "\n    "))

    # The fail-closed pin: without the shim opt-in, L1 must REFUSE.
    closed = verify_capstone(flow.bundle_dir, pins, allow_shim=False)
    l1_closed = not closed.check("L1.relation").ok
    print(
        f"    fail-closed probe: L1 without TEX_ZKPDP_ALLOW_SHIM refuses = "
        f"{l1_closed} ({closed.check('L1.relation').detail.split(' ')[0]})"
    )

    # ── 4: the tamper matrix ──────────────────────────────────────────────
    rows = run_tamper_matrix(flow, os.path.join(work, "tamper"))
    print("\n[4] The tamper matrix — every attack caught, attributed right")
    for row in rows:
        mark = "CAUGHT" if row.caught else "MISSED"
        print(f"    [{mark}] {row.name}")
        print(f"             by: {', '.join(row.caught_by)}")
    all_caught = all(r.caught for r in rows)

    # ── 5: the in-tree sub-demos, not regressed ──────────────────────────
    from tex.bench.honest_decline import run_honest_decline
    from tex.bench.replay_trial import run_replay_trial
    from tex.main import build_runtime

    print("\n[5] Sub-demos (full runtime, separate evidence chains)")
    rt_work = os.path.join(work, "runtime")
    os.makedirs(rt_work, exist_ok=True)
    runtime = build_runtime(evidence_path=os.path.join(rt_work, "evidence.jsonl"))
    replay = run_replay_trial(
        runtime, bundle_path=os.path.join(rt_work, "replay.bundle.jsonl")
    )
    print(
        f"    replay trial     : {'PASSED' if replay.passed else 'FAILED'} "
        f"({replay.paraphrase_count} paraphrases, all FORBID={replay.all_forbid}, "
        f"byteflip caught={replay.tamper_byteflip_caught}, "
        f"resign caught={replay.tamper_resign_caught})"
    )
    runtime2 = build_runtime(
        evidence_path=os.path.join(rt_work, "evidence_decline.jsonl")
    )
    decline = run_honest_decline(
        runtime2, bundle_path=os.path.join(rt_work, "decline.bundle.jsonl")
    )
    print(
        f"    honest decline   : {'PASSED' if decline.passed else 'FAILED'} "
        f"(verdict={decline.verdict}, named missing fact="
        f"{bool(decline.named_missing_fact)})"
    )

    # ── verdict ───────────────────────────────────────────────────────────
    passed = (
        offline.ok and l1_closed and all_caught and replay.passed and decline.passed
    )
    print("\n" + "=" * 72)
    print(f"CAPSTONE DEMO: {'PASSED' if passed else 'FAILED'}")
    print(
        "  one object: the manifest's digest is sealed into the verdict's "
        "own chain;\n  the witnessed root covers it; everything above "
        "replayed offline from files + pins."
    )
    print("=" * 72)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
