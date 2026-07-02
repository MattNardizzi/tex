"""
Re-link the tex_discovery_ledger hash chain after a split-brain fork.

WHY THIS EXISTS
Render zero-downtime deploys briefly run TWO web instances. Both hold the
write-through in-memory chain, both append at the same ``sequence``, and the
old flush path's ``ON CONFLICT (sequence) DO UPDATE`` let the second writer
overwrite the first one's link — forking the chain. ``verify_chain()`` then
fails from the first interleaved record forward, and the vigil (honestly)
refuses to greet: "My evidence chain broke…".

WHAT IT DOES — and does NOT do
- Reads every surviving row in sequence order (payloads are preserved).
- Recomputes ``payload_sha256`` from each row's actual candidate+outcome
  using Tex's own canonicalization (the exact helpers ``verify_chain`` uses).
- Recomputes ``previous_hash``/``record_hash`` so every record links to its
  predecessor again.
- Writes only those three hash columns, in ONE transaction, under a
  Postgres advisory lock. Sequences, payloads, and ``appended_at`` are
  never touched.
- Does NOT invent, drop, or reorder records. This is a re-link of the
  surviving history, not a rewrite of it — and it prints the before/after
  tip hashes so the repair itself is auditable.

RUNBOOK (Render shell, repo root)
    PYTHONPATH=src python scripts/repair_discovery_ledger.py            # dry-run
    PYTHONPATH=src python scripts/repair_discovery_ledger.py --apply    # repair
Then RESTART the web service immediately: the running instance still holds
the pre-repair chain in memory, and any append it makes before restarting
would chain off a tip that no longer exists (re-breaking the tail).
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg

from tex.domain.discovery import CandidateAgent, ReconciliationOutcome
from tex.stores.discovery_ledger import _sha256_hex, _stable_json, _to_jsonable

# Arbitrary-but-stable advisory key so two repairs can't interleave.
_ADVISORY_KEY = 0x54455844495343  # "TEXDISC"

_SELECT = """
    SELECT sequence, candidate, outcome,
           payload_sha256, previous_hash, record_hash,
           appended_at
      FROM tex_discovery_ledger
     ORDER BY sequence ASC
"""

_UPDATE = """
    UPDATE tex_discovery_ledger
       SET payload_sha256 = %s,
           previous_hash  = %s,
           record_hash    = %s
     WHERE sequence = %s
"""


def _recompute(rows: list[tuple]) -> tuple[list[tuple], dict]:
    """Walk rows in sequence order; return (updates, report).

    ``updates`` holds (payload_sha256, previous_hash, record_hash, sequence)
    for every row whose stored triple differs from the recomputed one.
    """
    updates: list[tuple] = []
    first_divergence: tuple | None = None  # (sequence, appended_at)
    previous_hash: str | None = None
    old_tip: str | None = None
    new_tip: str | None = None

    for sequence, candidate_payload, outcome_payload, \
            stored_payload_sha, stored_prev, stored_record, appended_at in rows:
        # Same round-trip verify_chain() performs: JSONB -> model -> mode="json".
        candidate = CandidateAgent.model_validate(candidate_payload)
        outcome = ReconciliationOutcome.model_validate(outcome_payload)
        payload = {
            "candidate": _to_jsonable(candidate.model_dump(mode="json")),
            "outcome": _to_jsonable(outcome.model_dump(mode="json")),
        }
        payload_sha256 = _sha256_hex(_stable_json(payload))
        record_hash = _sha256_hex(
            _stable_json(
                {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
            )
        )

        stored = (stored_payload_sha, stored_prev, stored_record)
        computed = (payload_sha256, previous_hash, record_hash)
        if stored != computed:
            if first_divergence is None:
                first_divergence = (sequence, appended_at)
            updates.append((payload_sha256, previous_hash, record_hash, sequence))

        old_tip = stored_record
        new_tip = record_hash
        previous_hash = record_hash

    report = {
        "total": len(rows),
        "to_fix": len(updates),
        "first_divergence": first_divergence,
        "old_tip": old_tip,
        "new_tip": new_tip,
    }
    return updates, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the re-linked hashes (default is a read-only dry-run)",
    )
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        print("DATABASE_URL is not set — run this from the Render shell.", file=sys.stderr)
        return 2

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_KEY,))
            cur.execute(_SELECT)
            rows = cur.fetchall()

            updates, report = _recompute(rows)

            print(f"rows in ledger:        {report['total']}")
            print(f"rows needing re-link:  {report['to_fix']}")
            if report["first_divergence"] is not None:
                seq, at = report["first_divergence"]
                print(f"first divergence:      sequence {seq} (appended_at {at})")
            print(f"stored tip hash:       {report['old_tip']}")
            print(f"re-linked tip hash:    {report['new_tip']}")

            if not updates:
                print("chain already verifies — nothing to do.")
                return 0
            if not args.apply:
                print("dry-run only; re-run with --apply to repair.")
                return 1

            cur.executemany(_UPDATE, updates)
        conn.commit()

    # Fresh pass over the repaired table — trust the read-back, not our math.
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(_SELECT)
            _, after = _recompute(cur.fetchall())

    if after["to_fix"] == 0:
        print(f"repaired: {report['to_fix']} rows re-linked; chain is WHOLE.")
        print("now RESTART the web service so it re-bootstraps the repaired chain.")
        return 0
    print(
        f"repair incomplete: {after['to_fix']} rows still diverge — do not trust "
        "the chain; investigate before re-running.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
