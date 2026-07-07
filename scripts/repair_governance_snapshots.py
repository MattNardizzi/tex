"""
Re-link the tex_governance_snapshots hash chain after a split-brain fork.

WHY THIS EXISTS
Render zero-downtime deploys briefly run TWO web instances. Each holds the
chain tip (``_last_chain_hash``) in per-process memory, and the snapshot
flush is a plain INSERT — so when both instances capture during the overlap
window, both children chain off the SAME parent and the persisted chain
forks. ``verify_chain()`` then fails at the second child forward, and the
vigil (honestly) refuses to greet: "My evidence chain broke…". This is the
governance-snapshot analog of the discovery-ledger fork repaired by
``repair_discovery_ledger.py``.

WHAT IT DOES — and does NOT do
- Reads every surviving row in chronological order (content is preserved).
- Recomputes ``previous_snapshot_hash``/``snapshot_hash`` so every snapshot
  links to its true predecessor again, using the exact canonicalization
  ``verify_chain`` uses (imported from the store, not re-implemented).
- Writes only those two hash columns, in ONE transaction, under a Postgres
  advisory lock — and COMMITS ONLY IF the freshly re-read chain verifies;
  otherwise it rolls back and reports.
- Counts, payloads, signatures, captured_at, tenant_id are never touched.
- Does NOT invent, drop, or reorder records. This is a re-link of the
  surviving history, not a rewrite of it — and it prints the before/after
  tip hashes so the repair itself is auditable.

RUNBOOK (repo root; DATABASE_URL in the environment)
    PYTHONPATH=src python scripts/repair_governance_snapshots.py            # dry-run
    PYTHONPATH=src python scripts/repair_governance_snapshots.py --apply    # repair
Then RESTART the web service immediately: the running instance still holds
the pre-repair tip in memory, and any capture it makes before restarting
would chain off a hash that no longer exists (re-breaking the tail).
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg

from tex.stores.governance_snapshots import (
    GovernanceSnapshotStore,
    _compute_snapshot_hash,
)

# Arbitrary-but-stable advisory key so two repairs can't interleave.
# Distinct from the discovery-ledger repair's key.
_ADVISORY_KEY = 0x544558534E4150  # "TEXSNAP"

_SELECT = """
    SELECT snapshot_id, captured_at, total_agents,
           governed, ungoverned, partial, unknown,
           high_risk_total, high_risk_ungoverned,
           governed_with_forbids,
           coverage_root_sha256, signature_hmac_sha256,
           payload, label,
           snapshot_hash, previous_snapshot_hash,
           scan_run_id, ledger_seq_start, ledger_seq_end,
           registry_state_hash, policy_version, tenant_id
      FROM tex_governance_snapshots
     ORDER BY captured_at ASC, sequence ASC
"""

_UPDATE = """
    UPDATE tex_governance_snapshots
       SET previous_snapshot_hash = %s,
           snapshot_hash          = %s
     WHERE snapshot_id = %s
"""


def _load_chain(cur) -> list[dict]:
    cur.execute(_SELECT)
    return [GovernanceSnapshotStore._row_to_record(row) for row in cur.fetchall()]


def _plan(chain: list[dict]) -> list[tuple[str, str | None, str]]:
    """Replay oldest→newest; return [(snapshot_id, new_prev, new_hash)] for
    every row whose stored link or hash disagrees with the true replay."""
    fixes: list[tuple[str, str | None, str]] = []
    previous_hash: str | None = chain[0].get("previous_snapshot_hash") if chain else None
    if chain and chain[0].get("previous_snapshot_hash") is not None:
        # Full-table replay should start at genesis (stored link None).
        # A non-None first link means the table doesn't start at genesis —
        # refuse rather than guess.
        raise SystemExit("first snapshot's previous_snapshot_hash is not NULL — refusing to replay a partial chain")
    for record in chain:
        # The store's own canonicalization — imported, not re-implemented.
        expected = _compute_snapshot_hash(record, previous_hash)
        stored_hash = record.get("snapshot_hash") or ""
        stored_prev = record.get("previous_snapshot_hash")
        if stored_hash != expected or stored_prev != previous_hash:
            fixes.append((record["snapshot_id"], previous_hash, expected))
        previous_hash = expected
    return fixes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--apply", action="store_true",
                        help="write the re-link (default is dry-run)")
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_ADVISORY_KEY,))

            chain = _load_chain(cur)
            if not chain:
                print("no snapshots — nothing to do")
                return 0
            tip_before = chain[-1].get("snapshot_hash", "")
            print(f"loaded {len(chain)} snapshots; tip {tip_before[:16]}…")

            fixes = _plan(chain)
            if not fixes:
                print("0 rows needing re-link — nothing to do")
                return 0

            by_id = {r["snapshot_id"]: r for r in chain}
            for snapshot_id, new_prev, new_hash in fixes:
                r = by_id[snapshot_id]
                print(
                    f"re-link {snapshot_id} captured_at={r['captured_at']} "
                    f"tenant={r.get('tenant_id')}\n"
                    f"    prev {str(r.get('previous_snapshot_hash'))[:16]}… → {str(new_prev)[:16]}…\n"
                    f"    hash {str(r.get('snapshot_hash'))[:16]}… → {new_hash[:16]}…"
                )

            if not args.apply:
                print(f"DRY RUN: {len(fixes)} row(s) would be re-linked. Re-run with --apply.")
                return 0

            for snapshot_id, new_prev, new_hash in fixes:
                cur.execute(_UPDATE, (new_prev, new_hash, snapshot_id))

            # Commit ONLY a chain that verifies: re-read inside the same
            # transaction and replay before deciding.
            repaired = _load_chain(cur)
            if _plan(repaired):
                conn.rollback()
                print("post-repair replay STILL broken — rolled back, nothing written", file=sys.stderr)
                return 1
            conn.commit()
            tip_after = repaired[-1].get("snapshot_hash", "")
            print(f"APPLIED: {len(fixes)} row(s) re-linked; tip {tip_before[:16]}… → {tip_after[:16]}…")
            print("RESTART the web service now — its in-memory tip predates this repair.")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
