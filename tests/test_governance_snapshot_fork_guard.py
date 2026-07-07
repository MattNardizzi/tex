"""
Regression: the persisted governance-snapshot chain must never fork.

Render zero-downtime deploys briefly run TWO web instances over one
Postgres. Each holds the chain tip (``_last_chain_hash``) in per-process
memory, so during the overlap both can try to chain a child off the same
parent. The old flush was a plain INSERT — both children landed and the
persisted chain forked (prod, 2026-07-06; repaired by
scripts/repair_governance_snapshots.py).

These tests run real ``GovernanceSnapshotStore`` instances over one fake
Postgres that enforces exactly the guard semantics the real schema now
declares: at most one child per parent, at most one genesis (partial
unique indexes + ``INSERT ... ON CONFLICT DO NOTHING`` → rowcount 0).

The doctrine under test: the second writer REFUSES and re-links instead
of forking; history is never rewritten; a capture is never silently
dropped.
"""

from __future__ import annotations

import logging

import pytest

from tex.stores.governance_snapshots import GovernanceSnapshotStore

FAKE_DSN = "postgresql://fake-host/fake-db"

# Column order shared by _flush_capture's INSERT params and the store's
# SELECT list (they match on purpose).
_COL_SNAPSHOT_ID = 0
_COL_CAPTURED_AT = 1
_COL_PAYLOAD = 12
_COL_HASH = 14
_COL_PREV = 15


class FakeChainDb:
    """One shared 'Postgres' implementing the chain-guard semantics."""

    def __init__(self) -> None:
        self.rows: list[tuple] = []
        self.fail_inserts = False        # simulate an outage
        self.fail_guard_index = False    # simulate CREATE UNIQUE INDEX failing

    def try_insert(self, params: tuple) -> bool:
        row = list(params)
        # psycopg Jsonb wrapper → plain dict, like the driver would store it.
        row[_COL_PAYLOAD] = getattr(row[_COL_PAYLOAD], "obj", row[_COL_PAYLOAD])
        prev = row[_COL_PREV]
        for existing in self.rows:
            if existing[_COL_SNAPSHOT_ID] == row[_COL_SNAPSHOT_ID]:
                return False  # primary key
            if prev is None and existing[_COL_PREV] is None:
                return False  # genesis guard: at most one root
            if prev is not None and existing[_COL_PREV] == prev:
                return False  # parent guard: one child per parent
        self.rows.append(tuple(row))
        return True

    def rows_desc(self, limit: int) -> list[tuple]:
        # ORDER BY captured_at DESC, sequence DESC — insertion index is
        # the sequence.
        ordered = sorted(
            range(len(self.rows)),
            key=lambda i: (self.rows[i][_COL_CAPTURED_AT], i),
            reverse=True,
        )
        return [self.rows[i] for i in ordered[:limit]]

    def tip_hash(self) -> str | None:
        rows = self.rows_desc(1)
        return rows[0][_COL_HASH] if rows else None


class FakeCursor:
    def __init__(self, db: FakeChainDb) -> None:
        self._db = db
        self.rowcount = -1
        self._results: list[tuple] = []

    def execute(self, sql: str, params: tuple | None = None) -> None:
        db = self._db
        flat = " ".join(sql.split()).lower()
        if flat.startswith("insert into tex_governance_snapshots"):
            if db.fail_inserts:
                raise RuntimeError("simulated Postgres outage")
            self.rowcount = 1 if db.try_insert(params) else 0
        elif flat.startswith("select snapshot_hash from tex_governance_snapshots"):
            tip = db.tip_hash()
            self._results = [(tip,)] if tip is not None else []
        elif flat.startswith("select"):
            if "where snapshot_id" in flat:
                self._results = [
                    r for r in db.rows if r[_COL_SNAPSHOT_ID] == params[0]
                ]
            else:
                self._results = db.rows_desc(int(params[0]))
        else:
            # DDL (CREATE TABLE / ALTER / guard indexes)
            if db.fail_guard_index and "parent_uidx" in flat:
                raise RuntimeError(
                    "simulated: duplicate parents block the unique index"
                )

    def fetchall(self) -> list[tuple]:
        return list(self._results)

    def fetchone(self) -> tuple | None:
        return self._results[0] if self._results else None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConn:
    def __init__(self, db: FakeChainDb) -> None:
        self._db = db

    def cursor(self) -> FakeCursor:
        return FakeCursor(self._db)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture()
def chain_db(monkeypatch) -> FakeChainDb:
    db = FakeChainDb()
    monkeypatch.setattr(
        "tex.stores.governance_snapshots.psycopg.connect",
        lambda dsn, **kwargs: FakeConn(db),
    )
    return db


def _store() -> GovernanceSnapshotStore:
    return GovernanceSnapshotStore(dsn=FAKE_DSN)


def _payload(*, governed: int = 5) -> dict:
    return {
        "counts": {
            "total_agents": 10,
            "governed": governed,
            "ungoverned": 10 - governed,
            "partial": 0,
            "unknown": 0,
            "high_risk_total": 2,
            "high_risk_ungoverned": 1,
            "governed_with_forbids": 1,
        },
        "agents": [],
        "coverage_root_sha256": "root-abc",
        "signature_hmac_sha256": "sig-abc",
    }


class TestDeployOverlapForkRefusal:
    def test_second_writer_refuses_relinks_and_chain_stays_linear(
        self, chain_db, caplog
    ):
        store_a = _store()
        genesis = store_a.capture(governance_payload=_payload(governed=1))
        # The deploy overlap: B bootstraps while A is still live — both
        # now hold tip == genesis in per-process memory.
        store_b = _store()
        a1 = store_a.capture(governance_payload=_payload(governed=2))
        with caplog.at_level(logging.WARNING):
            b1 = store_b.capture(governance_payload=_payload(governed=3))
        # B's stale-tip insert refused and re-linked onto A's child —
        # this exact sequence used to fork the chain.
        assert b1["previous_snapshot_hash"] == a1["snapshot_hash"]
        assert "chain-fork refused" in caplog.text
        # Nothing lost, nothing rewritten: all three captures persisted.
        assert len(chain_db.rows) == 3
        persisted_hashes = {r[_COL_HASH] for r in chain_db.rows}
        assert persisted_hashes == {
            genesis["snapshot_hash"],
            a1["snapshot_hash"],
            b1["snapshot_hash"],
        }
        # A fresh reader replays the persisted chain intact.
        verdict = _store().verify_chain()
        assert verdict["intact"] is True
        assert verdict["checked"] == 3
        # Nothing was parked — the refusal healed in-line.
        assert store_b.pending_resync_count == 0
        # B's tip moved to its re-linked hash, so its next capture chains
        # cleanly without another refusal.
        b2 = store_b.capture(governance_payload=_payload(governed=4))
        assert b2["previous_snapshot_hash"] == b1["snapshot_hash"]
        verdict = _store().verify_chain()
        assert verdict["intact"] is True
        assert verdict["checked"] == 4

    def test_genesis_race_yields_one_root(self, chain_db):
        # Two empty-DB processes both believe they are genesis.
        store_a = _store()
        store_b = _store()
        root = store_a.capture(governance_payload=_payload(governed=1))
        second = store_b.capture(governance_payload=_payload(governed=2))
        assert root["previous_snapshot_hash"] is None
        # The second "genesis" refused and became the root's child.
        assert second["previous_snapshot_hash"] == root["snapshot_hash"]
        assert len(chain_db.rows) == 2
        verdict = _store().verify_chain()
        assert verdict["intact"] is True
        assert verdict["checked"] == 2

    def test_double_refusal_parks_loudly_and_reseeds_tip(
        self, chain_db, caplog, monkeypatch
    ):
        store_a = _store()
        store_a.capture(governance_payload=_payload(governed=1))  # genesis
        store_b = _store()  # holds tip == genesis
        a1 = store_a.capture(governance_payload=_payload(governed=2))

        # Make B's refusal re-read return a stale tip once so the retry
        # collides again (three-way race), then answer truthfully.
        real_read = GovernanceSnapshotStore._read_db_tip
        calls = {"n": 0}

        def stale_then_real(self):
            calls["n"] += 1
            if calls["n"] == 1:
                return None  # stale: retry becomes a second genesis → refused
            return real_read(self)

        monkeypatch.setattr(
            GovernanceSnapshotStore, "_read_db_tip", stale_then_real
        )
        with caplog.at_level(logging.WARNING):
            store_b.capture(governance_payload=_payload(governed=3))
        # Parked loudly — not persisted, not dropped, not forked.
        assert store_b.pending_resync_count == 1
        assert "refused twice" in caplog.text
        assert "NOT persisted" in caplog.text
        assert len(chain_db.rows) == 2
        # The tip re-seeded from Postgres, so B's next capture chains off
        # persisted reality (a1), not off the parked record.
        b_next = store_b.capture(governance_payload=_payload(governed=4))
        assert b_next["previous_snapshot_hash"] == a1["snapshot_hash"]
        assert len(chain_db.rows) == 3
        verdict = _store().verify_chain()
        assert verdict["intact"] is True
        assert verdict["checked"] == 3
        # The parked record's parent is taken for good: replay refuses
        # loudly and keeps it pending (operator/repair territory).
        with caplog.at_level(logging.ERROR):
            assert store_b.replay_pending() == 0
        assert store_b.pending_resync_count == 1
        assert "replay refused" in caplog.text


class TestFlushFailureSeam:
    def test_outage_parks_capture_and_replay_fills_the_hole(
        self, chain_db, caplog
    ):
        store = _store()
        store.capture(governance_payload=_payload(governed=1))  # genesis
        chain_db.fail_inserts = True
        with caplog.at_level(logging.ERROR):
            parked = store.capture(governance_payload=_payload(governed=2))
        # The capture was parked, not dropped — and said so loudly.
        assert store.pending_resync_count == 1
        assert "NOT persisted" in caplog.text
        assert len(chain_db.rows) == 1
        chain_db.fail_inserts = False
        # The old bug: _last_chain_hash had advanced past the failed
        # flush, so the next capture linked to an unpersisted hash and
        # the hole was permanent. The link still happens (the in-memory
        # chain stays coherent)...
        after = store.capture(governance_payload=_payload(governed=3))
        assert after["previous_snapshot_hash"] == parked["snapshot_hash"]
        assert len(chain_db.rows) == 2
        # ...but the parked record now fills the hole byte-identically.
        assert store.replay_pending() == 1
        assert store.pending_resync_count == 0
        assert len(chain_db.rows) == 3
        verdict = _store().verify_chain()
        assert verdict["intact"] is True
        assert verdict["checked"] == 3

    def test_replay_is_noop_when_nothing_pending(self, chain_db):
        store = _store()
        store.capture(governance_payload=_payload(governed=1))
        assert store.replay_pending() == 0


class TestGuardIndexBootstrap:
    def test_index_failure_keeps_durability_and_logs(self, chain_db, caplog):
        # A table still holding an unrepaired fork rejects the unique
        # index. That must degrade to "guard off + loud log", never to
        # "store falls back to in-memory".
        chain_db.fail_guard_index = True
        with caplog.at_level(logging.ERROR):
            store = _store()
        assert store.is_durable is True
        assert "guard index" in caplog.text
        assert "repair_governance_snapshots" in caplog.text
        store.capture(governance_payload=_payload(governed=1))
        assert len(chain_db.rows) == 1
