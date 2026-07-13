"""Counts derive from the DURABLE store — the deploy-survival pin.

The prod incident this pins against (2026-07-10): every Render deploy restarts
the process, the DurableDecisionStore's in-memory hot cache starts empty, and
"how many decisions today" answered zero while Postgres held 5,461 durable
rows. These tests prove the exhibits layer measures the store's durable read
(``count_matching`` / ``find_matching``) when one exists — so a fresh, empty
cache can never reset a spoken tally — and that an unreadable durable source
fails OPEN to the in-process cache scan (never an error, and a held row is
never hidden, only ever over-surfaced).
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta

from tex.answers.exhibits import (
    count_decisions,
    count_held_waiting,
    get_decision_record,
    list_decisions,
    list_held_waiting,
)
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore

from .test_exhibits import _decision


# ───────────────────────────────────────────────────────────────── fake stores
class _DeployFreshDurableStore:
    """Quacks like a DurableDecisionStore the moment after a deploy: the
    in-process cache is EMPTY (``list_all`` sees nothing) while Postgres still
    holds every row (the ``*_matching`` durable reads serve them). Captures the
    kwargs each durable read receives so tests can pin the exhibit→store
    contract (normalized verdict, concrete UTC bounds)."""

    def __init__(self, rows):
        self._durable = sorted(rows, key=lambda d: d.decided_at, reverse=True)
        self.count_calls: list[dict] = []
        self.find_calls: list[dict] = []

    def list_all(self):
        return ()  # the deploy emptied the cache

    def get(self, decision_id):
        return None  # cache miss, like any post-deploy get

    def count_matching(self, *, tenant_visible_to, verdict=None, since=None, until=None):
        self.count_calls.append(
            {
                "tenant_visible_to": tenant_visible_to,
                "verdict": verdict,
                "since": since,
                "until": until,
            }
        )
        return len(self._select(tenant_visible_to, verdict, since, until))

    def find_matching(
        self, *, tenant_visible_to, verdict=None, since=None, until=None, limit=None
    ):
        self.find_calls.append(
            {
                "tenant_visible_to": tenant_visible_to,
                "verdict": verdict,
                "since": since,
                "until": until,
                "limit": limit,
            }
        )
        rows = self._select(tenant_visible_to, verdict, since, until)
        return tuple(rows if limit is None else rows[:limit])

    def _select(self, tenant_visible_to, verdict, since, until):
        out = []
        for d in self._durable:
            row_tenant = d.tenant_id.casefold()
            if row_tenant not in (tenant_visible_to, "default"):
                continue
            if verdict is not None and d.verdict != verdict:
                continue
            if since is not None and d.decided_at < since:
                continue
            if until is not None and d.decided_at >= until:
                continue
            out.append(d)
        return out


class _FaultingDurableStore(InMemoryDecisionStore):
    """A durable store whose Postgres read path is DOWN: both durable reads
    raise. The in-memory scan underneath (InMemoryDecisionStore) is the cache
    the exhibits must fall back to."""

    def count_matching(self, **kwargs):
        raise RuntimeError("postgres unreachable")

    def find_matching(self, **kwargs):
        raise RuntimeError("postgres unreachable")


class _KeylessDurableStore(InMemoryDecisionStore):
    """A DurableDecisionStore in the keyless dev posture (DATABASE_URL unset):
    the durable reads exist but honestly answer ``None`` — not durable."""

    def count_matching(self, **kwargs):
        return None

    def find_matching(self, **kwargs):
        return None


# ─────────────────────────────────────────────── THE pin: counts survive deploy
def test_count_derives_from_durable_store_not_the_cache():
    """A deploy empties the cache; the spoken count must not reset with it."""
    now = datetime.now(UTC)
    store = _DeployFreshDurableStore(
        [
            _decision(verdict=Verdict.PERMIT, tenant="acme", decided_at=now, seed="p1"),
            _decision(verdict=Verdict.PERMIT, tenant="acme", decided_at=now, seed="p2"),
            _decision(verdict=Verdict.FORBID, tenant="acme", decided_at=now, seed="f1"),
        ]
    )
    assert store.list_all() == ()  # the cache is genuinely empty

    ex = count_decisions(store, "acme")
    assert ex["value"] == 3
    assert ex["spoken"] == "three"

    forbids = count_decisions(store, "acme", verdict="FORBID")
    assert forbids["value"] == 1


def test_held_waiting_derives_from_durable_store_not_the_cache():
    """The waiting queue — all three hold wires read it — survives a deploy."""
    now = datetime.now(UTC)
    store = _DeployFreshDurableStore(
        [
            _decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now, seed="a1"),
            _decision(
                verdict=Verdict.ABSTAIN,
                tenant="acme",
                decided_at=now - timedelta(hours=1),
                seed="a2",
            ),
        ]
    )
    assert store.list_all() == ()

    count = count_held_waiting(store, "acme")
    assert count["value"] == 2

    listing = list_held_waiting(store, "acme")
    assert len(listing["rows"]) == 2
    assert all(row["decision_id"] for row in listing["rows"])


def test_last_recorded_derives_from_durable_store():
    now = datetime.now(UTC)
    newest = _decision(verdict=Verdict.PERMIT, tenant="acme", decided_at=now, seed="new")
    store = _DeployFreshDurableStore(
        [
            _decision(
                verdict=Verdict.FORBID,
                tenant="acme",
                decided_at=now - timedelta(hours=2),
                seed="old",
            ),
            newest,
        ]
    )

    record = get_decision_record(store, None, "acme")
    fields = dict(record["value"])
    assert fields["decision_id"] == str(newest.decision_id)


def test_list_derives_from_durable_store_newest_first():
    now = datetime.now(UTC)
    rows = [
        _decision(
            verdict=Verdict.PERMIT,
            tenant="acme",
            decided_at=now - timedelta(minutes=i),
            seed=f"r{i}",
        )
        for i in range(5)
    ]
    store = _DeployFreshDurableStore(rows)

    listing = list_decisions(store, "acme", limit=3)
    assert len(listing["value"]) == 3
    assert listing["value"][0]["decision_id"] == str(rows[0].decision_id)


# ─────────────────────────────────── the exhibit→durable-store query contract
def test_exhibits_pass_normalized_verdict_and_utc_bounds_to_durable_store():
    """The FLOOR owns window resolution and verdict normalization: the durable
    store must receive the store-vocabulary verdict (HELD ⇒ ABSTAIN) and a
    concrete tz-aware UTC lower bound — never a label to interpret."""
    store = _DeployFreshDurableStore([])
    count_decisions(store, "Acme", verdict="HELD", window_label="today")

    call = store.count_calls[-1]
    assert call["tenant_visible_to"] == "acme"  # casefolded by the floor
    assert call["verdict"] is Verdict.ABSTAIN  # HELD normalized, never a string
    assert call["since"] is not None
    assert call["since"].utcoffset() == timedelta(0)  # concrete UTC bound
    assert call["until"] is None


# ───────────────────────────────────────── fail-open: fall back, never hide
def test_count_falls_back_to_cache_scan_when_durable_read_faults():
    store = _FaultingDurableStore()
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", seed="c1"))
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", seed="c2"))

    ex = count_decisions(store, "acme")  # must not raise
    assert ex["value"] == 2


def test_held_waiting_fails_open_to_cache_scan_never_hidden():
    store = _FaultingDurableStore()
    store.save(_decision(verdict=Verdict.ABSTAIN, tenant="acme", seed="h1"))

    count = count_held_waiting(store, "acme")
    assert count["value"] == 1  # the hold still surfaces from the cache

    listing = list_held_waiting(store, "acme")
    assert len(listing["rows"]) == 1


def test_keyless_store_answers_from_cache_scan():
    """DATABASE_URL unset: durable reads honestly return None; the cache scan
    (the whole store, in this posture) is the answer."""
    store = _KeylessDurableStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", seed="k1"))

    ex = count_decisions(store, "acme", verdict="FORBID")
    assert ex["value"] == 1


# ──────────────────────────── the real store's SQL is tenant-scoped + windowed
# No live Postgres in the test default, so — like
# tests/presence/memory/test_tenant_isolation.py — we pin the property at the
# layer it lives in: the SQL actually handed to the driver.
class _FakeCursor:
    def __init__(self, rows=(), one=None):
        self.executed: list[tuple[str, tuple]] = []
        self._rows = list(rows)
        self._one = one
        self.itersize = None

    def execute(self, sql, params=None):
        self.executed.append((sql, tuple(params or ())))

    def fetchone(self):
        return self._one

    def __iter__(self):
        return iter(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self, name=None, **kwargs):
        return self._cur

    def transaction(self):
        return nullcontext()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _fake_connect(cur):
    @contextmanager
    def connect():
        yield _FakeConn(cur)

    return connect


def _sql_probe_store(monkeypatch, cur):
    import tex.memory.decision_store as ds_mod
    from tex.memory.decision_store import DurableDecisionStore

    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = DurableDecisionStore(tenant_id="default", bootstrap=False)
    store._postgres_enabled = True  # force the SQL path for the probe
    monkeypatch.setattr(ds_mod, "connect", _fake_connect(cur))
    return store


def test_count_matching_sql_is_tenant_scoped_and_windowed(monkeypatch):
    cur = _FakeCursor(one=(42,))
    store = _sql_probe_store(monkeypatch, cur)
    since = datetime(2026, 7, 10, 4, 0, tzinfo=UTC)

    n = store.count_matching(
        tenant_visible_to="acme", verdict=Verdict.FORBID, since=since
    )

    assert n == 42
    sql, params = cur.executed[-1]
    assert "COUNT(*)" in sql
    assert "tenant_id = %s" in sql  # this store's partition, always bound
    assert "metadata->>'tenant_id'" in sql  # the exhibits visibility rule
    assert "'default'" in sql  # the shared partition stays visible
    assert "verdict = %s" in sql
    assert "decided_at >= %s" in sql
    assert params == ("default", "acme", "FORBID", since)


def test_find_matching_sql_orders_newest_first_with_backstop(monkeypatch):
    cur = _FakeCursor(rows=())
    store = _sql_probe_store(monkeypatch, cur)

    rows = store.find_matching(tenant_visible_to="acme")

    assert rows == ()
    sql, params = cur.executed[-1]
    assert "ORDER BY decided_at DESC" in sql
    assert "LIMIT %s" in sql
    assert params[-1] == 20000  # the runaway backstop, mirroring the held floor


def test_durable_reads_return_none_when_not_durable(monkeypatch):
    """The keyless posture never fabricates a zero: not durable ⇒ None, so the
    exhibits fall back to the cache scan instead of speaking an empty count."""
    from tex.memory.decision_store import DurableDecisionStore

    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = DurableDecisionStore(tenant_id="default", bootstrap=False)

    assert store.count_matching(tenant_visible_to="acme") is None
    assert store.find_matching(tenant_visible_to="acme") is None
