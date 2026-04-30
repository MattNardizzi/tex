"""
V15 tests: DriftEventStore.

Append-only log with kind filter, tenant filter, ring-buffer cap.
"""

from __future__ import annotations

from uuid import uuid4

from tex.stores.drift_events import DriftEvent, DriftEventKind, DriftEventStore


def _emit_one(
    store: DriftEventStore,
    *,
    tenant_id: str = "default",
    kind: DriftEventKind = DriftEventKind.NEW_AGENT,
    recon_key: str = "openai:asst_abc",
    severity: str = "INFO",
    summary: str = "test event",
    details: dict | None = None,
) -> DriftEvent:
    return store.emit(
        tenant_id=tenant_id,
        kind=kind,
        reconciliation_key=recon_key,
        discovery_source="openai",
        agent_id=uuid4(),
        severity=severity,
        summary=summary,
        details=details or {},
        scan_run_id=uuid4(),
    )


class TestDriftEventStoreFallback:
    def test_falls_back_when_no_dsn(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        assert store.is_durable is False
        assert len(store) == 0

    def test_emit_appends(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        event = _emit_one(store)
        assert event.kind is DriftEventKind.NEW_AGENT
        assert event.event_id
        assert len(store) == 1

    def test_to_dict_serializable_shape(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        event = _emit_one(store, summary="hello")
        d = event.to_dict()
        assert d["kind"] == "NEW_AGENT"
        assert d["summary"] == "hello"
        assert d["event_id"] == str(event.event_id)


class TestDriftEventStoreFilters:
    def test_list_recent_returns_newest_first(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        first = _emit_one(store, summary="first")
        second = _emit_one(store, summary="second")
        third = _emit_one(store, summary="third")
        recent = store.list_recent(limit=10)
        # Newest first.
        assert recent[0].event_id == third.event_id
        assert recent[1].event_id == second.event_id
        assert recent[2].event_id == first.event_id

    def test_list_for_tenant(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        _emit_one(store, tenant_id="tenant-a")
        _emit_one(store, tenant_id="tenant-a")
        _emit_one(store, tenant_id="tenant-b")
        a = store.list_for_tenant("tenant-a", limit=10)
        b = store.list_for_tenant("tenant-b", limit=10)
        assert len(a) == 2
        assert len(b) == 1

    def test_list_by_kind(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        _emit_one(store, kind=DriftEventKind.NEW_AGENT)
        _emit_one(store, kind=DriftEventKind.AGENT_CHANGED)
        _emit_one(store, kind=DriftEventKind.AGENT_DISAPPEARED)
        _emit_one(store, kind=DriftEventKind.NEW_AGENT)
        new_only = store.list_by_kind(DriftEventKind.NEW_AGENT, limit=10)
        changed_only = store.list_by_kind(DriftEventKind.AGENT_CHANGED, limit=10)
        gone = store.list_by_kind(DriftEventKind.AGENT_DISAPPEARED, limit=10)
        assert len(new_only) == 2
        assert len(changed_only) == 1
        assert len(gone) == 1

    def test_limit_caps_results(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        for _ in range(20):
            _emit_one(store)
        assert len(store.list_recent(limit=5)) == 5
        assert len(store.list_recent(limit=100)) == 20


class TestRingBuffer:
    def test_buffer_caps_at_limit(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore(cache_limit=10)
        for i in range(25):
            _emit_one(store, summary=f"event-{i}")
        # Only the most recent 10 are retained.
        assert len(store) == 10
        recent = store.list_recent(limit=20)
        # Newest ones survived.
        assert recent[0].summary == "event-24"


class TestQueryHistory:
    def test_in_memory_query_with_filters(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        _emit_one(store, tenant_id="t1", kind=DriftEventKind.NEW_AGENT)
        _emit_one(store, tenant_id="t2", kind=DriftEventKind.NEW_AGENT)
        _emit_one(store, tenant_id="t1", kind=DriftEventKind.AGENT_CHANGED)
        results = store.query_history(tenant_id="t1", kind=DriftEventKind.NEW_AGENT)
        assert len(results) == 1
        assert results[0].tenant_id == "t1"
        assert results[0].kind is DriftEventKind.NEW_AGENT
