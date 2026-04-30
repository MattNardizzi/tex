"""
V16 tests: ScanRunStore — per-tenant locking, idempotency, lifecycle.

The store is the spine of V16 hardening: every scan opens a run,
holds the per-tenant lock, and closes it. Discovery service tests
exercise the integration; these tests exercise the store contract
in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.stores.scan_runs import ScanLockHeld, ScanRunStatus, ScanRunStore


class TestAcquireLifecycle:
    def test_first_acquire_returns_running_run(self) -> None:
        store = ScanRunStore()
        run, is_new = store.acquire(tenant_id="acme", trigger="manual")
        assert is_new is True
        assert run.status is ScanRunStatus.RUNNING
        assert run.tenant_id == "acme"

    def test_tenant_normalization(self) -> None:
        store = ScanRunStore()
        run, _ = store.acquire(tenant_id="  ACME  ", trigger="manual")
        assert run.tenant_id == "acme"

    def test_complete_releases_lock(self) -> None:
        store = ScanRunStore()
        run, _ = store.acquire(tenant_id="acme", trigger="manual")
        store.complete(
            run.run_id,
            ledger_seq_start=0,
            ledger_seq_end=2,
            registry_state_hash="abc",
            policy_version="v1",
            summary={"candidates_seen": 3},
        )

        # Now a second acquire for same tenant must succeed.
        run2, is_new = store.acquire(tenant_id="acme", trigger="manual")
        assert is_new is True
        assert run2.run_id != run.run_id
        assert run2.status is ScanRunStatus.RUNNING

    def test_fail_releases_lock(self) -> None:
        store = ScanRunStore()
        run, _ = store.acquire(tenant_id="acme", trigger="manual")
        store.fail(run.run_id, error="boom")

        run2, is_new = store.acquire(tenant_id="acme", trigger="manual")
        assert is_new is True
        assert run2.run_id != run.run_id


class TestPerTenantLock:
    def test_concurrent_acquire_raises_lock_held(self) -> None:
        store = ScanRunStore()
        store.acquire(tenant_id="acme", trigger="manual")
        with pytest.raises(ScanLockHeld) as exc:
            store.acquire(tenant_id="acme", trigger="manual")
        assert exc.value.tenant_id == "acme"

    def test_different_tenants_can_run_concurrently(self) -> None:
        store = ScanRunStore()
        store.acquire(tenant_id="acme", trigger="manual")
        # Different tenant: should not collide.
        run2, is_new = store.acquire(tenant_id="globex", trigger="manual")
        assert is_new is True
        assert run2.tenant_id == "globex"

    def test_stale_lock_is_reclaimed(self) -> None:
        store = ScanRunStore(stale_lock_seconds=1)
        run1, _ = store.acquire(tenant_id="acme", trigger="manual")
        # Force the lock to look stale.
        run1.last_heartbeat_at = datetime.now(UTC) - timedelta(seconds=10)

        run2, is_new = store.acquire(tenant_id="acme", trigger="manual")
        assert is_new is True
        assert run2.run_id != run1.run_id
        # Old run was force-failed.
        reloaded = store.get(run1.run_id)
        assert reloaded is not None
        assert reloaded.status is ScanRunStatus.FAILED


class TestIdempotency:
    def test_same_idempotency_key_returns_same_run(self) -> None:
        store = ScanRunStore()
        run1, is_new1 = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="req-123",
        )
        store.complete(
            run1.run_id,
            ledger_seq_start=0, ledger_seq_end=1,
            registry_state_hash="h", policy_version="v",
            summary={"candidates_seen": 1},
        )
        # Replay with same key returns same run.
        run2, is_new2 = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="req-123",
        )
        assert is_new1 is True
        assert is_new2 is False
        assert run2.run_id == run1.run_id

    def test_different_idempotency_keys_produce_different_runs(self) -> None:
        store = ScanRunStore()
        run1, _ = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="req-1",
        )
        store.complete(
            run1.run_id,
            ledger_seq_start=None, ledger_seq_end=None,
            registry_state_hash=None, policy_version=None,
            summary={},
        )
        run2, _ = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="req-2",
        )
        assert run1.run_id != run2.run_id

    def test_idempotency_replay_works_even_when_lock_already_released(self) -> None:
        store = ScanRunStore()
        run1, _ = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="key",
        )
        store.complete(
            run1.run_id,
            ledger_seq_start=0, ledger_seq_end=0,
            registry_state_hash="h", policy_version=None,
            summary={"candidates_seen": 1},
        )
        # Lock is released now. Replay should still get same run.
        run2, is_new = store.acquire(
            tenant_id="acme", trigger="manual", idempotency_key="key",
        )
        assert is_new is False
        assert run2.run_id == run1.run_id


class TestReads:
    def test_active_for_tenant_when_running(self) -> None:
        store = ScanRunStore()
        run, _ = store.acquire(tenant_id="acme", trigger="manual")
        active = store.active_for_tenant("acme")
        assert active is not None
        assert active.run_id == run.run_id

    def test_active_for_tenant_when_completed(self) -> None:
        store = ScanRunStore()
        run, _ = store.acquire(tenant_id="acme", trigger="manual")
        store.complete(
            run.run_id,
            ledger_seq_start=None, ledger_seq_end=None,
            registry_state_hash=None, policy_version=None,
            summary={},
        )
        assert store.active_for_tenant("acme") is None

    def test_latest_completed_for_tenant(self) -> None:
        store = ScanRunStore()
        # Run 1 completed
        r1, _ = store.acquire(tenant_id="acme", trigger="manual")
        store.complete(
            r1.run_id,
            ledger_seq_start=0, ledger_seq_end=2,
            registry_state_hash="h1", policy_version="v",
            summary={"candidates_seen": 3},
        )
        # Run 2 completed
        r2, _ = store.acquire(tenant_id="acme", trigger="manual")
        store.complete(
            r2.run_id,
            ledger_seq_start=3, ledger_seq_end=4,
            registry_state_hash="h2", policy_version="v",
            summary={"candidates_seen": 2},
        )
        latest = store.latest_completed_for_tenant("acme")
        assert latest is not None
        assert latest.run_id == r2.run_id
        assert latest.registry_state_hash == "h2"

    def test_list_recent_filters_by_tenant(self) -> None:
        store = ScanRunStore()
        store.acquire(tenant_id="acme", trigger="manual")
        store.acquire(tenant_id="globex", trigger="manual")
        acme = store.list_recent(tenant_id="acme", limit=10)
        assert len(acme) == 1
        assert acme[0].tenant_id == "acme"
