"""
V16 tests: ConnectorHealthStore — per-(tenant, connector) health.

Status thresholds: 0 fails = HEALTHY, 1-2 = DEGRADED, 3+ = OFFLINE.
Tests cover transitions, isolation between tenants and connectors,
and failure reset on success.
"""

from __future__ import annotations

from tex.stores.connector_health import (
    ConnectorHealthStatus,
    ConnectorHealthStore,
)


class TestStatusDerivation:
    def test_unknown_when_never_seen(self) -> None:
        store = ConnectorHealthStore()
        assert store.get(tenant_id="acme", connector_name="x") is None

    def test_healthy_after_one_success(self) -> None:
        store = ConnectorHealthStore()
        h = store.record_success(
            tenant_id="acme",
            connector_name="openai_mock",
            discovery_source="openai",
            candidate_count=4,
        )
        assert h.status is ConnectorHealthStatus.HEALTHY
        assert h.last_candidate_count == 4

    def test_degraded_after_one_failure(self) -> None:
        store = ConnectorHealthStore()
        h = store.record_failure(
            tenant_id="acme",
            connector_name="openai_mock",
            discovery_source="openai",
            error="boom",
        )
        assert h.status is ConnectorHealthStatus.DEGRADED
        assert h.consecutive_failures == 1

    def test_degraded_after_two_failures(self) -> None:
        store = ConnectorHealthStore()
        store.record_failure(
            tenant_id="acme", connector_name="x", discovery_source="openai",
            error="e1",
        )
        h = store.record_failure(
            tenant_id="acme", connector_name="x", discovery_source="openai",
            error="e2",
        )
        assert h.status is ConnectorHealthStatus.DEGRADED
        assert h.consecutive_failures == 2

    def test_offline_after_three_failures(self) -> None:
        store = ConnectorHealthStore()
        for i in range(3):
            h = store.record_failure(
                tenant_id="acme", connector_name="x", discovery_source="openai",
                error=f"e{i}",
            )
        assert h.status is ConnectorHealthStatus.OFFLINE
        assert h.consecutive_failures == 3

    def test_success_resets_consecutive_failures(self) -> None:
        store = ConnectorHealthStore()
        for _ in range(3):
            store.record_failure(
                tenant_id="acme", connector_name="x", discovery_source="openai",
                error="e",
            )
        h = store.record_success(
            tenant_id="acme", connector_name="x", discovery_source="openai",
            candidate_count=10,
        )
        assert h.status is ConnectorHealthStatus.HEALTHY
        assert h.consecutive_failures == 0
        # Last failure timestamp is preserved for context.
        assert h.last_failure_at is not None


class TestIsolation:
    def test_per_tenant_isolation(self) -> None:
        store = ConnectorHealthStore()
        store.record_failure(
            tenant_id="acme", connector_name="x", discovery_source="s", error="e",
        )
        # Different tenant — should be unaffected.
        h_other = store.get(tenant_id="globex", connector_name="x")
        assert h_other is None

    def test_per_connector_isolation(self) -> None:
        store = ConnectorHealthStore()
        store.record_failure(
            tenant_id="acme", connector_name="conn_a", discovery_source="s", error="e",
        )
        h_b = store.get(tenant_id="acme", connector_name="conn_b")
        assert h_b is None

    def test_list_for_tenant_is_scoped(self) -> None:
        store = ConnectorHealthStore()
        store.record_success(
            tenant_id="acme", connector_name="a", discovery_source="s",
            candidate_count=1,
        )
        store.record_success(
            tenant_id="acme", connector_name="b", discovery_source="s",
            candidate_count=1,
        )
        store.record_success(
            tenant_id="globex", connector_name="c", discovery_source="s",
            candidate_count=1,
        )
        records = store.list_for_tenant("acme")
        assert len(records) == 2
        assert {r.connector_name for r in records} == {"a", "b"}


class TestTenantNormalization:
    def test_tenant_id_is_casefolded(self) -> None:
        store = ConnectorHealthStore()
        store.record_success(
            tenant_id=" Acme ", connector_name="x", discovery_source="s",
            candidate_count=1,
        )
        records = store.list_for_tenant("ACME")
        assert len(records) == 1
        assert records[0].tenant_id == "acme"
