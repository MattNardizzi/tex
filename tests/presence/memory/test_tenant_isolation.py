"""Per-tenant isolation — at the store level AND in the two substrate SQL fixes.

The substrate fixes can't be round-tripped without a live Postgres (the test
default has none), so we prove the security property at the layer it lives in:
the SQL actually sent to the driver is tenant-scoped and binds THIS store's
tenant. A fake connection captures the statement + params, so the test fails if
anyone drops the tenant filter again.
"""

from __future__ import annotations

from uuid import uuid4

from tex.presence.memory import SealedPresenceMemory

from .conftest import (
    FakeCursor,
    fake_connect_factory,
    make_claim_verdict,
    make_decision,
)


# ---- store level: A cannot recall / get / forget B's records ---------------


def test_recall_is_strictly_per_tenant(mem: SealedPresenceMemory):
    a_claim, a_verdict = make_claim_verdict("forbid_count", value=3)
    b_claim, b_verdict = make_claim_verdict("forbid_count", value=7)
    ref_a = mem.seal(tenant="acme", claim=a_claim, verdict=a_verdict)
    ref_b = mem.seal(tenant="globex", claim=b_claim, verdict=b_verdict)

    acme_refs = mem.recall(tenant="acme", query="")
    globex_refs = mem.recall(tenant="globex", query="")

    assert ref_a in acme_refs and ref_b not in acme_refs
    assert ref_b in globex_refs and ref_a not in globex_refs


def test_get_and_forget_cannot_cross_tenant(mem: SealedPresenceMemory):
    a_claim, a_verdict = make_claim_verdict("forbid_count", value=3)
    ref_a = mem.seal(tenant="acme", claim=a_claim, verdict=a_verdict)

    # globex sees nothing of acme's, even with the exact record_id.
    assert mem.get(tenant="globex", record_id=ref_a.record_id) is None
    assert mem.forget(tenant="globex", record_id=ref_a.record_id) is False
    # acme's record survives globex's attempts.
    assert mem.get(tenant="acme", record_id=ref_a.record_id) is not None


# ---- substrate fix 1: DurableEvidenceStore.list_for_aggregate --------------


def test_list_for_aggregate_is_tenant_scoped(monkeypatch):
    import tex.memory.evidence_store as es_mod
    from tex.memory.evidence_store import DurableEvidenceStore

    store = DurableEvidenceStore(tenant_id="acme")  # DATABASE_URL unset → disabled
    store._postgres_enabled = True  # force the SQL path for the test
    cur = FakeCursor(rows=())
    monkeypatch.setattr(es_mod, "connect", fake_connect_factory(cur))

    agg = uuid4()
    store.list_for_aggregate(agg)

    sql, params = cur.executed[-1]
    assert "tenant_id = %s" in sql and "aggregate_id = %s" in sql
    # Tenant is bound FIRST and is this store's tenant — a cross-tenant aggregate
    # id can no longer leak another tenant's chain.
    assert params == ("acme", str(agg))


# ---- substrate fix 2: DurableDecisionStore.delete --------------------------


def test_decision_delete_is_tenant_scoped(monkeypatch):
    import tex.memory.decision_store as ds_mod
    from tex.memory.decision_store import DurableDecisionStore

    store = DurableDecisionStore(tenant_id="acme", bootstrap=False)
    decision = make_decision(final_score=0.5)
    store._cache.save(decision)  # so the cache delete succeeds after the SQL
    store._postgres_enabled = True
    cur = FakeCursor(rowcount=1)
    monkeypatch.setattr(ds_mod, "connect", fake_connect_factory(cur))

    store.delete(decision.decision_id)

    deletes = [(s, p) for (s, p) in cur.executed if "DELETE" in s.upper()]
    assert deletes, "expected a DELETE to be issued"
    sql, params = deletes[-1]
    assert "tenant_id = %s" in sql and "decision_id = %s" in sql
    # A forged/known cross-tenant decision_id now matches zero rows.
    assert params == ("acme", str(decision.decision_id))


# ---- the presence durable mirror is itself tenant-scoped -------------------


def test_presence_mirror_delete_is_tenant_scoped(monkeypatch):
    import tex.presence.memory.durable as dur

    monkeypatch.setattr(dur, "database_url", lambda: "postgresql://fake/db")
    monkeypatch.setattr(dur, "_ddl_applied", True)  # skip DDL; we test the DELETE
    cur = FakeCursor(rowcount=1)
    monkeypatch.setattr(dur, "connect", fake_connect_factory(cur))

    mirror = dur.PresenceDurableMirror()
    assert mirror.is_durable is True

    n = mirror.delete(tenant="acme", record_id="pm-abc")
    assert n == 1
    sql, params = [(s, p) for (s, p) in cur.executed if "DELETE" in s.upper()][-1]
    assert "tenant_id = %s AND record_id = %s" in sql
    assert params == ("acme", "pm-abc")
