"""forget(): present→unrecoverable returns True; absent returns False; a durable
delete failure RAISES rather than lying about success."""

from __future__ import annotations

import pytest

from tex.presence.memory import SealedPresenceMemory
from tex.presence.memory.records import SealedPresenceRecord

from .conftest import make_claim_verdict


def test_forget_makes_record_unrecoverable(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)

    assert mem.get(tenant="acme", record_id=ref.record_id) is not None
    assert mem.forget(tenant="acme", record_id=ref.record_id) is True

    # Unrecoverable from this store: neither get nor recall returns it.
    assert mem.get(tenant="acme", record_id=ref.record_id) is None
    assert ref not in mem.recall(tenant="acme", query="")


def test_forget_absent_id_returns_false(mem: SealedPresenceMemory):
    assert mem.forget(tenant="acme", record_id="pm-nope") is False


def test_forget_other_tenant_id_returns_false(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    # globex cannot forget acme's record even with the exact id.
    assert mem.forget(tenant="globex", record_id=ref.record_id) is False
    # ... and acme's record is untouched.
    assert mem.get(tenant="acme", record_id=ref.record_id) is not None


def test_double_forget_second_is_false(mem: SealedPresenceMemory):
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    assert mem.forget(tenant="acme", record_id=ref.record_id) is True
    assert mem.forget(tenant="acme", record_id=ref.record_id) is False


# ---- the unrecoverable-lie guard: durable failure must RAISE, not return True --


class _RaisingMirror:
    """A durable mirror whose DELETE always fails — to prove forget never reports
    success while a durable copy may survive."""

    is_durable = True

    def __init__(self) -> None:
        self.upserts: list[str] = []

    def hydrate(self, tenants):  # noqa: ANN001
        return {}

    def list_for_tenant(self, tenant):  # noqa: ANN001
        return ()

    def upsert(self, record: SealedPresenceRecord) -> None:
        self.upserts.append(record.record_id)

    def delete(self, *, tenant: str, record_id: str) -> int:
        raise RuntimeError("postgres unreachable")


def test_forget_raises_and_restores_on_durable_delete_failure():
    mirror = _RaisingMirror()
    mem = SealedPresenceMemory(mirror=mirror)
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)

    with pytest.raises(RuntimeError, match="postgres unreachable"):
        mem.forget(tenant="acme", record_id=ref.record_id)

    # forget did NOT lie: the record is still present (re-inserted on failure),
    # so a caller cannot mistake the raise for a successful forget.
    assert mem.get(tenant="acme", record_id=ref.record_id) is not None
    assert ref in mem.recall(tenant="acme", query="")


# ---- forget drives the mirror DELETE (rowcount path) -----------------------


class _CountingMirror:
    """A durable mirror that records calls and returns a configurable rowcount."""

    is_durable = True

    def __init__(self, rowcount: int = 1) -> None:
        self._rowcount = rowcount
        self.deletes: list[tuple[str, str]] = []
        self.upserts: list[str] = []

    def hydrate(self, tenants):  # noqa: ANN001
        return {}

    def list_for_tenant(self, tenant):  # noqa: ANN001
        return ()

    def upsert(self, record: SealedPresenceRecord) -> None:
        self.upserts.append(record.record_id)

    def delete(self, *, tenant: str, record_id: str) -> int:
        self.deletes.append((tenant, record_id))
        return self._rowcount


def test_forget_through_durable_mirror_deletes_the_row():
    mirror = _CountingMirror(rowcount=1)
    mem = SealedPresenceMemory(mirror=mirror)
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    assert mirror.upserts == [ref.record_id]  # write-through on seal

    assert mem.forget(tenant="acme", record_id=ref.record_id) is True
    assert mirror.deletes == [("acme", ref.record_id)]  # tenant-scoped delete issued
    assert mem.get(tenant="acme", record_id=ref.record_id) is None


def test_forget_completes_when_durable_copy_never_persisted():
    # rowcount==0 → the mirror matched no row: the durable copy never persisted
    # (a best-effort seal-time upsert that had failed). The in-memory record WAS
    # present, so there is no durable survivor and forget still completes.
    mirror = _CountingMirror(rowcount=0)
    mem = SealedPresenceMemory(mirror=mirror)
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)

    assert mem.forget(tenant="acme", record_id=ref.record_id) is True
    assert mirror.deletes == [("acme", ref.record_id)]
    assert mem.get(tenant="acme", record_id=ref.record_id) is None


def test_concurrent_forget_returns_exactly_one_true():
    # The lock makes the membership-check+pop atomic: N racing forgets of the same
    # record yield exactly one True (the winner) and N-1 False.
    import threading

    mem = SealedPresenceMemory(mirror=None)
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)

    n = 8
    results: list[bool] = []
    barrier = threading.Barrier(n)

    def worker() -> None:
        barrier.wait()  # maximize contention on the same record
        results.append(mem.forget(tenant="acme", record_id=ref.record_id))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert results.count(False) == n - 1
