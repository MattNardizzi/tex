"""Tests for the NeuroTaint MemoryStream (Thread 11)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
)
from tex.governance.private_data_exec.ifc.memory import MemoryItem, MemoryStream


def _label_untrusted() -> IfcLabel:
    return IfcLabel(
        integrity=IntegrityLevel.TOOL_UNTRUSTED,
        confidentiality=ConfidentialityLevel.INTERNAL,
        capacity=CapacityType.TEXT,
    )


def _item(session_key: str, content_hash: str) -> MemoryItem:
    return MemoryItem(
        session_key=session_key,
        content_hash=content_hash,
        label=_label_untrusted(),
        recorded_at=datetime.now(UTC),
        reason="test",
    )


def test_record_and_lookup_hit() -> None:
    stream = MemoryStream()
    item = _item("agent:1", "hash:abc")
    stream.record(item)
    hits = stream.lookup(session_key="agent:1", content_hashes={"hash:abc"})
    assert len(hits) == 1
    assert hits[0].content_hash == "hash:abc"


def test_lookup_miss_returns_empty() -> None:
    stream = MemoryStream()
    hits = stream.lookup(session_key="agent:1", content_hashes={"hash:xyz"})
    assert hits == ()


def test_lookup_isolates_by_session_key() -> None:
    stream = MemoryStream()
    stream.record(_item("agent:A", "hash:1"))
    stream.record(_item("agent:B", "hash:1"))
    hits = stream.lookup(session_key="agent:A", content_hashes={"hash:1"})
    assert len(hits) == 1
    assert hits[0].session_key == "agent:A"


def test_capacity_bound_enforced() -> None:
    stream = MemoryStream(capacity=2)
    stream.record(_item("s", "h1"))
    stream.record(_item("s", "h2"))
    stream.record(_item("s", "h3"))
    assert len(stream) == 2
    # First entry should have been evicted (FIFO LRU).
    assert stream.lookup(session_key="s", content_hashes={"h1"}) == ()


def test_ttl_eviction() -> None:
    stream = MemoryStream(ttl=timedelta(seconds=0))
    # Already-expired item.
    stale = MemoryItem(
        session_key="s",
        content_hash="h",
        label=_label_untrusted(),
        recorded_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    stream.record(stale)
    # The next put triggers eviction.
    fresh = _item("s", "fresh")
    stream.record(fresh)
    assert stream.lookup(session_key="s", content_hashes={"h"}) == ()


def test_clear_drops_everything() -> None:
    stream = MemoryStream()
    stream.record(_item("s", "h"))
    stream.clear()
    assert len(stream) == 0


def test_session_items_returns_only_matches() -> None:
    stream = MemoryStream()
    stream.record(_item("a", "h1"))
    stream.record(_item("b", "h2"))
    a_items = stream.session_items("a")
    assert len(a_items) == 1
    assert a_items[0].session_key == "a"


def test_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError):
        MemoryStream(capacity=0)
