"""Tests for tex.events.event (Event model + genesis sentinel)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tex.events.event import Event, _GENESIS_LEDGER_HASH, genesis_ledger_hash


def _make_event(**overrides) -> Event:
    base = {
        "event_id": "evt_abc",
        "kind": "agent_invokes_tool",
        "actor_entity_id": "agent_1",
        "target_entity_id": None,
        "payload": {"tool_id": "search_v1"},
        "timestamp": datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC),
        "sequence_number": 1,
        "upstream_event_ids": (),
        "previous_ledger_hash": "0" * 64,
        "payload_sha256": "a" * 64,
        "record_hash": "b" * 64,
        "pq_signature_b64": "c2lnbmF0dXJl",
        "pq_signing_key_id": "k1",
    }
    base.update(overrides)
    return Event(**base)


def test_event_is_frozen() -> None:
    e = _make_event()
    with pytest.raises(ValidationError):
        e.kind = "mutated"  # type: ignore[misc]


def test_event_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Event(
            event_id="evt_abc",
            kind="x",
            actor_entity_id="a",
            payload={},
            timestamp=datetime.now(UTC),
            sequence_number=1,
            previous_ledger_hash="0" * 64,
            payload_sha256="a" * 64,
            record_hash="b" * 64,
            pq_signature_b64="x",
            pq_signing_key_id="k",
            unknown_field="oops",  # type: ignore[call-arg]
        )


def test_event_default_signature_algorithm() -> None:
    e = _make_event()
    assert e.pq_signature_algorithm == "ecdsa-p256"


def test_event_canonical_record_input_keys() -> None:
    e = _make_event()
    keys = set(e.canonical_record_input().keys())
    assert keys == {
        "kind",
        "actor_entity_id",
        "target_entity_id",
        "payload_sha256",
        "timestamp",
        "sequence_number",
        "upstream_event_ids",
        "previous_ledger_hash",
        "tool_receipt_id",
    }


def test_event_canonical_record_input_excludes_signature_fields() -> None:
    """The signature is computed *over* canonical_record_input, so it must not
    contain itself or the record_hash."""
    e = _make_event()
    inp = e.canonical_record_input()
    assert "record_hash" not in inp
    assert "pq_signature_b64" not in inp
    assert "pq_signing_key_id" not in inp
    assert "pq_signature_algorithm" not in inp
    assert "event_id" not in inp


def test_event_canonical_record_input_includes_full_tamper_surface() -> None:
    """Every field that should break the chain on mutation must appear."""
    e = _make_event(
        target_entity_id="tool_x",
        upstream_event_ids=("evt_a", "evt_b"),
        tool_receipt_id="rcpt_1",
    )
    inp = e.canonical_record_input()
    assert inp["kind"] == "agent_invokes_tool"
    assert inp["actor_entity_id"] == "agent_1"
    assert inp["target_entity_id"] == "tool_x"
    assert inp["payload_sha256"] == "a" * 64
    assert inp["sequence_number"] == 1
    assert inp["upstream_event_ids"] == ["evt_a", "evt_b"]
    assert inp["previous_ledger_hash"] == "0" * 64
    assert inp["tool_receipt_id"] == "rcpt_1"


def test_genesis_ledger_hash_is_64_zeros() -> None:
    assert _GENESIS_LEDGER_HASH == "0" * 64
    assert genesis_ledger_hash() == "0" * 64
    assert len(genesis_ledger_hash()) == 64
